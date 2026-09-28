# Versioned BOM installer (Stage 1)

The gateway VM installs itself from a versioned Bill of Materials. The old
setup Job, which logged in to the VM over SSH and ran scripts, is gone.

## What runs where

```text
helm / Argo ──► openshell-saw chart
                 ├─ VirtualMachine (+ root disk clone)
                 ├─ <vm>-installer ConfigMap ─┐  installer-bom.yaml, config.json,
                 │                            │  apply_bom.py, setup-dashboard.sh
                 ├─ saw-bom-profiles ConfigMap ┤  (saw-bom chart: SAW-BOM profiles)
                 ├─ provider Secrets ─────────┤  inference, web-search, ...
                 ├─ <vm>-cloudinit Secret     │  attached as read-only disks
                 └─ <vm>-prepare Job          │  (cluster-side only, never touches the VM)
                                              ▼
VM boot ─► cloud-init ─► saw-install.service ─► saw-apply.service
                          apply_bom.py install    apply_bom.py apply
                          (root)                  (root → runs profiles as cloud-user)
```

- **saw-install** pulls each BOM component image by digest with podman,
  copies the binary out, checks `--version` against the BOM, installs it
  atomically into `/usr/local/bin`, re-syncs `gateway.env`, `gateway.toml`
  and the route-SAN drop-in from the installer disk, then starts the
  user-level `openshell-gateway.service` (restarting it if a binary or the
  config changed; an owed restart survives a failed attempt). Unchanged
  components are skipped, so reboots pull nothing.
- **saw-apply** runs only after `install` finished for the same BOM. It reads
  the profiles and mounted Secrets, then runs the profile step as
  `cloud-user` with the plan on stdin. Provider keys are passed to the CLI
  as `--credential NAME` with the value in the environment, never in argv;
  existing providers get the current key via `provider update`. If the gateway has no profile
  for a provider type (e.g. `brave` when governance is off), the installer imports the copy
  shipped in `charts/openshell-saw/files/provider-profiles/` (kept identical to
  `charts/governance-policy/profiles/`) into that workspace; a type with no shipped profile is
  skipped with a warning. It registers a local **mTLS**
  gateway entry, creates workspaces, providers, inference routes and
  sandboxes, optionally starts the dashboard, and verifies the result.
- The prepare Job only bootstraps the golden image DataSource and registers
  the dashboard redirect URI in Keycloak (admin API). It has no VM access.

cloud-init runs once per VM, so it only writes static files (mount script,
units) and first-boot copies of the gateway config. Everything that can
change after install (BOM, gateway config, Secret list, route host) is on
the installer disk and is re-read on every boot.

Both steps also run on every boot. Status is in `/var/lib/saw/status.json`
(one section per step), and `/var/lib/saw/ready` exists only when both
steps succeeded for the same BOM. Logs go to the serial console:

```bash
oc logs -f -l vm.kubevirt.io/name=<vm> -c guest-console-log --tail=-1
# or: make openshell-saw-logs OPENSHELL_SAW_NAME=<vm>
```

## Namespaces

| Namespace | What lives there |
| --- | --- |
| `saw-<name>` (one per SAW) | the SAW's VM, its installer/profile ConfigMaps, its provider Secrets, prepare Job. Labelled `openshell.pattern/saw=true`. |
| `openshell-agents` (shared, `NS`) | golden image DataSource, image builds, governance interceptor + policy |
| `saw-keycloak` (`KEYCLOAK_NS`, any name) | Keycloak and the RHBK operator |

- A VM can only attach ConfigMaps/Secrets from its own namespace, so each
  SAW's `inference`/`web-search` Secrets and `saw-bom-profiles` ConfigMap
  must be in its `saw-<name>` namespace.
- The governance interceptor admits gateway VMs from namespaces labelled
  `openshell.pattern/saw=true` (`make openshell-saw-create` and
  `values-prod.yaml` set it). Without the label, sandbox creation is denied
  (`fail_closed`).
- Each SAW gets a Role in the golden image namespace that lets its
  `default` service account (which KubeVirt clones the root disk as) and its
  prepare Job clone the image (`datavolumes/source`) and create the
  DataSource there on first use.
- Quickstart: `make openshell-saw-create OPENSHELL_SAW_NAME=alice` deploys
  into `saw-alice`; override with `SAW_NS=...`. Keycloak is looked up in
  `KEYCLOAK_NS` (default `saw-keycloak`; `KEYCLOAK_NS=keycloak` to use a Keycloak the cluster already runs there). `make openshell-saw-delete` also
  deletes the namespace if it carries the SAW label.
- Pattern: `values-prod.yaml` puts Keycloak/RHBK in `saw-keycloak` (so it never
  collides with a platform Keycloak in `keycloak`, as on many demo clusters).
  Each person is one entry in [`overrides/saw-users.yaml`](../overrides/saw-users.yaml).
  The `saw-users` chart creates namespace `saw-<name>` and the three apps
  (secrets, bill of materials, and virtual machine `<name>`).

## Authentication

| Who | How | Role |
| --- | --- | --- |
| In-VM installer (`apply_bom.py`) | its own mTLS client certificate `CN=saw-installer, OU=openshell-admin`, gateway entry `saw-installer` | platform admin (`openshell-admin`) |
| Users (laptop CLI, dashboard) | their own OIDC token from Keycloak | from `realm_access.roles`: `openshell-admin` / `openshell-user` |

The installer never logs in to Keycloak and never configures the CLI for
OAuth. Set `accessControl.ownerSubject` (the owner's `openshell whoami`
subject) to make the owner admin of every workspace the installer creates.

To use the gateway from a laptop, register the gateway Route with OIDC in
your local OpenShell CLI and log in with your Keycloak account. You need the
gateway CA (`scripts/extract-gateway-ca.sh`); the Route hostname is added to
the gateway certificate by cloud-init.

The gateway takes an mTLS caller's roles from the client certificate's OU.
The certificate the gateway generates for local use carries
`OU=openshell-user`, which is not enough once OIDC RBAC is on, so the
installer issues its own `CN=saw-installer, OU=openshell-admin` certificate
with the gateway's CA (`~/.local/state/openshell/tls`), keeps it in
`~/.local/state/saw-installer/tls` (re-issued when missing, signed by a
different CA, or within 30 days of expiry) and registers it as the
`saw-installer` gateway entry. The default `openshell` entry is left alone.

## SSH into the VM

Provisioning never uses SSH. For debugging, the VM's `accessCredentials`
point at the `<name>-ssh-pubkey` Secret, which the chart creates empty.
KubeVirt's guest agent writes every key in it into `cloud-user`'s
`authorized_keys`, also while the VM runs
([KubeVirt docs](https://kubevirt.io/user-guide/user_workloads/accessing_virtual_machines/)).

```bash
make openshell-saw-vm-ssh OPENSHELL_SAW_NAME=alice            # interactive shell
make openshell-saw-vm-ssh OPENSHELL_SAW_NAME=alice CMD='sudo cat /var/lib/saw/status.json'
```

The target adds `$(SSH_KEY_PATH).pub` to the Secret under your login name
(`KEY_NAME=` to change), waits until the VM accepts the key, then runs
`virtctl ssh` (stdin closed for a `CMD=` command, so `openshell sandbox exec`
inside it does not wait for input). make expands `$(...)` in `CMD=`, so write
`$$(...)` or call `scripts/openshell-saw-vm-ssh.sh` directly for command
substitution. The chart never sets the Secret's `data`, so added keys
survive upgrades; remove one with
`oc patch secret alice-ssh-pubkey -n saw-alice --type json -p '[{"op":"remove","path":"/data/<name>"}]'`.
The guest needs SELinux boolean `virt_qemu_ga_manage_ssh=on`; cloud-init and
`saw-install` set it.

## Upgrading

1. Change `bom:` in the chart values (versions + digests; tags are refused
   at render time and by the installer).
2. Sync/upgrade the chart. The VM template changes, so KubeVirt marks the VM
   `RestartRequired`.
3. `virtctl restart <vm>` (or `make openshell-saw-restart`). On boot,
   `saw-install` installs only the changed components.

Profile or Secret changes are applied the same way (restart).

## Testing

```bash
make test-installer        # installer + chart tests; chart tests need helm
```

- `tests/installer`: the real `apply_bom.py` against fake `podman`,
  `openshell`, `nemoclaw` and `sudo` executables: BOM validation, component
  install/skip/upgrade/rollback-on-failure, profile apply and idempotency,
  mTLS-only access, credential masking, status/ready handling, dry-run.
- `tests/scripts`: `openshell-saw-vm-ssh.sh` against fake `oc`/`virtctl`
  (key added via patch file, other keys kept, waits for sync, timeouts).
- `tests/charts`: renders both charts, checks VM disks ↔ mount script ↔
  Secrets, systemd units, gateway TOML (parsed), render-time guards, and
  runs the shipped installer's `validate` against the rendered ConfigMaps.

## Signing

`signing.mode` is `off`, `warn`, or `enforce`. The chart default is `warn`.
On the pattern path set it in `defaults.openshellSaw` in
`charts/saw-users/values.yaml`, or in one user's `values`. `enforce` fails
at render time unless `signing.trustKeys` or both `signing.identity` and
`signing.issuer` are set.

Each OpenShell component in the InstallerBOM may name its signer:

```yaml
signature:
  keyRef: openshell          # /etc/saw/trust/openshell.pub in the golden image
# or, for keyless signing:
# identity: https://github.com/org/repo/.github/workflows/release.yml@refs/tags/v1
# issuer: https://token.actions.githubusercontent.com
```

`warn` installs the component and records `signature: unsigned` (or `failed`)
in `/var/lib/saw/status.json`. `enforce` stops `saw-install` before any
binary is replaced. The message is `image <ref> is not signed by <signer>`.
`saw-install.service` runs `/usr/libexec/saw/verify-bundle` before
`apply_bom.py`. That program is part of the golden image. A changed
`apply_bom.py` without a new `bundle.sigstore.json` stops an `enforce` boot
and leaves the binaries already on disk running. `warn` logs the unsigned
bundle and continues. An image built before this file exists has no verifier:
`warn` and `off` still boot, `enforce` does not.

The golden image also ships `/etc/saw/trust/` (the trust root),
`/etc/containers/registries.d/saw.yaml` (`use-sigstore-attachments: true`
for `quay.io/opendatahub`), and `/etc/saw/policy/enforce.json`. The system
policy stays permissive so `warn` can still pull. `enforce` pulls through
`/usr/libexec/saw/podman-signed-pull`, which uses the enforce policy for
that one pull.

Spike on the `quay.io/opendatahub/odh-openshell-*` digests in
`charts/openshell-saw/values.yaml`: each digest has a cosign `.sig` tag and
an empty certificate, so the signature is key-based, not Fulcio keyless.
The public key is not in the signature and is not published next to the
image. The gateway VM's Podman is 5.8 (newer than 4.4). Rekor answers from
the VM. Key-based trust is the one that works without Fulcio, including
air-gapped, once the publisher key is placed in `/etc/saw/trust`. Until
that key is known, leave `signing.mode` at `warn`. Do not put a guessed key
in the image.

Key custody for the installer bundle: the private key is a GitHub Actions
secret named `COSIGN_PRIVATE_KEY`, never a file in git. The public key is
the matching `*.pub` added to the golden image under `/etc/saw/trust` and
listed in `signing.trustKeys`. Rotation: generate a new cosign key pair,
add the new public key beside the old one, rebuild the golden image, sign
new bundles with the new key (`.github/workflows/sign-installer-bundle.yml`),
then drop the old public key on the following image build. A bundle signed
only by the retired key then fails `enforce`.

## Live inputs

`vm.liveInputs` defaults to `false`. The installer ConfigMap, `saw-bom-profiles`,
and provider Secrets are iso9660 disks filled at boot. Set it to `true` to
serve those same objects over virtiofs. The guest mounts them at the same
`/run/saw` paths. A path unit starts `saw-reconcile` after a change, and a
60-second timer is the fallback. Reconcile waits 10 seconds so one Helm
upgrade is one run, holds `/run/saw/lock` together with the boot units, and
then:

- runs `install` when the installer tree changed (BOM or gateway config).
  Unchanged binaries are skipped. The gateway restarts only when a binary
  or its config changed.
- runs `apply` when profiles or Secrets changed. Existing providers get
  `provider update` with the new key. Sandboxes keep running.
- writes the applied hashes to `inputs` in `/var/lib/saw/status.json`.
  `make openshell-saw-status` shows whether that matches the cluster.

Spike on OpenShift 4.22 (virtiofs is part of the API; no extra feature gate):
a ConfigMap attached to a Fedora 44 VM was visible in the guest, a content
change and a new key appeared together in about 37 seconds, and writing to
the mount was denied. The kernel reports the mount `rw`, and the files are
labeled `virtiofs_t`. SELinux has no xattr handler for virtiofs and falls
back to genfs; reads still succeed. Live migration of that VM was refused
because the root disk is ReadWriteOnce. The refusal did not mention
virtiofs. Migration was not retested with a shared disk.

These still need a restart: VM size, disks, and anything cloud-init writes
(the reconcile units included). Turning `vm.liveInputs` on does not edit an
existing VM's cloud-init. Recreate the VM after the value is true. With
live inputs, a change to the installer ConfigMap or a provider Secret does
not set `RestartRequired`. The cloud-init checksum still does.

## Removing things from a profile

`prune.mode` is `off`, `report`, or `on`. The default is `report`: the
installer logs `would delete ...` and deletes nothing. `on` deletes. Even
then, `prune.sandboxes` defaults to `false`, so sandboxes stay until that is
set to `true`. This is per VM. It is not `pruneOnRemove`, which only decides
whether removing a user from `overrides/saw-users.yaml` also deletes that
user's VM.

The installer records objects it creates in `/var/lib/saw/managed.json`.
Only those objects can be removed. A workspace, provider, or sandbox created
by hand is never deleted. The first successful apply adopts whatever already
matches the current profiles and does not delete anything. Deletion order is
sandboxes, the workspace inference route, providers, provider profiles the
installer imported, then workspaces. The `default` workspace and the system
inference route are never deleted. A workspace is deleted only when it is
empty afterwards; otherwise it is kept and the log names what is left in it.

Workspaces and sandboxes are labeled `saw.redhat.com/managed=true` (OpenShell
0.0.116 accepts labels on those two kinds, and on no other kind this installer
creates). Providers, inference routes, and imported provider profiles are
identified by the ledger alone. A missing or empty profile ConfigMap fails
the apply and deletes nothing.

Spike on the gateway CLI: `workspace delete`, `sandbox delete`, `provider
delete`, `inference delete`, and `provider profile delete` exist. `workspace
create` and `sandbox create` take `--label`. `provider create` and `inference
set` do not.

## Not in Stage 1

- Reporting status to the cluster beyond the optional readiness probe
  (`vm.readinessProbe: true`, needs guest-agent exec).
- Docker as the VM container runtime.
- Moving an existing pattern install's Keycloak from `openshell-agents` to
  `saw-keycloak`: the new instance starts with a fresh database (realm, test
  users and clients come from the chart; other data is not migrated).
- Migrating VMs created by the old SSH-based chart in place: cloud-init has
  already run on them, so the installer units are never written. Recreate
  the VM (delete the VM and its `-root` DataVolume) after upgrading the chart.

## Custom inference

A self-hosted OpenAI-compatible endpoint (vLLM, Ollama, ...) is an `openai`
provider with `OPENAI_BASE_URL` plus the workspace inference route, as in
OpenShell's inference routing docs. Select the `custom-inference` SAW-BOM
profile and put `provider: openai`, `model`, `url` and `api_key` in the
`inference` Secret; see [Custom inference](custom-inference.md).
