# Confidential Kata workspaces with Trustee

Status: implementation in progress. Deployment requires restrictive launch
policies and verified platform approvals. The real NVIDIA workspace is not yet
qualified.

## Current integration

The confidential driver is now ported to the OpenShell 0.1.10 source selected
by PR #173. The port keeps dedicated supervisor VMs, workload VMs, and
registration-specific measured init-data. The gateway uses the default runtime.
The source lock records build inputs. Its qualification fields remain unset.

Ordinary workspaces retain PR #173's native credential bindings. Confidential
workspaces send public credential markers to OpenShell. Their supervisor fetches
the real keys from Trustee through CDH and keeps them in process memory.
The existing credential helper tests pass. This does not qualify live release.

Standard audit uses three RWO claims. Signed receipts remain an optional
configuration with a separate history claim. The confidential notebook harness
uses its content-addressed directory in the read-only gate volume. Startup
checks its digest. It does not add a subpath mount. Harnesses that require the
separate briefing mount remain rejected.

A fresh Azure lab has one ready peer-pod worker and an imported confidential
guest image. Trustee runs with verified HTTPS. The first credential-free guest reached
the Kata agent. Its measured policy
rejected the infrastructure container: the pinned generator emits containerd
metadata, while OpenShift sends CRI-O metadata and a different pause process.
The probe was removed and its Trustee approval was revoked. An explicit
CRI-O 1.34 / OCI 1.2.1 profile now passes executable offline checks against the
captured request and public fixtures. Those offline checks did not qualify a real workspace or provider credential
release. Later guest results are listed below.

The pinned [guest image handler](https://github.com/openshift/kata-containers/blob/b17f640901e87e620ab74db428e8e0883cb91b81/src/agent/src/storage/image_pull_handler.rs)
uses the signed, measured guest's embedded `/pause_bundle` for sandbox storage.
It does not fetch CRI-O's host pause image inside the guest. Application pulls
use `storage.source`. The CRI-O profile binds that source and its metadata to
the approved application image. It rejects a change between sandbox and
application storage paths.

The next probe passed infrastructure startup. Its application request was
rejected before execution because CRI-O added an unapproved host subscription
mount at `/run/secrets`. The profile now models the verified runtime marker,
bind flags, and fixed `NSS_SDB_USE_CACHE=no` value. It still rejects the host
subscription mount and conflicting environment entries.

For a dedicated confidential worker pool, the reviewed
[host-mount configuration](../deploy/confidential/bootstrap/crio-host-mounts.yaml)
creates an override with no optional subscription mounts. Review the pool
selector before applying it. This changes all Pods on that pool and can cause
a drain and reboot. Keep this step separate from workspace creation. Verify
the pool and Trustee are Ready before another credential-free test. Removing
the MachineConfig restores the vendor defaults and can cause another reboot.
Do not allow an opaque host directory to satisfy the guest launch policy.

The earlier results below are historical component tests. They do not establish
qualification of this new cluster or the OpenShell 0.1.10 image pairing.

## Latest lab results (2026-11-25)

The Validated Pattern foundation install completed. All 12 foundation Argo
applications reported Synced and Healthy. The user list remains empty. The
`kata-data-science` profile is present. No real workspace has been qualified.

The Vault KV v2 → External Secrets → KBS bridge passed a generated-value test
with verified Vault TLS and Kubernetes authentication. The test role could read
its exact Vault path. A foreign path returned HTTP 403. The resulting provider
Secret existed only in the Trustee namespace. KBS loaded the expected value.
This verifies the storage transfer, not release to an attested supervisor.

A later Vault value did not reach KBS automatically. The controlled reload
below passed with generated values: ESO acknowledged the refresh, a replacement
KBS Pod loaded the new value, and the deny-by-default resource policy stayed
unchanged. The test removed its Vault data, role, policy, service account,
ExternalSecret, SecretStore, and KBS membership. No NVIDIA key was used.
The full supervisor rotation remains unverified.

A later credential-free guest produced hardware evidence with a 32-byte nonce
and received a Trustee token. Its PCR08 claim matched the reference generated
by Veritas. Azure reported ConfidentialVM with vTPM enabled. The earlier
64-byte evidence request returned HTTP 500; the successful 32-byte request
isolates that diagnostic input issue. The probe's `/version` check returned 404.

Process exit remains unqualified. A signed small program slept for three
seconds and returned. On the same worker, the default runtime reported
Succeeded with exit code 0. The confidential runtime continued to report
Running. This also occurred with production stream restrictions and CloseStdin
allowed. It narrows the failure to the confidential runtime path; it does not
identify a specific failing component or prove that an upgrade will fix it.

A preceding larger application image failed during layer unpacking. Guest
volume transport and audit file ownership also remain unqualified. Keep real
enrollment blocked until these gates pass. All guest tests used public image
policy resources and no provider credentials. After the tests, the previous
Trustee approvals were restored. The diagnostic VMs were removed and their
absence was checked independently in Azure. CRI-O still retains orphaned
test sandbox records, so host runtime cleanup remains incomplete.

## Deployment integration (2026-11-25)

The shared preflight now checks the approved platform and Trustee endpoint
instead of rejecting all confidential deployments. It accepts schema version 2
launch bundles. Schema version 1 remains available only for isolated artifact
and probe checks; deployment rejects it with `AttestationLaunchPolicyRequired`.
Missing qualifications, changed object identities or hashes, and dependency
failures still block deployment. A passing local fixture does not qualify a
live platform or authorize credential release.

The projector generates public init-data placements before the first
enrollment. It derives them from the reviewed launch policies and registration
identity. This removes the dependency on a publication that enrollment has not
yet created. Confidential enrollment uses 31 approval entries, including the
Trustee objects and public provider policy, with no external proxy approval.
Set `bootstrapEgress` on a confidential site for trusted control-plane access.
The ordinary container and Kata paths retain their native provider configuration.

GitOps and RHDH readers get `get` access to named public approval objects. They
receive no Trustee Secret permission. For RHDH sites supplied through
`portal.containerSitesSecretName`, list those exact public API paths in
`portal.attestationPreflightRefs`. These permissions do not approve the objects;
preflight still verifies their UIDs, hashes, qualification, and readiness.

RHDH mounts site settings at `/etc/saw-sites/container-sites.json` and passes
only that path through `SAW_CONTAINER_SITES_FILE`. Large launch policies do not
enter an environment value. Inline values use a ConfigMap; Secret-backed sites
keep their existing Secret. The loader checks size and JSON structure, reads
file updates again, and reports safe errors. It does not fall back to another
source after a file failure. The legacy environment interface remains available
for existing direct callers, but the charts use files.

Enrollment reads KbsConfig again after changing membership and waits for the
Trustee Deployment to include the exact resource input and finish its rollout.
Approval hashing excludes only validated SAW Secret input volumes and their
exact `secret-converter` mounts under `/tmp/kbs-secrets/`. All operator code,
commands, security settings, non-SAW volumes, and repository mounts stay pinned.
This fixes first-registration approval invalidation. Shared resource-policy
and RVPS approval scope, complete supervisor rotation, guest storage access,
and live workspace qualification still require verification.

The charts package one canonical Python preflight, one attestation module,
and one shared Helm gate through source links. No provider keys are embedded
in these assets. Build and pin an updated runtime image before live enrollment;
old controller images do not contain these integration fixes.

## Storage gate (2026-11-25)

A live check of a reserved Azure File audit claim failed the file ownership
precondition in `saw_kubernetes.prepare_audit`. The check created an empty file
under the configured workspace UID, but the filesystem reported a different
owner. File flag reads succeeded. Setting the append-only flag was not tested.
The check removed its temporary file and Pod. It used the default runtime and
no provider credentials. It does not qualify confidential guest volume access.

A Bound claim is insufficient for enrollment. Verify the CSI transport inside
the confidential guest, UID/GID mapping, gate mount modes, audit append-only
semantics, and persistence. Keep enrollment disabled until these checks pass.
Use dedicated storage configuration for workspace UID mapping; do not change
the shared default StorageClass to fix one owner.

The inspected [OSC 1.13 Azure CSI wrapper example](https://github.com/openshift/cloud-api-adaptor/blob/ab140f1932a6f369a422677f92bb4c47aee085f9/src/csi-wrapper/examples/azure/README.md)
targets AKS. It changes controller and node driver socket paths and adds
[root, privileged guest storage containers](https://github.com/openshift/cloud-api-adaptor/blob/ab140f1932a6f369a422677f92bb4c47aee085f9/src/csi-wrapper/examples/azure/file/nginx-kata-with-my-pvc-and-csi-wrapper.yaml).
It is not a drop-in configuration for managed OpenShift CSI drivers. Adding
such helpers changes the measured workspace boundary and requires review of
their pinned images, commands, mounts, privileges, and rollback. Do not enable
a driver flag or replace the guest policy and report storage as qualified.

## Latest verification (2026-11-24)

Credential-free Azure SNP image checks passed: a signed agent image ran,
an unsigned manifest was rejected by the guest's `sigstoreSigned` rule, and a
valid signed AMD64 manifest was rejected with a different public key. The same
canonical manifest ran after the correct key was restored. Trustee accepted
attestation and returned the public image policy in these cases. The events
expose rule rejection, not the verifier's inner error. An initial wrong-key
case resolved an unsigned cache alias and is excluded from the result.

The temporary public resource and measurement binding were removed. The
original default-deny policy is loaded, original KBS membership is preserved,
and no test Pods or PeerPods remain. No provider credential was used. These
component checks used the public qualification guest policy. Restrictive
per-slot launch policies, the real NVIDIA workspace, and the complete
workspace matrix remain unqualified. Confidential enrollment stays disabled.

This operator reverts `rollout restart` annotations on its managed Deployment.
A resource update must reach the replacement Trustee Pod's init converter.
For the tests, recycling only that managed Pod loaded the new public policy;
the loaded file hash was checked before the next Pod started. Readiness alone
was insufficient. Do not expose resource contents during these checks.

AA and CDH use separate TLS clients. Generated init-data must set both
`token_configs.kbs.cert` in `aa.toml` and `kbc.kbs_cert` in `cdh.toml` to the
approved Trustee CA. Changing these settings changes the measured init-data.
Recompute and review reference values before a new enrollment.

The installed token exposes Azure SNP PCR08 at
`submods.cpu0["ear.veraison.annotated-evidence"]["az-snp-vtpm"].tpm.pcr08`.
Its `init_data` field in the same annotated evidence holds the verified PCR08
value, not the raw init-data SHA256. The token did not expose parsed
`policy_data.saw_identity`. Do not use a requested owner name or label as
attested identity.

### Administrator measurement binding

`scripts/trustee-resource-policy.py --approvals FILE` renders a default-deny KBS
resource policy. Run it through `uv run`. The input is a public JSON approval
record with `schemaVersion: 1` and a `bindings` list. Each binding has these
fields: `owner`, `registration`, `installation`, `slot`, `role`, `pcr08`,
`initdataSHA256`, `referenceSetSHA256`, `expiresAt`, and `resources`.

The administrator must derive PCR08 from verified platform inputs and the exact
approved init-data. The renderer checks format and consistency; it does not
prove measurement provenance or approve a release. Keep this approval review
separate from workspace-owner input. Use a distinct approved measurement for
each owner, registration, slot, and role. Duplicate measurements are rejected.

For the initial Azure SNP CPU path, the generated policy requires an exact PCR08
binding, matching verified `init_data`, affirmative measured-platform scores,
disabled debug and migration, and an unexpired approval. It compares the exact
KBS resource path array with `default/saw-<owner>-<registration>/<resource>`.
Supervisor bindings can permit named inference and web-search resources.
Workload bindings can permit only `image-policy`. Missing fields, other TEEs,
additional devices, foreign paths, and revoked bindings fail closed.

This is an administrator policy tool, not an enrollment integration. Review its
full policy before installation. It replaces a KBS resource policy and does not
merge rules for other applications. Revoke a registration by removing its
measurement bindings and reloading the policy.

A live synthetic-only probe passed its exact measurement check, retrieved its
own test resource, and received `PolicyDeny` for a foreign registration and the
legacy status path. This KBS version returns HTTP 401 with JSON `type` set to
its `PolicyDeny` URI. A generic 401 is not enough to prove policy isolation.
The test measurement and synthetic resources were removed after the run.
All 186 affected local tests passed, including 51 executable policy and
protocol cases.

Production credential release is not qualified. The current agent policy still
permits `CreateContainerRequest` broadly. Constrain the approved image, startup
command, and relevant container settings in the measured policy before using
provider keys. The synthetic result verifies the KBS measurement-to-resource
mapping; it does not complete the application launch boundary. Live changed-
measurement, debug-mode, and old-token revocation tests also remain open.

## Guest image-signature key format

The pinned OSC image-rs verifier reads `sigstoreSigned.keyData` as PEM bytes.
Use the public-key PEM text directly in the guest image policy. Host
containers/image tools use Base64-encoded PEM in this field; keep their policy
file separate. Do not copy a host policy into a Trustee resource unchanged.
The shared preflight rejects that encoding with `GuestImagePolicyKeyRejected`.
It also rejects private-key labels, malformed PEM, and simultaneous `keyData`
and `keyPath`. This is an encoding check. Registry verification and live guest
acceptance and rejection tests are still required.

## Guest image-signature artifact format

The pinned OSC image-rs verifier reads legacy Cosign Simple Signing artifacts
from the `sha256-<manifest-digest>.sig` tag. A successful default Cosign 3
verification can instead verify a newer bundle. That result does not prove
that the guest can find and verify the legacy signature.

For this pinned guest, publish and verify the legacy format explicitly:

```bash
cosign sign --key SIGNING_KEY --new-bundle-format=false \
  --registry-referrers-mode=legacy IMAGE@sha256:DIGEST
cosign verify --key PUBLIC_KEY --new-bundle-format=false \
  IMAGE@sha256:DIGEST
skopeo inspect --raw docker://REPOSITORY:sha256-DIGEST.sig
```

Check that the signature manifest has a
`application/vnd.dev.cosign.simplesigning.v1+json` layer and the
`dev.cosignproject.cosign/signature` annotation. The tag check proves artifact
availability, not signature validity. Keep the public-key verification and
then test the pinned guest. `--registry-referrers-mode=legacy` alone does not
select the legacy bundle format in Cosign 3.

The credential-free CRI-O probe reached Trustee and passed Azure SNP
endorsement verification on 2026-11-25. Trustee released its public image
policy. Application launch then failed at the signature rule because only
the newer bundle existed. No provider key was used. The compatible artifact
was added without changing the approved image manifest or guest policy.
The corrected guest launch still requires a live retest. This result does
not qualify provider credential release or the complete workspace.

See the pinned [Cosign 3.1.4 signing options](https://github.com/sigstore/cosign/blob/v3.1.4/cmd/cosign/cli/options/sign.go)
and [image-rs Cosign verifier](https://github.com/openshift/confidential-containers-guest-components/blob/ba72d6d13db4bf66d21f407a90b62c8b890a7bb0/image-rs/src/signature/policy/cosign/mod.rs).

## Measured public bootstrap configuration

The confidential supervisor receives `SAW_CONFIDENTIAL_BOOTSTRAP_JSON`.
This value contains schema version 1, the public provider routing policy,
registration-specific KBS resource paths, and the public proxy CA file path.
It contains no provider credentials. The generated launch policy must pin the
complete JSON value. Duplicate values, the legacy file variable, a changed
bootstrap value, or wider environment rules fail validation.

The gateway driver passes this value directly to the supervisor Pod. The
confidential path no longer mounts a bootstrap ConfigMap into that Pod. A
separate immutable policy ConfigMap remains in the controller boundary for
comparison with the approved driver configuration. The credential proxy
parses its public policy once, fetches credentials from local CDH, and keeps
those credentials in memory. It has no file fallback in confidential mode.

This interface requires rebuilt gateway and supervisor images. Earlier lab
images use the file interface and are incompatible. Do not deploy a mixed pair.
The Go tests and chart contracts pass. The rebuilt gateway passed all nine
confidential driver tests on AMD64. Full workspace qualification remains open.

## Reserve storage before launch-policy generation

The measured policy needs the real namespace UID range and claim identities.
Do not generate it from preview IDs. Use the same public user values as Make,
with one Kata profile, `attestation.enabled: true`,
`automaticEnrollment.enabled: false`, the approved `kataRuntimeClass`, and
`stack.audit.values.storageClass` and `exchangeStorageClass`. No enrolled
intent is permitted at this stage. Keep provider key values out of this file.

```sh
export DEPLOYMENT_MODE=kata
export SAW_USERS_VALUES_FILE=/path/to/reviewed-public-values.yaml
export OPENSHELL_SAW_NAME=alice
export SAW_KUBE_CONTEXT=approved-cluster-context
make saw-prepare-confidential
make saw-prepare-confidential-apply
```

The first command reads the selected cluster and performs server admission dry
runs where the destination namespace exists. It reports `admissionPending` for
claims and policies whose namespace does not exist. It does not report full
admission success for these resources.

The apply command creates only the runtime and retained history namespaces,
default-deny NetworkPolicies, and the claims from the production audit chart.
Each new object gets a server dry run before creation. It starts no workload,
creates no credential object, reads no Secret, and makes no Trustee change.
It rejects foreign objects and changes to an existing claim. A repeat retains
the same object UIDs. The returned IDs and namespace ranges are public policy
inputs. Use `uv run scripts/confidential-prepare.py --output NEW_FILE` with the
same environment to save them. Add `--apply` only for the reservation step.

`StorageReserved` means the claims exist. It does not prove that claims are
Bound, that their CSI driver supports peer pods, or that a guest can mount them.
Qualify the selected storage transport before enabling enrollment. The command
checks the approved RuntimeClass identity and placement, storage-class
existence, ownership, permissions, and admission. It is not the full
confidential preflight. The enrollment and credential-release gates stay closed.

## Bounded diagnostic results

The measured policy denies `ReadStreamRequest`. Empty `oc logs` output does not
show whether a guest application ran. Keep this protection enabled. A
credential-free diagnostic image can write fixed status codes, booleans, and
public measurement hashes to its termination message. Never write a Trustee
token, TEE private key, raw credential response, or provider key there.

Set a diagnostic Pod's `activeDeadlineSeconds` to at most 300 seconds. The
shared input conversion accepts only an integer from 1 through 300. It removes
this Kubernetes lifecycle field only from generator input, because the pinned
generator rejects it. The deployed and enrolled Pod retains the deadline.
Guest launch permissions remain unchanged. A terminating Pod or an Azure VM
removal timeout is a failed lifecycle check, not successful completion.

## Preparing measured launch policies

`deploy/confidential/source-lock.yaml` pins the Red Hat tools image and the
Kata release rules and settings by revision and SHA256. Use these inputs;
do not enable the generator's unsupported-field suppression option.

Use the actual approved supervisor or workload Pod manifest, after admission
has resolved its nonzero UID. Keep this manifest as the deployment input.
Prepare a separate generator input with:

```sh
uv run --with pyyaml scripts/confidential-artifacts.py launch-input \
  --pod approved-pod.yaml --output generator-input.yaml
```

The conversion requires explicit `automountServiceAccountToken: false`, a
nonzero numeric UID, `runAsNonRoot: true`, and RuntimeDefault seccomp. It moves
inherited seccomp to container security contexts and removes only the redundant
nonroot flag and unsupported explicit automount field from generator input.
It rejects host namespaces, privileged containers, Secret environment imports,
and unsafe init containers. It also removes the stock Sandbox owner reference,
the exact `openshell.ai/bootstrap` scheduling gate, and `OnRootMismatch` volume
ownership handling from generator input. These API fields do not become guest
OCI fields. Numeric `fsGroup` remains, so additional groups stay constrained.
Other ownership shapes, scheduling gates, or volume ownership policies are
rejected. The conversion removes only an admission MCS label with the shape
`seLinuxOptions: {level: s0:c29,c19}` from generator input. The enrolled Pod
retains it. The pinned runtime clears host labels when guest SELinux is off,
and the locked agent rules require empty guest process and mount labels.
Custom SELinux user, role, type, or level shapes are rejected. Other unsupported fields remain for genpolicy to reject. The actual
deployment manifest is not modified.

The pinned generator models projected volumes as read-only shared mounts, but
its parser does not accept their `sources`. The conversion accepts only the
stock supervisor token: volume `sa-token`, mode `0440`, audience
`openshell-gateway`, path `token`, lifetime at most 3600 seconds, and one
read-only mount at `/var/run/secrets/openshell`. It retains the projected-volume
type for policy generation and keeps the full projection in the enrolled Pod.
It rejects other projections. This check does not measure the token contents;
the token provides gateway authentication and contains no provider credential.

Run the pinned genpolicy tool with the locked rules and settings, then validate
its raw output against the original Pod:

```sh
uv run --with pyyaml scripts/confidential-artifacts.py launch-policy \
  --pod approved-pod.yaml --policy generated-policy.rego \
  --output launch-template.rego
```

For the supported CRI-O format, provide an administrator-reviewed JSON file:

```json
{
  "name": "crio-1.34-oci-1.2.1-v1",
  "pauseImage": "registry.example.test/infra@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
}
```

Use the actual infrastructure image digest from the approved cluster release.
Add `--runtime-profile runtime-profile.json` to `launch-policy`. Include that
same object as `runtimeProfile` beside `pod` and `template` in each launch
bundle entry. The bundle digest enrolls this selection. Unknown profiles and
fields fail closed. Omit the flag only for the existing containerd format.

CRI-O can send a cold-cache pull reference or a warm-cache image configuration
ID in `io.kubernetes.cri-o.Image`. That field is a node cache hint. The profile
accepts the approved pull reference or the strict SHA256 cache-ID form. It
keeps `io.kubernetes.cri-o.ImageName` and guest `storage.source` bound to the
approved manifest digest. A cached ID cannot select different guest content.
Tests cover both cache forms and reject a changed pull source.

The canonical `crio_policy.py` validates native identity and guest-pull metadata,
then passes an equivalent request to the pinned vendor checks. It checks the
root infrastructure process separately. Application and supervisor processes
must remain nonroot with no privilege escalation. Host execution, policy
replacement, and diagnostic streams remain denied. Enrollment recovers the
original generator data, recompiles the complete template, and requires an
exact match. A change to the adapter or profile requires a new reviewed bundle.

The validator accepts only the exact locked rules code followed by JSON policy
data. It requires the Pod's image digest, command, namespace, UID, read-only-root
setting, and no-new-privileges flag to match. Exec, stream, and diagnostic
permissions must remain denied. A single measured SAW identity marker is added.
The commands write new private files and never print manifests or replace an
existing file. Generated mounts, environment, and all remaining policy data
still require administrator review against the actual Pod and image inputs.

A local generation check passed for the signed supervisor candidate. Normal OPA
compilation passed. Strict OPA lint rejects unused arguments in the upstream
rules; the rules were not edited to suppress that diagnostic. This result is
not a live launch qualification.

Attestation settings schema version 2 use `launchPolicies` instead of the
legacy `guestPolicy`. Map each `workspace/sandbox` slot to exactly two entries:
`supervisor` and `workload`. Each entry contains the original `pod` manifest
and its generated `template`. Set `policyDigest` to the canonical JSON SHA256
of the complete `launchPolicies` map. Both manifests and templates are enrolled.
The validator rechecks each template against its Pod and the locked generator
rules. Each supervisor must use the guest-local proxy wrapper. Init-data binds
the selected policy to its owner, registration, installation, slot, and role.
The placement contract rejects missing or extra slots and a changed RuntimeClass.

The original Pod manifest must come from the pinned driver and resolved site
configuration. The supervisor policy accepts only the driver's canonical
UUIDv4 runtime ID and its matching Pod-name annotations. It adds one fixed,
anchored environment rule after checking the locked generator rules. It
retains exact bootstrap JSON, namespace, image, command, and workspace identity.
The runtime ID does not grant Trustee access. Resource release uses the
enrolled registration measurement. Enrollment reverses and rechecks this
conversion, so broader patterns fail even if their digest is recomputed.

A driver-generated supervisor preview passed policy generation and validation.
Six executable Rego checks accepted a new UUID and rejected invalid IDs and
changed bootstrap JSON. These are offline checks.

The workload preview exposed two storage checks. The locked generator treats
PVC mounts as writable. The launch validator checks each PVC mount source,
destination and options, then narrows protected mounts to read-only. Enrollment
revalidates that narrowing. Strict supplemental groups and the stock low-port
sysctl must also match generated OCI values. The original Pod retains those
settings.

The pinned generator rejects `subPath` mounts. Confidential tool gates now
mount the full dedicated PVC read-only at `/sandbox/.saw/gate-volume` and
read the checked bundle from its `bundle/` directory. Audit exchange mounts
its full PVC read-write at `/sandbox/.saw/audit-volume` and uses `log/`.
The on-disk directories and atomic publication stay the same. The publisher
and compiler derive the path-bound bundle digest from one shared source.
Startup checks the mount roots and hashes only the nested approved bundle.
The gateway guard and admission policy restrict these fixed paths and modes.
Other workspace modes retain their existing subpath layout.

The actual driver rendered the workspace profile with its tool gate and with
optional harnesses disabled. The pinned generator and launch validator accepted
that Pod. Sixteen executable Rego cases checked mount modes, foreign sources,
user IDs, and denied exec and diagnostic requests. This preview used unenrolled
identities and test attestation inputs. It did not create a live workspace or
approve credential release. Optional harnesses still use subpaths and need a
compatible layout before confidential use. The input checker continues to
report `LaunchPolicySubPathUnsupported` for any remaining subpath; it never
removes one from generator input.

PR #173 adds shared ReadWriteMany storage provisioning, but its current compiler
still sets those subpaths. It does not resolve this generator incompatibility.
Its workspace Secret credential path also needs separate integration review
against the confidential Trustee-only release requirement.

The supervisor preview now encodes the exact compiled workspace command with
OpenShell's native `MainProcessConfig` encoder. The compiler checks that the
measured `OPENSHELL_MAIN_PROCESS_SPEC` matches the compiled command, TTY,
attachment mode, and workload image. A mismatch reports
`AttestationLaunchSpecMismatch`. Duplicate environment entries, duplicate JSON
fields, and Secret projections cannot replace this public launch value.
The native supervisor/workload pair passes schema-2 compilation and normal
OPA compilation. These checks use offline bindings and do not qualify release.
The compiler rejects optional confidential harnesses before plan publication
with `ConfidentialHarnessUnsupported` until their storage layout is supported.

The workload Pod and runtime mount paths still need live qualification. Do not
hand-edit a representative Pod and treat it as the live driver output. Schema version 1 remains available for
historical probes, but its broad launch policy does not qualify provider release.
The chart and preflight activation gates remain closed. Do not replace live
qualification with a manually asserted record or deploy a real provider key.

## Historical platform verification (2026-11-23)

At 2026-11-23T17:39:41Z, a read-only cluster check confirmed that the Kata
workers and Trustee components are ready. The Mac shell resolved the API host
for one read, then failed DNS lookups on follow-up reads. An approved read-only
API session succeeded. The `podman` CLI could not connect to its Linux socket
from this shell. Treat direct Mac API access as intermittent.

RuntimeClass `kata-remote` exists with handler `kata-remote` and selector
`node-role.kubernetes.io/kata-oc`. KataConfig `saw-confidential-kata` reports
`InProgress=False`. KbsConfig `saw-trustee-kbs-config` still lists only
`attestation-status`. The RVPS `reference_value` has no entries. The Trustee
deployment and operator Pods are Ready. No cluster resources changed during
this check.

The Pattern foundation is installed. All 10 Argo CD Applications checked in
`vp-gitops` report `Synced` and `Healthy`. `vault-backend` is `Valid`, the RHDH
OIDC ExternalSecret is Ready, and the RHDH bootstrap check passed. These checks
confirm the foundation only. The confidential feature branch is not deployed.

OSC and Trustee are ready for further qualification. All three Kata workers
report Ready. KataConfig `saw-confidential-kata` reports
`InProgress=False`. RuntimeClass `kata-remote` exists with handler
`kata-remote`, selector `node-role.kubernetes.io/kata-oc`, and overhead 250m
CPU and 120Mi memory. The Trustee deployment and operator Pods are Ready. The
Trustee KbsConfig still lists only `attestation-status`; no SAW credential
resource was added.

The read-only `make saw-init DEPLOYMENT_MODE=kata` check ran in the Pattern
container with Linux `uv`. It stopped before cluster checks because
`SAW_USERS_VALUES_FILE` is unset. The tracked `overrides/saw-users.yaml` has an
empty user list. The demo and CI files do not contain a live `containerSites`
approval or immutable registration identity. Do not use these files as live
approval. A complete, reviewed site values file is required to continue the
preflight. The check made no cluster changes, created no workspace, and read
no provider credentials. A cluster-independent regression run for the SAW
contract, portal, runtime, profile, Vault, and Make paths passed 576 tests in
the Linux container. This does not qualify attestation or secret release. The
confidential enrollment gate remains closed.

A credential-free PodVM probe on 2026-11-23 first showed the guest policy
rejecting `CopyFileRequest`. A second probe used the scoped shared-container
rule. It did not show that policy denial, but the Kata runtime logged
`CheckRequest timed out`, and the kubelet reported `CreateContainer failed:
create container timeout`. The container did not start. The cloud adaptor
deleted both probe VMs, including one retry created as pod deletion began. No
PeerPods or probe namespaces remain. A temporary `KataConfig.logLevel=debug`
update produced the same timeout and no guest-console lines. I restored
`logLevel=info`; all three Kata workers are Ready and the pool reports
`Updated=True`, `Degraded=False`. This does not verify attestation or Trustee
release.

A third credential-free PodVM probe on 2026-11-23 captured live worker and CAA
logs. At `2026-11-23T09:56:58Z`, CAA had assigned a VM IP, created the VXLAN
tunnel, and opened the guest TTRPC proxy. Kata failed its gRPC health check at
`09:57:28Z`. A kubelet retry failed at `09:59:35Z` because the agent connection
was not established. CRI-O reported a container-create timeout for both
attempts. CAA removed both VXLAN tunnels. The probe Pod, PeerPod, and namespace
were deleted. The captured logs contained no guest-console output. This
narrows the failure to guest boot or guest-agent transport after CAA set up the
tunnel, but does not identify which. Azure VM deletion was not independently
verified because this session had no Azure management login. The probe used no
credentials and returned no attestation evidence.

The first policy rejected all CopyFileRequest calls. A second policy allowed
the shared-container prefix but did not include the full Kata Agent defaults
or checks for .. traversal and unsafe symlink targets. A container-create
timeout followed. This evidence makes the incomplete policy a likely cause,
but it does not prove the root cause. The cluster has not run a probe with the
reviewed policy below.

Source update (2026-11-23): the reviewed policy is now stored at
deploy/confidential/kata-agent-policy.rego. The validator accepts only this
baseline and rejects changes that enable process exec, stream reads, guest
policy replacement, broad file copies, path traversal, or absolute symlinks.
The contract and affected chart tests pass: 292 tests. The Docker API is
unavailable in this shell, so the policy was not compiled with OPA. A new
read-only cluster check found all three Kata workers Ready, the approved
kata-remote RuntimeClass present, and no PeerPods. No PodVM or workspace was
created. Do not run another VM probe until the guest image and exact init-data
measurements are pinned and the RVPS reference values are approved.

Follow-up on 2026-11-23: existing shared Vault entries were copied inside the
Vault pod to owner-scoped paths for `hacohen`. The inference path is
`secret/data/hub/saw-hacohen/credentials/inference`. It contains the existing
inference key and model `nvidia/nemotron-3-super-120b-a12b`; the model's public
NVIDIA endpoint is `https://integrate.api.nvidia.com/v1`. No key value was
returned or used for an API call. The existing Brave path was left unchanged.
A mock, invalid Brave key is now the current value at
`secret/data/hub/saw-hacohen/credentials/web-search` (version 2). The shared
Brave source path remains unchanged. The draft values file disables web search
and does not reference the mock path. Use it only for a later secret-plumbing
test. Version 1 remains in Vault history. The temporary redundant mock path was
removed.

The shared preflight now accepts the approved `kata` and `kata-remote` handlers.
The `openshell.ai/sandbox-attachable=true` label is on the live `kata-remote`
class. Its observed placement digest is
`8e9def2db3b24635eca0de86999883a955f84585ee32bccde8a775e03e7aa1db`; owner
approval is still required. The draft is at
`local-docs/confidential-kata-hacohen-values.template.yaml`. It contains
placeholders and is not ready for `make saw-create`.

Trustee still has no SAW resource. Its live resource policy checks generic EAR
trust claims, not the SAW owner and registration. RVPS has no reference values.
Do not add even the mock resource until Trustee binds a verified SAW identity
to that resource and synthetic allow and deny cases pass. No workspace was
created. The confidential gate remains closed.

The 2026-11-22 platform details below are a historical snapshot. The 2026-11-23
checks above supersede their statements that Vault, External Secrets, and SAW
foundation services were absent.

The current Kata mode places the workload in Kata and leaves its supervisor on
the default runtime. The confidential design must place both Pods in confidential
VMs. The gateway stays on the default runtime. This design has not passed a live
workspace test.

## Implemented source components

Attestation logic has one source file:
`kubernetes-runtime/saw_kubernetes/attestation.py`. The `saw-users`,
`openshell-rhdh`, and `saw-portal-container` chart assets are relative symlinks
to that file. Edit the runtime source only. `make catalog` repairs missing or
incorrect links; its check mode rejects regular copies. Helm resolves the links
when rendering and writes regular files into chart packages, so packaged charts
do not require the repository checkout.


- `make saw-init` calls the existing read-only workspace preflight. It uses the
  same `SAW_USERS_VALUES_FILE`, `OPENSHELL_SAW_NAME`, and `DEPLOYMENT_MODE` inputs.
- Make, GitOps, and RHDH share confidential configuration and public-object
  checks. Each approval binds an object UID and its complete spec or data hash.
  The KBS attestation and resource policy ConfigMaps have separate references,
  so a policy edit invalidates the approval.
- Init-data generation uses supported `aa.toml`, `cdh.toml`, and `policy.rego`
  entries. deploy/confidential/kata-agent-policy.rego is the reviewed
  baseline, based on Red Hat's OSC 1.13 Azure guidance. It allows normal Kata
  Agent lifecycle requests, including CreateContainerRequest and
  CreateSandboxRequest. It denies ExecProcessRequest, ReadStreamRequest,
  SetPolicyRequest, and CopyFileRequest by default. Its copy rule allows only
  the Kata shared-container path, rejects .. traversal, and accepts symlinks
  only when their targets are relative and traversal-free. attestation.py
  accepts only this exact policy template with one
  policy_data.saw_identity: __SAW_IDENTITY_JSON__ marker. Init-data generation
  replaces that marker with the installation, owner, registration, slot, and
  role identity. A policy change alters the init-data and approval digests.
  The previous timeout remains unexplained until a credential-free live probe
  boots with this reviewed policy. The probe must not include provider
  credentials, and it does not qualify attestation or Trustee release.
  Trustee parses Kata `policy_data` from init-data only after it verifies the
  measured init-data. This creates a candidate verified identity claim. The
  deployed Red Hat Trustee claim shape and KBS policy path still need live
  qualification.
- The proxy can fetch JSON credential resources from the guest-local CDH REST
  API. Provider material and its private interception CA stay in process memory.
  The public CA file contains no private key. Startup has a 300-second deadline.
  A denial stops startup. OAuth refresh is rejected in this initial path.
- The supervisor wrapper requires the guest-local proxy. It rejects external
  proxy bypasses and never falls back to Kubernetes provider Secrets.
- The Trustee resource renderer emits only Vault references. External Secrets
  assembles credential resource JSON in the Trustee namespace. The referenced
  `ClusterSecretStore` must use a Vault policy scoped to the owner path.
- The generated confidential RHDH form omits credential fields and requests
  only the approved owner Vault references. The portal checks KV v2 metadata
  before registration. Its Vault role can create and update KV data and read or
  delete metadata; it cannot read KV data. The form is disabled by default and
  the confidential deployment gate remains closed.
- Trustee approval hashes cover stable KbsConfig settings and exclude the
  mutable `kbsSecretResources` list. Enrollment checks that its own
  `saw-<owner>-<registration>` ExternalSecret is Ready, then adds its name to
  `kbsSecretResources` with a resourceVersion-checked patch. The patch preserves
  all other resource names. The enrolled controller also rechecks the named
  public Trustee objects and resource membership on each reconcile. Its
  permissions use GET-only Roles in the referenced namespaces. GitOps creates
  the ExternalSecret; enrollment updates KbsConfig after the Secret is ready.
- Confidential enrollments carry the approved settings and owner, registration,
  and installation identity into the controller configuration. The compiler
  emits schema-version 2 placement contracts with separate measured init-data
  for each supervisor and workload slot. The controller recomputes that
  contract from the enrolled settings before it can proceed.

The KBS preflight now sends a TLS-verified empty authentication request to
the approved `/kbs/v0/auth` endpoint. It follows no redirects, sends no token,
and reports fixed failure codes. HTTP 400 or 401 proves only that the approved
endpoint answered; it does not prove attestation or resource release. Tests
cover accepted responses, rejected responses, and transport failures.

The shared gate returns `AttestationIntegrationUnavailable` even after its
platform checks pass. Helm also rejects an enabled confidential site. These
controls prevent a partial configuration from using the existing external proxy
or provider Secret path. They are not a completed confidential deployment.

## Platform and dependency preparation

To render init-data locally, use:

```bash
uv run --locked python scripts/confidential-artifacts.py initdata \
  --values /path/to/public-user-values.yaml --owner alice \
  --registration 0123456789abcdef \
  --installation 11111111-1111-4111-8111-111111111111 \
  --slot default/notebook --role supervisor
```

To render the ESO bridge, provide a public values file with the approved
`credentialReferences` for the owner and selected profile. The values contain
Vault paths only, never credential data:

```yaml
containerSites:
  alice:
    credentialReferences:
      data-science:
        inference: secret/data/hub/saw-alice/credentials/inference
        web-search: secret/data/hub/saw-alice/credentials/web-search
```

Then run:

```bash
uv run --locked python scripts/confidential-artifacts.py trustee-resources \
  --values /path/to/public-user-values.yaml --owner alice \
  --registration 0123456789abcdef --profile data-science \
  --secret-store trustee-vault
```

These commands do not apply objects, register KBS resources, approve
measurements, or fetch credentials.

The `deploy/confidential` directory contains operator subscriptions, an OpenShell
source patch, a supervisor image recipe, and the source inventory. The operator
manifest starts from OSC 1.13.1 and Trustee 1.2.1 with manual InstallPlan approval.
A Subscription's `startingCSV` does not pin future upgrades. Review each resolved
InstallPlan and record the installed versions before qualification.

For a cluster where the Trustee operator is already installed, the reviewed
bootstrap command is:

```bash
bash scripts/install-confidential-trustee.sh
```

The script refuses to replace its named Secrets, TrusteeConfig, or local
certificate. It creates self-signed TLS certificates for a lab setup. Use
approved certificates and a rotation procedure before production use.

On 2026-11-22, the Azure test cluster had the OSC 1.13.1 and Trustee 1.2.1
operator CSVs in `Succeeded`. A Restricted `TrusteeConfig` named `saw-trustee`
is now installed in `trustee-operator-system`. The Trustee deployment has one
available replica. Its KBS route presents the generated certificate, and a
client verified that certificate. A request with an empty attestation payload
reached KBS and received HTTP 401. This checks TLS and route reachability only;
it does not prove attestation or resource release.

The Trustee operator generated a `KbsConfig` and its default policy
ConfigMaps. The generated resource policy has `default allow = false`, but it
does not bind a verified SAW identity to a resource. The KbsConfig has only the
operator's `attestation-status` resource. No SAW credential resource was added.
The default reference values are not SAW image measurements. Do not add
credentials until the workspace-specific resource policy and verified
measurements are in place. The public KBS trust certificate is saved at
`local-docs/trustee-server-ca.crt`; the private TLS keys exist only in
Kubernetes Secrets and the installer’s temporary directory.

KataConfig `saw-confidential-kata` created the Azure PodVM image successfully.
The first configuration used `checkNodeEligibility: true`, but the Kata pool
had zero workers. Azure peer pods do not need host KVM hardware. The
reproducible Azure peer-pod configuration is in
`deploy/confidential/kataconfig.yaml`; it disables host eligibility filtering
and enables peer pods. After this approved change, all three workers entered
the Kata pool. At `2026-11-22T14:24:07Z`, a read-only check confirmed that all
three Kata workers were Ready, KataConfig had completed on all three nodes, and
RuntimeClass `kata-remote` existed with UID
`ee28c9d7-9eb2-4eca-96e2-01de7c9d2758`, handler `kata-remote`, selector
`node-role.kubernetes.io/kata-oc`, and overhead 250m CPU and 120Mi memory.
Trustee KBS and operator Pods were Running and Ready. The External Secrets API
was absent, and the `vault` and `saw-portal` namespaces had no Pods. A follow-up
API check from this Mac failed at about `2026-11-22T14:25Z` because the API
hostname did not resolve. The 14:24 values were the latest verified state on
2026-11-22. See the 2026-11-23 platform check above for the current foundation
status.

A separate job created the dedicated peer-pod network and verified both VNet
peering links. The worker subnet remains unchanged. The confidential feature
gate and Azure peer-pod ConfigMap are applied with `DISABLECVM=false`; `INITDATA`
remains unset until policy review. OSC's Azure identity path is not verified,
and no peer VM has been allocated. Guest DNS, image pulls, Trustee access,
worker communication, and return traffic remain unverified. Both deployment
probe Jobs and ConfigMaps were removed. SAW foundation services and confidential
workspace enrollment remain incomplete.

The OpenShell patch targets the revision in `source-lock.yaml`. It adds
administrator-owned confidential placement for both supervisor and workload
Pods. Each placement binds a RuntimeClass and measured init-data. Supervisor
entries also bind a read-only per-slot configuration ConfigMap. The ODH source
checkout matches the pinned revision. Its complete diff matches the saved patch,
and the reverse-apply check passed. The Kubernetes driver library tests passed:
287 passed, 0 failed, and 1 loopback telemetry test was skipped because this
environment denies local socket binding. Rust formatting passed. These checks
do not qualify the Linux gateway image, supervisor image, image signature,
attestation, or guest path. Build and sign the deployment images before using
the patch on the cluster.

The public ConfigMap is intended to contain `policy.json` and a per-supervisor
JSON file with this shape:

```json
{
  "policy": "/etc/saw-confidential/policy.json",
  "publicCAFile": "/run/openshell/saw-proxy-ca.pem",
  "resources": {
    "inference": "default/saw-alice-0123456789abcdef/inference"
  }
}
```

Build the patched gateway through OpenShell's normal release procedure. Build a
supervisor image with `supervisor.Containerfile`, supplying digest-pinned
`GO_BUILDER_IMAGE` and `SUPERVISOR_IMAGE` build arguments. Sign both images and
record the resulting digests. The source patch alone does not change any deployed
image. Admission and measured guest policy must constrain the command, environment,
public ConfigMap contents, images, and both role-specific init-data annotations.
Do not enable the path before those controls pass positive and negative tests.

## Azure administrator handoff

The peer-pod VNet and subnet are deployed at `192.168.240.0/24` with a Standard
NAT gateway, the existing NSG, and connected peering to the cluster VNet. This
does not prove peer VM traffic. The remaining platform work is to qualify the
OSC Azure identity and role assignments, outbound access, image-gallery access,
and confidential VM allocation. Prefer an approved DCasv5 SEV-SNP size for the
first canary. Use `kata-remote` and `DISABLECVM=false`. Host worker VMs do not
need nested virtualization for peer pods.

Once the image build and worker rollout complete, verify the supported guest
image and measured boot references. Keep all workloads blocked until the Trustee
policy, Azure identity path, and measured init-data pass synthetic tests. Install
the SAW foundation through the README Validated Pattern procedure. Keep all users absent until the
synthetic Trustee test passes.

## Credential release and the remaining integration

Vault remains the source of truth. First check whether the installed Red Hat
Trustee build supports the actual Vault engine, authentication method, and TLS
configuration. The upstream Vault backend alone does not prove that compatibility.
Use the namespaced External Secrets bridge if the installed build is incompatible.

For the bridge, the target Secret name is `saw-<owner>-<registration>`. Its
`inference`, `web-search`, and public `image-policy` keys become KBS resource tags.
Append only that Secret to `KbsConfig.spec.kbsSecretResources`, using a
resourceVersion check and preserving all unrelated entries. Reload KBS through
the installed operator's supported procedure.

The remaining work is required before removing the deployment guard:

1. Verify the installed Trustee token and evidence claim shapes. Confirm the
   parsed `agent_policy_claims.saw_identity` is present only for init-data that
   Trustee matched to hardware evidence. Bind it to one installation, owner,
   registration, slot, and role. Reject debug guests and unapproved measurements.
2. Generate deny-by-default attestation and resource policies. Only approved
   supervisor measurements may fetch provider credentials. Workloads may fetch
   the public image policy but cannot fetch credentials. Test cross-owner,
   cross-registration, and workload-to-supervisor denial.
3. The source now carries and verifies the confidential boundary. Validate it
   against the installed Red Hat Trustee objects and confirm that the approved
   object schemas match the live API.
4. Compose the patched gateway settings and both Pod annotations from the same
   enrolled data. Replace the external proxy and provider ExternalSecrets for
   this path. Update admission and network rules for confidential supervisors.
5. Qualify the generated confidential RHDH form and reference-only handler.
   The form omits key values. The portal checks only Vault metadata and stores
   approved references in the registry. Keep the form disabled until the full
   attestation, Trustee resource policy, and no-secret-isolation tests pass.
6. Publish reference values from verified build and platform provenance. Do not
   approve a new reference from an observed failed report without review.
7. Revoke resource access before deletion. Remove only that registration's KBS
   membership, ESO target, and Vault material. Test rotation with a controlled
   supervisor restart and a fresh fetch.

Provider plaintext may exist in Vault and, with the approved bridge, in the
Trustee namespace's Kubernetes Secret. Cluster administrators remain trusted in
this initial model. No provider Secret may exist in a workspace, controller, or
portal request namespace for the confidential path.

## Administrator-controlled credential rotation

Use this workflow only for an enrolled confidential RHDH registration that
already supports managed stop/start (`lifecycleVersion: 1`). Its existing model
and audit gates still apply. A fixed-model registration without that lifecycle
fails with `RotationManagedLifecycleRequired`. This command does not upgrade
its lifecycle or relax an audit requirement.

1. Update the credential through the approved Vault administration procedure.
   Do not put its value in Make arguments, manifests, or a shell command line.
2. Set these public selectors for the current registration:

   ```bash
   export SAW_CONTEXT='<kubeconfig-context>'
   export OPENSHELL_SAW_NAME='<owner>'
   export SAW_REGISTRATION='<16-hex-registration>'
   export SAW_TRUSTEE_SECRET_STORE='<trustee-scoped-store>'
   make saw-rotation-plan
   ```

3. Review the plan. Then run `make saw-rotate-confidential` during an approved
   maintenance window. A single-replica Trustee briefly stops accepting new
   attestations. The affected registration's supervisor and workload Pods also
   restart. Existing PVC data remains in place.

The command reads enrolled public configuration and the approved boundary.
It checks the RuntimeClass UID and placement digest, the measured supervisor
image and init-data, the Trustee identity, and the exact Vault resource scope.
It checks write permissions before changing resources. It never reads a
Kubernetes Secret or a Vault value. Its SecretStore must be restricted to the
Trustee namespace and use verified TLS with Vault KV v2 and Kubernetes auth.

A shared `saw-credential-rotation` Lease serializes these commands. A process
crash leaves the lock held. An administrator must confirm that no maintenance
command is active before clearing it. The workflow never takes over a held
lock automatically. The command forces an ESO refresh and waits for the exact metadata acknowledgement used by
ESO 1.3. An unknown acknowledgement format fails before Trustee is restarted.
It then evicts only the approved Trustee operand Pod. The eviction has UID and
resourceVersion preconditions and respects PodDisruptionBudgets. It does not
change the approved Deployment or policy. Multi-replica Trustee is rejected
until that topology has been qualified.

After Trustee is Ready, the command changes the selected portal source entry
to Stopped, waits for the controller barrier, then changes it to Running. It
waits for a complete set of new supervisor Pod UIDs under the same measured
placement. OpenShell requires this fresh sandbox generation when a dedicated
supervisor is replaced. The workflow keeps the gateway running.

The default timeout is 900 seconds. The CLI accepts `--timeout` from 60 to
1800 seconds. Any error stops the sequence with a fixed reason. A failed start
can leave the selected registration Stopped. Collect status before recovery;
do not bypass its enrollment or use a provider Secret as fallback. A killed
command can leave the maintenance Lease held. An administrator must verify
that no rotation command remains active before releasing that stale lock.

`RotationComplete` confirms the controlled restart and Pod placement. Verify
a fresh owner inference request separately. Provider-side key revocation and
release-denial tests remain separate acceptance checks.

## Verification sequence

| Check | Required result |
| --- | --- |
| Synthetic credential | Attested supervisor receives its own resource |
| Changed boot or init-data measurements | Release denied |
| Debug guest, host exec, guest-policy replacement | Denied |
| Foreign owner, old registration, workload role | Credential release denied |
| Both profile slots | Supervisor and workload Pods use confidential VMs |
| Guest evidence | Produced by the guest startup path, without enabling host exec |
| Owner chat and tools | Allowed operations work; denied tools and egress fail |
| Isolation | Provider keys absent from workspace Secrets, request objects, logs, and manifests |
| Lifecycle | Persistence, restart, stop/start, rotation, and deletion pass |
| Entry paths | Make, GitOps, and RHDH pass |
| Regression | Plain container and Kata pass; two owners remain isolated |

Stop after the first failure. Preserve the registration and collect safe evidence
before another request. AWS qualification follows the Azure acceptance run.

## References

- [Red Hat confidential containers on Azure](https://docs.redhat.com/en/documentation/openshift_sandboxed_containers/1.13/html/deploying_confidential_containers_on_microsoft_azure/configure-cc-overview_azure-cc)
- [Red Hat Trustee configuration on Azure](https://docs.redhat.com/en/documentation/openshift_sandboxed_containers/1.13/html/deploying_red_hat_build_of_trustee_for_workloads_running_on_microsoft_azure/configure-trustee-overview_azure-trustee)
- [Red Hat KB 7149016](https://access.redhat.com/kb/7149016): Trustee Secret resources and CDH delivery. Its KServe/model-serving installation steps do not apply to SAW.
- [Trustee KBS protocol](https://github.com/confidential-containers/trustee/blob/main/kbs/docs/kbs_attestation_protocol.md): KBS authenticates an attester before it releases encrypted resources.
- [Guest component REST API](https://github.com/confidential-containers/guest-components/blob/main/api-server-rest/README.md)
- [Trustee attestation token](https://github.com/confidential-containers/trustee/blob/main/attestation-service/docs/attestation_token.md): parsed `agent_policy_claims` are emitted only when the supplied init-data plaintext is bound to hardware evidence. The installed Red Hat build must still be checked.

## Init-data encoding

The Kata init-data annotation uses gzip-compressed TOML encoded as Base64. The
reported `sha256` is the hash of the uncompressed TOML. Keep this distinction:
OSC uses the TOML hash when it derives PCR 8, and it uses the compressed form in
the Pod annotation. See the [Red Hat OSC 1.13 Azure Red Hat OpenShift guide](https://docs.redhat.com/en/documentation/openshift_sandboxed_containers/1.13/html/deploying_confidential_containers_on_microsoft_azure_red_hat_openshift/configure-cc-overview_aro-cc).

The 2026-11-23 runtime smoke Pod reached `Running` with `kata-remote`. This
confirmed the peer-pod runtime launch only. A separate Trustee status probe did
not start its container and did not return an attestation result. Do not count
that probe as confidential-workspace qualification.

## Matched image and init-data probe (2026-11-23)

A credential-free UBI 9 baseline Pod without init-data reached `Running` and
`Ready` on worker `coco-azure-d5ft7-worker-eastus3-wzsl6` with RuntimeClass
`kata-remote`. Its resolved image digest was
`sha256:08d4c70f1baf6537a0728656cf7942d561e74a35916509d205b6519861266352`.

A second Pod used the same image digest, worker, and RuntimeClass with the
existing restrictive init-data annotation. CAA created a peer VM and tunnel,
and reported the TCP agent proxy ready on port 15150. CRI-O then reported
`CheckRequest timed out` and `CreateContainer failed: create container timeout`
at `2026-11-23T10:17:08Z`. The sandbox and container did not start. Kubelet
retried, and CAA started another peer VM at `2026-11-23T10:18:59Z`.

I deleted the temporary namespace to stop the retries. The namespace and
PeerPod object are gone, and the two node-debug Pods used for log capture were
removed. CAA did not report successful deletion of the second Azure VM by
`2026-11-23T10:21:29Z`; Azure-side cleanup remains unverified because no Azure
management login is available in this session. Do not start another VM probe
until cleanup is verified.

This matched test shows that `kata-remote` and the guest image start without
init-data. The failure occurs after the init-data case opens its network path,
but before the Kata Agent answers its health check. The init-data or guest boot
path remains the leading area to diagnose. No attestation report, Trustee
release, or SAW workspace was tested. Capture guest serial/console output and
verify Azure VM cleanup before another attempt.

## Init-data correction and current stop point (2026-11-23)

The API version endpoint reports Kubernetes `v1.35.9`. Later CAA logs confirmed
that the probe VMs were deleted. The probe namespaces and PeerPod objects are
also gone.

Review of the generator found that `aa.toml` placed the certificate under the
Attestation Agent token settings and omitted the `coco_as` URL. Red Hat's Azure
init-data example puts both `coco_as.url` and `kbs.url` in `aa.toml`; it puts
the certificate in `cdh.toml` as `kbs_cert`. The generator and its three chart
copies now follow this structure. The initial cluster-independent contract
suite passed 69 tests. The suite now also covers Trustee RVPS format validation;
it passed 79 tests on 2026-11-23.

This source correction has not been tested on a live peer pod. Do not retry
until platform qualification is complete. `deploy/confidential/source-lock.yaml`
still has no qualified guest image or reference set, and the live Trustee RVPS
ConfigMap contains no usable reference values. Generate and approve measurements
from the pinned guest image and exact init-data before another attestation test.
See the [Red Hat OSC 1.13 Azure init-data guide](https://docs.redhat.com/en/documentation/openshift_sandboxed_containers/1.13/html/deploying_confidential_containers_on_microsoft_azure/configure-cc-overview_azure-cc).

The pinned `coco-tools` image was inspected locally. Its Veritas command writes
Trustee BoT 1.2 data under the ConfigMap key `reference_value`. The value is a
JSON object keyed by TEE-prefixed PCR name. Each map value is base64-encoded
JSON with `name`, `expiration`, and `value` fields. The shared preflight now
validates this format, checks the Azure `snp_pcr03`, `snp_pcr08`,
`snp_pcr09`, `snp_pcr11`, and `snp_pcr12` entries, rejects expired values,
and compares the SHA-256 digest of the canonical JSON map (sorted keys,
compact separators) with the approved `referenceSet`.
The `referenceValues` object approval still pins the ConfigMap UID and complete
data content.

No measurements were added to Trustee. The pinned `coco-tools` image used an
old default Rekor hostname, which returned `NXDOMAIN`. Current Veritas source
lists a replacement Red Hat endpoint in its
[Rekor configuration](https://github.com/confidential-devhub/veritas/blob/main/src/veritas/container.py).
I passed that endpoint with `--rekor-url` and `--rekor-pub-key-url`. Cosign
then verified the image signature. Veritas resolved OSC image tag `1.13.1` to
`sha256:cd0bbdc464dfe0060b33a07474f30ed093a6efc839ba910a44915ef9f55b195b` and
generated `snp_pcr03`, `snp_pcr09`, `snp_pcr11`, and `snp_pcr12`.

The partial output is in
`local-docs/kata-confidential-veritas-azure-snp-1.13.1.partial.yaml`. It does
not contain `snp_pcr08`, which Veritas computes from init-data. The exact
approved SAW init-data is not available yet. Do not apply this partial file.
No cluster resources changed. The full reference set remains blocked until
Veritas measures the exact init-data for the approved SAW registration and
roles. Do not use test measurements or measurements from an untrusted probe
Pod as RVPS references.

## OPA policy validation and live gate (2026-11-24)

The reviewed Kata Agent policy now passes `opa check --strict` with OPA v1.22.4.
Nine OPA tests pass through `make saw-test-kata-policy`. They check normal
container lifecycle requests, denied process execution, denied stream reads,
denied policy replacement, allowed shared-container copies, rejected copies
outside the shared path, path traversal, and absolute symlink targets. Tests
use a synthetic SAW identity. The OPA binary and generated policy copy stayed
under `/private/tmp`.

Read-only checks on the Azure cluster confirm that `kata-remote` still uses
handler `kata-remote` and selector `node-role.kubernetes.io/kata-oc`, and the
KataConfig reports `InProgress=False`. No PeerPods exist. The Trustee RVPS
reference ConfigMap contains zero entries. The `qualified` gateway image,
supervisor image, guest image, and reference set in
`deploy/confidential/source-lock.yaml` remain unset. No cluster resource
changed during these checks.

This confirms local policy syntax and the listed policy decisions only. It does
not verify init-data parsing, guest boot, attestation, or Trustee release. Do
not launch another PodVM until the pinned guest inputs and exact approved
init-data have a reviewed reference set in RVPS. The next step is to produce
and review those measured build artifacts. The confidential deployment gate
stays closed.

## Local supervisor candidate (2026-11-24)

The supervisor build script now defaults to `PLATFORM=linux/amd64` and accepts
only Linux AMD64 or ARM64 targets. It passes the selected platform to Podman.
This prevents the ARM64 build host from selecting the wrong output architecture.

The local candidate `localhost/saw-confidential-supervisor:f2968dd` built with
the pinned supervisor base in `source-lock.yaml` and the Go builder
`docker.io/library/golang@sha256:d2d2bc1c84f7e60d7d2438a3836ae7d0c847f4888464e7ec9ba3a1339a1ee804`.
Podman reports Linux AMD64 and local manifest digest
`sha256:34d579d6eafe4c790839a5b33e9703f96d594f0f39f3ee43dbdfa57f2bb15d64`.
The supervisor starts with `--help`. The packaged proxy's `supervise` command
exits with `AttestationConfigurationRejected` when its public configuration is
absent. Both checks used a read-only filesystem, no network, and no credentials.
The base supervisor records source revision
`71b5bdbf4222b593e397609821726abaa229fa9d`; the patched driver targets the
separate OpenShell revision in `source-lock.yaml`. Their integration is untested.

This candidate exists only in the local Podman store. It has not been pushed,
signed, or qualified. Do not put its digest in the qualified source-lock fields.
The patched gateway image also needs a Linux build. Its documented Konflux
build needs Hermeto and Linux RPM tools; Hermeto is absent from the Mac shell.

A read-only cluster check found the Azure gallery image version ending in
`1104433989.0.1`, VM size `Standard_DC2as_v5`, and `DISABLECVM=false` in
`peer-pods-cm`. These are configuration observations, not attestation evidence.
No cluster resources changed. The next gates are a patched gateway build,
reviewed image signatures, and approved guest and exact init-data measurements.

## Kata canary profile

The `kata-data-science` catalog profile provides one default OpenClaw notebook
with NVIDIA inference. It does not request a web-search credential. It defines
workspace content only; the confidential RHDH template selects Kata separately.
The confidential form selects this profile by default.
The profile does not qualify its image or prove confidential execution. Keep
workspace creation blocked until the approved site values, measured init-data,
Trustee resource policy, and live boot checks pass.
