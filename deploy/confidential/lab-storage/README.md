# Experimental Azure peer-pod storage lab

Status: **experimental and unqualified**. This component is not part of the
SAW pattern. It must not carry provider credentials or production data.

This lab tests an alternative to waiting for a documented Red Hat ARO storage
procedure. It does not establish Red Hat support. It does not replace the
ARO-managed Azure Disk CSI deployment, driver name, socket or StorageClass.

## Design and limits

The chart uses one registration, one test namespace and one canary worker.
Each release has its own CSI driver name, socket, RBAC and StorageClass.
The backend uses the installed vendor Azure Disk image by digest. The wrapper
uses the pinned Cloud API Adaptor source and the reviewed isolation patch.
See `source-lock.yaml` for the source and build inputs. A completed image build
is not proof that a guest can mount a volume.

The wrapper rejects foreign claim namespaces, foreign staging paths, CSI secret
references and credential-bearing CSI requests. The guest can update a volume
record only with a Pod-bound identity that matches its recorded Pod UID.
The node registrar and health probe use the wrapper socket owner UID. The
probe drops all capabilities and mounts only the socket, not the Azure config.
These controls supplement RBAC. They do not remove the trust placed in the
privileged host plugin or a guest helper with storage access.

The host plugin requires privileged access to the selected worker's kubelet
mounts, devices, CSI registration directory and Kata direct-volume registry.
The backend runs outside the confidential VM. It uses an Azure configuration
Secret in the lab control namespace. This is an infrastructure credential;
it must not contain an NVIDIA key. Neither the driver nor the guest receives
Kubernetes Secret read permissions through this chart.

An explicit init container creates the `/var/lib/kubelet` direct-volume marker.
The marker tool refuses foreign ownership, symlinks, changed contents and removal
while sandbox references remain. **Only one lab registration can own this marker
on each worker.** This design does not yet qualify two owners on the same worker.
Do not remove or replace an existing marker to bypass this check.

A guest helper is also required. Its image, commands, privileges, mount targets,
API identity and network access must be part of a reviewed measured policy.
The current chart does not deploy this helper or a guest Pod. Do not relax the
normal SAW launch policy to admit an unmeasured helper.

## Build and local checks

Build `Containerfile` with a repository-root build context. It fetches the exact
upstream revision, checks the patch hash, runs Go tests, and builds static AMD64
binaries. Its context needs only the public lab source files. Do not include a
local credentials directory or a values file with secrets.

```sh
uv run --locked pytest tests/charts/test_peerpod_csi_lab.py tests/test_peerpod_storage_admission.py
helm lint charts/saw-peerpod-csi-lab
```

Record the build UID, source hashes, test result and output digest in the private
acceptance record. Use a digest for each chart image. Keep site values, personal
registry names and live results outside Git.

## Install stages

1. Read the current managed driver UIDs and specifications. Save a hash baseline.
   Check that the proposed namespace, release, driver, StorageClass and policy
   names do not exist. Stop on a collision. Do not adopt an existing resource.
2. Prepare public site values from the chart defaults. Set `enabled: true`,
   `activate: false`, and `enforceGuards: false`. Pin all six images. Supply the
   exact API endpoint CIDRs and an ordinary lab Azure resource group.
   `wrapperBuildNamespace` can grant image pulls to the two lab service accounts.
3. Verify the `PeerpodVolume` CRD. If absent, create the supplied CRD after a
   server dry run. If present, compare its schema and ownership. Do not replace
   an existing CRD without a separate review.
4. Render the chart. For a new release namespace, create only its rendered
   Namespace with Helm release ownership metadata. Then install the chart.
   Both namespaces have Helm's `keep` policy. Do not copy the Azure credential.
   Confirm controller replicas and scheduled node Pods are both zero.
5. Wait for the four admission policies to pass server type checking. Enable
   `enforceGuards`, with `activate` still false. Run the checker:

   ```sh
   uv run --locked python scripts/check-peerpod-storage-admission.py \
     --context "$LAB_CONTEXT" --values "$LAB_VALUES" \
     --output "$LAB_ADMISSION_RESULT" --exercise
   ```

   The checker creates one public `PeerpodVolume` record. It tests claims,
   volumes and guest updates with server dry runs, then removes its own record
   with a UID precondition. It never reads a Secret. It verifies that dry-run
   resources and updates did not persist. Impersonation tests do not qualify
   the claims from a real guest token; test those separately inside the guest.
6. Prepare an exact activation and rollback proposal. Get review for the new
   credential location, privileged node plugin and shared mount marker. Do not
   set either acknowledgement to true before this review.
7. After approval, copy only the dedicated Azure identity's required fields into
   the lab configuration Secret. Do not print the value. Set both
   `acknowledgePrivilegedNodeAccess` and `acknowledgeGuestKubeletMarker` to true,
   then set `activate: true`. Verify only the selected worker runs the plugin.
8. Before a guest launch, verify the measured helper policy, image signatures,
   Trustee reference values, API identity and restricted network rules. Launch
   one credential-free guest. Stop after a failure and collect safe evidence.

No real workspace request is allowed until guest volume transport and normal
cleanup pass. The chart retains disks. Do not assume uninstall removes data.

## Actual Pod-bound API identity check

After the host stage is ready, run this check with the lab registration:

```sh
uv run --locked python scripts/check-peerpod-storage-identity.py \
  --context "$LAB_CONTEXT" --registration "$LAB_REGISTRATION" \
  --output "$LAB_IDENTITY_RESULT"
```

It creates a Pod with a scheduling gate and no runtime class. The Pod never
runs. The API issues a short-lived token bound to its UID. A SelfSubjectReview
must confirm that exact identity before the checker uses it. It then tests an
own-record update and rejects foreign Pod and disk updates with server dry runs.
The token stays in memory. Temporary objects are deleted with UID preconditions.
This does not qualify guest API connectivity or attestation.

`guest.Containerfile` can package the vendor driver tools and the lab wrapper
in one guest image. Supply only approved digest references for both build
arguments. It contains no cloud configuration, Kubernetes token or provider key.
Sign the resulting digest and verify it before admitting a guest. The resulting
image remains experimental until the measured launch and mount checks pass.

## Measured lab policy preview

`scripts/peerpod_storage_contract.py` defines one closed Pod shape. It is a
separate administrator tool. The normal SAW compiler still rejects this shape.
It does not add a portal option or enable confidential workspace enrollment.

The disk helper has guest mount authority. The wrapper runs as root with all
capabilities dropped and a read-only projected API token. The application runs
as a non-root user and has no API identity mount. Every role uses one signed
image digest and a fixed command. Unknown fields, extra roles, changed tokens,
foreign claims and new mounts fail validation.

The generator adapter removes only verified API-only controls and projection
sources that the pinned parser cannot read. It resolves the four known downward
fields to the reviewed Pod name, namespace, UID and worker. The original Pod
keeps those fields and all projection sources. Numeric UID, privilege,
capabilities, seccomp and mount authority remain in the generator input.

The lab compiler calls the canonical CRI-O converter. It then adds a separate
role-specific UID and no-new-privileges guard, an exact Pod UID, and direct mount
sources. Only the disk helper gets shared root propagation. The application
gets slave propagation. Host execution, policy replacement, stream access and
diagnostic requests stay denied. Its changed rule prefix cannot pass normal
SAW enrollment validation.

Before using it, verify the selected runtime has
`privileged_without_host_devices=true`. Do not permit host devices or loosen
that runtime setting. The reviewed generator settings permit CloseStdinRequest
for normal lifecycle handling. Record this one change from vendor defaults;
keep the other host-control defaults denied.

Generated preview identities are not reserved Kubernetes or volume identities.
They must never be used for a guest launch. The actual Pod must pass server
admission and be held by a scheduling gate while its real UID and volume name
are bound into the measured policy. Verify fresh reference values before release.
A preview that compiles is not proof of a guest mount or a complete workspace.

## Acceptance gates

- The managed CSI specifications and identities stay unchanged.
- Only the lab namespace can request its StorageClass.
- The driver rejects foreign claims, paths, disk records and CSI secret input.
- The actual guest token cannot change another Pod's record.
- Each mounted filesystem supports the configured UID/GID and a read-only mount.
- Three separate volumes support the SAW workspace and standard audit paths.
  Check actual log writes; do not apply the obsolete inode-sealing requirement
  to the default `localAudit` path. Signed receipts need separate qualification.
- A restart and a recreated VM preserve public test data.
- Normal Pod, PeerPod, Azure VM, volume attachment, CSI record and runtime cleanup
  completes. Allow for the configured kubelet stopped-container retention time.
- A second registration cannot use the first registration's disk or marker.
- Trustee, Argo CD and the SAW foundation remain healthy.

Keep `realCredentialUseAllowed: false` until these checks pass. A successful
admission dry run is not a successful mount or attestation test.

## Rollback

1. Keep the lab CSI components running while deleting the guest normally.
   Wait for detach, PeerPod and Azure VM removal. Do not force-delete or restart
   CRI-O to make a failed cleanup appear successful.
2. Confirm there are no live attachments, guest processes or runtime sandbox
   references for this registration. Save identifiers and safe status reasons.
3. Set `activate: false`. Wait for the controller and node Pods to stop.
4. Run the same pinned image's `/saw-lab-marker --mode=remove` in a reviewed,
   canary-only privileged cleanup Job. Mount only the direct-volume registry.
   Pass the same registration. Stop if the tool reports a foreign owner, changed
   marker or remaining sandbox reference. Never remove the registry recursively.
5. Uninstall only this release. The namespaces and disks remain. Confirm the
   managed driver baseline still matches. Remove the lab credential copy and
   pull binding after checking ownership; preserve the original OSC credential.
6. Review retained PVCs, PVs and Azure disk IDs before deleting test data. Remove
   only the lab's detached disks and empty namespaces. Do not delete shared
   Secrets, the original Azure identity, its roles or ARO-managed resources.
7. Remove the CRD only if this lab created it and no instance exists in any
   namespace. Preserve it if another application now uses it.

If normal detach fails, stop and diagnose it with the storage components still
available. Do not change host software or the confidential runtime as rollback.

## Admitted guest policy input

Reserve the test Pod behind its scheduling gate. Compile the launch policy from
the admitted Pod, with its actual UID and bound PV. The lab adapter accepts only
the pinned peer-pod webhook conversion and known OpenShift API defaults. It keeps
the admitted VM sizing and the one-VM resource allocation. Unknown fields or
changes to privileges, projections, placement and mounts fail closed.

The generator does not support the inherited Pod seccomp field. The adapter
removes that field only after it verifies each container's explicit profile.
The disk helper retains Unconfined; the wrapper and application retain
RuntimeDefault. The adapter does not change the deployed Pod. An offline preview
is not a launch approval. Production enrollment remains disabled for this lab.

The volume monitor must use a namespace-scoped informer. Filtering objects after
a cluster-wide list is insufficient with namespaced RBAC. The lab patch rejects
an empty or invalid namespace and scopes both the list and watch requests. Its
HTTP regression test checks the actual API paths. Do not grant cluster-wide
volume-record access to hide an informer configuration error.

A Bound claim or an attached VolumeAttachment does not prove guest access. The
wrapper returns a placeholder publish response before it attaches the disk to
the peer VM. Qualification requires the real VM identity, provider-specific device identification,
completed guest stage/publish operations, and an application write/read result.
Do not report the placeholder response as Azure disk attachment.

OpenShift adds public build name and namespace variables to each built image.
The compiler validates these two values as DNS labels and keeps their exact
values in the measured launch policy. A new build may change these labels.
All other base image environment variables retain their pinned hash. Missing,
duplicate, invalid or unknown environment values fail closed.

Before removing a scheduling gate, call `launch_input` on the actual Pod. This
check imports the production init-data annotation constant. It rejects a missing
key, a wrong key, duplicate aliases, malformed or oversized compressed data, and
a digest mismatch. Local policy generation and a healthy guest do not prove that
the runtime received init-data. Record fresh attestation evidence separately.

The reviewed helper makes CRI-O mark the infra container as a privileged runtime
context. The lab policy requires that exact pause annotation. Application OCI
requests must omit it or set it to false. This exception is confined to the lab
compiler. The production CRI-O policy still rejects privileged runtime contexts.
The handler must continue to exclude host devices.

The lab compiler also checks CRI-O's guest-local `emptyDir` representation.
The helper socket and temporary directory use the `local` storage driver.
Their paths must select the same sandbox ID. Their type, options, group and
storage count remain fixed. A foreign sandbox path fails the policy.

The privileged disk helper has a separate, fixed CRI-O mount and capability
layout. Only this role can use the bounded `container_file_t` MCS mount label.
The label does not prove workspace identity. The wrapper keeps all capabilities
dropped. Complete portable helper requests test the pinned vendor validator,
including rejected command, identity, capability and storage changes. These
checks do not qualify live storage or enable production enrollment.

Guest staging uses one bounded request. The wrapper limits a backend connection
to 10 seconds and its operation to 90 seconds. A failed request sets
`status.state: nodeStageVolumeFailed` and a finite `status.reason`. The reason
can identify a backend connection, request, timeout, device or mount failure.
It never contains the backend error text. Before a status update, the wrapper
checks the current Pod, volume, VM and target identities with a fresh resource
version. A replacement registration receives no update.

These diagnostics do not grant access to provider credentials or host execution.
The live Azure test reached real disk attachment. Guest staging and an
application write remain unqualified.
