# Storage setup for `./pattern.sh make install`

The Secure Agent Workspace pattern provisions **per-user VM root disks** (CDI
`DataVolume`s) and a few supporting PVCs. The charts do **not** set a
`storageClassName` on any of them, so every disk and PVC is provisioned from
the cluster's **default StorageClass**. Before you run `./pattern.sh make
install`, make sure storage is ready — otherwise the VMs never get a disk and
the install stalls.

## TL;DR

1. A **default StorageClass must exist** (`oc get storageclass` shows one marked
   `(default)`). The pattern sets no storage class of its own.
2. That class must actually **provision** and have a working **CDI
   StorageProfile** (so DataVolume imports don't hang).
3. The VM root disk asks for **ReadWriteOnce** — any CSI works; RWX is **not**
   required for the workspaces.
4. **Bare-metal clusters (x86 or arm64):** turn on the internal image registry
   with storage (RWX recommended). `make images-mirror` copies the golden image
   there; an optional on-cluster build also pushes there.

---

## 1. Make sure a default StorageClass exists

The VM root disk template requests storage with **no class name**:

```yaml
storage:
  accessModes: [ReadWriteOnce]
  resources: { requests: { storage: <vm.diskSize> } }
```

With no `storageClassName`, CDI/Kubernetes use the cluster **default**
StorageClass. If there is no default, the `DataVolume`/PVC stays `Pending`
forever and the VM never boots.

Check:

```bash
oc get storageclass
# look for the one annotated storageclass.kubernetes.io/is-default-class=true,
# shown as "(default)" in the NAME column
```

If none is marked default, set one (pick a class that provisions on your
cluster — ODF/Ceph, LVMS, hostpath, NFS, etc.):

```bash
oc patch storageclass <name> \
  -p '{"metadata":{"annotations":{"storageclass.kubernetes.io/is-default-class":"true"}}}'
```

If more than one is marked default, remove the annotation from the extras
(`...is-default-class":"false"`) — multiple defaults make provisioning
ambiguous.

## 2. Make sure the default class works with CDI

The DataVolume sets `cdi.kubevirt.io/storage.bind.immediate.requested: "true"`,
so CDI binds the PVC immediately rather than waiting for the VM. CDI decides the
access/volume mode from a **StorageProfile** for the class. If the class has no
usable profile (common with a brand-new or `WaitForFirstConsumer`-only class),
imports can hang in `ImportScheduled`/`Pending`.

```bash
oc get storageprofile <default-class-name> -o yaml   # claimPropertySets should be populated
```

If `claimPropertySets` is empty, set the access/volume mode explicitly on the
StorageProfile (match what your CSI supports), e.g.:

```bash
oc patch storageprofile <default-class-name> --type merge -p \
  '{"spec":{"claimPropertySets":[{"accessModes":["ReadWriteOnce"],"volumeMode":"Filesystem"}]}}'
```

## 3. Access mode — RWO is enough

The root disk is `ReadWriteOnce`, so **any** CSI/StorageClass that provisions
RWO works. You do **not** need ReadWriteMany for the workspace VMs. (A
consequence: these VMs are not live-migratable, because an RWO root disk pins
them to one node — expected.)

## 4. Bare-metal clusters: the internal image registry

On bare-metal clusters (x86 or arm64, including **Grace / GB200**) the internal
image registry is often off (`managementState: Removed`). `make images-mirror`
copies the multi-architecture golden VM image into the internal registry; an
optional on-cluster build pushes its result there too. Workspace VMs import
their root disk from the registry, so it needs storage. Turn it on with a
class that can hold it, ideally **ReadWriteMany**:

```bash
oc get configs.imageregistry.operator.openshift.io cluster \
  -o jsonpath='{.spec.managementState}{"\n"}'

oc patch configs.imageregistry.operator.openshift.io cluster --type merge -p \
  '{"spec":{"managementState":"Managed","defaultRoute":true,"storage":{"pvc":{"claim":""}}}}'
```

`"claim":""` lets the registry operator create its PVC from the **default**
StorageClass, so step 1 covers this too. See [arm64 notes](arm64.md) for the
optional on-cluster build flow.

## 5. Verify, then install

```bash
oc get storageclass                       # exactly one (default)
oc get storageprofile                      # default class has claimPropertySets
# run the install
./pattern.sh make install
# watch the disks land
oc get dv,pvc -A | grep saw-               # DataVolumes go Bound / Succeeded, not Pending
oc get vm,vmi -A                           # VMs reach Running
```

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `DataVolume`/PVC stuck `Pending` | No default StorageClass, or the default class's provisioner can't bind (step 1) |
| Import stuck `ImportScheduled` / CDI never binds | Default class has no usable CDI StorageProfile / access mode (step 2) |
| VM never starts, no `-root` PVC | Same as above — the disk was never provisioned |
| Image mirror or on-cluster build can't push | Internal registry still `Removed` or has no storage (step 4) |
| Two classes marked default | Ambiguous provisioning — leave exactly one default |

## Automated pre-check (`make storage-class-check`)

`./pattern.sh make install` now runs `scripts/storage-class-check.sh` before the
GitOps apply (it is a prerequisite of `pattern-install`), so the install stops
with a clear message instead of leaving the VM DataVolumes `Pending` when no
default StorageClass exists. On a terminal it is interactive:

- **A default already exists** — it prints the class name and continues.
- **Classes exist but none is default** — it lists them and, on confirmation,
  marks one default (`oc patch`). Pick one non-interactively with
  `SAW_STORAGE_DEFAULT_CLASS=<name>`.
- **No StorageClass at all** — with a prominent warning, it offers to enable the
  **HostPath Provisioner (HPP)** through OpenShift Virtualization and create a
  default `saw-hostpath` class. HPP needs OpenShift Virtualization present, which
  the pattern installs during `make install`; on a brand-new cluster, either
  install a provisioner first (LVMS for local disks) or let `make install` bring
  up Virtualization and re-run `make storage-class-check`.

Non-interactive runs (CI/GitOps, no TTY) do not prompt: they print this guidance
and fail, so nothing hangs. Set `SAW_STORAGE_ASSUME_YES=1` to accept the prompts
unattended. You can also run the check on its own at any time with
`make storage-class-check`.
