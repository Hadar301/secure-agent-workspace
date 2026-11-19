# Azure confidential container workspaces

SAW owns the workspace lifecycle. A CoCo workspace uses the same gateway,
supervisors, profiles, credential proxy, audit, and owner routes as a container
workspace. Its OpenShell worker Pods use the approved `kata-remote` RuntimeClass.
Each worker gets a peer-pod virtual machine. The gateway and supervisors use
the default runtime.

## Select one platform owner

Use `overrides/values-coco-azure-managed.yaml` on a new Azure cluster. It adds
the OpenShift Sandboxed Containers and Trustee operator subscriptions and the
`sandbox`, `sandbox-policies`, and `trustee` Argo CD Applications to SAW. These
components install before any RHDH owner selects a workspace mode. The values
file pins operator CSVs and chart versions. Approve the manual install plans
after you review them. Review the Trustee policy and Azure VM reference values
for the target VM family before you grant owner approval.

Use `overrides/values-coco-azure-external.yaml` if another pattern already
owns these components. SAW does not create or prune those subscriptions and
Applications. SAW reads their current revisions and health before it creates
a CoCo workspace. The current Azure test cluster uses this option. Do not
install both values files.

Pass the selected file to the Validated Pattern install through
`EXTRA_HELM_OPTS`, in addition to the normal SAW install inputs. The file also
passes `portal.deploymentModes: [vm, kata, coco]` to the RHDH chart. A menu entry
appears only when the signed-in owner has a reviewed CoCo site and profile.

The CoCo platform values do not create owner sites. Add one approved site per
owner to the RHDH `portal.containerSites` input or its operator-owned Secret.
The same site works in `containerSites` for GitOps and Make.

The RHDH preflight role reads only the policy ConfigMaps named by `portal.coco`.
Use those same namespaces and names in each owner site. This keeps the portal
read role narrow.

Set:

- `deployment.mode: coco` on the owner request.
- `cocoRuntimeClass.name`, `uid`, and `sha256` from the live `kata-remote`
  RuntimeClass. The hash covers its handler, scheduling, and overhead.
- `coco.platform: azure`, `bypassAttestation: false`, and a reviewed secure
  `securityPolicyFlavour`.
- `coco.platformRevision` and the chart revisions of `sandbox`,
  `sandbox-policies`, and `trustee`. All three Applications must be Synced and
  Healthy at these revisions.
- `coco.attestationPolicy.namespace`, `name`, and the canonical SHA-256 of
  its public ConfigMap data. Review the policy before you approve its hash.
- `coco.guestPolicy.namespace`, `name`, and the canonical SHA-256 of the
  peer-pod `initdata` ConfigMap data. The preflight reads its `cdh.toml` and
  rejects an `insecure` image security policy URI.

- The normal SAW profile, network, storage, source revision, enrollment, and
  boundary approvals. The boundary also covers the sandbox placement policy.

The shared preflight runs before Make changes a workspace, before GitOps
projects it, and before RHDH writes credentials or registers it. It checks
Azure, peer-pod KataConfig readiness, RuntimeClass identity and handler,
platform Application revisions, Trustee and guest policy hashes, and the existing SAW
admission and service checks. A failed check returns a fixed reason. It does
not print a Secret value.

## In-place handoff on the Azure test cluster

The test cluster already has a CoCo pattern root. Keep that root as the
platform owner. Install SAW with the **external** values file. First check
that the three platform Applications are Synced and Healthy. Check that no
SAW Application or namespace is owned by both roots. Keep the existing
platform Applications under the CoCo root; do not copy them to the SAW root.
Create one disposable SAW owner only after the platform and owner approvals
pass. If any gate fails, keep the existing registration for diagnosis and
collect controller, gateway, Argo, and Pod events before another request.

## Live acceptance

The Azure canary must pass both profile slots and show two different peer-pod
virtual machines. Check the default runtime on the gateway and supervisors.
Then check owner chat, allowed and denied tools, network denial, Secret
isolation, audit, persistence, restart, stop/start, and deletion. Repeat the
path through RHDH, GitOps, and Make. Test a normal container workspace and
two active owners. Record observed results before marking this work complete.

AWS is not enabled by these values. Add an AWS platform adapter only after its
attestation, policy, and Secret release paths pass the same checks.

## Current live check

Read-only checks on 2026-11-19 found the three CoCo platform Applications
(`sandbox`, `sandbox-policies`, and `trustee`) Synced and Healthy. The default
KataConfig has peer pods enabled, with 3 of 3 nodes ready. RuntimeClass
`kata-remote` uses handler `kata-remote`.

The current guest `initdata` in namespace `imperative` selects the `insecure`
image policy. The shared preflight rejects this with `GuestPolicyInsecure`.
No CoCo workspace was created. Live acceptance remains blocked until the
platform owner installs and verifies the signed image policy and its KBS
resource, then updates the approved guest policy digest. The CoCo platform root
Application also reports OutOfSync while its child platform Applications are
Synced and Healthy; resolve that drift before using the managed install path.
