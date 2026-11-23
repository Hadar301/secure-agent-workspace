# Confidential Kata workspaces with Trustee

Status: implementation in progress. Confidential enrollment is disabled.

## Latest platform verification (2026-11-23)

The Pattern utility can reach the Azure cluster API when it runs in its Linux
AMD64 Podman container. The Mac host still cannot resolve the API name. The
host DNS issue does not block commands run through the Pattern container.

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
The feature branch now rejects missing, broad, or additional copy rules before
deployment. The change has 66 focused contract tests passing; the branch is
not deployed to the cluster.

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

- `make saw-init` calls the existing read-only workspace preflight. It uses the
  same `SAW_USERS_VALUES_FILE`, `OPENSHELL_SAW_NAME`, and `DEPLOYMENT_MODE` inputs.
- Make, GitOps, and RHDH share confidential configuration and public-object
  checks. Each approval binds an object UID and its complete spec or data hash.
  The KBS attestation and resource policy ConfigMaps have separate references,
  so a policy edit invalidates the approval.
- Init-data generation uses supported `aa.toml`, `cdh.toml`, and `policy.rego`
  entries. The reviewed Rego template must define one `policy_data` object with
  a `saw_identity: __SAW_IDENTITY_JSON__` member. Generation replaces that
  marker with the installation, owner, registration, slot, and role identity.
  It must also deny `CopyFileRequest` by default and define exactly one rule,
  which allows requests only when `input.path` starts with
  `/run/kata-containers/shared/containers/`. The preflight rejects a missing
  rule, a broader path, or an additional rule. A live 2026-11-23 probe showed
  that the Kata Agent needs this request to create a container's shared
  filesystem. The later scoped-policy probe timed out before the container
  started; it did not verify attestation or Trustee release.
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
