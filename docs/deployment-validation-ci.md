# Deployment validation CI

`Deployment validation` runs for each PR update and each push to `main`.
It renders all application and image builder charts, checks schemas, checks
external dependencies, and checks the OpenShell BOM version. The report is
`deployment-validation.json`.

`Pattern E2E` is a manual workflow. Start it from the default branch with
the PR number and its full current head SHA. The control job checks the PR,
the SHA, and the automatic check before it creates a temporary Git branch.
The execution job has cluster credentials and read-only Git access. A final
control job removes the branch and sets the `Pattern E2E` commit status.

## GitHub environment

Create an environment named `pattern-e2e`. Add these values:

| Name | Type | Value |
| --- | --- | --- |
| `CI_KUBECONFIG_B64` | secret | Base64 of a cluster-admin kubeconfig |
| `CI_CA_B64` | secret | Base64 of the PEM CA bundle for application routes and downloads |
| `CI_INFERENCE_KEY` | secret | NVIDIA inference API key |
| `CI_CLUSTER_API` | variable | Exact `oc whoami --show-server` URL |
| `CI_CLUSTER_UID` | variable | UID of the `kube-system` namespace |
| `CI_PROVIDER` | variable | `build` |
| `CI_MODEL` | variable | Model in `charts/saw-bom/profiles/ci-nvidia/default/providers.yaml` |

The runner needs access to the cluster API, application routes, internal
registry, GitHub, the OpenShift client mirror, and public package registries.
The fresh cluster must have a default StorageClass for the VM disks. The
runner checks this before it starts builds and does not change the cluster
default.
The kubeconfig and CA stay in a private temporary home. The workflow uploads
only structured results and resource status. It does not upload credentials.
The runner requires the NVIDIA key for a real inference request. The two CI
users use the `ci-nvidia` profile, which needs only that key. Normal users
can still use the data science profile with Brave web search.

The cluster runner creates `saw-ci-lock` outside Pattern ownership. It creates
the `saw-pattern-e2e` ConfigMap there with an atomic create call. The lock
holds the repository, PR, SHA, run ID, and run URL. A second run fails with
the active run link. If cleanup fails or the runner stops, the lock remains.
An administrator must inspect the cluster and remove the lock before another
run. Do not use an age limit to release it. Every other workflow that changes
this test cluster must honor this lock.

Use a fresh cluster for each run. The E2E test builds the sandbox, CLI,
Podman gateway, and governance interceptor images. It installs two ordinary
users, checks Argo application health and revision, waits for both VMs to run,
checks the built image digest references, requires both guest installer phases
to finish, tests two-user access, makes a real NVIDIA inference request,
checks network isolation, and uninstalls the Pattern twice.
The NemoClaw sandbox image is built and checked in the deployed profile; the
`cuda-sandbox` remains disabled in this first scope.

## Rollout

Merge the manual workflow into the default branch before the first GitHub
Actions run. Add environment values, then run one full E2E test. Start
two manual runs together to verify that only one gets the lock. Require the
E2E status for merge only after a complete run passes. A new PR commit needs
a new manual `Pattern E2E` result. No nightly run is configured.

## Local checks and schema sources

Run `make test-dependencies` with Helm 3, `kubeconform` 0.7.0, `skopeo`, Git,
and `uv`. Run `uv run --locked pytest -q tests/scripts/test_deployment_validation_ci.py tests/scripts/test_pattern_e2e_ci.py`
for the control and validation unit tests.

The `registry.redhat.io` PostgreSQL image requires Red Hat registry login.
The automatic check verifies its tag through the public Red Hat Container
Catalog API. The live cluster run checks that OpenShift can pull the image.

The vendored CRD schemas in `scripts/ci/schemas/` come from these pinned
upstream revisions. `scripts/ci/vendor_crd_schemas.py` extracts the selected
served OpenAPI v3 schemas from their CRD files:

- [RHDH Backstage CRD](https://github.com/redhat-developer/rhdh-operator/blob/82b4a840d12c06abb771bc6957b365c245477667/config/crd/bases/rhdh.redhat.com_backstages.yaml)
- [HyperConverged CRD](https://github.com/kubevirt/hyperconverged-cluster-operator/blob/37b709d5d9400d47dc03f96fef5f6ac21dc70f8f/config/crd/bases/hco.kubevirt.io_hyperconvergeds.yaml)
- [Tekton Pipeline CRD](https://github.com/tektoncd/pipeline/blob/592dfb840f02a0e9e2920f75b1737372ceb17c15/config/300-crds/300-pipeline.yaml)
- [Tekton Task CRD](https://github.com/tektoncd/pipeline/blob/592dfb840f02a0e9e2920f75b1737372ceb17c15/config/300-crds/300-task.yaml)
