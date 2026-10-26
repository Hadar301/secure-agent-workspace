# Deployment validation CI

`Deployment validation` runs for each PR update and each push to `main`.
It renders all application and image builder charts, checks schemas, checks
external dependencies, and checks the OpenShell BOM version. The report is
`deployment-validation.json`.

`Pattern E2E` is a manual workflow. Start it from the default branch and enter
the PR number. The control job reads the latest head SHA from GitHub when the
run starts. It checks that the PR is open, targets this repository, and has a
passing `Deployment validation` check. It accepts PRs from forks. It then pins
the tested SHA to a temporary branch. A new commit pushed after this check
needs a new run.

The cluster job waits for approval through the protected `pattern-e2e`
environment before it receives cluster or inference credentials. Configure
required reviewers for this environment and enable **Prevent self-review**.
Reviewers must check the PR and SHA shown in the job name before they approve
access. The cluster job has read-only Git access. A final control job removes
the branch and sets the `Pattern E2E` commit status.

GitHub queues Pattern E2E runs so one workflow uses the cluster at a time.
It keeps up to 100 runs waiting. The OpenShift ConfigMap lock also protects
against other workflows that use the same cluster.

## GitHub environment

Create an environment named `pattern-e2e`. Add these values:

| Name | Type | Value |
| --- | --- | --- |
| `CI_CLUSTER_USERNAME` | secret | OpenShift user for the dedicated CI cluster |
| `CI_CLUSTER_PASSWORD` | secret | Password for the OpenShift user |
| `CI_CA_B64` | secret | Base64 of the PEM CA bundle for the API, application routes, and downloads |
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
Each run uses `oc login` to create a fresh kubeconfig. The workflow stores it
under a private runner temporary directory, copies it into the runner's
private home, and removes the login files after cleanup. The workflow uploads
only structured results and resource status. It does not upload credentials.
The runner requires the NVIDIA key for a real inference request. The two CI
users use the `ci-nvidia` profile, which needs only that key. Normal users
can still use the data science profile with Brave web search.

The cluster runner creates `saw-ci-lock` outside Pattern ownership and keeps
the namespace across runs. It creates the `saw-pattern-e2e` ConfigMap there
with an atomic create call. The lock holds the repository, PR, SHA, run ID,
and run URL. A second run fails with the active run link. Cleanup removes only
the ConfigMap after it verifies the lock owner. If cleanup fails or the runner
stops, the ConfigMap remains. An administrator must inspect the cluster and
remove the lock before another run. Do not use an age limit to release it.
Every other workflow that changes this test cluster must honor this lock.

Each run labels its Pattern utility container with the GitHub run ID. If a
command times out, the runner stops the command process group and any utility
container for that run before it starts cluster cleanup. Cleanup checks for
leftover run-labeled utility containers and stops if it cannot remove them.

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
Actions run. Add environment values and required reviewers, enable
**Prevent self-review**, then run one full E2E test. Start two manual runs
together to verify that the second waits in the GitHub queue. Require the E2E
status for merge only after a complete run passes. A new PR commit needs a new
manual `Pattern E2E` result. No nightly run is configured.

The first `Deployment validation` run starts when a PR opens or changes. The
first `Pattern E2E` run needs its workflow on the default branch. It also needs
an open PR with a passing `Deployment validation` check. A required reviewer
must approve the protected environment before the cluster job can access its
secrets. Maintainers can manually select any PR, including a fork PR, before
merge.

## Test coverage by stage

| Stage | Test | What was tested |
| --- | --- | --- |
| Existing PR tests | Lint charts and project files | `make lint` checks charts and project files in the existing installer test workflow. |
| Existing PR tests | Run Python test suite | `make test-installer` runs installer, chart, script, portal, and CLI tests under Python 3.12 and 3.14. |
| Existing PR tests | Check installer bundle drift | If a signed bundle exists, render the installer and verify its signature; skip this check when no bundle is committed. |
| Deployment validation | Render charts | All application and image-builder Helm charts render with CI values. |
| Deployment validation | Validate schemas | Rendered resources pass Kubernetes and vendored CRD schemas; missing or skipped schemas fail. |
| Deployment validation | Check external dependencies | Referenced external images, Git refs, and package URLs exist; repository-built images are checked during E2E. |
| Deployment validation | Check OpenShell versions | CLI, gateway, supervisor, and sandbox versions agree with the BOM; the interceptor ref matches the API version. |
| PR control | Read and pin the latest PR commit | The PR is open, targets this repository, and the run pins the latest head SHA returned by GitHub; fork PRs are allowed. |
| PR control | Check automatic validation | `Deployment validation` passed for the PR head or current merge commit. |
| Environment approval | Protect cluster credentials | A required reviewer approves the `pattern-e2e` deployment before the job receives cluster and inference credentials. |
| Workflow queue | Serialize cluster runs | GitHub runs one Pattern E2E workflow at a time and queues up to 100 waiting runs. |
| Cluster preflight | Check cluster identity and freshness | The API URL and cluster UID match; no Pattern, VM, build, or test namespace from an earlier run exists. |
| Cluster preflight | Check cluster capacity | The cluster has a default StorageClass, a Ready node with at least 4 CPU and 8 GiB, and valid CNV webhook state when present. |
| Cluster preflight | Reserve the cluster | An atomic lock blocks concurrent runs and records the repository, PR, SHA, and run link. |
| Build | Build runtime images | The discovery runtime, sandbox, CLI, Podman gateway, and governance interceptor builds complete and produce image digests. |
| Registry setup | Prepare guest image pulls | A short-lived, scoped registry token is added to private CI inputs for the guest VMs. |
| Install | Install the tested revision | Pattern installs the PR SHA for two CI users with the built image digests and CI network settings. |
| Deployment readiness | Check Argo applications | At least six selected applications become healthy at the tested SHA; allowed parent drift must be healthy child applications at that SHA. |
| Deployment readiness | Check virtual machines | Both CI user VMs reach `Running`. |
| Deployment readiness | Check image digests | The interceptor deployment, each user BOM and profile, and each VM gateway disk use the images built in this run. |
| Guest installer | Check installer phases | Both users report `install` and `apply` phases as `Done`; either phase failing stops the run. |
| Live cluster | Authenticate both users | Keycloak issues usable OIDC tokens for the owner and second user. |
| Live cluster | List the sandbox | The owner can list the `notebook` sandbox through OpenShell. |
| Live cluster | Execute in the sandbox | The owner can run a command in `notebook` and confirm `/sandbox` exists. |
| Live cluster | Deny cross-user access | The second user receives gRPC `PERMISSION_DENIED` when accessing the owner's sandbox. |
| Live cluster | Call NVIDIA inference | A real request with the configured model and NVIDIA key returns a completion. |
| Live cluster | Block undeclared egress | A request from the sandbox to `example.org` fails. |
| Cleanup | Uninstall Pattern | The cleanup stage runs Pattern uninstall twice to check repeat behavior. |
| Cleanup | Verify resource removal | Test namespaces and VMs, the Pattern, and repository Argo applications are gone; only namespaces created by the run are removed. |
| Cleanup | Release the lock and source ref | The cluster lock and temporary Git ref are removed only after cleanup verification; otherwise both remain for recovery. |
| Reporting | Publish result and artifacts | GitHub sets `Pattern E2E` to success only when tests and cleanup pass, and uploads structured results and resource status without credentials. |

The existing installer test workflow runs the Python test suite on every PR.
It does not deploy to a cluster. `Deployment validation` checks rendered
charts and dependencies. `Pattern E2E` checks the live cluster behavior.

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
