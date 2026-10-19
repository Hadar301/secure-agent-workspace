# Minimal SAW deployment test

This test deploys a dedicated Validated Pattern configuration to a base
OpenShift cluster. It creates one Fedora 44 VM. The VM runs a Podman sandbox
and OpenClaw with NVIDIA inference. The test checks Keycloak/OIDC, Vault,
External Secrets, network controls, and cleanup.

## Private inputs

Each PR author supplies a dedicated cluster. Copy
`examples/saw/tp-e2e.example.yaml` outside the repository. Put the cluster
API URL, username, password, and NVIDIA API key in that private copy. Set
its mode to `0600`. The controller logs in and creates a temporary
kubeconfig. It also supports a kubeconfig and separate API key file for
existing setups. A local test machine needs `oc`, `helm`, `podman`,
`ssh-keygen`, `git`, `make`, `jq`, and `uv`. The controller downloads `virtctl`
from the cluster after OpenShift Virtualization starts. It needs network access
to the cluster, ingress routes, the source Git remote, and required images.
Create the local private file with an editor. Do not place credential values
in a shell command.

The cluster needs cluster-admin access, a default StorageClass or an explicit
`vm.storageClassName`, and capacity for the requested VM. Use a base cluster
without SAW, Vault, External Secrets, Keycloak, or OpenShift Virtualization
namespaces. The controller rejects an existing Pattern installation. This
protects resources that belong to another owner.

Check out a clean, pushed branch at the exact SHA to test. Set
`E2E_TARGET_BRANCH` if the checkout has no branch name. The controller checks
that this branch on `origin` points to the same SHA. For a fork PR, configure
`origin` to that fork before the run.

Run locally:

```sh
make test-saw-tp-e2e E2E_CONFIG=/absolute/private/test.yaml
```

The test writes JSON, JUnit, and a private run inventory under
`~/.local/state/saw-tp-e2e` by default. Set `E2E_STATE_DIR` to change this
location. The reports contain stage outcomes, the source SHA, component
versions, image digests, and timestamps. They contain no credential values.
Temporary inputs are removed after the run. The source private files remain.

## Manual CI

Use a fork that has the manual workflow file on its default branch. The API
and ingress routes must be reachable from a GitHub-hosted Ubuntu runner.

Start **SAW minimal Pattern deployment E2E** with `workflow_dispatch` in
that fork. Select the PR branch. Enter the cluster API URL, username,
password, and NVIDIA API key in the manual form. The workflow uses the
selected branch's SHA and the repository's default NVIDIA model. It creates
one owner-only config file on the temporary runner and calls the same
`make test-saw-tp-e2e` target. It uploads filtered reports. It has no push
or PR trigger. Do not add it as a required branch check.

GitHub does not provide a protected password field for manual workflow
inputs. The values entered in the form are workflow event data. The first
step masks them in job logs, but this does not turn the stored event inputs
into GitHub Secrets. Use credentials intended for this test and rotate them
after the run. Do not put the values in a PR comment or issue.

Record the local report, manual workflow link, CI report, and tested SHA on
the implementation PR or child ticket. The local and CI runs must use the
same SHA. Live acceptance remains pending until both runs pass and finish
cleanup. Later PRs can run the workflow when their authors supply inputs.

## Cleanup and recovery

The default is `cleanup: always`. Set `cleanup: retain` in the private config
or run the controller with `--retain` to keep the deployment and cluster lock
for inspection. The lock also remains when cleanup fails. To retry cleanup:

```sh
make clean-saw-tp-e2e E2E_CONFIG=/absolute/private/test.yaml
```

Use the same cluster and source checkout. Cleanup reads the cluster
lock inventory. It removes test resources, checks that they are gone, and
then releases the lock. It does not use the NVIDIA key. If a runner
stops during a run, use this command from another runner with the same
checkout and cluster access.

## Coverage

The resolved owner subject uses a live virtiofs ConfigMap mount, even when
the other VM inputs use ISO disks. The guest can receive the subject after
Keycloak becomes ready without a VM restart.

With governance disabled, the installer supplies the SAW sandbox policy
explicitly. The pinned OpenClaw image has a legacy policy schema that
OpenShell 0.1.2 rejects. The explicit policy uses the same filesystem and
process restrictions as the normal SAW policy. Provider profiles supply
the permitted inference endpoints.

The test covers the minimal Pattern, OpenShift Virtualization, one Fedora 44
VM, Podman, OpenClaw, NVIDIA inference, Keycloak/OIDC, Vault, External
Secrets, and network controls. SPIRE, RPM installation, Codex, Anthropic,
and the Kubernetes sandbox driver need later tests.
