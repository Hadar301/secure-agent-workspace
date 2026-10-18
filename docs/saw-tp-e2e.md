# Minimal SAW deployment test

This test deploys a dedicated Validated Pattern configuration to a base
OpenShift cluster. It creates one Fedora 44 VM. The VM runs a Podman sandbox
and OpenClaw with NVIDIA inference. The test checks Keycloak/OIDC, Vault,
External Secrets, network controls, and cleanup.

## Private inputs

Each PR author supplies a dedicated cluster and Linux runner. Copy
`examples/saw/tp-e2e.example.yaml` outside the repository. Set the config,
kubeconfig, and NVIDIA key files to mode `0600`. The config must give an
explicit kubeconfig context. The runner needs `oc`, `helm`, `podman`,
`virtctl`, `ssh-keygen`, `git`, `make`, `jq`, and `uv`. It needs network access
to the cluster, ingress routes, the source Git remote, and required images.

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

Start **SAW minimal Pattern deployment E2E** with `workflow_dispatch`. Give
the dedicated runner label, the absolute config path on that runner, and the
full pushed PR SHA. Put the config, kubeconfig, and key file on that runner
before dispatch. The workflow uses the same `make test-saw-tp-e2e` target and
uploads the filtered reports. It has no push or PR trigger. Do not add it as
a required branch check.

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

Use the same cluster context and source checkout. Cleanup reads the cluster
lock inventory. It removes test resources, checks that they are gone, and
then releases the lock. It does not need the NVIDIA key file. If a runner
stops during a run, use this command from another runner with the same
checkout and cluster access.

## Coverage

The test covers the minimal Pattern, OpenShift Virtualization, one Fedora 44
VM, Podman, OpenClaw, NVIDIA inference, Keycloak/OIDC, Vault, External
Secrets, and network controls. SPIRE, RPM installation, Codex, Anthropic,
and the Kubernetes sandbox driver need later tests.
