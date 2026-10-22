# CI baseline and follow-up work

Status on 2026-10-22. This file records the checks and the last cluster trial.
It does not claim that a full E2E run has passed.

## Checks in this branch

`Deployment validation` runs on pull requests and pushes to `main`. It checks
rendered Helm resources, schemas, external dependencies, and version
consistency. It does not deploy the Pattern.

`Pattern E2E` is a manual workflow for a reviewed pull request. It uses one
fresh cluster and a cluster lock. It builds the five images, records their
digests, installs the Pattern, checks Argo health and tested revision, waits
for both VMs, checks image digest references, requires both guest installer
phases to finish, and tests live behavior. Live checks include two-user
authentication, sandbox listing and command execution, a real NVIDIA
inference request, access denial, and network isolation. The runner then
uninstalls the Pattern twice. Failed cleanup fails the check and retains the
lock. The workflow must be on the default branch before GitHub Actions can
start it.

The local cluster run reads the existing NVIDIA key from `local-docs/.env`.
The key does not enter Git or test artifacts. The two CI users use the
`ci-nvidia` profile, which needs only that key. The normal data science
profile and its Brave support stay available.

## Evidence from the cluster trials

The 2026-10-22 trial at commit `aa859296386bc5ef05f1ce50aa9decf6969b71d5`
completed all five builds and Pattern install. Argo applications reached the
tested revision and both VMs ran. The trial stopped in the guest readiness
check because `ciowner` reported a failed `install` or `apply` phase. The
report did not record which phase failed. The image digest and live behavior
checks did not run. The first automated uninstall timed out while waiting
for a VM instance to disappear. A later manual uninstall and resource check
completed. This branch names the failed guest phase and extends the VM
shutdown wait from 120 to 600 seconds. A new run must verify both changes.

The next local trial at commit `6a64ffccf2bbfc0536b1857897def7aabc3c6fa6`
completed all five builds. Pattern install stopped before creating a Pattern
resource because the local Podman connection was hidden by the runner's
private `HOME`. Automated cleanup hit the same local error. Manual cleanup
removed the build namespace and lock, and restored the prior StorageClass
setting. The local launcher now preserves Podman's config directory, and the
runner checks Podman before it starts builds. This change still needs a full
cluster run.

## Gaps for a later task

1. Add Brave web search coverage when its API key is available. Extend the
   CI profile and its live checks; the normal data science profile already
   supports Brave.
2. Add the optional OpenAI and Anthropic provider checks when their keys are
   available. The current E2E run tests NVIDIA inference.
3. Test two simultaneous manual runs and confirm that the lock rejects the
   second run without changing the cluster.
4. Set up the GitHub environment and add the workflow to the default branch.
   Require the E2E status for merge only after a complete run passes at the
   required commit.
5. Provide a default StorageClass for each fresh cluster run, or add an
   explicit per-VM class setting. The runner stops at preflight if the
   cluster has no default class.

## PR description text

This PR adds automatic deployment validation and a manual full Pattern E2E
check. The E2E check covers builds, Pattern install, Argo health and revision,
running VMs, image digest references, guest installer completion, live NVIDIA
inference and access checks, network isolation, and cleanup. Brave web search
and other optional providers are deferred until their API keys are available.
The last cluster trial reached a guest installer phase failure and an
automated cleanup timeout. A complete E2E run must pass before this check is
required for merge.
