# CI baseline and follow-up work

Status on 2026-10-22. This file describes the checks in this branch. It does
not claim that a GitHub Actions cluster run has passed.

## Checks in this branch

`Deployment validation` runs on pull requests and pushes to `main`. It checks
rendered Helm resources, schemas, referenced dependencies, and version
consistency. It does not deploy the Pattern.

`Pattern cluster smoke` is a manual workflow for a reviewed pull request. It
uses one fresh cluster and a cluster lock. It builds the five images, records
their digests, installs the Pattern, checks repository Argo applications at the
tested commit, waits for both VMs to run, checks that deployed resources refer
to the new image digests, and uninstalls the Pattern. Failed cleanup fails the
check and retains the lock. A maintainer supplies credentials through the
`pattern-e2e` GitHub environment. The workflow must first be on the default
branch before it can be started from GitHub Actions.

The local `make test-pattern-e2e` target still runs guest installer and live
behavior checks after the smoke checks. It is for diagnosis and is not the
published `Pattern cluster smoke` status.

## Evidence from the cluster trials

The 2026-10-22 trial at commit `aa859296386bc5ef05f1ce50aa9decf6969b71d5`
completed all five builds and the Pattern install. Argo applications reached
the tested revision and both VMs ran. The trial stopped in the later guest
readiness check because `ciowner` reported a failed `install` or `apply` phase.
The report did not record which phase failed. No live behavior checks ran.
The image digest check was after the guest check, so that trial did not reach
it. The first automated uninstall timed out while waiting for a VM instance
to disappear. A later manual uninstall and resource check completed. This
branch extends that wait from 120 to 600 seconds, but a new cluster trial must
verify the change.

## Gaps for a later task

1. Diagnose the `ciowner` guest failure. Capture the phase name and a safe
   error category without publishing credentials. Require both guest phases
   to finish for full deployment acceptance.
2. Restore the full live checks as a CI gate: two-user authentication, sandbox
   listing and command execution, inference, access denial, and network
   isolation. These checks did not run in the last trial.
3. Run the new smoke workflow on a fresh cluster. Confirm image digests and
   automated cleanup, including a second uninstall. If cleanup still fails,
   fix it before reporting smoke acceptance.
4. Test two simultaneous manual runs and confirm that the lock rejects the
   second run without changing the cluster.
5. Add the manual workflow to the default branch. Set branch protection only
   after the related check has passed at the required commit. Do not label
   this smoke status as full end-to-end deployment validation.
6. Provide a default StorageClass for each fresh cluster run, or add an
   explicit per-VM class setting. The current runner stops at preflight if
   the cluster has no default class.

## PR description text

This PR adds automatic deployment validation and a manual Pattern cluster
smoke check. The smoke check covers builds, Pattern install, Argo revision and
health, running VMs, image digest references, and cleanup. It does not certify
guest installer completion or live application behavior. The last cluster
trial passed builds and Pattern install, then found a guest phase failure.
Automated cleanup also timed out once; a later manual cleanup succeeded. The
new smoke path and longer VM shutdown wait still need a fresh cluster run.
