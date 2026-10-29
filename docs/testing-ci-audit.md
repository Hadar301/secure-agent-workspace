# CI test-flow audit

Scope: `main` at `533be02ec02a69bd1bf9b20274bf9ce8bbef6668`.
Implementation branch: `codex/ci-test-flow`. Tests from open PR #134 are excluded.
See [Testing](testing.md) for contributor rules and commands.

## Removed-test map

The table lists every removed function. Named parameter cases retain distinct
input variations. A smaller function count is not a performance measurement.

| Original test | Retained assertion or removed behavior |
|---|---|
| `test_apply_profiles::test_fresh_apply_creates_everything` | `test_shipped_profile_lifecycle`: gateways, workspaces, providers, sandbox set, admin command environment, and verification. |
| `test_apply_profiles::test_openclaw_calls_the_native_endpoint_with_the_placeholder_key` | The old body had only a docstring. The lifecycle test now checks the NVIDIA endpoint and the sandbox-side key-variable reference. |
| `test_apply_profiles::test_system_inference_skipped_without_default_workspace_model` | Removed the ineffective provider-model mutation. The model now comes from sandbox inference. The lifecycle test retains endpoint checks and rejects `inference.local` and inference commands. |
| `test_apply_profiles::test_nemoclaw_gets_the_provider_key_via_environment` | Lifecycle: one fresh NemoClaw onboarding call with its key in the environment. |
| `test_apply_profiles::test_keepalive_units_are_written_for_agent_sandboxes` | Lifecycle: both unit paths, CUDA workspace, and runtime user. |
| `test_apply_profiles::test_second_apply_is_idempotent` | Lifecycle: unchanged workspaces, providers and sandboxes; two initial creates; no repeated NemoClaw onboarding. |
| `test_apply_profiles::test_credentials_never_appear_in_logs` | Lifecycle retains the positive credential-variable log assertion. Removed absence checks for values never supplied by fixtures. Explicit synthetic-value redaction remains in provider onboarding tests. |
| `test_cli::test_credentials_never_appear_in_argv` | `test_install_then_apply_reaches_ready`: marker provider state and credential-variable argv. Removed unused-value absence checks. The rejected-key test supplies a synthetic value and checks stdout, stderr, and status. |
| `test_sandbox_config::test_without_a_base_url_the_provider_types_own_api_is_used` | `test_official_api_providers::test_onboarding_uses_the_provider_protocol[typed-nvidia]`: native NVIDIA endpoint and OpenAI protocol. |
| `test_sandbox_config::test_an_official_api_without_a_base_url_onboards_natively` | Onboarding `[typed-openai-native]`: native auth choice, no custom flags, model selection. |
| `test_sandbox_config::test_anthropic_protocol_on_a_custom_endpoint` | Onboarding `[typed-anthropic-custom]`: custom endpoint and Anthropic protocol. Five named legacy-field cases remain in the same table. |
| `test_review_135::test_a_changed_env_recreates_the_sandbox_with_its_files` | `test_env_update_preserves_files[changed]`: changed env and label, create/delete counts, backup/upload, files retained, archive cleanup. |
| `test_review_135::test_removing_a_variable_recreates_too` | Env `[removed]`: no old env, recreation, and file preservation. |
| `test_review_135::test_an_unchanged_env_leaves_the_sandbox_alone` | Env `[unchanged]`: one create, no delete/backup/upload, unchanged label and files. |
| `test_reconcile::test_reconcile_does_not_retry_a_freshly_failed_input` | `test_reconcile_failed_input_backoff[same-failed-input]`: return 0 with no install call. |
| `test_reconcile::test_reconcile_retries_immediately_once_the_input_changes_again` | Backoff `[changed-input]`: install call and return 1. |
| `test_apply_profiles::test_full_apply_mounts_the_harness_into_notebook` | Lifecycle: read-only harness mount, three expected mounts, bundle files, plugin paths and enablement, MCP command and environment. |
| `test_apply_profiles::test_verify_runs_openclaw_in_agent_sandboxes_only` | Lifecycle: verification runs the OpenClaw version command in both agent sandboxes. |
| `test_apply_profiles::test_no_import_when_the_gateway_has_the_profile` | Lifecycle now supplies shipped provider profiles and checks that no import occurs when the gateway already has them. |
| `test_apply_profiles::test_profile_is_imported_once_across_applies` | `test_missing_profile_is_imported_from_the_chart_then_provider_created` checks the first import and unchanged reapply in one scenario. |

These changes remove 11 executed cases. Five new helper-contract cases cover
the cache, fixture isolation, and shared CI failure handling. The net count
falls from 1,688 to 1,682. Every existing test file still covers supported
behavior; no whole file met the removal criteria.

The apply-profile file falls from 57 to 47 cases. Across one CI run, the
scheduled pytest case executions fall from 3,540 to 3,000 (15.3%): external
checks run once, and the 82 Make-interface cases no longer run through lint
as well as pytest in each matrix job. These counts include skipped cases.

The fake no longer implements `inference set` or `inference delete`, and no
longer stores inference-route state. Contract tests require exit code 2 for
both commands. No production code uses these removed routes.

Supported migration tests remain. This includes 0.0-to-0.1 upgrades, old PKI
rotation, retired environment cleanup, backup failures, restore retries,
identity mismatches, and interrupted migrations. PR numbers and old versions
were not used as deletion criteria.

## Runtime changes

- The shipped-profile success checks share two applies instead of repeating
  separate full setups and applies.
- Prune tests use generic sandboxes and only the objects they inspect.
- Harness tests normally use one sandbox. Multi-sandbox contracts request the
  complete profile explicitly.
- Fake command setup is separate from PKI setup. Workers share immutable
  certificate bytes and copy private files for each test. PKI contract and CLI
  tests still create and clean up real certificates.
- Each test has a private temporary root in Python and child processes. This
  also isolates the installer's default backup-archive directory.
- Identical successful Helm renders reuse results within a worker. Chart and
  values-file content changes invalidate the cache. Each caller gets a separate
  result and parses separate documents. Failures are never cached.
- Polling logic uses a fake monotonic clock. Process, socket, and lock checks
  retain real timing. Gateway helper teardown stops the entire process group,
  including supervisors and their child processes.
- CI uses two pytest workers with load scheduling. Serial runs remain available.
- Static lint runs once. Make-interface tests run through the pytest matrix.
- Explicit per-test markers select external checks once. Python integration
  tests stay in both matrix jobs. Failed or cancelled shared checks cause the
  existing matrix checks to fail.

## Evidence and acceptance

The initial local probe covered five tests. It recorded 552 fake OpenShell and
Podman calls, which used about 36 of 42 seconds. That probe substituted the
missing Linux `shred` utility for temporary files. It is directional evidence,
not an acceptance measurement.

The two reported PR #134 jobs ran a different scope: 1,727 passed and 3 skipped.
Their pytest steps took 28:27 on 3.12 and 20:46 on 3.14. They are context only.

Local Ubuntu measurements use a non-root Ubuntu 24.04 arm64 container on the
same six-CPU Podman VM. Python versions are 3.12.16 and 3.14.10; pytest is 9.2.0,
pytest-xdist is 3.8.0, and Helm is 3.17.3. The arm64 `cryptography` 50.0.2 wheel
failed to import with an illegal instruction in this VM. Both comparison sides
therefore use 46.0.3. This local-only constraint does not change CI dependencies.

An initial image also lacked `jq`, OpenSSH, and gettext. Its failed run is not
used for runtime acceptance. The corrected image supplies these tools.

| Local run | Passed | Skipped | Elapsed |
|---|---:|---:|---:|
| Main, Python 3.12, serial | 1,685 | 3 | 733.22 s |
| Main, Python 3.14, serial | 1,685 | 3 | 730.77 s |
| Final, Python 3.12, serial | 1,679 | 3 | 567.80 s |
| Final, Python 3.12, two workers | 1,679 | 3 | 283.05 s |
| Final, Python 3.14, serial | 1,679 | 3 | 575.29 s |
| Final, Python 3.14, two workers | 1,679 | 3 | 304.64 s |

These elapsed times come from JUnit suite reports. All final runs use the
test code at `002b77d`. The 3.12 serial run is 22.6% faster. The two-worker run
is 61.4% faster than the original serial run. The 3.14 reductions are 21.3%
serial and 58.3% with two workers. These are local measurements, not the CI median.
The three unchanged skips cover the absent committed APF bundle and two
embedded Rust cases without Cargo. There are no new skips in these runs.

The largest local savings come from less work per scenario:

| Test file | Original serial total | Revised serial total | Cases before / after |
|---|---:|---:|---:|
| `test_apply_profiles.py` | 106.29 s | 80.25 s | 57 / 47 |
| `test_harness_mount.py` | 229.70 s | 148.61 s | 84 / 84 |
| `test_prune.py` | 68.15 s | 22.80 s | 25 / 25 |

These Python 3.12 sums come from JUnit case durations, which include fixture
time. The harness and prune reductions preserve their case counts.

JUnit files include fixture time. Separate serial baseline repetitions recorded
all phases with `--durations=0 --durations-min=0`. Both passed 1,685 cases with
the same three skips: 727.20 s on 3.12 and 737.65 s on 3.14.

| Serial phase report | Setup | Test calls | Teardown |
|---|---:|---:|---:|
| Main, Python 3.12 | 36.74 s | 633.32 s | 53.77 s |
| Main, Python 3.14 | 36.59 s | 643.51 s | 54.04 s |
| Final, Python 3.12 | 18.28 s | 492.10 s | 53.77 s |
| Final, Python 3.14 | 18.17 s | 499.57 s | 53.73 s |

These totals use pytest's rounded duration lines. The remaining difference
from wall time includes collection and runner overhead.

Collection selects 364 external cases and 1,318 Python cases, for 1,682 total.
The selections have zero overlap and zero uncovered cases. Markers are attached
to individual tests, so new unmarked tests enter both Python jobs.

The following failure checks remain active:

| Fault | Evidence |
|---|---|
| Retired inference call | The command-fixture contract sends both operations to the fake and requires exit code 2. |
| Leaked synthetic value | `test_shell_masks_secrets_in_logs` sends a synthetic value through a real subprocess. A temporary pytest hook disabled `Shell.mask`; the test failed at its output assertion as expected. The hook changed no source file. |
| Failed backup | `test_a_failed_backup_never_deletes_the_sandbox` checks that a failed download preserves the original sandbox. |
| Corrupt restore | `test_restore_rejects_corrupted_source_archive_before_upload` rejects a changed archive before upload. The content/mode cases execute real GNU tar and preserve retry data on failure. |
| Missing proxy binding | `test_named_credentials_have_distinct_markers_and_require_each_binding` removes a required binding and requires an installer error. |
| Failed shared checks | `test_matrix_check_propagates_shared_result` executes the workflow gate with success, failure, cancellation, and skipped results. Only success returns zero. |

The gateway process scan found no running test gateways or supervisors after
the revised process tests. The foreign-gateway case also verifies that one
test cannot stop another test's process. PKI-copy and render-cache contracts
check that changes to one caller's files or documents do not affect another.

The documented Make commands passed on Ubuntu: aggregate lint, interface lint,
one file, name selection, one lifecycle test, and complete phase reports.
The full suite passed serially and with two workers on both Python versions.
Collection through Make confirmed both CI selections. Documentation checks
also verified local links and matched all 20 removed functions to this map.

An initial CI sample at `f782adf` exposed a separate archive collision in
`test_profile_model_changes_remove_only_managed_choices[recreated]`. Two workers
could use `/tmp/saw-sandbox-archives` with the same sandbox name and timestamp.
One worker then removed the other worker's backup. The fixture now sets a
private `TMPDIR` and Python's cached temporary root. Its contract checks the
parent process, a child process, and the default archive path. Final acceptance
runs use `002b77d`, which includes this fix. Initial CI samples are not used for
the final performance claim.

## Three-run CI comparison

The baseline runs use `533be02` in `validatedpatterns-sandbox/secure-agent-workspace`.
The final runs use `002b77d` in the `Hadar301/secure-agent-workspace` origin fork.
Both are public repositories and use the same GitHub-hosted `ubuntu-24.04`
runner label and tool setup. The removed-test map accounts for the scope change
from 1,688 to 1,682 unique cases. PR #134 tests are excluded on both sides.

All six runs below passed. Times use minutes and seconds. Job time runs from
job start to completion. Total runner time sums all workflow jobs, including
shared checks and bundle checks. Workflow elapsed time also includes queue
time and job dependencies.

| Run | Longest test job | Total runner time | Workflow elapsed |
|---|---:|---:|---:|
| [Before 1](https://github.com/validatedpatterns-sandbox/secure-agent-workspace/actions/runs/40856364059) | 28:35 | 50:10 | 28:40 |
| [Before 2](https://github.com/validatedpatterns-sandbox/secure-agent-workspace/actions/runs/40860148096) | 27:12 | 53:43 | 27:17 |
| [Before 3](https://github.com/validatedpatterns-sandbox/secure-agent-workspace/actions/runs/40868375115) | 29:17 | 49:44 | 29:23 |
| **Before median** | **28:35** | **50:10** | **28:40** |
| [After 1](https://github.com/Hadar301/secure-agent-workspace/actions/runs/40868798998) | 11:47 | 22:03 | 13:00 |
| [After 2](https://github.com/Hadar301/secure-agent-workspace/actions/runs/40870520645) | 11:11 | 23:16 | 12:28 |
| [After 3](https://github.com/Hadar301/secure-agent-workspace/actions/runs/40872207552) | 11:27 | 22:39 | 12:51 |
| **After median** | **11:27** | **22:39** | **12:51** |

The median longest test job fell by **59.9%**.
Median total runner time fell by **54.9%**.
Median workflow elapsed time fell by **55.2%**.
The change meets the target of at least 50% less time in the median longest
test job, with lower total runner time. Runner variation remains visible in
the individual samples; these are measurements, not a runtime guarantee.

All three final runs published JUnit and duration reports. Each shared job
ran 364 cases with no skips. Each Python job ran 1,318 cases: 1,315 passed and
the same three cases skipped. The skips cover the absent committed APF bundle
and two Rust checks whose `serde_json` dependency was not in the Cargo cache.
The local Linux runs skip those same Rust cases because Cargo is absent.
No new skipped cases were introduced.

An earlier baseline run exceeded the Python 3.14 job timeout. It was replaced
by the completed Before 3 sample and remains in the excluded-run record.
The initial `f782adf` runs are also retained there, including the archive
collision described above. The failed initial run successfully uploaded its
JUnit result and duration log.

The [machine-readable results](testing-ci-results.json) contain source commits,
case counts, individual job times, local phase totals, skipped case IDs, and
excluded runs. Final CI reports are available from the linked runs. Full local
logs and JUnit files are retained in the ignored `test-results/ci-test-flow/`
directory.
