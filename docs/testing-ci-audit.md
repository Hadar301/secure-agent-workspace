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

The [current main run](https://github.com/validatedpatterns-sandbox/secure-agent-workspace/actions/runs/40697711577)
finished its 3.12 pytest step in 27:33. Its 3.14 step was cancelled at 30:00.
A cancelled job is not a completed timing sample.

Local Ubuntu measurements use a non-root Ubuntu 24.04 arm64 container on the
same six-CPU Podman VM. Python versions are 3.12.16 and 3.14.10; pytest is 9.2.0,
pytest-xdist is 3.8.0, and Helm is 3.17.3. The arm64 `cryptography` 50.0.2 wheel
failed to import with an illegal instruction in this VM. Both comparison sides
therefore use 46.0.3. This local-only constraint does not change CI dependencies.

An initial image also lacked `jq`, OpenSSH, and gettext. Its failed run is not
used for runtime acceptance. The corrected image supplies these tools.

Collection selects 364 external cases and 1,318 Python cases, for 1,682 total.
The selections have zero overlap and zero uncovered cases. Markers are attached
to individual tests, so new unmarked tests enter both Python jobs.

Full serial and parallel results and the remaining
performance acceptance work will be recorded after verification. The target
is a reduction of at least 50% in the median longest test job, with lower total
runner time, across three comparable before and after CI runs. Do not infer
that target from parameterization, case counts, or a single local run.
