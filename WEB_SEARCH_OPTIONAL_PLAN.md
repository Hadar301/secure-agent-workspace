Make web search optional in the GitOps deploy

 Context

 Saurabh's report: a user who leaves web search out (comments out the web-search entry in
 values-secret.yaml, so Vault has no hub/web-search) still gets a web-search ExternalSecret.
 ESO then reports SecretSyncedError, and the GitOps deploy goes Degraded and gets stuck. Today the
 only workaround is a code change on a fork, which is inconvenient for anyone deploying straight from
 main.

 About web-search-secret.yaml: charts/pattern-secrets/templates/web-search-secret.yaml is
 already conditional: {{- if has "web-search" (.Values.secrets | default list) }}. The bug is
 upstream of it. saw-users builds that secrets list from the profile catalog. The default
 data-science profile has a brave provider with credentialSecret: web-search, so web-search
 is always on the list. The same list drives three things, and all three break when the key is
 missing:

 ┌───────────────────┬─────────────────────────────────────────────────────────────────────┬────────────────────────────────────────────────────────────────┐
 │       Step        │                                Where                                │                  What breaks without the key                   │
 ├───────────────────┼─────────────────────────────────────────────────────────────────────┼────────────────────────────────────────────────────────────────┤
 │ 1. ExternalSecret │ pattern-secrets (via saw-<u>-secrets app)                           │ SecretSyncedError, so the app is Degraded                      │
 ├───────────────────┼─────────────────────────────────────────────────────────────────────┼────────────────────────────────────────────────────────────────┤
 │ 2. VM Secret      │ openshell-saw additionalProviderSecrets, a required volume in       │ virt-launcher stays in ContainerCreating (FailedMount) and the │
 │ mount             │ virtualmachine.yaml                                                 │  VM never boots                                                │
 ├───────────────────┼─────────────────────────────────────────────────────────────────────┼────────────────────────────────────────────────────────────────┤
 │ 3. Installer      │ apply_bom.py resolve_credentials (brave provider enabled)           │ credential for provider 'brave' in workspace 'default' not     │
 │                   │                                                                     │ found                                                          │
 └───────────────────┴─────────────────────────────────────────────────────────────────────┴────────────────────────────────────────────────────────────────┘

 Gating only the template (what the ticket suggests) fixes step 1 and leaves steps 2 and 3 broken.
 The VM would hang forever on the mount instead. Decision (agreed with the user): add one switch,
 resolved in saw-users. It drops web-search from the list (which fixes steps 1 and 2 at once,
 because both read the same list) and tells saw-bom to turn off the providers that read it (step 3).
 web-search-secret.yaml stays as it is; its existing list guard is the gate. Add only a one-line
 comment there pointing to the switch.

 The default stays on, so existing installs see no change.

 Changes

 1. charts/saw-users (core)

 - templates/_helpers.tpl: add a saw-users.webSearch helper that returns "true" or "". The
   user's own webSearch.enabled wins, then global.webSearch.enabled, then on. Compare with
   ne (toString $v) "false", because a Pattern extraParameter can arrive as the string "false".
   Use hasKey rather than default, because default true false gives true. This follows the
   same user-over-default pattern as saw-users.prune (line 61).
 - saw-users.secretNames (line 198): when web search is off, unset $names "web-search" after both
   the catalog branch and the defaults.secrets fallback branch. Nothing else is needed for
   pattern-secrets or the VM mounts: saw-users.vaultPrefix (line 231) and saw-users.openshellValues
   (additionalProviderSecrets) both already read this list.
 - saw-users.profiles (line 213): when web search is off, set webSearch: {enabled: false} in the
   bom values. Like harnessEnabled, set it only when off, so existing users'
   saw-*-bom Application specs don't change.
 - values.yaml: document the per-user webSearch.enabled in the users comment block.

 2. charts/saw-bom

 - values.yaml: add webSearch: {enabled: true}, with a comment saying that off disables every
   provider whose credentialSecret is web-search.
 - templates/configmap-bom.yaml: when off, first collect, for each workspace directory
   (dir $path), the names of the providers with credentialSecret: web-search. Then, in the
   existing rewrite loop:
   - providers.yaml: set enabled: false on those providers. enabled is already part of the
     schema; apply_bom.py (around lines 1260, 1400, 1478) and saw-profile-catalog.py both honor it.
   - sandbox.yaml: remove those names from each sandbox's providers: list. Otherwise
     validate_profiles fails with "uses provider … which is not an enabled provider". This has to
     compose with the existing harnessEnabled harnessRef strip in a single fromYaml/toYaml
     pass.
   - When nothing changes, emit the original file bytes (so the ConfigMap doesn't churn and live
     inputs aren't re-applied).

 3. Pattern-wide switch and install knob

 - values-global.yaml: add global.webSearch.enabled: true, with a comment about turning it off
   when there is no web-search key in Vault.
 - Makefile-quickstart (lines 69–80): add WEB_SEARCH_ENABLED (it must be true or false, or
   make $(error …)). Collect the explicit GOVERNANCE_ENGINE and WEB_SEARCH_ENABLED into a
   name=value word list and number them main.extraParameters[0..n], using $(join) over an index
   list. A hard-coded [0] would collide when both are given, and a gap would produce a null entry.
   Emit the value with --set-string, so false reaches the Pattern CR as a string.
   Effect: ./pattern.sh make install WEB_SEARCH_ENABLED=false works off main without editing git.

 4. Quickstart (scripts/openshell-saw-create.sh lines 267–286)

 - When secret/web-search is absent, also pass --set webSearch.enabled=false to the saw-bom
   install. Today line 285 assigns BOM_OPTS=(-f …), which would wipe that option, so set a flag
   in the check and append to BOM_OPTS after it is built.
 - Update the comment at line 267.

 5. Live test (scripts/test-deployment.sh)

 - Line 17: WEB_SEARCH_API_KEY becomes optional. Derive web_search=on|off from it and record
   config.web-search.
 - When off: run pattern.install and pattern.reinstall (lines 393 and 406) with
   WEB_SEARCH_ENABLED=false. At line 398–399, replace the presence check with an absence check:
   oc get externalsecret web-search and oc get secret web-search in the pattern namespace must
   both return NotFound (record pattern.secret-delivery). Skip the web-search-credentials repeat
   check (line 412).
 - The manual quickstart phase needs no change; item 4 makes make saw-create work without the key.

 6. Docs

 - values-secret.yaml.template: in the web-search block, change "so this key is required" to say
   it is required unless web search is off, and how to turn it off.
 - README.md lines ~209–215 and ~300–314 (the quickstart says the key is required).
 - docs/deployment-guide.md: the Phase 3 secrets table (line 218), the live-test section
   (lines ~520–545), and "Web search in the default sandbox" (line ~671).

 Offline tests (CI; make test / uv run pytest)

 Reuse the existing helpers: render_file, app and helm_values in tests/charts/test_saw_users_chart.py;
 helm_template in tests/charts/test_saw_bom_chart.py; install_opts in tests/scripts/test_make_interface.py;
 and the fake-helm run fixture in tests/scripts/test_saw_create_custom_inference.py.

 - saw-users
   - global.webSearch.enabled: false gives: saw-alice-secrets with secrets == ["inference"];
     saw-alice with additionalProviderSecrets == []; saw-alice-bom values containing
     webSearch.enabled: false.
   - The string "false" behaves the same.
   - Per-user override works both ways (user off with global on, and user on with global off).
   - With the default on, the existing assertions stay unchanged and the bom values have no
     webSearch key.
   - Chain test: factor the /run/saw layout out of
     test_rendered_machine_values_validate_in_the_shipped_installer. With web search off, render
     saw-bom with the bom app's values, mount only the inference Secret, and run
     apply_bom.py validate. Expect inputs are valid and 2 credential(s) (down from 3).
   - Negative control: with web search on and no web-search dir, validate fails with
     "credential for provider 'brave'". This reproduces the original bug offline.
 - saw-bom
   - Off: data-science/default and custom-inference/default have brave with enabled: false,
     nvidia is untouched, and no sandbox lists brave.
   - On (the default): the ConfigMap data is byte-identical to the source files.
   - Off together with harness off: both rewrites apply.
   - A tmp-copy chart whose sandbox lists [nvidia, brave] loses brave.
 - pattern-secrets
   - An explicit regression test: secrets: [inference] renders no web-search ExternalSecret.
 - make
   - WEB_SEARCH_ENABLED=false gives extraParameters[0] = global.webSearch.enabled.
   - With both knobs, governance is [0] and web search is [1].
   - WEB_SEARCH_ENABLED=maybe errors.
   - Update the governance test for --set-string, and strip WEB_SEARCH_ENABLED from the env in
     test_values_global_decides_without_an_explicit_engine.
 - quickstart
   - Extend test_without_a_web_search_key_the_vm_does_not_wait_for_that_secret: the saw-bom helm
     call gets webSearch.enabled=false.
   - Extend test_a_rerun_keeps_the_existing_web_search_secret: the saw-bom call does not get it.
 - runner (tests/scripts/test_deployment_runner.py)
   - Without WEB_SEARCH_API_KEY, preflight reaches the prereqs stop instead of failing on :?.
 - scripts/saw-profile-catalog.py --check must stay green: the catalog is unchanged.

 Are new cluster tests needed?

 Yes, but no new suite. The failure is a live-integration one (ESO health, the KubeVirt mount,
 Argo health), and render tests can't observe it. The offline chain test proves the logic. What's
 needed live is:
 1. The test-deployment.sh off mode from item 5. This makes the existing acceptance test cover the
    new path, so no new script is needed.
 2. A one-time manual e2e run before merge, below.

 E2E plan for mtalvi (dedicated test cluster, pushed test branch)

 Setup: push a test branch with overrides/saw-users.yaml listing alice and bob. Check that the
 Keycloak users exist (make keycloak-add-users).

 #: E1
 Scenario: Saurabh's case: no key, switch off
 Steps: Remove web-search from ~/values-secret-secure-agent-workspace.yaml, then run ./pattern.sh make install WEB_SEARCH_ENABLED=false
 Expected: oc get pattern -o yaml shows extraParameter global.webSearch.enabled: "false". ./pattern.sh make argo-healthcheck passes. saw-alice-secrets is
 Synced/Healthy. oc get externalsecret,secret -n saw-alice lists no web-search. The VM is Running with no FailedMount events (oc get events -n  saw-alice).
 make saw-status OPENSHELL_SAW_NAME=alice shows the installer done. ConfigMap saw-bom-profiles shows brave enabled: false. openshell  provider list in the
 default workspace shows nvidia only. The notebook sandbox answers an inference request.
 ────────────────────────────────────────
 #: E2
 Scenario: Regression: switch on (default)
 Steps: Put web-search back in values-secret, then run ./pattern.sh make load-secrets and ./pattern.sh make install WEB_SEARCH_ENABLED=true (or a fresh install
 without the knob)
 Expected: The web-search ExternalSecret and Secret exist, and the brave provider exists on the gateway. Argo is healthy. The saw-alice-bom app's values have no
 webSearch key.
 ────────────────────────────────────────
 #: E3
 Scenario: Per-user override
 Steps: Global on; give bob webSearch: {enabled: false} in overrides on the test branch
 Expected: Only saw-bob lacks the web-search ExternalSecret and Secret, and both VMs install.
 ────────────────────────────────────────
 #: E4
 Scenario: Turn off on a running workspace
 Steps: From E2, re-run install with WEB_SEARCH_ENABLED=false
 Expected: Write down what actually happens: (a) whether the per-user app (selfHeal, no prune) leaves the old web-search ExternalSecret behind and what Argo
 shows; (b) whether the VM goes RestartRequired because a volume was removed (fix with make saw-restart-pending); (c) whether the existing brave provider stays
  on the gateway (prune mode report). Document the cleanup steps in the deployment guide. Do not treat these as blockers.
 ────────────────────────────────────────
 #: E5
 Scenario: Negative control (reproduces the bug)
 Steps: No key in Vault, switch left on
 Expected: Expect the original failure (SecretSyncedError, VM stuck in ContainerCreating). Record the error text and add it to the doc as the symptom that tells
 you to turn the switch off.
 ────────────────────────────────────────
 #: E6
 Scenario: Quickstart
 Steps: make saw-create with WEB_SEARCH_API_KEY unset
 Expected: The installer completes. Before this change it failed with "credential for provider 'brave'…".
 ────────────────────────────────────────
 #: E7
 Scenario: Live acceptance
 Steps: make test-deployment once with WEB_SEARCH_API_KEY unset, and once with it set
 Expected: Both pass. Keep both evidence TSVs for the PR.

 Out of scope (follow-ups)

 - The self-service portal (charts/openshell-rhdh) still requires the web-search key in its form.
   Its ApplicationSet renders saw-users with SAW_USERS_VALUES and no global.webSearch, so portal
   workspaces keep web search on, which is consistent. Making the field optional is a separate change.
 - Attaching brave to the notebook sandbox (see "Web search in the default sandbox") is unrelated.
Implementation adjustment from live validation (October 21, 2026)

The deployed clustergroup 0.9.58 chart uses `printf "%s"` on the Pattern
operator's unquoted `extraParametersNested` boolean. A Pattern CR containing
value: "false" therefore becomes `%!s(bool=false)` on the saw-users Application.
Keep the requested Pattern CR value and helper semantics. Add a final saw-users
Application override in values-prod.yaml, templated from the correctly typed
root `global.webSearch.enabled` with `forceString: true`. Clustergroup's final
overrides use tpl/toString, which preserves false. Cover this handoff with an
offline Helm bridge regression and verify the generated parameters live.
