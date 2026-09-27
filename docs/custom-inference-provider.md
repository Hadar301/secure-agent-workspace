# Custom inference with a governed vLLM endpoint

This configuration adds a dedicated `custom-inference` provider profile. It does
not replace the OpenAI, NVIDIA, or Gemini profiles. The example provisions
`vllm/notebook` and configures OpenClaw to call your OpenAI-compatible base URL
with your model ID. Endpoint approval and credentials have separate owners.

The implementation targets OpenShell v0.0.116 and the repository's OpenClaw image.
The stage-1 in-VM installer uses Podman.
The feature does not install an inference server or require a GPU in the sandbox.
The inference server needs whatever hardware its model requires.

## Configure credentials and approve the endpoint

In your private `values-secret.yaml`, replace the existing inference entry under
`secrets` with this example. Do not commit the private file or API key:

```yaml
- name: inference
  fields:
    - name: provider
      value: custom
    - name: model
      value: YOUR_SERVED_MODEL_ID
    - name: url
      value: https://inference.example.com/v1
    - name: api_key
      path: ~/.custom-inference-api-key
```

Use the model ID reported by your server, which can differ from its model's
download name. `url` is the API base URL, not `/chat/completions`. Its path is
preserved. A nonempty key, model, and absolute HTTP/HTTPS URL are required for
custom inference. URLs containing user information, query strings, fragments,
or whitespace are rejected. The current chart accepts DNS names and IPv4 hosts.

Approve the same endpoint in `overrides/governance-policy.yaml`:

```yaml
customInference:
  enabled: true
  host: inference.example.com
  port: 443
  scheme: https
```

`values-prod.yaml` loads this override. The checked-in default is disabled with
an empty hostname. For direct Helm deployment, pass equivalent values with `-f`.
Setup compares the URL's host, effective port, and scheme with the catalog
profile. Host comparison ignores case and a trailing DNS dot. HTTPS defaults to
443 and HTTP to 80; a nonstandard port must appear in both configurations.
The profile approves the whole host/port, not just the URL's base path.

For a private HTTP development endpoint, explicitly set `scheme: http`, its port,
and an `http://` URL. HTTP sends the injected API key without transport encryption;
use HTTPS for production. HTTPS uses proxy TLS termination to inject credentials.

Existing cloud secrets may omit `url` or set it to empty. ESO extracts the Vault
inference object and defaults only the missing URL; `provider`, `model`, and
`api_key` remain required fields. Existing Gemini configuration and profile data
are retained. A Gemini secret does not enable the custom example.

## Profile and provisioning lifecycle

The profile is defined in
`charts/governance-policy/profiles/custom-inference.yaml`. Helm renders it into
the profile ConfigMap, which is mounted into the governance interceptor. The
interceptor derives its catalog ID from the filename and publishes it to the
gateway. The file's explicit `id` matches that filename.

This deployment selects the interceptor as its sole profile source. Do not add
a parallel `openshell provider profile import` step: CLI-managed imports are a
different catalog source and are not selected by this configuration.

The VM installer reads profiles from `/run/saw/profiles` and credentials from
`/run/saw/secrets/inference/{provider,model,url,api_key}`. It passes the resolved
plan to the runtime user through stdin; it does not generate a shell `bom.env`
file or use an SSH setup Job. The Secrets and profile ConfigMap must be in the
VM's namespace (the default example is `saw-alice`), while gateway workspace
names such as `vllm` are independent of Kubernetes namespaces.

Follow [the versioned installer guide](versioned-bom-installer.md) for deployment
and VM access. In the VM, inspect `sudo systemctl status saw-install saw-apply`,
`sudo journalctl -u saw-apply`, and `/var/lib/saw/status.json`. Input disks are
refreshed on VM boot; syncing a ConfigMap alone does not rerun an existing VM.
A VM restart or rollout is a separate operational action.

After the normal GitOps deployment has published the profile and secrets, setup:

1. Selects the custom BOM example only for explicit `provider: custom`.
2. Waits for `custom-inference` in the workspace's catalog and checks its endpoint
   and required bearer credential binding.
3. Creates the provider instance with type `custom-inference` in workspace `vllm`.
   The secret becomes `OPENAI_API_KEY`; values are supplied through the command's
   environment rather than its arguments.
4. Creates `notebook` with that provider explicitly attached, then checks sandbox
   readiness, attachment identity, and its composed `_provider_custom_inference`
   policy. A global policy override that suppresses provider policy is rejected.
5. Waits for a new exec process to receive an `openshell:resolve:env:` credential
   placeholder, and passes that placeholder to OpenClaw's custom-provider setup.
   OpenClaw uses the configured model and direct base URL, not `inference.local`.
6. Starts its loopback OpenClaw gateway and checks local HTTP health.

The API key is not copied into OpenClaw configuration. A missing managed placeholder
is an error; there is no raw-key fallback. Incompatible required providers cause
an intentional skip before image pulls or readiness polling. Creation,
configuration, attachment, and readiness errors fail setup rather than being
reported as intentional skips.

On repeat setup, a matching provider's credentials and required configuration
are reconciled. The CLI exposes configuration keys, not values, so setup does
not infer that an existing endpoint is current. Conflicting types, workspaces,
unexpected credential/configuration keys, terminal sandboxes, or mismatched
attachments fail without deleting the sandbox. This feature does not migrate
PR #46's older custom instances named `openai`.

If repeat onboarding saves an inactive replacement credential, setup runs the
explicit activation test for that saved profile. Failed activation remains a
setup failure; it does not replace the working connection or trigger a raw-key
fallback. The OpenClaw process is restarted after successful onboarding or
activation to observe new configuration.
The custom example binds its gateway to sandbox loopback. External dashboard
exposure and dashboard service repair are outside this feature.

## Validate rendering and the catalog

Local checks do not contact a cluster:

```bash
helm template governance charts/governance-policy \
  --set customInference.enabled=true \
  --set customInference.host=inference.example.com
helm template secrets charts/pattern-secrets
helm template bom charts/saw-bom
python3 -m pytest tests/installer tests/charts/test_custom_inference_chart.py -q
```

The tests require pytest, PyYAML, Helm, Go, Bash, and Python. Go executes the ESO
template expressions in strict missing-key mode; it does not run an ESO controller.

After an authorized deployment, authenticate and select the intended gateway,
then inspect its authoritative profile:

`make openshell-saw-configure-gateway` keeps the token produced by that gateway's
OIDC login. It does not copy the separate `make login` cache, which may belong to
another cluster. If an older configuration copied a stale token, run
`openshell gateway logout <gateway>` followed by `openshell gateway login <gateway>`.

```bash
openshell provider list-profiles --workspace vllm
openshell provider profile export custom-inference --workspace vllm -o yaml \
  > /tmp/custom-inference-profile.yaml
openshell provider profile lint -f /tmp/custom-inference-profile.yaml --workspace vllm
openshell provider list --workspace vllm -o json
openshell sandbox list --workspace vllm
openshell sandbox provider list notebook --workspace vllm
openshell policy get notebook --workspace vllm --full
```

Lint the exported canonical profile, not the unrendered Helm file. In v0.0.116,
`profile lint` contacts the gateway; it is not an offline YAML-only validator.
Confirm the endpoint, bearer binding, `/usr/bin/node-26` executable, and
`_provider_custom_inference` policy. This is the kernel-resolved Node executable
in the Hummingbird OpenClaw image; `/usr/sbin/node` is a symlink. This image does
not contain curl, so probes below use Node. Plain `sandbox list` queries
the default workspace and may correctly show no sandboxes.

## Validate inference after an authorized rollout

Use an endpoint that enforces its API key. Run these commands in Bash, substituting
your endpoint and served model. Only the sandbox expands the managed credential:

```bash
openshell sandbox exec -n notebook --workspace vllm --no-tty -- /usr/bin/node-26 -e '
  const key = process.env.OPENAI_API_KEY || "";
  if (!key.startsWith("openshell:resolve:env:")) process.exit(1);
  fetch("https://inference.example.com/v1/chat/completions", {
    method: "POST", signal: AbortSignal.timeout(120000),
    headers: {"Content-Type": "application/json", Authorization: "Bearer " + key},
    body: JSON.stringify({model: "YOUR_SERVED_MODEL_ID",
      messages: [{role: "user", content: "Say hello"}], max_tokens: 32})
  }).then(async r => {
    if (!r.ok) throw new Error("HTTP " + r.status);
    console.log(await r.text());
  }).catch(e => { console.error(e.message); process.exitCode = 1; });
'
```

Require a successful completion with nonempty assistant text and the expected
model. Record whether the server is actually vLLM; another OpenAI-compatible
engine tests API compatibility but does not prove the literal vLLM criterion.

Check OpenClaw health separately, then request an agent-generated response through
its running gateway:

```bash
openshell sandbox exec -n notebook --workspace vllm --no-tty -- \
  /usr/bin/node-26 -e 'fetch("http://127.0.0.1:18789/health", {signal: AbortSignal.timeout(5000)}).then(r => { console.log(r.status); process.exitCode = r.ok ? 0 : 1; }).catch(() => { process.exitCode = 1; });'
openshell sandbox exec -n notebook --workspace vllm --no-tty -- \
  env OPENCLAW_HOME=/sandbox SQLITE_TMPDIR=/sandbox/.openclaw/state \
    TMPDIR=/sandbox/.openclaw/state openclaw agent --agent main \
    --session-id custom-inference-validation \
    --message 'Reply with a short greeting. Do not use tools.' --timeout 120 --json
```

Require an actual agent reply and verify the reported provider/model. An HTTP
health response, a successful `saw-apply.service` run, or a direct HTTP completion does not prove
the OpenClaw agent path. Very small models may support basic completions while
failing agent context-size or tool requirements; record that distinction.

Do not add `--local` while the managed gateway is running for this state directory.
Use a fresh session ID for an independent test. Asking the model not to use tools
does not remove tool definitions from the request. For a text-only smoke test
with a model that rejects tools, explicitly disable them in this sandbox:

```bash
openshell sandbox exec -n notebook --workspace vllm --no-tty -- \
  env OPENCLAW_HOME=/sandbox openclaw config set tools.deny '["*"]' --strict-json
```

This is a persistent sandbox configuration change, not a default imposed on all
custom providers. Restore the previous tool policy when testing a tool-capable
model. The running gateway hot-reloaded this setting in the tested deployment.

In a separately approved test workspace, repeat the request with an invalid
provider credential, then restore the valid key securely:

```bash
OPENAI_API_KEY=deliberately-invalid openshell provider update custom-inference \
  --workspace vllm --credential OPENAI_API_KEY
# Repeat both inference requests above; require authentication failure.
read -rsp 'Restore inference API key: ' OPENAI_API_KEY; printf '\n'
export OPENAI_API_KEY
openshell provider update custom-inference --workspace vllm --credential OPENAI_API_KEY
unset OPENAI_API_KEY
```

Credential updates propagate asynchronously to the sandbox. Before interpreting
the negative agent test, poll a small authenticated request (such as `/v1/models`)
until it returns 401 with the managed placeholder. After restoration, wait for
200 before resuming normal use. A request started immediately after a provider
update may still use the previous credential.

For a reproducible negative OpenClaw test, use a separate sandbox and a fresh
OpenClaw home/state directory with the test provider's current managed placeholder.
The reused-state test received successful responses even after direct requests
returned 401; the fresh-state test correctly returned HTTP 401 and exit code 1.
Do not interpret a reused-state test as proof that the intended credential was
selected, or claim immediate revocation across existing OpenClaw auth state.

If the invalid key succeeds, the endpoint is not a valid authentication fixture.
For endpoint-binding validation, use an approved test fixture outside the custom
profile's endpoint boundary. Attempt to use the same managed placeholder there;
require rejection and verify the fixture never receives the real credential.
Distinguish ordinary egress denial from a credential-binding test: the latter
needs a separately approved network rule allowing the fixture without granting
it the custom provider's credential. Never expand the production profile for this test.

Inspect setup and OpenClaw logs without printing credentials. Compare captured
logs and generated configuration with the key using a local script that emits
only pass/fail; do not run verbose curl or print credential environments. Check
that OpenClaw contains a managed placeholder rather than the raw inference key.

## Acceptance record

Local validation on Python 3.12: 357 regression tests passed (clean-main baseline:
275), plus 43 OIDC template checks. All four affected charts passed Helm lint;
rendering, affected shell syntax, and whitespace checks passed. These results
use local fixtures, not a deployed gateway or inference server.

Live troubleshooting confirmed that the deployed OpenClaw process resolves to
`/usr/bin/node-26`, which the previous custom profile denied. The corrected
allowlist, Node-based health checks, replacement-credential activation, and
gateway token preservation have local regression coverage.

Live validation on 2026-09-27 after deploying commit `8a33917`: installer
verification passed and reported `apply: Done`. OpenClaw selected
`custom-inference/tinyllama:latest` and received generated responses through the
running gateway after tools were disabled. This fixture uses Ollama behind an
API-key-enforcing proxy, not vLLM. Responses were incoherent; backend logs showed
a 7,210-token prompt truncated to 1,026 tokens, slow CPU generation, and a request
that received HTTP 504 before retrying successfully. This establishes transport
and response generation, not useful agent behavior or reliable latency.

Additional live checks used a separate validation workspace and provider, leaving
the user's notebook credential unchanged. A managed-placeholder completion
returned HTTP 200; changing the test provider to an invalid key returned HTTP 401
after propagation, and restoring the valid key returned HTTP 200. Comparison
against the real key found no match in the captured OpenClaw JSON/JSONL/config
and log files, runtime logs, or current installer console. This scan covers those
captured files, not arbitrary historical data or encoded representations.
An isolated OpenClaw agent turn with fresh auth state also rejected the invalid
key with HTTP 401 and exit code 1. Temporary test resources were removed afterward.

The exported canonical profile's original ID triggers the CLI linter's
interceptor-ownership check. A schema-equivalent copy with a temporary ID and
without source/signature metadata passed lint; it was not imported. An attempted
isolated fixture policy update was rejected because governance annotations were
required. Consequently, denial of the second hostname establishes egress denial,
not the stronger test of credential binding over an otherwise allowed connection.

| Check | Current evidence |
| --- | --- |
| Secret compatibility, profile rendering, provisioning failure handling | Local regression tests |
| Gemini profile preservation and missing-URL compatibility | Local regression tests; live Gemini needs credentials |
| Catalog publication and installer endpoint checks | Deployed profile consumed; installer verification passed; schema-equivalent canonical copy passed lint under a temporary ID |
| Custom-provider response through the authentication-enforcing fixture | OpenClaw received HTTP 200 and generated responses; managed credential observed during setup |
| Incorrect-key rejection through the custom provider | Direct request and fresh-state OpenClaw agent returned 401; agent exited 1; restored key returned 200 after propagation |
| Endpoint isolation | Unapproved hostname denied; credential binding over an otherwise allowed fixture connection not established because unsigned policy updates were rejected |
| OpenClaw agent-generated inference | Responses received with tools disabled; meaningful instruction following failed with this TinyLlama fixture |
| Credentials absent from generated configuration and logs | Real key absent from captured OpenClaw JSON/config/log files, runtime logs, and current installer console |
| Actual vLLM-hosted model | Still pending; current fixture uses Ollama |
| Dashboard readiness/access | Outside this feature; not implied by OpenClaw health |

References: [OpenShell v0.0.116 providers](https://docs.nvidia.com/openshell/v0.0.116/sandboxes/manage-providers),
[Providers v2](https://docs.nvidia.com/openshell/v0.0.116/sandboxes/providers-v2),
[OpenClaw onboarding](https://docs.openclaw.ai/cli/onboard), and
[OpenClaw agent command](https://docs.openclaw.ai/cli/agent).
