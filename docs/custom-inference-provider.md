# Custom inference with a governed vLLM endpoint

This configuration adds a dedicated `custom-inference` provider profile. It does
not replace the OpenAI, NVIDIA, or Gemini profiles. The example provisions
`vllm/notebook` and configures OpenClaw to call your OpenAI-compatible base URL
with your model ID. Endpoint approval and credentials have separate owners.

The implementation targets OpenShell v0.0.116 and the repository's OpenClaw image.
The runtime remains Podman by default; Docker is an explicit deployment option.
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

The OpenClaw process is restarted on repeat setup to observe new configuration.
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
python3 -m pytest charts/saw-bom/scripts/test_apply_bom.py tests/test-custom-inference.py -q
```

The tests require pytest, PyYAML, Helm, Go, Bash, and Python. Go executes the ESO
template expressions in strict missing-key mode; it does not run an ESO controller.

After an authorized deployment, authenticate and select the intended gateway,
then inspect its authoritative profile:

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
Confirm the endpoint, bearer binding, `/usr/local/bin/node` and `/usr/bin/curl`
executables, and `_provider_custom_inference` policy. Plain `sandbox list` queries
the default workspace and may correctly show no sandboxes.

## Validate inference after an authorized rollout

Use an endpoint that enforces its API key. Run these commands in Bash, substituting
your endpoint and served model. Only the sandbox expands the managed credential:

```bash
openshell sandbox exec -n notebook --workspace vllm --no-tty -- sh -c '
  set -eu
  case "${OPENAI_API_KEY:-}" in openshell:resolve:env:*) ;; *) exit 1;; esac
  curl -sS --fail-with-body --max-time 120 \
    https://inference.example.com/v1/chat/completions \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $OPENAI_API_KEY" \
    -d "{\"model\":\"YOUR_SERVED_MODEL_ID\",\"messages\":[{\"role\":\"user\",\"content\":\"Say hello\"}],\"max_tokens\":32}"
'
```

Require a successful completion with nonempty assistant text and the expected
model. Record whether the server is actually vLLM; another OpenAI-compatible
engine tests API compatibility but does not prove the literal vLLM criterion.

Check OpenClaw health separately, then request an agent-generated response through
its running gateway:

```bash
openshell sandbox exec -n notebook --workspace vllm --no-tty -- \
  curl -fsS --max-time 5 http://127.0.0.1:18789/health
openshell sandbox exec -n notebook --workspace vllm --no-tty -- \
  env OPENCLAW_HOME=/sandbox openclaw agent --agent main \
    --message 'Reply with a short greeting. Do not use tools.' --timeout 120 --json
```

Require an actual agent reply and verify the reported provider/model. An HTTP
health response, a completed setup Job, or a direct curl completion does not prove
the OpenClaw agent path. Very small models may support basic completions while
failing agent context-size or tool requirements; record that distinction.

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

| Check | Current evidence |
| --- | --- |
| Secret compatibility, profile rendering, provisioning failure handling | Local regression tests |
| Gemini profile preservation and missing-URL compatibility | Local regression tests; live Gemini needs credentials |
| Catalog validation by the running interceptor and gateway linter | Pending authorized deployment |
| Authenticated sandbox completion and invalid-key rejection | Pending authorized deployment |
| OpenClaw agent-generated inference and secret-free logs | Pending authorized deployment |
| Actual vLLM-hosted model | Pending authorized deployment |
| Dashboard readiness/access | Outside this feature; not implied by OpenClaw health |

The existing OIDC template suite reports 47 passes and 6 failures both on this
branch and clean upstream main. Those pre-existing expectations are not changed here.

References: [OpenShell v0.0.116 providers](https://docs.nvidia.com/openshell/v0.0.116/sandboxes/manage-providers),
[Providers v2](https://docs.nvidia.com/openshell/v0.0.116/sandboxes/providers-v2),
[OpenClaw onboarding](https://docs.openclaw.ai/cli/onboard), and
[OpenClaw agent command](https://docs.openclaw.ai/cli/agent).
