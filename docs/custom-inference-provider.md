# Using a Custom vLLM / OpenAI-Compatible Inference Endpoint

This guide explains how to configure the Secure Agent Workspace (SAW) to use a self-hosted vLLM model or any OpenAI-compatible inference endpoint instead of a cloud provider.

## Overview

By default SAW connects agents to cloud inference APIs (NVIDIA NIM, Gemini, Anthropic, etc.). You can point it at any OpenAI-compatible endpoint — for example, a [vLLM](https://github.com/vllm-project/vllm) or [Ollama](https://ollama.com) server running inside your OpenShift cluster.

## Prerequisites

- SAW installed on an OpenShift cluster (see [README](../README.md))
- An OpenAI-compatible inference server accessible via an OpenShift Route
- The cluster domain (e.g. `apps.cluster-abc.example.com`)

## Step 1: Get an OpenAI-Compatible Endpoint

You need an HTTP endpoint that implements the [OpenAI chat completions API](https://platform.openai.com/docs/api-reference/chat). Any of the following work:

- **[vLLM](https://docs.vllm.ai/en/latest/serving/openai_compatible_server.html)** — high-throughput serving, GPU recommended
- **[Ollama](https://ollama.com)** — easy to run on CPU; exposes `/v1` for OpenAI compatibility
- **[RHOAI Model Serving](https://docs.redhat.com/en/documentation/red_hat_openshift_ai_self-managed)** — if you have Red Hat OpenShift AI installed, use a KServe InferenceService with a vLLM ServingRuntime
- **Any other OpenAI-compatible server** — as long as it exposes `/v1/chat/completions`

The endpoint must be reachable as an OpenShift Route (HTTPS). Note the Route **hostname** (e.g. `my-model.apps.cluster-abc.example.com`) — you will need it in Steps 2 and 3.

## Step 2: Set the Inference Secret

Add the `url` field to your local `~/values-secret.yaml` under the `inference` block:

```yaml
- name: inference
  fields:
  - name: provider
    value: custom          # tells the BOM to use the custom/openai profile
  - name: model
    value: tinyllama:latest  # must match the model name served by your endpoint
  - name: api_key
    value: "any-string"    # vLLM/Ollama don't enforce API key auth
  - name: url
    value: "https://<your-vllm-route>/v1"
```

> **Note:** Setting `provider: custom` automatically creates the compatible provider in `vllm`. NVIDIA providers and sandboxes requiring them are skipped before image pulls or readiness polling. Workspace records and independent providers such as Brave may still be created. Sandboxes in `vllm` connect to your endpoint through the OpenShell governance proxy.

## Step 3: Set the Governance Profile Host

The governance interceptor enforces egress from sandboxes. You must declare the allowed endpoint host before installing.

Edit `overrides/governance-policy.yaml` (tracked in git — commit per cluster):

```yaml
customEndpointHost: "<your-vllm-route-hostname>"
# Example:
# customEndpointHost: "vllm-tinyllama-vllm-test.apps.cluster-abc.example.com"
```

Commit and push this file:

```bash
git add overrides/governance-policy.yaml
git commit -m "chore: set vLLM endpoint for <cluster-name>"
git push
```

## Step 4: Install

```bash
export TARGET_REVISION=<your-branch>   # e.g. main
./pattern.sh make install
```

The installation:
1. Pushes secrets to Vault (including the `url` field)
2. Deploys the governance-policy chart with the `openai.yaml` profile containing your endpoint
3. Runs the BOM setup job which creates:
   - A `vllm` workspace on the gateway
   - An `openai`-type provider with `base_url` pointing to your endpoint
   - A `notebook` sandbox using the `openai` provider

## Step 5: Verify

SSH into the gateway VM and check:

```bash
# List provider profiles — should show your endpoint
openshell provider list-profiles | grep openai

# List providers in the vllm workspace
openshell provider list --workspace vllm

# Check sandbox is Ready
openshell sandbox list --workspace vllm
```

Test inference from inside the sandbox:

```bash
openshell sandbox exec -n notebook --workspace vllm -- curl -sk \
  https://<your-vllm-route>/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer any-string' \
  -d '{
    "model": "tinyllama:latest",
    "messages": [{"role": "user", "content": "hello"}],
    "max_tokens": 20
  }'
```

A successful response looks like:
```json
{
  "choices": [{"message": {"role": "assistant", "content": "Hello! ..."}}],
  "model": "tinyllama:latest"
}
```

> **Note:** The first inference request may take 1–2 minutes on CPU while the model loads. Subsequent requests are fast.

## How It Works

```
values-secret.yaml (url field)
  → Vault → ESO → inference K8s Secret
    → setup-bom-profiles.sh → PROV_OPENAI_URL in bom.env
      → apply_bom.py → openshell provider create \
          --type openai \
          --config base_url=<url>
        → Sandbox created with _provider_openai network policy
          → Sandbox egress to <vllm-host>:443 allowed for node + curl
```

The OpenShell governance proxy enforces egress at the CONNECT-tunnel level. Only the declared binaries (`/usr/local/bin/node`, `/usr/bin/curl`) can connect to the vLLM endpoint from inside the sandbox. This prevents arbitrary outbound connections while still allowing the inference agent to call your model.

## Switching Back to a Cloud Provider

Change `~/values-secret.yaml`:

```yaml
- name: inference
  fields:
  - name: provider
    value: build            # NVIDIA NIM
  - name: model
    value: nvidia/nemotron-3-super-120b-a12b
  - name: api_key
    path: ~/.nvapi-key
  - name: url
    value: ""               # empty = no custom endpoint
```

And clear the governance override:

```yaml
# overrides/governance-policy.yaml
customEndpointHost: ""
```

Then reinstall.

## Known Limitations

- **Profile selection**: workspace directories are still processed. Disabled or incompatible providers and sandboxes requiring any of them are skipped consistently during deployment and verification. Independent compatible providers remain enabled. Selection of entire workspaces remains future work.

- The `vllm` provider accepts `inference.provider=custom` through its `nemoclawProvider: custom` alias. Its `urlSecretKey: url` and `modelSecretKey: model` fields read the endpoint and model from the inference secret. Set `model` to the exact name served by the endpoint; the setup fails if that required secret field is missing.

## Compatibility and deployment checks

Existing cloud-provider Vault records do not need `url`: missing or empty URLs
become an empty string in the inference Secret. `provider`, `model`, and `api_key`
remain required fields. Custom inference requires a nonempty URL and model.
No manual provider creation is needed. URLs and models in `bom.env` are shell-quoted.

Check each layer separately on the gateway VM:

```bash
systemctl --user status openshell-gateway.service --no-pager
systemctl --user show openshell-gateway.service -p ExecStartPre -p NRestarts
openshell sandbox get notebook --workspace vllm
openshell sandbox provider list notebook --workspace vllm
# OpenClaw readiness does not prove successful inference
openshell sandbox exec -n notebook --workspace vllm -- curl -sf http://127.0.0.1:18789/health
# Dashboard and authentication proxy, when enabled
systemctl --user is-active openshell-dashboard.service openshell-dashboard-proxy.service
curl -f http://127.0.0.1:8090/api/v1/healthz
curl -f http://127.0.0.1:8080/ping
```

Then run the chat-completion request in the verification section and confirm a
valid response. Open the web UI route and complete OIDC login separately.

## Troubleshooting and upgrades

- The cache hook uses `zz-prepopulate-cache.conf` to run after `route-san.conf`,
  which resets `ExecStartPre`. Upgrades remove the old `prepopulate-cache.conf`.
  Certificate generation and cache preparation must both succeed.
- Dashboard setup replaces its two managed unit entries, including baked-in
  symlinks or read-only files, with VM-user-owned files. It does not recursively
  change home-directory ownership. Enabled dashboard installation, restart, or
  120-second readiness failures now fail the setup Job.
- Intentional provider/sandbox skips appear as `SKIP`. Actual creation failures
  or readiness timeouts fail setup and stop OpenClaw onboarding for that sandbox.
- Uninstall watching defaults to 600 seconds; override with
  `./pattern.sh make uninstall UNINSTALL_TIMEOUT_SECONDS=900`. A failed playbook
  or timeout returns nonzero and prevents subsequent forced cleanup. Inspect the
  Pattern in `patterns-operator` and Applications in `vp-gitops` before retrying.
