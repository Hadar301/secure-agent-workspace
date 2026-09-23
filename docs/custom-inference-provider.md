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

> **Note:** Setting `provider: custom` causes the BOM to skip the default NVIDIA workspace and use the `vllm` workspace instead. Sandboxes in the `vllm` workspace connect directly to your endpoint through the OpenShell governance proxy.

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

- **Profile selection**: when `provider: custom` is set, the default NVIDIA workspace is skipped. Both provider configurations cannot be active simultaneously in a single deployment. A follow-up will add provider-aware profile selection so users only get the workspace they need.

- The `vllm` provider accepts `inference.provider=custom` through its `nemoclawProvider: custom` alias. Its `urlSecretKey: url` and `modelSecretKey: model` fields read the endpoint and model from the inference secret. Set `model` to the exact name served by the endpoint; the setup fails if that required secret field is missing.
