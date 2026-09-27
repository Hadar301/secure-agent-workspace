# Custom inference endpoint (vLLM, Ollama, any OpenAI-compatible server)

A SAW can use a model server of your own instead of a cloud provider. It uses
OpenShell's [inference routing](https://github.com/NVIDIA/OpenShell/blob/v0.0.116/docs/sandboxes/inference-routing.mdx):

- The installer creates an `openai` provider with the endpoint's base URL
  (`--config OPENAI_BASE_URL=<url>`) and the key (passed via the environment),
  then sets the workspace inference route (`openshell inference set`).
- The gateway's inference router calls the endpoint with the key. Sandboxes
  call `https://inference.local/v1` and never see the key or the endpoint.
- OpenClaw is onboarded against `inference.local`, exactly like the default
  NVIDIA setup, so the dashboard, keepalive and verification are unchanged.

## Configure

1. Use the `custom-inference` SAW-BOM profile instead of `data-science`
   (saw-bom values, e.g. `overrides/saw-bom.yaml`):

   ```yaml
   profiles:
     - custom-inference
   ```

2. Put the endpoint in the `inference` Secret (pattern: `~/values-secret-*.yaml`,
   see `values-secret.yaml.template`). With the quickstart, one command does
   steps 1 and 2:

   ```bash
   make openshell-saw-create OPENSHELL_SAW_NAME=<name> PROFILES=custom-inference \
     PROVIDER=openai MODEL=<served model> ENDPOINT_URL=https://<host>/v1 API_KEY=<key>
   ```

   The Secret's keys:

   | Key | Value |
   |---|---|
   | `provider` | `openai` (OpenShell's provider type for any OpenAI-compatible API) |
   | `model` | the model name the server serves, e.g. `meta-llama/Llama-3.1-8B-Instruct` |
   | `url` | the OpenAI-compatible base URL, ending in `/v1` |
   | `api_key` | the server's key; any non-empty value if it needs none |

3. Restart the VM (`make openshell-saw-restart`) so the installer applies it.

## Requirements

- The **gateway VM** must reach the URL, not your laptop: use a cluster Service
  (`http://vllm.<ns>.svc:8000/v1`) or Route host. `localhost` is refused.
- `url` must be `http(s)://host[:port][/path]` without credentials, query or
  fragment. The installer rejects anything else without logging the value.
- With governance on, the gateway only accepts provider types from the
  governance catalog, so `charts/governance-policy/profiles/openai.yaml` must
  be deployed (a profile the installer imports itself is not enough). The
  profile has no endpoints: sandboxes get no direct egress from it.
- Self-hosted models can be slow: the profile sets `inferenceTimeout: 300`
  seconds (OpenShell's default is 60).

## Limitations

- One inference route per workspace (an OpenShell limitation).
- NemoClaw sandboxes onboard their own provider settings; the profile only
  ships an OpenClaw sandbox.
