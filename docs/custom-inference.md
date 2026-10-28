# Custom inference endpoint (vLLM, Ollama, NIM, any OpenAI-compatible server)

A SAW can use a model server of your own instead of a cloud provider.
OpenShell 0.1.x removed managed inference routing (`openshell inference`,
`https://inference.local`), so the agent calls the endpoint itself:

- The endpoint, the model and the key are the `inference` Secret (`url`,
  `model`, `api_key`). The `custom-inference` SAW-BOM profile reads them
  through the sandbox's `inference:` block; the installer validates the URL
  and onboards OpenClaw against it.
- The key never enters the VM or sandbox. The namespace credential proxy
  replaces a marker only for the host of `url` in the credential Secret.
  Keyed endpoints require HTTPS on port 443 with a publicly trusted
  certificate. The gateway's governance profile separately permits the
  sandbox binary to reach that host.
- The pattern ships no profile for a host it cannot know. **You add one**,
  as a plain OpenShell profile file under `overrides/governance-profiles/`,
  and the `governance-extra-profiles` application serves it next to the
  shipped profiles. OpenShell recommends exactly this (one profile per
  credential) over reusing the `openai` profile for another host.

## Configure

1. **The profile.** Copy the chart's example,
   `charts/governance-policy/profiles/examples/custom-inference.yaml`, to
   `overrides/governance-profiles/custom-inference.yaml` (shipped as that
   same example), set `endpoints` to your server, and uncomment the
   `configMapGenerator` in `overrides/governance-profiles/kustomization.yaml`
   listing the file:

   ```yaml
   id: custom-inference
   ...
   endpoints:
     - host: models.example.com    # the host of the url below
       port: 443                   # keyed HTTPS only
       protocol: rest
       enforcement: enforce
       access: read-write
   ```

   The proxy binds a deployment-owned provider only to the Secret's `url`
   host, even if its governance profile lists more hosts. A second server
   with its own key is a second file with its own
   `id`, used by a provider with that `type` **and that name**: the
   governance interceptor matches a sandbox's providers by profile id, so a
   governed provider is always named after its type (the installer refuses
   anything else).

2. **Egress.** A host outside the cluster must be allowed by the VM
   firewall: `egress.extraAllow` under `defaults.openshellSaw` (or one
   user's `values`) in `overrides/saw-users.yaml`. An in-cluster Service
   (`*.svc`) needs a `networkPolicy.extraEgress` rule instead
   ([Egress from the VM](deployment-guide.md#egress-from-the-vm)).

3. **The profile selection.** The workspace uses `profiles: [custom-inference]`
   (a user entry in `overrides/saw-users.yaml`, the portal, or
   `make saw-create ... PROFILES=custom-inference`).

4. **The Secret** (`~/values-secret-secure-agent-workspace.yaml`, then
   `./pattern.sh make load-secrets`; the quickstart's `make saw-create
   PROVIDER=custom-inference MODEL=... ENDPOINT_URL=... API_KEY=...` writes
   the same keys):

   | Key | Value |
   |---|---|
   | `url` | the OpenAI-compatible base URL, ending in `/v1` |
   | `model` | the model name the server serves |
   | `api_key` | the server's key, mounted only by the namespace proxy; for keyless HTTP use `API_KEY=''` in quickstart |
   | `provider` | optional: `custom-inference` (the installer refuses a key labelled for another service); leave it out of a Secret shared with other profiles |

   The VM mounts `inference-meta`, containing every non-credential field
   selected by the profile catalog (including `url`, `model`, and optional
   `provider`), with no `api_key`. A deployment-owned keyed provider's
   `inference.baseUrl` must reference `{secretKeyRef: {name: inference, key: url}}`
   so the installer and proxy use the same host.

5. Commit and push steps 1-3, wait for Argo CD, then restart the VM
   (`make saw-restart`) so the installer applies the Secret.

### Changing the endpoint

Change `url` in the Secret and `host`/`port` in the profile file (and
`extraAllow`), push, restart the VM. The sandbox is not recreated: the
endpoint is agent configuration (`inference:`), not sandbox environment, so
`/sandbox` is untouched; OpenClaw is onboarded again against the new URL.

## How the pieces fit

| Where | What | Changed by |
|---|---|---|
| `overrides/governance-profiles/<id>.yaml` | which host(s) the key may reach | git |
| `inference` Secret in Vault | `url`, `model`, `api_key` | `load-secrets` / the portal |
| `charts/saw-bom/profiles/custom-inference` | provider `type: custom-inference`; sandbox `inference:` reading the Secret | shipped |

The installer sees `custom-inference` as a type it neither has built in
nor ships, looks it up in the gateway's live catalog, and takes the
credential variable (`CUSTOM_INFERENCE_API_KEY`) from the served profile.
If the profile is not there yet (the extra-profiles app has not synced,
or the file is not listed), the apply fails before creating anything, with
a message naming this directory. The sandbox's `inference.protocol` is
stated (`openai`): the installer cannot infer it for a profile of your own.

## Requirements

- The **credential proxy** must reach keyed HTTPS endpoints; the **VM**
  must reach keyless HTTP endpoints such as `http://vllm.<ns>.svc:8000/v1`.
  `localhost` is refused.
- `url` must be `http(s)://host[:port][/path]` without credentials, query or
  fragment. The installer rejects anything else without logging the value.
- A keyed HTTPS endpoint must use port 443 and a publicly trusted
  certificate. Other HTTPS ports are refused. HTTP bypasses credential
  injection and sends only a marker, so use it only for a keyless server.
  Custom keyed ports and in-cluster service-CA trust are follow-up work.
- `inferenceTimeout` on a provider is no longer used: there is no gateway
  router to time out. Use the sandbox's `inference.timeoutSeconds`.

## Limitations

- One custom endpoint per deployment is the shipped shape; a second server
  is a second profile file and a provider of that type (and, for the shipped
  `custom-inference` BOM profile, a copy of it with that type).
- With governance **off** the gateway reads only the profiles the installer
  ships; extra profiles are not delivered to the VM. Keep governance on for
  custom endpoints.
- NemoClaw sandboxes onboard their own provider settings; the profile only
  ships an OpenClaw sandbox.
