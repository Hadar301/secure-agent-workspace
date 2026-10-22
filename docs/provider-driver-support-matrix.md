# SAW TP provider and driver support matrix

**Validation date:** 2026-10-21

This matrix records successful inference smoke tests against official provider
APIs. Kubernetes driver integration must be completed before provider validation
can begin.

## Validation matrix

| Provider | Tested model | Podman driver | Kubernetes driver |
|---|---|---|---|
| OpenAI (primary) | `gpt-6-luna` | Validated | Not tested |
| Anthropic (secondary) | `claude-sonnet-4-6` | Validated | Not tested |
| NVIDIA | `nvidia/nemotron-3.5-lightning-30b-a3b` | Validated | Not tested |

## Test results

All three providers passed authenticated inference requests from inside the
sandbox through OpenShell's credential proxy. Each API returned **HTTP 200**
with a response matching the test prompt.

OpenClaw chat also returned responses from all three providers. NVIDIA passed
with both an explicit model selection and the configured notebook default.

**Environment:** OpenShift with Podman running inside KubeVirt VMs;
`default/notebook` in `saw-provider-test` (OpenAI and Anthropic) and
`saw-nvidia-test` (NVIDIA). Running on OpenShift does not validate the
OpenShell Kubernetes driver.

## Remaining work

Complete Kubernetes compute driver integration, then validate OpenAI, Anthropic,
and NVIDIA using the same inference checks and update this matrix.

## Scope

Validation covers inference in existing workspaces after credential and model
updates. Clean deployment, restart recovery, tools, and memory embeddings are
not validated. A memory-embedding credential error was observed separately
while chat succeeded.
