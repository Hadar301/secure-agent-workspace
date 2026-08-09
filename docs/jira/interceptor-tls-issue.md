# Gateway interceptor cannot connect to external HTTPS endpoints

**Project:** APPENG
**Type:** Bug / Upstream Dependency
**Epic:** Secure Agent Workspace Validated Pattern
**Priority:** High
**Component:** RH_AI_Blueprints
**Labels:** secure_agent_workspace, governance, interceptor, tls, upstream

## Summary

The OpenShell gateway cannot connect to an external governance interceptor over HTTPS because the interceptor gRPC client does not configure TLS trust. This prevents running the interceptor as a shared cluster service — it must run inside the VM on localhost instead.

## Upstream Issue

**[NVIDIA/OpenShell #2623](https://github.com/NVIDIA/OpenShell/issues/2623)** — *"feat: add shared alpha extension authentication and custom CA transport"*

- Status: Open, validated, assigned to `pimlock`
- Scope: adds custom CA configuration and shared TLS channel builder for both gateway interceptors and supervisor middleware

## Problem

The governance interceptor is deployed as a Kubernetes pod with an envoy TLS sidecar exposed via an OpenShift Route (passthrough TLS). The gateway VM can reach the Route (verified with curl), but the gateway's gRPC client fails to connect:

```
Error: configuration error: gateway interceptor initialization failed:
  interceptor transport error: connect https://governance-interceptor-openshell-agents.apps.<domain>: transport error
```

## Root Cause

In `openshell-gateway-interceptors/src/plan.rs` line 860-872:

```rust
async fn connect_endpoint(endpoint: &str) -> Result<Channel> {
    Endpoint::from_shared(endpoint.to_string())
        .map_err(|e| ...)?
        .connect()       // ← no .tls_config() called
        .await
        .map_err(|e| ...)
}
```

The `Endpoint::connect()` call does not include `.tls_config(ClientTlsConfig::new())`. Even though tonic is compiled with `tls-native-roots` feature, the native root store is not applied to the endpoint connection without explicit TLS configuration.

In contrast, the gateway's OIDC client (using `reqwest` / `hyper-rustls`) connects to the same OpenShift Route successfully because `reqwest` configures TLS separately and does use native roots.

## What We Tested

| Approach | Result |
|----------|--------|
| Interceptor pod → ClusterIP service | VM can't reach pod network (masquerade NAT) |
| Interceptor pod → OpenShift Route (edge TLS, h2c backend) | 502 Bad Gateway (HAProxy gRPC issue) |
| Interceptor pod → envoy TLS sidecar → Route (passthrough TLS) | curl works, gateway tonic client fails (no TLS trust) |
| Interceptor pod → NodePort | VM can't reach node IPs |
| Interceptor as Docker container inside VM (localhost) | **Works** |
| Adding OpenShift ingress CA to VM system trust store + `update-ca-trust` | curl trusts it, gateway tonic still fails |

## Verification

The system trust store works for other HTTPS clients on the same VM:

```
# curl trusts the OpenShift ingress CA
$ curl -sf https://governance-interceptor-openshell-agents.apps.<domain>
  → content-type: application/grpc (envoy responds)

# OIDC client (reqwest) trusts the same CA
$ journalctl | grep rustls
  → Using ciphersuite TLS13_AES_128_GCM_SHA256 (connects to Keycloak route)

# Gateway tonic interceptor client fails
$ journalctl | grep interceptor
  → interceptor transport error: connect https://governance-interceptor-...: transport error
```

## Fix Required (Upstream)

One-line change in `connect_endpoint()`:

```rust
// Before
Endpoint::from_shared(endpoint.to_string())?.connect().await

// After
Endpoint::from_shared(endpoint.to_string())?
    .tls_config(tonic::transport::ClientTlsConfig::new())?
    .connect().await
```

Or, as described in #2623, add a `tls_ca` field to the interceptor TOML config:

```toml
[[openshell.gateway.interceptors]]
name           = "governance"
grpc_endpoint  = "https://governance-interceptor.example.com"
tls_ca         = "/path/to/ca.crt"   # ← new field
```

## Current Workaround

Run the interceptor inside the gateway VM as a Docker container on `127.0.0.1:18081`. The gateway connects via plaintext HTTP locally.

Limitation: the interceptor is per-VM, not shared across gateways.

## Impact

- Cannot deploy the governance interceptor as a shared cluster service
- Each gateway VM must run its own interceptor container
- Policy changes require updating every VM's interceptor (no centralized control)
- Does not affect in-VM interceptor functionality (signed policies work correctly)

## Blocked By

- [NVIDIA/OpenShell #2623](https://github.com/NVIDIA/OpenShell/issues/2623)
