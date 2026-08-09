# Governance Interceptor — Open Questions

Questions to resolve as we build and integrate the governance interceptor.

## Architecture

1. **One interceptor per gateway or shared?**
   - Current decision: one shared interceptor pod for all gateways
   - If per-tenant/per-workspace policies are needed, should we run one interceptor per SAW or have a single interceptor select policy based on workspace metadata?
   - How does the interceptor know which policy to apply if multiple workspaces exist on the same gateway?

2. **Where does the interceptor run?**
   - As a Kubernetes pod in the same namespace as the SAW? (current plan)
   - Inside the gateway VM as a sidecar container?
   - The gateway VM connects to the interceptor via ClusterIP service — does the VM have network access to cluster services?

3. **How does the gateway VM reach the interceptor pod?**
   - The gateway runs inside a KubeVirt VM, not a regular pod
   - Does the VM have access to the cluster's pod network / service DNS?
   - May need a Route or NodePort to expose the interceptor to the VM network

## Policy

4. **Who writes the policy.yaml?**
   - Is it the SAW Composer (Nic), the use-case builder (Alice), or a separate security admin?
   - How does the policy.yaml relate to the BOM policy.yaml from the BOM-driven configuration story?

5. **Policy versioning and rollback**
   - How do we version policies? Git commit hash? Semantic version in the YAML?
   - Can we roll back to a previous policy version for a running sandbox?
   - What happens to running sandboxes when the policy is updated?

6. **Policy scope**
   - One policy for all sandboxes on a gateway? (current)
   - Per-workspace policies? Per-user policies?
   - Can a user request a more restrictive policy (narrowing is OK, widening is blocked)?

## Key Management

7. **Ed25519 signing keys**
   - The upstream example generates keys in-memory at startup — acceptable for mock/demo?
   - For production: load from Vault? From a Kubernetes Secret? From an HSM?
   - Key rotation: how do we rotate without invalidating all running sandbox policies?
   - Key distribution: how does a verifier (e.g., audit system) get the public key?

## Provider Profiles

8. **Which profiles do we vend?**
   - The example ships github.yaml and slack.yaml — what profiles does our use case need?
   - Should profiles be derived from the BOM providers.yaml?
   - If a provider isn't in the vended profile set, does sandbox creation fail?

## Integration

9. **Gateway TOML injection**
   - Currently the gateway TOML is baked via cloud-init — how do we add interceptor config?
   - Add it to the cloud-init template? Or inject via the setup Job?
   - The interceptor endpoint needs to be known at gateway startup — chicken-and-egg with DNS?

10. **Testing**
    - How do we test the interceptor in CI without a running gateway?
    - Can we run the upstream `smoke.sh` test suite in our CI pipeline?
    - Do we need our own integration tests?

## Networking

12. **VM to interceptor connectivity**
    - Current approach: interceptor runs as a cluster pod, exposed via OpenShift Route (passthrough TLS)
    - Gateway VM reaches interceptor via the Route hostname
    - Should the gateway-to-interceptor connection use mTLS for mutual authentication?
    - If mTLS: who issues the client cert for the gateway? Same CA as the gateway's own TLS? Separate governance CA?
    - Alternative: run interceptor inside the VM as a Docker container (simpler but per-VM, not shared)

## Upstream

11. **Upstream stability**
    - The governance interceptor is an example, not a supported product — how stable is the gRPC API?
    - Will protobuf definitions change between OpenShell versions?
    - Should we pin to a specific OpenShell commit or track main?
