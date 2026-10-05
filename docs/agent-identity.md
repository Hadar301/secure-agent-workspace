# SAW agent identity (implementation in progress)

This feature is experimental and disabled by default. **Full acceptance has not
passed.** TCP enrollment, grants, isolation, NetworkPolicy for new connections,
live migration, cold reschedule, a second SAW, and an idempotent upgrade are
recorded below. Configurable registrar TTLs and disabled-mode provisioning
are recorded below, including a secret-backed provider that keeps working
after SPIFFE is turned off. Re-enable was not tested and is not a supported
result. Shared SPIRE server outage and
correlated audit remain open and are retained
as blockers. The live runner executes compatibility probes and reports the
remaining scenarios as blocked.

## Architecture

`charts/spire-identity` installs the ZTWIM subscription and its SPIRE server,
cluster agents, CSI driver and HTTPS discovery operands. Installation is staged
by `scripts/deploy-spire-identity.py`. A separately built Go registrar uses a
CSI-projected, explicitly authorized administrator workload identity to call
the SPIRE API. Server persistence retains the trust domain and signing state.

The registrar watches SAW VMs and reconciles periodically. Both the namespace
label `openshell.pattern/saw=true` and VM label `saw.redhat.com/spiffe=true` are
required. Each opted-in VM has a namespaced Role for its enrollment Secret,
finalizer and restart operations. The guest diagnostic also needs `pods/exec`
in that namespace. That permission is not restricted to the launcher pod name.
Namespace administrators and VM/root administrators are trusted; sandbox
workloads are not.

Exec into virt-launcher is admitted only if the caller can `use` the OpenShift
constraint that already admits that pod. The registrar ServiceAccount therefore
has a cluster-scoped binding to `use` `kubevirt-controller`. Naming that one
constraint does not make the grant least privilege. The constraint disallows
privileged containers, host network, host ports, host PID, and host IPC. It
allows host-directory volumes, every volume plugin, any UID, any SELinux
context, privilege escalation, and `SYS_NICE` plus `NET_BIND_SERVICE`. `use`
would also allow this account to create pods matching that constraint wherever
it can create pods. It currently cannot create pods. On this cluster the exec
Roles exist only in `saw-identity-a` and `saw-identity-b`, so the working
effect is exec into pods admitted by `kubevirt-controller` in those two
namespaces.

Workload identities are:

```text
spiffe://<trust-domain>/saw/<namespace>/<vm>/gateway
spiffe://<trust-domain>/saw/<namespace>/<vm>/ws/<workspace>/sandbox/<name>
```

The agent's internal node identity is separate. Registration entries are parented
to the join-token-attested agent. Gateway selectors require both the configured
host UID and gateway executable path. Sandbox selectors require gateway-owned
Podman labels for managed status, workspace and sandbox. There is no UID-only
fallback. On the dedicated cross-VM pair, those labels selected only the local
sandbox. The gateway, the other workspace, and the other VM's identical
workspace and sandbox names were not selected.

Bootstrap material is stored in the VM-owned `<vm>-spire-join-token` Secret and
delivered on a read-only Secret disk. It is never a Helm value or sandbox mount.
The guest retains agent credentials in `/var/lib/spire/agent` and projects the
local Workload API at `/spiffe-workload-api/agent.sock`. Trust-domain changes are
rejected by the guest and registrar. Ordinary reboot reuses credentials.

The recovery controller uses a fixed root-owned guest diagnostic helper through
QEMU Guest Agent. A narrow SELinux executable transition allows this helper to
read state; SELinux remains enforcing for sandboxes. A diagnostic failure or
server outage does not prove state loss. The optional VM readiness helper
checks installer completion and current agent health separately. Its failure
does not feed recovery and does not by itself start re-enrollment. Confirmed loss or an expired unused
bootstrap token starts a new generation and requests a VM restart. Retries are
bounded and reset after confirmed healthy enrollment. One TCP state-loss
recovery and ordinary reboot passed on the dedicated test VM. TCP bootstrap
failure also passed, including the retry limit. At 2026-10-04T06:55:49Z the
dedicated VM was still generation 13, `recovery-attempts` was `"3"`, VMI
`0163a2c9-1ff1-4e30-8ce1-3dc1d795c3cf` was Running since 2026-09-29T14:59:02Z,
and the generation-13 agent record was absent. During that minute the registrar
continued to log `bootstrap retry limit reached` while the Secret resource
version and VMI stayed unchanged. A Ready registrar and a Running VM do not
restore identity service.

Operator restore is not automatic recovery. Remove any test fault that stops
the agent from starting. Then delete only the Secret annotation
`saw.redhat.com/recovery-attempts`. Do not replace the token, edit the
generation, or create SPIRE registrations. The registrar mints the next
generation and restarts the VM. After the guest reports that generation
present, the registrar clears the counter. That restore ran at
2026-10-04T07:01:14Z. The registrar minted generation 14, restarted once onto
VMI `da35a67a-5606-4460-bcbc-056a661cc7cb`, cleared the counter at 07:03:41Z,
and parented the gateway and both sandbox registrations to the new agent.
Both workspaces then received protected grants. This is operator restore, not
automatic recovery.

Two TCP infrastructure faults were then applied separately. Scaling the
registrar to zero from 07:05:22Z to 07:05:43Z left SPIRE reachable. Generation
14, its agent, and both workspace grants stayed in place, and the registrar's
return did not mint a generation. From 07:12:10Z to 07:14:27Z an nft output drop
on the test VM made the SPIRE Service address time out. Credentials stayed
present, the agent record stayed present, and generation 14 was not replaced.
Removing the table restored the dial, and both workspaces granted again.
Those windows closed while the recorded access tokens were still inside a
five-minute lifetime. They do not show whether an expired access token or
JWT-SVID can still succeed, and the HTTP 200 results were not paired with a
recorded provider list.

The runner later executed `--scenario vm-spire-deny-expiry` with the registrar
left at one ready replica. Both workspaces listed provider `protected` of type
`saw-demo-cc`. Baseline grants were HTTP 200, with sandbox `sub`, `azp`, and
`client_id`, audience `saw-protected-service`, and expiries 2026-10-04T07:30:20Z
(default) and 07:30:21Z (research) for both the access token and the JWT-SVID.
The nft drop stayed in place until guest time 07:31:04Z. The default workspace
then returned HTTP 502 `token_grant_failed`. The research workspace produced no
parseable HTTP status in that run. Generation stayed 14, VMI stayed
`da35a67a-5606-4460-bcbc-056a661cc7cb`, agent `f2462bf16641` stayed present, and
the credential files stayed in place. The runner then deleted the nft table and
the dial succeeded. Both workspaces received new HTTP 200 grants, expiries
07:37:31Z and 07:37:32Z, on that same generation and VMI. That run did not record
providers again after restoration, and it did not repeat a protected request
during the drop before expiry. The 07:12:10Z–07:14:27Z window remains that
pre-expiry sample.

The missing research assertion was repeated by `--scenario research-expiry-denial`
at 2026-10-04T07:54:33Z. Providers before the drop were `protected` /
`saw-demo-cc` on both workspaces. The research access token and JWT-SVID expired
at 07:59:47Z. At guest time 08:00:27Z curl exited 0 and the protected request
returned HTTP 502 with `token_grant_failed` (`dynamic token grant failed`).
Generation, VMI, agent, and credential files stayed in place, and the registrar
stayed ready. After the runner removed the nft table, providers were again
`protected` / `saw-demo-cc` on both workspaces. The research grant was HTTP 200,
curl exit 0, expiry 08:06:22Z, with the sandbox SPIFFE ID in `sub`, `azp`, and
`client_id`. Enrollment was not replaced. A SPIRE server outage has not been run. The server is
one shared StatefulSet pod with PVC `spire-data-spire-server-0`. Stopping it
would also disconnect `saw-alice` and `identity-a`.

Profile removal and restoration was executed by `--scenario profile-remove-restore`
starting at 2026-10-04T07:39:37Z. The registrar was scaled to zero, the research
workspace, sandbox, and provider documents were removed from `saw-bom-profiles`,
and after 20 seconds the research registration was still present. Generation 14,
VMI `da35a67a-5606-4460-bcbc-056a661cc7cb`, and agent `f2462bf16641` stayed in
place. After the registrar returned, that registration was gone and the gateway
and default registrations remained parented to the same agent. This run did not
sample a research grant before the baseline access token expired at 07:44:59Z.
At guest time 07:45:31Z the research grant was HTTP 502 `token_grant_failed`
and its JWT-SVID fetch failed, while default returned HTTP 200 with a new
expiry 300 seconds later. Providers on both workspaces remained `protected` /
`saw-demo-cc`. Restoring the documents recreated the research registration with
the same selectors, `admin` false, and the same parent, without a new generation
or VM restart. The restored research grant was HTTP 200, expiry 07:51:07Z, with
the sandbox SPIFFE ID in `sub`, `azp`, and `client_id`.

VM recreation went through Helm release `identity-b`. Before deletion the VM UID
was `e409a5ea-c672-423a-8b1a-be347e0dd3c0`, agent `f2462bf16641`, and registration
IDs `3bd2e36c-bc0a-46a6-9e4f-b02f804a1ca3`, `6a089670-ac36-43df-9709-a949ce7fa641`,
and `b6a081d8-5e25-4aad-88b2-72d06f99da5b`. Helm uninstall removed those
registrations and left that agent banned. `identity-a` agent `b08237ec2912`
stayed unbanned. The release install created VM UID
`831dec66-c0cd-4a3a-8b7d-436e488ac5eb` and VMI
`df331bd7-5e0a-48c8-89eb-6036038367ed`. Enrollment was automatic: generation 1,
no recovery-attempt annotation, guest state `present`, agent `9889b8abb92e`
unbanned. The gateway and both sandbox registrations are parented only to that
agent, with the previous selectors and `admin` false. Their IDs are
`d5c0464c-ca95-42fb-ba68-168e3befbe87`, `444c03c3-5633-4584-8adc-db74ab1f16da`,
and `23eac5a3-3bc6-47ab-99e6-7efac0718bef`. Both workspace grants were HTTP 200
with the sandbox SPIFFE ID in `sub`, `azp`, and `client_id`, audience
`saw-protected-service`, and provider `protected` / `saw-demo-cc`. From each
sandbox, fetching the gateway identity or the other workspace's identity returned
`PermissionDenied` / `no identity issued`; fetching its own identity succeeded.
After another 45 seconds the new registration IDs and generation were unchanged,
and the old IDs were still absent. Generation 1 is that VM UID's own bootstrap
state. The first grant snapshot ran before the sandbox containers were listed
and is excluded from the grant evidence. The grant evidence is only the later
`vm-recreate-verify` run.

Namespace deletion was recorded outside the namespace, then performed with the
registrar scaled to zero. At 2026-10-04T08:21:49Z the namespace stayed
`Terminating` with finalizer `saw.redhat.com/spire-registration`, and the three
new registration IDs were still present. After the registrar returned, the
namespace was gone, those IDs were gone, and agent `9889b8abb92e` was banned.
The SPIRE server stayed ready. `identity-a`, both `saw-alice` VMs, and
`openshell-agents/openshell-saw` kept their UIDs. A SPIRE server outage has
not been run.

Cross-VM isolation used two new VMs in `saw-identity-c`, installed from the
current chart with the enforcing policy. `identity-a` was not an acceptance
baseline. Both VMs use the workspace and sandbox names `default`/`agent` and
`research`/`agent`. The passing run started at 2026-10-04T10:08:31Z.
`identity-c` is VM UID `3c5b8675-2430-47bb-b4c2-cc4fe50e035d`, VMI
`c3c10391-3a1a-468d-9183-d893f92d3854`, generation 1, agent `7931f99739c9`.
`identity-d` is VM UID `67b4fabc-24af-49cd-b2b2-d91cd1bff72d`, VMI
`f26153aa-2727-42e6-8656-9c8db268ba15`, generation 1, agent `168f10570902`.
Each agent's three registrations are parented only to that agent, with `admin`
false and generation 1 present on the guest. The selectors match on both VMs:
gateway `unix:uid:1000` and `unix:path:/usr/local/bin/openshell-gateway`; each
sandbox `docker` labels `openshell.managed:true`,
`openshell.ai/sandbox-workspace:<workspace>`, and
`openshell.ai/sandbox-name:agent`.

Both workspaces on both VMs returned HTTP 200, curl exit 0, audience
`saw-protected-service`, and the local sandbox SPIFFE ID in `sub`, `azp`, and
`client_id`. Providers were `protected` / `saw-demo-cc`. Access-token expiry was
2026-10-04T10:14:06Z on `identity-c` and 2026-10-04T10:15:27Z on `identity-d`.
Each sandbox fetched its own identity. Fetching the gateway identity, the other
workspace, or any of the peer VM's three identities returned `PermissionDenied`
/ `no identity issued`.

Both agents were Enforcing, `saw_spire_agent_t` was not permissive, and the
process context was `system_u:system_r:saw_spire_agent_t:s0`. The unix attestor
had `discover_workload_path: true` and `workload_size_limit: -1`. The policy
package was `selinux-policy-43.3-1.fc44`. `journalctl -u spire-agent` exited 0.
The attestor and selector error filter was empty at that sample. The agent's
error lines during the identity fetches are `FetchJWTSVID` / `No identity
issued`; those are the rejected requests, not selector-collection failures.

Two earlier runner attempts, at 2026-10-04T08:34:11Z and 2026-10-04T09:03:42Z,
recorded only that `identity-c` did not become ready. The demo issuer allowlist
then contained only the `identity-a` and `identity-b` prefixes, so these grants
were HTTP 502 after the issuer returned 401 `invalid_grant`. Those attempts are
not the isolation evidence. The allowlist was extended to the two new SPIFFE
prefixes and the demo pod was recreated, which rotated its ephemeral signing
key. That rotation is a test boundary: access tokens and assertions signed by
the previous demo pod cannot support later expiry or continuity conclusions.
The isolation evidence is the 10:08:31Z run.

TCP NetworkPolicy enforcement was measured in `saw-identity-c` only, starting at
2026-10-04T11:51:17Z. Before the policy, both guests completed a new TCP
connection to the SPIRE ClusterIP on port 443. A policy selecting
`kubevirt.io: virt-launcher`, with egress policy type and no egress rules,
made both of those new connections time out. After that policy was deleted,
both connections succeeded. It was not left in place. The cluster
NetworkPolicy inventory and every VM UID stayed unchanged, and the SPIRE
server stayed ready. The measured policy was a temporary object in `saw-identity-c`.
Each sample was a new TCP connection. This run did not show whether an
already-open connection is terminated when the policy appears.

`vm.storageClass`, `vm.accessMode`, and `vm.volumeMode` are configurable. The
defaults remain an empty storage class, `ReadWriteOnce`, and an unset volume
mode. `identity-c-root` and `identity-d-root` stay `ReadWriteOnce` block
volumes on `ocs-external-storagecluster-ceph-rbd`, and both VMIs report
`LiveMigratable` false because those PVCs are not shared. Those two VMs remain
the isolation baselines.

Migration prerequisites were read from the reconciled objects, not from the
empty HyperConverged `liveMigrationConfig` and `featureGates`. KubeVirt
`kubevirt-kubevirt-hyperconverged` is Available. Its migration settings are
`completionTimeoutPerGiB: 150`, `progressTimeout: 150`,
`parallelMigrationsPerCluster: 5`, and `parallelOutboundMigrationsPerNode: 2`.
All five nodes are Ready, unschedulable is false, `kubevirt.io/schedulable` is
true, and a virt-handler pod is Running on each. At the request snapshot,
every node had room for another 2 CPU / 4Gi guest, including a second copy of
those requests on a different node during migration. The Ceph cluster reported
`HEALTH_OK` at 2026-10-04T12:02:33Z with 176735028924416 bytes available. The
RBD StorageProfile advertises `ReadWriteMany` with volume mode `Block`, which
matches the golden image's block mode. CephFS advertises `ReadWriteMany` with
volume mode `Filesystem`. The migration canary uses that RBD shared block setting. `identity-c` and
`identity-d` were not moved.

`identity-e` in `saw-identity-e` is that canary: 2 CPU, 4Gi, root PVC
`identity-e-root` (`pvc-7688ee45-510e-4f54-bb09-25a75a9e6dc7`) bound
`ReadWriteMany` block on `ocs-external-storagecluster-ceph-rbd`. Its VMI
reported `LiveMigratable` true before the move. VM UID
`6d2d2555-e6a6-4f84-ac55-721614ba72d4`, generation 1, agent `6fb88b67b417`,
guest state present. The three registrations, parented only to that agent with
`admin` false, are gateway `0e3252d2-93d1-4b7c-9b74-6eed3280c6f1`, default
`fceb72cc-7904-478d-92ae-9b57c1624213`, and research
`98b26c6b-7a69-4ef1-9790-a0d186c19e3e`. Adding this SPIFFE prefix recreated the
demo pod as `identity-demo-bbb4d7bc4-vm9nw` at 2026-10-04T12:13:53Z. That is a
second signing-key boundary. Grants below were issued after it. Later
rotations are separate boundaries: adding the `identity-f` prefix
recreated the demo as `identity-demo-5b6c7f55b5-klgm6` at
2026-10-04T13:18:12Z, removing that prefix recreated it as
`identity-demo-bbb4d7bc4-gfx8d` at 2026-10-04T13:31:13Z, and adding the
`identity-q` prefix recreated it as `identity-demo-6dd56b8475-slcpw` at
2026-10-04T13:40:23Z (Helm `identity-demo` revision 6 at
2026-10-04T13:39:47Z). That pod was still Running on 2026-10-05. Tokens from
these later pods cannot support expiry or continuity conclusions for the
migration and reschedule samples.

Live migration `identity-e-live-1` was created at 2026-10-04T12:16:10Z. The
migration state ran from 2026-10-04T12:16:22Z to 2026-10-04T12:16:36Z and
finished `Succeeded`, with `failed` unset. Source node
`control-plane-cluster-2p7tv-3`, destination
`control-plane-cluster-2p7tv-2`. The VMI UID stayed
`54d9debd-463d-477b-a6eb-770d6c9296ae`. Generation stayed 1, the agent hash
stayed `6fb88b67b417`, and the registration IDs and parents stayed the same.
Protected requests for both workspaces ran from 2026-10-04T12:16:07Z through
2026-10-04T12:16:40Z. All 32 samples were HTTP 200, curl exit 0, audience
`saw-protected-service`, with that workspace's sandbox SPIFFE ID in `sub`,
`azp`, and `client_id`. Samples at 12:16:22Z, 12:16:26Z, 12:16:30Z, 12:16:35Z,
and 12:16:38Z cover the migration interval and the following seconds. No sample
recorded an error or interruption. That is sampled continuity, not a guarantee
that every connection stayed uninterrupted. `identity-c` and `identity-d` kept
their VM UIDs, VMI UIDs, and nodes.

Rescheduling was a separate cold start. At 2026-10-04T12:18:52Z the canary
gained a required node affinity for `worker-cluster-2p7tv-1`. The running VMI
did not move. Its VMI was deleted at 2026-10-04T12:19:09Z, and a new VMI
`e3beaf94-a247-4c44-820f-e887321ad479` was Running on
`worker-cluster-2p7tv-1` at 2026-10-04T12:19:45Z. The VM UID, generation 1,
agent `6fb88b67b417`, registration IDs, and parents were unchanged.
`recovery-attempts` stayed unset. The guest reported state present and
credentials present. At 2026-10-04T12:20:30Z both workspace grants were HTTP
200, curl exit 0, audience `saw-protected-service`, with the sandbox SPIFFE ID
in `sub`, `azp`, and `client_id`, expiring at 2026-10-04T12:25:19Z. The
required node affinity for `worker-cluster-2p7tv-1` was removed at
2026-10-04T13:40:52Z. The running VMI stayed
`e3beaf94-a247-4c44-820f-e887321ad479` on `worker-cluster-2p7tv-1`, Ready,
with `RestartRequired` unset. It was still that VMI on that node at
2026-10-05T07:08Z. No second live migration was created for this restart.

The measured NetworkPolicy scope stays new TCP connections from the dedicated
launchers in `saw-identity-c`, not termination of an already-open connection,
and the policy was not left in place.

## Pattern, quickstart, upgrade, and disable

The Validated Pattern is already installed from branch
`codex/custom-inference-vm-installer`. Argo applications in `vp-gitops` own
the platform charts and the user SAW `saw-alice` (`charts/openshell-saw`,
automated sync). `alice` is Ready and has no `saw.redhat.com/spiffe=true`
label. At the start of this Pattern measurement Helm release `saw-spire`
was revision 11 in `zero-trust-workload-identity-manager`, updated
2026-10-04T13:29:55Z. The registrar TTL upgrades below moved that release
to revision 15. It is not an Argo application. `charts/spire-identity` fails unless that release
namespace is `zero-trust-workload-identity-manager`.
`examples/agent-identity/pattern-values.yaml` would add an Argo application
for that same chart and namespace. It was not applied. `spire-server-0` is
still the pod created at 2026-09-27T11:09:38Z.

`identity-q` in `saw-identity-q` is the second SAW measured for this TCP
delivery. The namespace carries `openshell.pattern/saw=true` and
`saw.redhat.com/identity-test-run=agent-identity-quickstart-20261004`. Helm
`saw-bom` revision 1 and `identity-q` revision 1 were installed at
2026-10-04T13:39:58Z and 2026-10-04T13:40:02Z from the current charts. Those
are the charts `scripts/openshell-saw-create.sh` installs. That script appends
route, dashboard, governance, inference, and OIDC `--set` values after the
values files, which would override the acceptance values, so this install
passed the acceptance values to Helm directly. The VM became Ready at
2026-10-04T13:43:52Z. VM UID `cd87080c-34aa-4f5b-a1a7-e95d2d024cf0`, generation
1, VMI `a6cecb86-aa32-4788-a97e-39a3623be9f9`, agent `151356e3791b`. The three
registrations, parented only to that agent with `admin` false and JWT-SVID TTL
300, are gateway `17254674-14eb-4355-9213-5b11c0c60150`, default
`d5ac67ea-191b-4ca5-8d63-bbce0f426fbc`, and research
`811129ad-f9b7-4585-b2e2-a0894105a4e5`. The guest agent address was
`spire-server.zero-trust-workload-identity-manager.svc.cluster.local` port
443. SELinux was Enforcing, policy
`selinux-policy-43.3-1.fc44.noarch`, process context
`system_u:system_r:saw_spire_agent_t:s0`, and `saw_spire_agent_t` was not
permissive. `recovery-attempts` was unset. At 2026-10-04T13:46:06Z both
workspace grants were HTTP 200, curl exit 0, audience `saw-protected-service`,
with that workspace's sandbox SPIFFE ID in `sub`, `azp`, and `client_id`,
expiring at 2026-10-04T13:51:00Z and 2026-10-04T13:51:01Z. Those grants follow
the `identity-demo-6dd56b8475-slcpw` signing key.

Helm upgrade of `identity-q` with `--reuse-values` at 2026-10-04T13:48:14Z
created revision 2. The VM UID, VMI UID, generation 1, agent hash, and the
three registration IDs stayed the same. The guest state stayed present,
`RestartRequired` stayed unset, the VM stayed Ready, and `recovery-attempts`
stayed unset. That same enrollment was still present at 2026-10-05T07:09:09Z.

The first disablement pass used only `identity-q`. It revoked that VM's
identity. The fresh disabled install on `identity-s` and the disablement of
the already enrolled `identity-t` are recorded below. Together those are the
disabled-mode checks for this revision. Re-enable was not tested. At 2026-10-05T07:10:02Z
`saw-bom` revision 2 replaced the profile with workspaces whose provider lists
are empty. At 2026-10-05T07:10:08Z `identity-q` revision 3 set
`spiffe.enabled=false`. The SPIFFE label and the registrar finalizer were
removed. The VM UID stayed `cd87080c-34aa-4f5b-a1a7-e95d2d024cf0`. At
2026-10-05T07:10:57Z the three registrations were gone, agent `151356e3791b`
was banned, and `recovery-attempts` was unset. The join-token Secret remained.
The VMI was deleted then. New VMI `cea4a17f-5d9c-43df-aa16-b01a24c3ad4b` was
created at 2026-10-05T07:11:14Z on `control-plane-cluster-2p7tv-3`, and the VM
was Ready at 2026-10-05T07:13:06Z. Guest install and apply were both Done. The
agent unit file was absent and the relay unit was absent. That missing unit
does not by itself establish complete disablement.

Revision 4 at 2026-10-05T07:34:15Z is a separate installer upgrade, not another
identical-values idempotent upgrade. Helm `--reuse-values` rendered the local
chart after the gateway-env and sandbox-mount changes. The installer checksum
annotation is `250d044a9c78bf05`. `RestartRequired` stayed unset, so the
running guest did not read the new installer disk until the VMI was deleted.
The current VMI is `7abeeb8d-072b-4833-82c2-0af6d13b5086` on
`control-plane-cluster-2p7tv-3`. Re-measured after that restart: both gateway
env files and both gateway toml files omit
`OPENSHELL_GATEWAY_SPIFFE_WORKLOAD_API_SOCKET` and
`provider_spiffe_workload_api_socket`. The recreated sandboxes
`openshell-default--agent-10213d94-9263-4d1e-8d11-e57a0076a372` and
`openshell-research--agent-4a97e2c5-d885-4023-aaf8-79fdd39835a4` have no
SPIFFE or SPIRE binds. The agent unit file is absent and
`spire-agent.service` is `inactive`. The SPIFFE label, trust-domain
annotation, `saw-spire` volume, and registrar Role are absent. SPIRE has no
entries hinted `saw:cd87080c-34aa-4f5b-a1a7-e95d2d024cf0`. Agent
`151356e3791b` is still banned. `recovery-attempts` is unset.

Retained on purpose: Secret `identity-q-spire-join-token`,
`/etc/spire/agent.conf`, `/etc/spire/trust-domain`,
`/var/lib/spire/agent/agent-data.json`, and
`/var/lib/spire/agent/keys/keys.json`. `disable()` stops and deletes the
`spire-agent.service` unit file. It does not delete those files or the
join-token Secret. That retention was measured. It does not show that a
later enable recovers the enrollment. Re-enable was not tested, and it was
not a required acceptance case. The registrar has already deleted the
entries and banned the agent.

The `protected` / `saw-demo-cc` providers are still listed in both the
`default` and `research` workspaces, each with `CREDENTIAL_KEYS` 0 and
`CONFIG_KEYS` 0. The installer does not delete a provider that leaves the
profile. Those leftovers are reconciliation behavior. They were not removed.
This profile never had a `credentialSecret` provider, so the 502
`token_grant_failed` grants, and the later 403 `policy_denied` grants after
the sandboxes were recreated, do not show that a secret-backed provider still
works. At that measurement `identity-q` was the disabled canary, and
`identity-a`, `identity-c`, `identity-d`, `identity-e`, and `alice` were Ready.
`saw-spire-registrar-5d68d8d5c-ckg65`, created 2026-10-04T08:22:15Z, was still
Running on 2026-10-05. The compatibility gate records `disabled-mode-live` as
blocked because it does not execute this mutation.

`identity-s` in `saw-identity-s` is a separate fresh disabled canary. It was
created through `make openshell-saw-create` with `OWNER=static-check`,
`SAW_VALUES`, and `SAW_BOM_VALUES`. The namespace is labelled
`openshell.pattern/saw=true`. The VM label
`saw.redhat.com/identity-test-run=agent-identity-static-20261005` is set.
Helm `identity-s` revision 1 was installed at 2026-10-05T07:40:12Z. The
script appends `--set route.enabled=true` and `--set route.dashboard=true`
after the values files, so the release has both route flags true while
`dashboard.enabled` stays false. Routes `identity-s-gateway`,
`identity-s-webui`, and `identity-s-dashboard` exist. `vm.readinessProbe` is
false, so kubevirt Ready is not installer success.

The first boot's apply failed: the BOM provider type and the copied Secret
`provider` field were `custom`, which the installer rejects. `saw-bom` was
upgraded to revision 2 at 2026-10-05T07:43:25Z with provider `inference` of
type `openai`, `credentialSecret` `inference`, `credentialSecretKey`
`api_key`, `baseUrlSecretKey` `url`, and `modelSecretKey` `model`. The Secret
`provider` field was then set to `openai`. The VMI was deleted so the guest
would read that profile. Current VMI `676b68b6-5a6f-40a0-b9b8-218d1e7bd99e`
was created at 2026-10-05T07:46:28Z on `control-plane-cluster-2p7tv-1`. The
console on that VMI recorded `install: Done` and `apply: Done`, including
`PASS all workspaces, providers and sandboxes present`. VM UID
`85f2a3c4-2dbc-4eaf-9f5b-b469a4a843ba`, generation 1. The Helm value
`inference.provider` is still `custom` because the quickstart set it from the
original Secret field; the provider the installer created is the BOM's
`openai` provider.

That guest has no SPIFFE label, no trust-domain annotation, no join-token
Secret, no registrar Role, and no `saw-spire` volume. SPIRE has no entries
hinted with this VM UID. There is no `spire-agent` unit file, no relay unit,
no `/etc/spire/agent.conf`, no trust-domain file, and no
`/var/lib/spire` agent state. Gateway env and toml omit the SPIFFE socket
settings. Sandbox `openshell-default--agent-f5669255-3af4-4fe5-8097-b5c00ba4f8d4`
has no SPIFFE or SPIRE bind. `openshell provider list` shows `inference` /
`openai` with `CREDENTIAL_KEYS` 1 and `CONFIG_KEYS` 1. The credential key name
is `OPENAI_API_KEY` and the config key name is `OPENAI_BASE_URL`. Provider id
`05225dd7-9924-438d-9285-8a533258e83b`. `openshell inference get` names
provider `inference` and has a model set. The sandbox environment does not
export `OPENAI_API_KEY` or `OPENAI_BASE_URL`. At 2026-10-05T09:05:41Z
`openshell sandbox exec` in sandbox `agent` requested
`https://inference.local/v1/models`. curl exited 0, HTTP 200, and the body
was 112 bytes. The body was not recorded. Provider existence is not that
request: the gateway accepted the stored credential and the upstream
answered. A fresh disabled VM can be provisioned with a secret-backed
provider and without identity resources. That VM never had an enrollment, so
it does not show a provider that already existed on an enrolled VM.

Pattern deployment used a dedicated SAW and did not take ownership of the
shared identity stack. `examples/agent-identity/idpat-applications.yaml`
creates namespace `saw-idpat` and Applications `idpat-bom` and `idpat` at
revision `codex/agent-identity` commit `3b040d06`. It does not install
`charts/spire-identity`. `alice` was not modified: VM UID
`4d9604bb-4ebc-438a-a4e2-85175a744328`, Running, no
`saw.redhat.com/spiffe` label, Application `saw-alice` still tracking
`codex/custom-inference-vm-installer`. Helm `saw-spire` is still revision 11,
updated 2026-10-04T13:29:55Z, and there is no Argo application named
`saw-spire`. `spire-server-0` is still the pod created at
2026-09-27T11:09:38Z. The registrar pod was still
`saw-spire-registrar-5d68d8d5c-ckg65`.

The first `idpat` sync failed because client-side apply puts the installer
ConfigMap into `kubectl.kubernetes.io/last-applied-configuration`, which
exceeds the 262144-byte annotation limit. The Application's `syncOptions`
include `ServerSideApply=true`. A new sync started at 2026-10-05T07:49:34Z
with that option and reported success, and ConfigMap `idpat-installer`
exists. `idpat-bom` is Synced and Healthy at `3b040d06`. VM UID
`f5e24257-6717-41e2-b241-99fb334e5580`, generation 1, label
`saw.redhat.com/spiffe=true`, trust domain
`saw.cluster-2p7tv.dyn.redhatworkshops.io`, gateway UID 1000. VMI
`23af4565-0472-43de-9b3f-deaaa513081f` was created at 2026-10-05T07:41:30Z on
`control-plane-cluster-2p7tv-2` and Ready at 2026-10-05T07:52:42Z. Role
`idpat-spire-registrar` and Secret `idpat-spire-join-token` exist. The volume
list includes `saw-spire`. The guest agent is `active`, SELinux is Enforcing, policy `selinux-policy-43.3-1.fc44.noarch`, and
the agent context is `system_u:system_r:saw_spire_agent_t:s0`. Agent config
`server_address` is
`spire-server.zero-trust-workload-identity-manager.svc.cluster.local` and
`server_port` is 443. Entries, parented to agent hash `5b439a8bebdb`, with
`admin` false and JWT-SVID TTL 300, are gateway
`047b48c5-7075-47aa-bc53-45114e9f1ecb` (`/saw/saw-idpat/idpat/gateway`) and
default sandbox `cb59f124-04fb-4548-a5ef-e2078e52cc63`
(`/saw/saw-idpat/idpat/ws/default/sandbox/agent`). That agent is not banned.
`recovery-attempts` is unset. The deployed values set `serverTransport=tcp`.

At 2026-10-05T09:23:12Z Applications `idpat` and `idpat-bom` were Synced and
Healthy at commit `113781e`. VirtualMachine `idpat` stayed UID
`f5e24257-6717-41e2-b241-99fb334e5580`. Generation became 2. Ready stayed
true and `RestartRequired` stayed unset. The live installer checksum is
`cfe0b7edd07a0a48` and the cloud-init checksum is `4b6af389ec264962`, matching
that commit rendered for namespace `saw-idpat`. The Application
`ignoreDifferences` cover the controller-written firmware `serial` and
`uuid`, machine type, architecture, interface MAC, PCI topology annotation,
MAC-pool timestamp, KubeVirt API-version annotations, and finalizers.
`alice` stayed UID `4d9604bb-4ebc-438a-a4e2-85175a744328`, Running, with no
SPIFFE label. Helm `saw-spire` stayed revision 15. `spire-server-0` stayed
UID `c25daa63-085b-4216-a328-633658ea1e83`.

Helm `identity-demo` revision 7 at 2026-10-05T09:24:29Z added the `idpat`
prefix. That recreated the signer as `identity-demo-cc776b5d8-hx4wh` at
2026-10-05T09:25:07Z. Tokens from `identity-demo-6dd56b8475-slcpw` do not
belong to this key. The protected request from sandbox `agent` was HTTP 200,
curl exit 0, audience `saw-protected-service`, with
`spiffe://saw.cluster-2p7tv.dyn.redhatworkshops.io/saw/saw-idpat/idpat/ws/default/sandbox/agent`
in `sub`, `azp`, and `client_id`, expiring at 2026-10-05T09:31:00Z. The
allowlist is in `examples/agent-identity/demo-values.yaml`.

Route `idpat-webui` exists because `route.webui` defaults to true; the
Application values set `route.enabled` and `route.dashboard` false and did
not set `route.webui`. That route does not adopt the SPIRE server.

`identity-s` and `idpat` were left in place after this evidence. `identity-q`
was the disabled canary. `identity-c`, `identity-d`, and `identity-e` were
not mutated. The shared SPIRE server was not stopped.

`identity-t` in `saw-identity-t` is the enrolled VM that already had a
secret-backed provider. The namespace is labelled
`openshell.pattern/saw=true` and
`saw.redhat.com/identity-test-run=agent-identity-disable-static-20261005`.
Helm `saw-bom` revision 1 was installed at 2026-10-05T08:43:05Z. Helm
`identity-t` revision 1 completed at 2026-10-05T08:43:34Z with SPIFFE enabled
and `serverTransport=tcp`. VM UID `44a1ff8a-2de7-4702-aa55-d4db88c9cdaf`.
The first VMI `fb3341f3-3eb7-4c3a-acdb-896266d52e86` was created at
2026-10-05T08:43:43Z on `control-plane-cluster-2p7tv-3`. While SPIFFE was
still enabled, the same sandbox `agent` request to
`https://inference.local/v1/models` was HTTP 200 with a 112-byte body.
Entries, `admin` false, JWT-SVID TTL 300 and X.509 TTL 3600, parented to
agent `c130b3db9d5a`, were gateway `0d2589fa-6f32-4a5e-b930-f0cf307786f4`
and sandbox `ae947896-e0cc-4a62-b291-31ba3a19db5c`. Secret
`identity-t-spire-join-token` was created at 2026-10-05T08:43:32Z. Its
`expires` value is `1791190112`, exactly 300 seconds after that creation
time. The registrar's `JOIN_TOKEN_TTL` was 300 when it was minted.

Helm revision 2 at 2026-10-05T08:50:39Z set `spiffe.enabled=false` and reused
the other values, so the static provider stayed in the profile. The VM UID
stayed `44a1ff8a-2de7-4702-aa55-d4db88c9cdaf`. Generation became 2.
`RestartRequired` was true and the SPIFFE label was gone. The VMI was
deleted so the guest would read the new installer disk. VMI
`3ffd9d7b-1ef6-4518-b2d4-4b77c09a1698` was created at 2026-10-05T08:52:49Z
on `control-plane-cluster-2p7tv-3`, and the VM was Ready at
2026-10-05T08:54:26Z. `saw-install` and `saw-apply` both reported
`Result=success`. After that restart the same sandbox request was again
HTTP 200 with a 112-byte body. `openshell provider list` still shows
`inference` / `openai` with `CREDENTIAL_KEYS` 1 and `CONFIG_KEYS` 1.
Sandbox `openshell-default--agent-210ef058-cca6-4bea-90f6-025b9c3da693` has
no SPIFFE or SPIRE bind. Both gateway env files and both gateway toml files
omit the SPIFFE socket settings. The `saw-spire` volume and the registrar
Role are gone. The registrar finalizer is gone and `recovery-attempts` is
unset. SPIRE has no entries hinted `saw:44a1ff8a-2de7-4702-aa55-d4db88c9cdaf`.
The two entry IDs above are gone. Agent `c130b3db9d5a` is banned.

Retained on this VM: Secret `identity-t-spire-join-token` with the same
`expires` value `1791190112`, `/etc/spire/agent.conf`,
`/etc/spire/trust-domain`, `/var/lib/spire/agent/agent-data.json`, and
`/var/lib/spire/agent/keys/keys.json`. The retained agent config still names
`spire-server.zero-trust-workload-identity-manager.svc.cluster.local`, port
443, and trust domain `saw.cluster-2p7tv.dyn.redhatworkshops.io`. The
`spire-agent.service` unit file is absent and no `spire-agent` process is running. systemd still reports
`spire-agent.service` as `ActiveState=failed` and `Result=exit-code` with an
empty fragment path, which is the leftover state after the unit file was
removed. Re-enable was not tested. These results do not show that turning
SPIFFE back on recovers the enrollment.

## Registrar lifetimes

`registrar.joinTokenTTL`, `registrar.jwtSvidTTL`, and `registrar.x509SvidTTL`
are whole seconds from 60 through 86400. The chart rejects a duration suffix
or a fractional value. The registrar reads `JOIN_TOKEN_TTL`, `JWT_SVID_TTL`,
and `X509_SVID_TTL`, defaulting to 600, 300, and 3600. A join token that is
already stored keeps the expiry it was minted with. A new token uses the
configured lifetime only when that Secret does not exist yet. JWT and X.509
lifetimes are written onto existing registration entries. The entry ID is
kept.

The registrar image is
`image-registry.openshift-image-registry.svc:5000/zero-trust-workload-identity-manager/saw-spire-registrar@sha256:c9271667a9bc328c43ccd37d0e6852b97f4b32e918ac9cbabcede68ca43a34cf`.
Helm `saw-spire` revision 12 at 2026-10-05T08:32:22Z set join 600, JWT 300,
and X.509 3600. Revision 13 at 2026-10-05T08:33:30Z set join 300, JWT 180,
and X.509 1800. Revision 14 at 2026-10-05T08:35:36Z set join 300, JWT 300,
and X.509 3600. Revision 15 at 2026-10-05T08:58:36Z restored join 600 and
left JWT 300 and X.509 3600. `spire-server-0` stayed UID
`c25daa63-085b-4216-a328-633658ea1e83`, created 2026-09-27T11:09:38Z. The
registrar pod after revision 15 is `saw-spire-registrar-574d8688ff-56f56`,
created 2026-10-05T08:59:04Z. That replacement is the TTL rollout. The
earlier pod `saw-spire-registrar-5d68d8d5c-ckg65` is gone.

After revision 15 the workload entries still have their original IDs and
`created_at` values. Each has JWT-SVID TTL 300 and X.509 TTL 3600, `admin`
false. That includes `identity-a`, `identity-c`, `identity-d` (paths under
`/saw/saw-identity-c/identity-d/...`), `identity-e` (gateway
`0e3252d2-93d1-4b7c-9b74-6eed3280c6f1`, default
`fceb72cc-7904-478d-92ae-9b57c1624213`, research
`98b26c6b-7a69-4ef1-9790-a0d186c19e3e`), and `idpat` (gateway
`047b48c5-7075-47aa-bc53-45114e9f1ecb`, sandbox
`cb59f124-04fb-4548-a5ef-e2078e52cc63`). `identity-q` and `identity-t` have
no entries because they are disabled. Stored join-token expiries were
unchanged by revision 15: `identity-t` `1791190112`, `identity-e`
`1791116114`, `identity-q` `1791121817`, and `idpat` `1791186681`. The
`identity-t` expiry matching creation plus 300 is the new-token measurement.
The unchanged expiries are the existing-token measurement.

## Still outstanding

Full acceptance remains open. The idempotent upgrade is the `identity-q`
revision 1 to 2 result above. The revision 4 installer upgrade is a different
change and was measured on the already-disabled VM. Disabled-mode
provisioning, revocation, retained material, and a secret-backed provider
request before and after disablement are recorded above. Re-enable was not
tested.
These items remain:

- Shared SPIRE server outage. This is a mandatory blocker. The current chart
  can only install into `zero-trust-workload-identity-manager`, and that
  server is shared by the enrolled VMs. It was left running. An isolated
  environment or an authorized maintenance window is required. The TCP
  scheduling tests do not cover it.
- Correlated audit acceptance. This is a mandatory blocker. It needs the
  missing supervisor capability or an explicitly approved acceptance-scope
  change. The pinned OpenShell build does not emit the required identity
  claims. The supervisor was not patched.
- Re-enable of a disabled VM was not a required acceptance case and was not
  tested. Retained join-token and agent files are the measured disablement
  behavior. They do not show that turning SPIFFE back on recovers the
  enrollment.

Deleting a profile registration prevents renewal. Already issued JWT-SVIDs and
access tokens are expected to remain usable until expiry, normally five minutes.
The 07:39 profile run did not sample the research grant inside that window.
Bootstrap tokens default to ten minutes. The live registrar is set back to
that default.

## Deployment and examples

Use an explicit context and inspect existing shared infrastructure first:

```sh
python3 scripts/deploy-spire-identity.py --help
python3 scripts/test-agent-identity-live.py --help
```

A provider or profile change is not in effect for a sandbox request until the
sandbox successfully acknowledges the expected content revision. Read the
gateway policy with `policy get --full` and record `hash` and `config_revision`.
`active_version` does not identify that content. Call this snapshot the gateway
policy. After it shows the expected revision, wait for a successful sandbox
acknowledgement of that same revision, then issue the request and collect grant
evidence. The next `ReportPolicyStatus` event is not that acknowledgement unless
it corresponds to the expected revision and reports success. A success before
that acknowledgement can still carry the previous access token. On the measured
default-workspace switch, the gateway hash changed within a second and the
matching successful sandbox acknowledgement followed about six seconds later.
The previous token was reused only before that acknowledgement. That switch did
not show a cache-invalidation defect.

Direct issuer validation passed for the default sandbox JWT-SVID: a valid
assertion was accepted, and the same assertion was rejected after its signature
was tampered and again after expiry. That probe talks to the demo issuer
directly. It does not exercise OpenShell's grant flow or replay a gateway
assertion. Shared validation code explains why signature and expiry are checked
before the grant branch; it does not widen this live result.

Example values are in `examples/agent-identity/`. `cluster-values.yaml` describes
the current cluster installation; `pattern-values.yaml` shows the Pattern
application wiring. On this cluster the Pattern already owns `saw-alice` and
the platform applications, and `pattern-values.yaml` was not applied.
Do not let a second Helm/Argo application take ownership of an existing stack.

Build `identity/registrar`, publish its image, and set `registrar.image` to an
immutable digest before enabling it. The source Dockerfile documents the build.
The SPIRE agent component is separately digest pinned and verified during BOM
installation. TCP uses the SPIRE Service on port 443. VSOCK guest configuration
exists, but the host bridge and live validation remain outstanding; do not use
that transport as an accepted deployment option yet. No transport fallback occurs.

Quickstart accepts `DYNAMIC_PROVIDERS=true`, `SAW_VALUES=<file>` and
`SAW_BOM_VALUES=<file>` without an API key. Both files must be explicit. Approved
provider profiles go in `providerProfiles`; BOM profile documents can be supplied
through the `saw-bom` chart's `profileFiles` map. See `provider-values.yaml` and
`bom-values.yaml`. Existing static provider profiles retain their Secret handling.
The measured `identity-q` install passed acceptance values to Helm directly,
because the quickstart script's extra `--set` flags would have overridden
them. `identity-s` is the install that went through `make openshell-saw-create`,
as recorded above.

`runtimeCredentials: true` marks installer-created client-credential providers.
`externallyManaged: true` marks user-created token-exchange providers. The flags
are mutually exclusive and cannot be combined with `credentialSecret`.

The laptop helper uses an authenticated named gateway and its OIDC login:

```sh
make openshell-saw-token-provider OPENSHELL_SAW_NAME=my-gateway \
  WORKSPACE=research PROVIDER=protected PROVIDER_PROFILE=saw-demo-exchange
```

For a separate issuer, `scripts/openshell-saw-token-provider.py --token-stdin`
accepts a token acquired on the laptop through stdin. It passes the token to the
CLI in the environment, never in argv, Helm values or guest configuration. Do
not invoke it under shell tracing. The issuer must accept the subject token's
audience and issuer; a gateway login token is not automatically suitable for
every external service.

`charts/identity-demo` is an optional test fixture, not a production issuer. It
uses a pinned Node image and verifies JWT signatures, issuer, audience and
expiry. Its signing key is ephemeral. The enrollment secret for obtaining demo
user tokens must be generated per run and deleted during cleanup.

## Evidence, blockers and cleanup

The pinned OpenShell build does not include the sandbox identity claims needed
for the required correlated grant audit events. Details and source references
are in [the local dependency report](issues/agent-identity-audit-blocker.md).
No external issue is required to continue independent implementation/testing.
Protected-service logs cannot substitute for the missing audit functionality.

Use only dedicated test namespaces, labelled
`saw.redhat.com/identity-test-run=<run-id>`. Evidence must contain verified claim
summaries and immutable artifact identifiers, never raw bearer/bootstrap tokens.
The internal agent ID includes its join-token identifier and must be redacted
from exported evidence. Exit code 2 from the live runner means incomplete,
not success. Current reports do not establish VM acceptance.

The guest loads a prebuilt SELinux module, built from
`charts/openshell-saw/files/selinux/` against the golden-image baseline
`selinux-policy-43.3-1.fc44` and `selinux-policy-targeted-43.3-1.fc44`. The
installer does not install policy development packages or compile on the guest.
The module does not declare the agent domain permissive. `saw-identity-a` /
`identity-a` is a diagnostic VM: unpinned development-package installs on
2026-09-27 replaced that baseline with `selinux-policy` 44.10. A permissive
domain or `SELinuxContext=` on that VM does not establish enforcement, sandbox
attestation, or isolation. Final acceptance has to be repeated on a fresh VM
from the image baseline. Whether this module loads on 44.10 is unverified.

Delete run-owned VMs through Kubernetes so the registrar finalizer can revoke
their entries and agent. Confirm cleanup before removing run-owned namespaces
and demo resources. Never use broad repository uninstall targets. Preserve
pre-existing SAWs and shared identity infrastructure. Roll back values/images
through the owning Helm or Argo deployment. Disabling identity removes the
SPIFFE label, registrar entries, and agent unit. The join-token Secret,
`/etc/spire/agent.conf`, `/etc/spire/trust-domain`, and `/var/lib/spire` are
retained, as recorded for `identity-q`. Providers that leave the profile stay
until something else deletes them. A disable BOM that still lists dynamic
providers fails apply. After the evidence above was recorded, Helm releases
`identity-q`, `identity-s`, `identity-t`, and their `saw-bom` releases were
uninstalled, Applications `idpat` and `idpat-bom` were deleted, and
namespaces `saw-identity-q`, `saw-identity-s`, `saw-identity-t`, and
`saw-idpat` were removed by 2026-10-05T09:35:39Z. Their registrations were already gone before the
namespaces were deleted. BuildConfig `saw-registrar-ttl` was removed. The
registrar image digest used by Helm `saw-spire` revision 15 remains.

The remaining canaries were removed after their evidence was in this report.
Helm `identity-a` revision 14, Helm `identity-c` and `identity-d` revision 1
with `saw-bom` in `saw-identity-c`, and Helm `identity-e` revision 1 with
`saw-bom` in `saw-identity-e` were uninstalled. VM UIDs were
`c89c222c-166e-437a-af0f-2fa97bad0008`, `3c5b8675-2430-47bb-b4c2-cc4fe50e035d`,
`67b4fabc-24af-49cd-b2b2-d91cd1bff72d`, and
`6d2d2555-e6a6-4f84-ac55-721614ba72d4`. Namespaces `saw-identity-a`,
`saw-identity-c`, and `saw-identity-e` were gone at 2026-10-05T10:36:25Z.
SPIRE then had no `/saw/saw-identity-*` entries. `identity-d` had lived in
`saw-identity-c`.

What remains is not an identity canary. `alice` is UID
`4d9604bb-4ebc-438a-a4e2-85175a744328`, Running, with no SPIFFE label.
`spire-server-0` is UID `c25daa63-085b-4216-a328-633658ea1e83`, Running.
Helm `saw-spire` is revision 15. Helm `identity-demo` is revision 7 in
`saw-identity-demo`; it is the issuer for the recorded grants, not a SAW.
The allowlist is commit `14b645d` on `codex/agent-identity`. Argo had
already synced `113781e`, which is the chart revision the deleted `idpat`
Applications deployed, before those objects were deleted.
