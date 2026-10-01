# Self-service workspaces: user guide and manual test

Step by step: get the portal ready, open Red Hat Developer Hub (RHDH),
request a workspace, open its sandbox, and check each step on the way. How
the parts fit together is in [rhdh-architecture.md](rhdh-architecture.md).

Commands run from the repository root, logged in with `oc` as a cluster
admin. `<domain>` is the cluster's apps domain
(`oc get ingresses.config cluster -o jsonpath='{.spec.domain}'`). The example
user is `carol`.

## 1. Before you start (admin, once)

### 1.1 The pattern runs the portal

The portal is part of `values-prod.yaml`: the RHDH and OpenShift Pipelines
operators, the namespaces `rhdh` and `saw-portal`, the Argo CD application
`openshell-rhdh` and the imperative job `saw-portal-vault`.

```bash
oc get applications.argoproj.io -n vp-gitops openshell-rhdh openshell-keycloak
```

Expected: both `Synced` and `Healthy`. If `openshell-rhdh` is `Missing` with
"one or more synchronization tasks are not valid", look at the reason:

```bash
oc get application openshell-rhdh -n vp-gitops -o json \
  | jq -r '.status.operationState.syncResult.resources[] | select(.status != "Synced") | "\(.kind)/\(.name): \(.message)"'
```

A missing kind usually means an operator is still installing
(`oc get csv -A | grep -iE "rhdh|pipelines"` shows `Succeeded` when done).

### 1.2 Secrets in Vault

Two entries of `values-secret.yaml.template` are generated when missing:
`keycloak-users` (the test users' passwords) and `rhdh-oidc` (RHDH's
Keycloak client secret and session secret). Add them to your
`values-secret` file and load it:

```bash
./pattern.sh make load-secrets
oc get externalsecret -n saw-keycloak openshell-keycloak-user-passwords
oc get externalsecret -n rhdh rhdh-oidc
```

Expected: both `SecretSynced`, `READY True`.

### 1.3 The portal may write keys to Vault

The imperative job `saw-portal-vault` creates the Vault policy and role
`saw-portal-writer`. Without the imperative framework, run once:

```bash
make -f Makefile-quickstart portal-vault-setup
```

Check:

```bash
TOKEN=$(oc get secret vaultkeys -n imperative -o jsonpath='{.data.vault_data_json}' | base64 -d | jq -r .root_token)
oc exec -n vault vault-0 -- env VAULT_TOKEN=$TOKEN VAULT_SKIP_VERIFY=true \
  vault read auth/hub/role/saw-portal-writer
```

Expected: `bound_service_account_names [saw-portal-provisioner]`,
`bound_service_account_namespaces [saw-portal]`.

### 1.4 Keycloak: strong passwords, no self-registration

A new realm gets this from the chart. A realm imported before (an existing
cluster) needs it applied once:

```bash
make -f Makefile-quickstart keycloak-harden
```

It sets the password policy and brute-force lockout, turns registration
off, and gives the test users (developer, admin, alice, bob) their generated
passwords. Check that the old default no longer works:

```bash
KC=https://$(scripts/keycloak-host.sh saw-keycloak)
curl -sk -d grant_type=password -d client_id=openshell-cli -d username=alice -d password=alice \
  $KC/realms/openshell/protocol/openid-connect/token | jq -r .error
```

Expected: `invalid_grant`.

### 1.5 Add the portal's users

Users do not register themselves. Put the people who will request a
workspace in a list. Do **not** use `overrides/saw-users.yaml` for them: a
user in that file already has a workspace from Git, and the portal refuses
to create a second one.

```bash
cat > /tmp/portal-users.yaml <<'EOF'
users:
  - name: carol
    email: carol@example.com        # optional; also firstName, lastName
    roles: [openshell-user]         # default
EOF
make -f Makefile-quickstart keycloak-add-users USERS_FILE=/tmp/portal-users.yaml
```

The new password is printed once and kept in Secret
`openshell-keycloak-users`. Later:

```bash
make -f Makefile-quickstart keycloak-password KC_USER=carol         # show it
make -f Makefile-quickstart keycloak-reset-password KC_USER=carol   # new one
```

User names must be lowercase DNS labels of at most 19 characters. Running
`keycloak-add-users` again is safe: existing users are skipped.

## 2. Open RHDH

```bash
oc get route -n rhdh
```

Open `https://backstage-developer-hub-rhdh.apps.<domain>` (the route's
host). On the sign-in page choose the OIDC sign-in, sign in to Keycloak as
`carol` with her password, and RHDH opens on its home page.

Checks:

- The Backstage resource is ready:
  `oc get backstage -n rhdh developer-hub` and
  `oc get pods -n rhdh` (the `backstage-developer-hub-*` pod `Running`).
- The Keycloak client exists: the PostSync job
  `oc get job -n rhdh` completed. If Keycloak says "Invalid parameter:
  redirect_uri", the job did not run; sync `openshell-rhdh` again.
- A user who is not in the realm cannot sign in, and the Keycloak page has
  no "Register" link.

## 3. The catalog (already configured)

There is nothing to register. The chart configures three catalog locations:
the two templates (mounted into RHDH) and the generator's list of
workspaces. RHDH reads them every 30 seconds.

Check in RHDH:

1. **Create** (left menu): the templates "Create an agent workspace" and
   "Delete my agent workspace".
2. **Catalog**, Kind **Resource**: one entry `saw-<user>` per portal
   workspace (empty until the first request).

If the templates are missing, look at the RHDH logs:

```bash
oc logs -n rhdh deploy/backstage-developer-hub -c backstage-backend --tail=100 | grep -iE "catalog|location|error"
```

If the workspaces are missing, check the generator:

```bash
oc logs -n saw-portal deploy/saw-workspaces-generator --tail=20
```

## 4. Request a workspace

1. In RHDH: **Create** → **Create an agent workspace** → **Choose**.
2. **Profile**: pick one, e.g. `data-science`. The form now asks only for
   that profile's keys:
   - `inference: API key`: the NVIDIA API key (build.nvidia.com);
   - `web-search: API key`: the Brave Search API key.

   "Sandbox web UIs" lists the sandboxes that get their own route
   (`notebook (default)`).
3. **Review** → **Create**.

The run page shows two steps, "Submit the request" and "Create the
workspace", then "Workspace requested" with the pipeline run's name.

### Check what happened

```bash
# The pipeline run (Succeeded); its log names the user and what it wrote
oc get pipelinerun -n saw-portal --sort-by=.metadata.creationTimestamp | tail -3
oc logs -n saw-portal -l tekton.dev/pipelineRun=<run name> --all-containers

# The request Secret is gone; the registry entry is there
oc get secret -n saw-portal | grep saw-req- || echo "no pending requests"
oc get configmap -n saw-portal saw-ws-carol -o jsonpath='{.data.user\.json}' | jq .

# The keys are in Vault (names only)
oc exec -n vault vault-0 -- env VAULT_TOKEN=$TOKEN VAULT_SKIP_VERIFY=true \
  vault kv list secret/hub/saw-carol

# Argo CD builds the workspace
oc get applications.argoproj.io -n vp-gitops | grep -E "portal-ws-carol|saw-carol"
oc get ns saw-carol --show-labels
oc get vm,externalsecret,route -n saw-carol
```

Expected: Application `portal-ws-carol`, then `saw-carol-secrets`,
`saw-carol-bom` and `saw-carol`, all `Synced`/`Healthy`; namespace
`saw-carol` with label `saw.redhat.com/portal=true`; ExternalSecrets
`SecretSynced`; VM `carol` `Running`; routes `carol-gateway`, `carol-webui`
and `carol-default-notebook-ui`.

Follow the VM's installer until `apply: Done` (about 10 minutes):

```bash
make -f Makefile-quickstart openshell-saw-logs OPENSHELL_SAW_NAME=carol
```

In RHDH, **Catalog** → Kind **Resource** now lists `saw-carol` ("Agent
workspace: carol"), owned by carol, with links:

- **OpenShell web UI**
- **notebook UI (default)**
- **Delete workspace**

## 5. Open the sandbox

The installer creates the profile's sandboxes; there is nothing to start.

### In the browser

1. Open `saw-carol` in the RHDH catalog and click **notebook UI (default)**
   (`https://carol-default-notebook-ui.apps.<domain>`).
2. Sign in to Keycloak as carol (once per browser session).
3. The OpenClaw control UI opens and connects without asking for a gateway
   token. Send a message to check the model answers.

Check that only the owner gets in: in a private window, open the same URL
and sign in as another user (e.g. bob). Expected: 403 from the proxy, before
OpenClaw.

### From the command line (admin)

```bash
export OPENSHELL_SAW_NAME=carol
make -f Makefile-quickstart openshell-saw-configure-gateway
openshell gateway login carol          # sign in as carol in the browser
openshell sandbox list
make -f Makefile-quickstart openclaw-tui SANDBOX_NAME=notebook
```

The TUI talks to the same OpenClaw gateway with the gateway password; it
must keep working with the UI's trusted-proxy mode.

### If the UI does not connect

| What you see | Why | What to do |
|---|---|---|
| 403 after signing in | the user is not the owner or in `sandboxUiProxy.allowedUsers` | sign in as the owner |
| "Proxy authentication required", raw error `unauthorized` | OpenClaw did not accept the user from the proxy | read the reason in the sandbox log (below) |
| "Proxy authentication required", `proxy_attribution_required` | the request did not arrive from a trusted address | check `gateway.trustedProxies` (loopback) |
| 502 / 503 | OpenClaw is not running in the sandbox, or the VM is still installing | wait for `apply: Done`; check the gateway log |

```bash
make -f Makefile-quickstart openshell-saw-vm-ssh OPENSHELL_SAW_NAME=carol \
  CMD='openshell sandbox exec -n notebook --no-tty -- sh -c "tail -20 /tmp/openclaw-gateway.log; grep -h trusted_proxy /tmp/openclaw/openclaw-*.log | tail -5"'
```

`authReason=trusted_proxy_user_not_allowed` means OpenClaw received a user it
does not allow; `device-required` from a CLI means it has no gateway
password.

## 6. Refusals to try

Each of these must be refused, in the pipeline run's log or by the API
server:

| Try | Expected |
|---|---|
| Request a workspace as alice (declared in `overrides/saw-users.yaml`) | `namespace saw-alice exists and is not managed by the portal` |
| `oc create secret generic x -n saw-portal --from-literal=a=b --as=system:serviceaccount:rhdh:rhdh-portal` (RHDH's account, a name that is not `saw-req-*`) | denied by admission policy `saw-portal-requests` |
| Run the delete template for a user who has no portal workspace | `<user> has no portal workspace` |

## 7. Delete the workspace

1. In RHDH open `saw-carol` → **Delete workspace** (or **Create** → "Delete
   my agent workspace"), confirm, **Create**.
2. Check:

```bash
oc get configmap -n saw-portal saw-ws-carol            # NotFound
oc get applications.argoproj.io -n vp-gitops | grep -E "portal-ws-carol|saw-carol"   # gone
oc get ns saw-carol                                    # Terminating, then NotFound
oc exec -n vault vault-0 -- env VAULT_TOKEN=$TOKEN VAULT_SKIP_VERIFY=true \
  vault kv list secret/hub/saw-carol                   # no entries
```

The catalog entry disappears at the next refresh.

## Checklist

| # | Check | Expected |
|---|---|---|
| 1 | `openshell-rhdh`, `openshell-keycloak` | Synced, Healthy |
| 2 | ExternalSecrets `openshell-keycloak-user-passwords`, `rhdh-oidc` | SecretSynced |
| 3 | Vault role `saw-portal-writer` | bound to `saw-portal-provisioner` |
| 4 | alice/alice | refused |
| 5 | Keycloak sign-in page | no Register link |
| 6 | RHDH sign-in as carol | home page |
| 7 | Create menu | both templates |
| 8 | Workspace request | pipeline run Succeeded, registry entry, keys in Vault |
| 9 | Argo CD | `portal-ws-carol` and the three `saw-carol*` apps healthy |
| 10 | VM installer | `apply: Done` |
| 11 | Catalog | `saw-carol` with UI links |
| 12 | notebook UI as carol | OpenClaw connects, no token |
| 13 | notebook UI as bob | 403 |
| 14 | `openclaw-tui` | connects |
| 15 | Request as alice | refused |
| 16 | Delete | namespace, apps, registry entry and keys gone |
