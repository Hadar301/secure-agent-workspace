"""Render the self-service portal chart (charts/openshell-rhdh)."""
import json
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
CHART = ROOT / "charts" / "openshell-rhdh"
HELM = shutil.which("helm")

pytestmark = pytest.mark.skipif(not HELM, reason="helm is not installed")


def render(*args):
    result = subprocess.run([HELM, "template", "openshell-rhdh", str(CHART), "-n", "rhdh", *args],
                            capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    return [d for d in yaml.safe_load_all(result.stdout) if d]


def one(docs, kind, name):
    found = [d for d in docs if d["kind"] == kind and d["metadata"]["name"] == name]
    assert len(found) == 1, f"{kind}/{name}: {len(found)}"
    return found[0]


@pytest.fixture(scope="module")
def docs():
    return render()


def test_templates_are_the_generated_form_with_the_provisioner(docs):
    cm = one(docs, "ConfigMap", "saw-rhdh-templates")
    create = yaml.safe_load(cm["data"]["create-workspace.yaml"])
    delete = yaml.safe_load(cm["data"]["delete-workspace.yaml"])
    for template in (create, delete):
        run = next(s for s in template["spec"]["steps"] if s["id"] == "run")
        spec = run["input"]["body"]["spec"]
        assert spec["taskRunTemplate"]["serviceAccountName"] == "saw-portal-provisioner"
        assert [p["name"] for p in spec["params"]] == ["request"]
        request = next(s for s in template["spec"]["steps"] if s["id"] == "request")
        assert request["input"]["body"]["stringData"]["token"] == "${{ secrets.backstageToken }}"
    assert "__PROVISIONER_SA__" not in cm["data"]["create-workspace.yaml"]


def test_every_form_field_reaches_the_request(docs):
    """The form asks for what the catalog says each profile needs, and the
    request Secret carries each field under <secret>.<field>."""
    catalog = json.loads((CHART / "files" / "profile-catalog.json").read_text())["profiles"]
    create = yaml.safe_load(one(docs, "ConfigMap", "saw-rhdh-templates")["data"]["create-workspace.yaml"])
    string_data = create["spec"]["steps"][0]["input"]["body"]["stringData"]
    one_of = create["spec"]["parameters"][0]["dependencies"]["profile"]["oneOf"]
    assert sorted(o["properties"]["profile"]["const"] for o in one_of) == sorted(catalog)
    for profile, spec in catalog.items():
        for secret, s in spec["secrets"].items():
            for field in s["fields"]:
                assert f"{secret}.{field['key']}" in string_data
                if field["kind"] == "secret":
                    assert string_data[f"{secret}.{field['key']}"].startswith("${{ secrets.")


def test_proxy_endpoints_only_post_to_the_portal_namespace(docs):
    config = yaml.safe_load(one(docs, "ConfigMap", "saw-rhdh-app-config")["data"]["app-config-saw.yaml"])
    endpoints = dict(config["proxy"]["endpoints"])
    status = endpoints.pop("/saw-status")
    assert status["target"] == "http://saw-workspaces-generator.saw-portal.svc:4355/status"
    assert status["allowedMethods"] == ["GET"] and status["allowedHeaders"] == ["X-Saw-Token"]
    assert status["credentials"] == "require" and "headers" not in status
    assert set(endpoints) == {"/saw-requests", "/saw-pipelineruns"}
    for ep in endpoints.values():
        assert ep["allowedMethods"] == ["POST"]
        assert "/namespaces/saw-portal/" in ep["target"]
        assert ep["credentials"] == "require"
    assert config["auth"]["providers"]["oidc"]["production"]["metadataUrl"] == \
        "https://openshell-keycloak-ingress-saw-keycloak.apps.example.com/realms/openshell/.well-known/openid-configuration"
    urls = [loc["target"] for loc in config["catalog"]["locations"]]
    assert "http://saw-workspaces-generator.saw-portal.svc:4355/catalog.yaml" in urls


def test_rhdh_can_only_create_requests_and_runs(docs):
    role = one(docs, "Role", "rhdh-portal")
    assert role["metadata"]["namespace"] == "saw-portal"
    assert role["rules"] == [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["create"]},
                             {"apiGroups": ["tekton.dev"], "resources": ["pipelineruns"], "verbs": ["create"]}]


def test_admission_pins_the_pipeline_runs(docs):
    policy = one(docs, "ValidatingAdmissionPolicy", "saw-portal-pipelineruns")
    exprs = " ".join(v["expression"] for v in policy["spec"]["validations"])
    for needle in ("saw-workspace-create", "saw-workspace-delete", "saw-portal-provisioner",
                   "matches('^saw-req-[a-z0-9]{1,20}$')", "!has(object.spec.pipelineSpec)"):
        assert needle in exprs
    assert policy["spec"]["matchConditions"][0]["expression"] == \
        "request.userInfo.username == 'system:serviceaccount:rhdh:rhdh-portal'"


def test_the_applicationset_renders_saw_users_per_workspace(docs):
    aset = one(docs, "ApplicationSet", "saw-portal-workspaces")
    assert aset["metadata"]["namespace"] == "vp-gitops"
    template = aset["spec"]["template"]
    # Not saw-*: saw-users names a user's apps saw-<u>, saw-<u>-bom, saw-<u>-secrets.
    assert template["metadata"]["name"] == "portal-ws-{{ .name }}"
    assert aset["spec"]["syncPolicy"] == {"applicationsSync": "create-update",
                                          "preserveResourcesOnDeletion": True}
    assert template["spec"]["source"]["path"] == "charts/saw-users"
    assert template["spec"]["source"]["helm"]["values"] == "{{ .values }}"
    plugin = one(docs, "ConfigMap", "saw-portal-generator")
    token = one(docs, "Secret", "saw-portal-generator")
    assert plugin["data"]["token"] == "$saw-portal-generator:token"
    assert token["metadata"]["labels"]["app.kubernetes.io/part-of"] == "argocd"
    generator_token = one(docs, "Secret", "saw-workspaces-generator")
    assert generator_token["stringData"]["token"] == token["stringData"]["token"]


def test_the_generator_gets_valid_saw_users_defaults(docs):
    deploy = one(docs, "Deployment", "saw-workspaces-generator")
    env = {e["name"]: e.get("value") for e in deploy["spec"]["template"]["spec"]["containers"][0]["env"]}
    values = json.loads(env["SAW_USERS_VALUES"])
    assert values["namespaceLabels"] == {"saw.redhat.com/portal": "true"}
    assert values["global"]["vpArgoNamespace"] == "vp-gitops"


def test_the_pipeline_task_runs_portal_py(docs):
    task = one(docs, "Task", "saw-workspace")
    step = task["spec"]["steps"][0]
    assert step["command"] == ["python3", "/opt/saw/portal.py", "$(params.action)", "$(params.arg)",
                               "$(params.timeout)"]
    assert [r["name"] for r in task["spec"]["results"]] == ["user"]
    env = {e["name"]: e["value"] for e in step["env"]}
    # Review (#57): no switch to trust the form's owner instead of the token.
    assert "VERIFY_TOKEN" not in env
    values = yaml.safe_load((CHART / "values.yaml").read_text())
    assert "verifyToken" not in values["portal"]
    assert env["RHDH_INTERNAL_URL"] == "http://backstage-developer-hub.rhdh.svc:80"
    assert env["ARGO_NAMESPACE"] == "vp-gitops"
    assert env["RESULT_PATH"] == "$(results.user.path)"
    assert env["PIPELINE_RUN"] == "$(context.pipelineRun.name)"
    scripts = one(docs, "ConfigMap", "saw-portal-scripts")
    assert scripts["data"]["portal.py"] == (CHART / "files" / "portal.py").read_text()


def test_rbac_is_optional(docs):
    assert not [d for d in docs if d["kind"] == "ConfigMap" and d["metadata"]["name"] == "saw-rhdh-rbac"]
    with_rbac = render("--set", "rhdh.rbac.enabled=true")
    config = yaml.safe_load(one(with_rbac, "ConfigMap", "saw-rhdh-app-config")["data"]["app-config-saw.yaml"])
    assert config["permission"]["enabled"] is True


def test_the_provisioner_may_delete_only_portal_applications(docs):
    policy = one(docs, "ValidatingAdmissionPolicy", "saw-portal-application-deletes")
    expr = policy["spec"]["validations"][0]["expression"]
    assert "oldObject.metadata.labels['saw.redhat.com/portal'] == 'true'" in expr
    assert "startsWith('portal-ws-')" in expr
    role = [d for d in docs if d["kind"] == "Role" and d["metadata"]["name"] == "saw-portal-provisioner"
            and d["metadata"]["namespace"] == "vp-gitops"]
    assert role and role[0]["rules"] == [{"apiGroups": ["argoproj.io"], "resources": ["applications"],
                                          "verbs": ["get", "delete"]}]


def test_stale_requests_are_cleaned_up(docs):
    cron = one(docs, "CronJob", "saw-portal-cleanup")
    container = cron["spec"]["jobTemplate"]["spec"]["template"]["spec"]["containers"][0]
    assert container["command"] == ["python3", "/opt/saw/portal.py", "cleanup"]
    assert cron["spec"]["jobTemplate"]["spec"]["template"]["spec"]["serviceAccountName"] == "saw-portal-cleanup"
    role = [d for d in docs if d["kind"] == "Role" and d["metadata"]["name"] == "saw-portal-cleanup"][0]
    assert role["rules"] == [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["list", "delete"]}]


def test_the_backstage_version_is_the_newest_the_cluster_serves():
    """RHDH operator 1.10 serves v1alpha4 and v1alpha5 only (found live:
    v1alpha3 was refused). Argo CD passes the cluster's API versions."""
    def version(*args):
        return one(render(*args), "Backstage", "developer-hub")["apiVersion"]
    assert version() == "rhdh.redhat.com/v1alpha5"
    assert version("--api-versions", "rhdh.redhat.com/v1alpha4/Backstage",
                   "--api-versions", "rhdh.redhat.com/v1alpha5/Backstage") == "rhdh.redhat.com/v1alpha5"
    assert version("--api-versions", "rhdh.redhat.com/v1alpha3/Backstage",
                   "--api-versions", "rhdh.redhat.com/v1alpha4/Backstage") == "rhdh.redhat.com/v1alpha4"
    assert version("--set", "rhdh.apiVersion=rhdh.redhat.com/v1alpha3") == "rhdh.redhat.com/v1alpha3"


def test_only_rhdh_and_argo_cd_reach_the_generator(docs):
    """Review (#57): /catalog.yaml has no token, so the pod takes traffic
    only from RHDH's and Argo CD's namespaces."""
    policy = one(docs, "NetworkPolicy", "saw-workspaces-generator")
    assert policy["metadata"]["namespace"] == "saw-portal"
    assert policy["spec"]["podSelector"] == {"matchLabels": {"app.kubernetes.io/name": "saw-workspaces-generator"}}
    sources = [f["namespaceSelector"]["matchLabels"]["kubernetes.io/metadata.name"]
               for f in policy["spec"]["ingress"][0]["from"]]
    assert sources == ["rhdh", "vp-gitops"]
    assert policy["spec"]["ingress"][0]["ports"] == [{"protocol": "TCP", "port": 4355}]
    off = render("--set", "portal.generator.networkPolicy=false")
    assert not [d for d in off if d["kind"] == "NetworkPolicy"]


@pytest.mark.parametrize("name", ["saw-portal-pipelineruns", "saw-portal-requests"])
def test_admission_checks_updates_too(docs, name):
    """Review (#57): a later Role change must not let RHDH's account edit a
    request or a run into another shape."""
    policy = one(docs, "ValidatingAdmissionPolicy", name)
    assert policy["spec"]["matchConstraints"]["resourceRules"][0]["operations"] == ["CREATE", "UPDATE"]


CREATE_TASKS = ["register", "argo-cd-apps", "vm", "vm-running", "sandboxes"]
DELETE_TASKS = ["unregister", "argo-cd-removes", "finish"]


def test_each_stage_is_a_pipeline_task(docs):
    """The Tekton tab draws these: the first task acts, the others wait for
    Argo CD (which still builds and removes the workspace), in order."""
    for action, tasks, acts in (("create", CREATE_TASKS, ["create", "wait-apps", "wait-vm", "wait-running",
                                                           "wait-ready"]),
                                ("delete", DELETE_TASKS, ["delete", "wait-gone", "finish-delete"])):
        spec = one(docs, "Pipeline", f"saw-workspace-{action}")["spec"]
        assert [t["name"] for t in spec["tasks"]] == tasks
        assert [t.get("runAfter") for t in spec["tasks"]] == [None] + [[t] for t in tasks[:-1]]
        params = [{p["name"]: p["value"] for p in t["params"]} for t in spec["tasks"]]
        assert [p["action"] for p in params] == acts
        assert params[0]["arg"] == "$(params.request)"
        assert {p["arg"] for p in params[1:]} == {f"$(tasks.{tasks[0]}.results.user)"}


def test_the_templates_follow_the_pipeline_tasks(docs):
    cm = one(docs, "ConfigMap", "saw-rhdh-templates")
    create = yaml.safe_load(cm["data"]["create-workspace.yaml"])
    delete = yaml.safe_load(cm["data"]["delete-workspace.yaml"])
    tail = ["pipeline", "pipeline-log", "pipeline-check"]
    assert [s["id"] for s in delete["spec"]["steps"]] == \
        ["request", "run", *[f"task-{t}" for t in DELETE_TASKS], *tail]
    assert [s["id"] for s in create["spec"]["steps"]] == \
        ["request", "run", *[f"task-{t}" for t in CREATE_TASKS], *tail, "status", "status-log"]
    assert delete["spec"]["presentation"]["buttonLabels"]["createButtonText"] == "Delete workspace"
    picker = delete["spec"]["parameters"][0]["properties"]["workspace"]
    assert picker["ui:field"] == "OwnedEntityPicker"
    assert picker["ui:options"]["catalogFilter"] == {"kind": "Component", "spec.type": "agent-workspace"}
    assert delete["spec"]["steps"][0]["input"]["body"]["stringData"]["workspace"] == "${{ parameters.workspace }}"
    for template, action in ((create, "create"), (delete, "delete")):
        run = template["spec"]["steps"][1]["input"]["body"]
        # On the workspace's Tekton tab; the first task refuses another user's label.
        assert run["metadata"]["labels"]["backstage.io/kubernetes-id"] == \
            "saw-${{ user.ref | parseEntityRef | pick('name') }}"
        assert run["spec"]["pipelineRef"]["name"] == f"saw-workspace-{action}"
        for step in template["spec"]["steps"][2:]:
            if step["action"] == "debug:log":
                continue
            assert step["input"]["path"].startswith("/proxy/saw-status/")
            assert step["input"]["headers"] == {"X-Saw-Token": "${{ secrets.backstageToken }}"}
            # A waiting step carries on so the log and the check run.
            assert step["input"].get("continueOnBadResponse", False) == ("each" in step)
    steps = {s["id"]: s for s in create["spec"]["steps"]}
    assert steps["task-sandboxes"]["input"]["path"].endswith("?task=sandboxes&wait=50")
    assert steps["pipeline-check"]["input"]["path"].endswith("?assert=1")
    assert len(steps["task-sandboxes"]["each"]) * 50 >= 30 * 60
    assert create["spec"]["output"]["text"][0]["content"] == "${{ steps.status.output.body.text }}"


def test_the_tekton_tab_reads_only_the_portal_namespace(docs):
    config = yaml.safe_load(one(docs, "ConfigMap", "saw-rhdh-app-config")["data"]["app-config-saw.yaml"])
    k8s = config["kubernetes"]
    assert k8s["objectTypes"] == ["pods"]
    assert {c["plural"] for c in k8s["customResources"]} == {"pipelineruns", "taskruns"}
    assert k8s["clusterLocatorMethods"][0]["clusters"][0]["serviceAccountToken"] == \
        {"$file": "/opt/app-root/src/saw/token"}
    role = one(docs, "Role", "rhdh-kubernetes-reader")
    assert role["metadata"]["namespace"] == "saw-portal"
    assert {v for r in role["rules"] for v in r["verbs"]} == {"get", "list", "watch"}
    assert not [d for d in docs if d["kind"] == "ClusterRoleBinding"
                and any(s["name"] == "rhdh-kubernetes-reader" for s in d["subjects"])]
    plugins = yaml.safe_load(one(docs, "ConfigMap", "saw-rhdh-dynamic-plugins")["data"]["dynamic-plugins.yaml"])
    assert any("tekton" in p["package"] for p in plugins["plugins"])
    files = one(docs, "Backstage", "developer-hub")["spec"]["application"]["extraFiles"]
    assert files["secrets"] == [{"name": "rhdh-kubernetes-reader-token", "key": "token"}]
    off = render("--set", "rhdh.tekton.enabled=false")
    assert "kubernetes" not in yaml.safe_load(
        one(off, "ConfigMap", "saw-rhdh-app-config")["data"]["app-config-saw.yaml"])


def test_the_generator_may_only_read_progress(docs):
    roles = [d for d in docs if d["kind"] == "Role" and d["metadata"]["name"] == "saw-workspaces-generator"]
    verbs = {(r["metadata"]["namespace"], g, res, v) for r in roles for rule in r["rules"]
             for g in rule["apiGroups"] for res in rule["resources"] for v in rule["verbs"]}
    vm = one(docs, "ClusterRole", "saw-workspaces-generator-vm-reader")["rules"]
    assert vm == [{"apiGroups": ["kubevirt.io"], "resources": ["virtualmachines"], "verbs": ["get"]}]
    assert verbs == {("saw-portal", "", "configmaps", "get"), ("saw-portal", "", "configmaps", "list"),
                     ("saw-portal", "tekton.dev", "pipelineruns", "get"), ("saw-portal", "", "pods", "list"),
                     ("saw-portal", "", "pods/log", "get"), ("vp-gitops", "argoproj.io", "applications", "get")}
    env = {e["name"]: e["value"] for e in one(docs, "Deployment", "saw-workspaces-generator")
           ["spec"]["template"]["spec"]["containers"][0]["env"]}
    assert env["ARGO_NAMESPACE"] == "vp-gitops" and env["RHDH_INTERNAL_URL"].startswith("http")


def test_the_sidebar_hides_what_the_portal_does_not_use(docs):
    config = yaml.safe_load(one(docs, "ConfigMap", "saw-rhdh-app-config")["data"]["app-config-saw.yaml"])
    items = config["dynamicPlugins"]["frontend"]["default.main-menu-items"]["menuItems"]
    assert items == {name: {"enabled": False} for name in ("default.apis", "default.learning-path")}
    shown = yaml.safe_load(one(render("--set", "rhdh.hiddenMenuItems=null"), "ConfigMap", "saw-rhdh-app-config")
                           ["data"]["app-config-saw.yaml"])
    assert "dynamicPlugins" not in shown


def test_the_home_page_has_actions_and_workspaces_only(docs):
    plugins = yaml.safe_load(one(docs, "ConfigMap", "saw-rhdh-dynamic-plugins")["data"]["dynamic-plugins.yaml"])
    (home,) = [p for p in plugins["plugins"] if "dynamic-home-page" in p["package"]]
    conf = home["pluginConfig"]["dynamicPlugins"]["frontend"]["red-hat-developer-hub.backstage-plugin-dynamic-home-page"]
    # The override replaces the default config: the route must be kept.
    assert conf["dynamicRoutes"] == [{"path": "/", "importName": "DynamicHomePage"}]
    cards = [m["importName"] for m in conf["mountPoints"] if m["mountPoint"] == "home.page/cards"]
    assert cards == ["TemplateSection", "EntitySection"]           # no OnboardingSection
    titles = json.loads(one(docs, "ConfigMap", "saw-rhdh-templates")["data"]["translations.json"])
    assert titles["plugin.homepage"]["en"]["templates.title"] == "Actions"
    assert titles["plugin.homepage"]["en"]["entities.title"] == "Workspaces"
    config = yaml.safe_load(one(docs, "ConfigMap", "saw-rhdh-app-config")["data"]["app-config-saw.yaml"])
    assert config["i18n"]["overrides"] == ["/opt/app-root/src/saw/translations.json"]
    default = render("--set", "rhdh.homePage.enabled=false")
    plugins = yaml.safe_load(one(default, "ConfigMap", "saw-rhdh-dynamic-plugins")["data"]["dynamic-plugins.yaml"])
    assert not [p for p in plugins["plugins"] if "dynamic-home-page" in p["package"]]
    assert "translations.json" not in one(default, "ConfigMap", "saw-rhdh-templates")["data"]


def test_the_portal_is_branded_and_unused_plugins_are_off(docs):
    import base64
    config = yaml.safe_load(one(docs, "ConfigMap", "saw-rhdh-app-config")["data"]["app-config-saw.yaml"])
    assert config["app"]["title"] == "Secure Agent Workspace Self Service"
    assert config["catalog"]["orphanStrategy"] == "delete"
    for mode in ("light", "dark"):
        uri = config["app"]["branding"]["fullLogo"][mode]
        assert uri.startswith("data:image/svg+xml;base64,")
        assert b"Secure Agent Workspace" in base64.b64decode(uri.split(",", 1)[1])
    plugins = yaml.safe_load(one(docs, "ConfigMap", "saw-rhdh-dynamic-plugins")["data"]["dynamic-plugins.yaml"])
    off = {p["package"] for p in plugins["plugins"] if p["disabled"]}
    assert "./dynamic-plugins/dist/backstage-plugin-techdocs" in off
    assert "./dynamic-plugins/dist/red-hat-developer-hub-backstage-plugin-quickstart" in off
