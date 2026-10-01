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
    endpoints = config["proxy"]["endpoints"]
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
    assert step["command"] == ["python3", "/opt/saw/portal.py", "$(params.action)", "$(params.request)"]
    env = {e["name"]: e["value"] for e in step["env"]}
    assert env["VERIFY_TOKEN"] == "true"
    assert env["RHDH_INTERNAL_URL"] == "http://backstage-developer-hub.rhdh.svc:80"
    assert env["ARGO_NAMESPACE"] == "vp-gitops"
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
