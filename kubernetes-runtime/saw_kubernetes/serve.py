"""Run one retained controller for an administrator-defined workspace."""
import json
import os
from pathlib import Path
import signal
import urllib.error

from .adapters import KubernetesResourceVerifier
from .admin_session import GatewaySessions, TrustBundle
from .boundary import verify
from .compiler import compile_profile_files, ContractError, RUNTIME_CLASS
from .controller import ConfigMapClient, Controller, Scope, NAME
from .reconcile import Reconciler


def main():
    os.umask(0o077)
    config = json.loads(Path("/config/controller.json").read_text())
    scope = Scope(config["namespace"], config["profile"], config["intent"], config["status"], config["ownerID"])
    service_account = Path("/var/run/secrets/kubernetes.io/serviceaccount")
    api = ConfigMapClient("https://kubernetes.default.svc", scope, service_account / "ca.crt", service_account / "token")
    def get(path):
        with api._open("GET", path) as response:
            return api._json(response)

    def get_optional(path):
        try:
            return get(path)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None
            raise

    def read(kind, name, namespace=None):
        if kind == "runtimeclass":
            if not RUNTIME_CLASS.fullmatch(name) or name != config.get("workloadRuntimeClass"):
                raise ContractError("resource outside controller scope")
            return get(f"/apis/node.k8s.io/v1/runtimeclasses/{name}")
        if not NAME.fullmatch(name):
            raise ContractError("invalid resource name")
        if kind == "namespace" and name == scope.namespace:
            return get("/api/v1/namespaces/" + name)
        if kind == "persistentvolumeclaim" and namespace == scope.namespace:
            return get(f"/api/v1/namespaces/{namespace}/persistentvolumeclaims/{name}")
        if kind in {"pod", "sandbox"} and namespace == scope.namespace and name in config.get("sandboxNames", []):
            if kind == "pod":
                return get_optional(f"/api/v1/namespaces/{namespace}/pods/{name}")
            return get_optional(f"/apis/agents.x-k8s.io/v1beta1/namespaces/{namespace}/sandboxes/{name}")
        raise ContractError("resource outside controller scope")

    def boundary(plan):
        verify(config, plan, get)
    resources = KubernetesResourceVerifier(read, boundary)
    endpoint = f"https://{config['gateway']}-gateway.{scope.namespace}.svc:17670"
    trust = TrustBundle(api.request, scope.namespace, config["trustedNamespace"], config["gateway"],
                        scope.owner_id, Path("/identity/ca.crt").read_bytes(),
                        os.environ["POD_NAME"], os.environ["POD_UID"])
    sessions = GatewaySessions(trust, endpoint)
    state = Path("/state")
    def reconcile(plan, **kwargs):
        with sessions.open() as gateway:
            return Reconciler(gateway, state / "core", resources.verify_attachments,
                              verify_shutdown=resources.verify_shutdown,
                              verify_workload=resources.verify_workload).reconcile(plan, **kwargs)
    frontend = Controller(api, scope, state, compile_profile_files, reconcile, boundary)
    stopped = False
    def stop(signum, frame):
        nonlocal stopped
        stopped = True
    signal.signal(signal.SIGTERM, stop)
    frontend.run(stop=lambda: stopped)


if __name__ == "__main__":
    main()
