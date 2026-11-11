"""Opt-in live adapters. Importing this module makes no connection or mutation."""

from __future__ import annotations

import json
from pathlib import Path
import re
import subprocess
from urllib.parse import urlsplit

from .compiler import ContractError, OWNER
from .reconcile import RpcError

RPC_METHODS = {
    "GetGatewayInfo", "GetWorkspace", "CreateWorkspace", "ListWorkspaceMembers",
    "AddWorkspaceMember", "GetProviderProfile", "GetProvider", "CreateProvider", "GetSandbox",
    "CreateSandbox", "StartSandbox", "StopSandbox",
}


class GrpcGateway:
    """Use generated Python stubs from the pinned OpenShell source, over mTLS.

    No shell commands, insecure transport, server-name overrides or automatic
    mutation retry. The caller owns lifecycle and credential rotation.
    """

    def __init__(self, endpoint, ca_file, certificate_file, key_file, *, timeout=20):
        if not isinstance(endpoint, str) or any(c.isspace() for c in endpoint):
            raise ContractError("gateway endpoint must be an HTTPS authority")
        try:
            parsed = urlsplit(endpoint)
            port = parsed.port
        except ValueError:
            raise ContractError("gateway endpoint must have a valid host and port") from None
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
                or parsed.path not in {"", "/"} or parsed.query or parsed.fragment or port == 0):
            raise ContractError("gateway endpoint must be an HTTPS authority without credentials or path")
        if not isinstance(timeout, (float, int)) or isinstance(timeout, bool) or not 0 < timeout <= 60:
            raise ContractError("RPC timeout must be between zero and 60 seconds")
        try:
            import grpc
            from google.protobuf.json_format import MessageToDict, ParseDict, ParseError
            from openshell._proto import openshell_pb2, openshell_pb2_grpc
        except ImportError:
            raise ContractError("install the generated Python SDK from the pinned OpenShell source") from None
        try:
            roots = Path(ca_file).read_bytes()
            cert = Path(certificate_file).read_bytes()
            key = Path(key_file).read_bytes()
            if not roots or not cert or not key:
                raise ValueError()
        except (OSError, ValueError):
            raise ContractError("gateway CA and private client identity files are required") from None
        self.grpc, self.pb2 = grpc, openshell_pb2
        self.parse, self.serialize = ParseDict, MessageToDict
        self.parse_error = ParseError
        self.timeout = timeout
        target = parsed.netloc
        self.channel = grpc.secure_channel(target, grpc.ssl_channel_credentials(roots, key, cert))
        self.stub = openshell_pb2_grpc.OpenShellStub(self.channel)

    def call(self, method, request):
        if method not in RPC_METHODS:
            raise ContractError("RPC is outside the reconciler allowlist")
        try:
            message = self.parse(request, getattr(self.pb2, method + "Request")(), ignore_unknown_fields=False)
        except (self.parse_error, ValueError, TypeError, AttributeError):
            raise ContractError("request does not match the pinned OpenShell protobuf API") from None
        try:
            response = getattr(self.stub, method)(message, timeout=self.timeout)
        except self.grpc.RpcError as exc:
            raise RpcError(exc.code().name) from None
        return self.serialize(response, preserving_proto_field_name=True)

    def close(self):
        self.channel.close()


class OcReader:
    """Read only namespaces/PVCs/RuntimeClasses using existing verified oc auth."""

    def __init__(self, executable="oc", *, timeout=20):
        self.executable, self.timeout = executable, timeout

    def __call__(self, kind, name, namespace=None):
        if kind not in {"namespace", "persistentvolumeclaim", "runtimeclass"}:
            raise ContractError("resource lookup is outside the verifier allowlist")
        command = [self.executable, "get", kind, name, "-o", "json", "--request-timeout=15s"]
        if namespace:
            command.extend(["--namespace", namespace])
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=self.timeout, check=True)
            return json.loads(result.stdout)
        except (subprocess.SubprocessError, OSError, ValueError):
            raise ContractError("cannot verify current Kubernetes resource identity") from None


class KubernetesResourceVerifier:
    """Verify identities and default stock driver attachment approval labels.

    `verify_boundary` is mandatory: integration must separately prove its native
    CNI/admission enforcement prerequisite. Checking a label is not such proof.
    The OpenShell driver still performs its own admission at create/restart.
    """

    def __init__(self, read_json, verify_boundary):
        if not callable(read_json) or not callable(verify_boundary):
            raise ContractError("resource reader and boundary verifier are required")
        self.read, self.verify_boundary = read_json, verify_boundary

    @staticmethod
    def _identity(obj, uid):
        metadata = obj.get("metadata", {})
        if metadata.get("uid") != uid or metadata.get("deletionTimestamp"):
            raise ContractError("Kubernetes resource replaced or deleting")
        return metadata

    def verify_shutdown(self, plan):
        """Shutdown checks namespace identity, not renewed attachment permission.

        The reconciler still checks authenticated gateway identity and retained
        workspace/sandbox IDs. This method grants no create/start capability.
        """
        namespace = self.read("namespace", plan["namespace"])
        meta = self._identity(namespace, plan["namespaceUID"])
        if meta.get("labels", {}).get(OWNER) != plan["ownerID"]:
            raise ContractError("runtime namespace belongs to another installation")

    def __call__(self, plan):
        self.verify_boundary(plan)
        self.verify_attachments(plan)

    def verify_attachments(self, plan):
        """Frontend-owned Running passes already verified the boundary before opening the gateway."""
        self.verify_shutdown(plan)
        for reference in plan["claims"]:
            obj = self.read("persistentvolumeclaim", reference["name"], plan["namespace"])
            meta = self._identity(obj, reference["uid"])
            labels = meta.get("labels", {})
            if (labels.get("openshell.ai/sandbox-attachable") != "true"
                    or labels.get("openshell.ai/sandbox-attachable-workspace") != reference["workspace"]
                    or labels.get(OWNER) != plan["ownerID"]):
                raise ContractError("PVC is not approved for this workspace and installation")
            if meta.get("ownerReferences"):
                raise ContractError("retained PVC must not have garbage-collecting owner references")
            sync = meta.get("annotations", {}).get("argocd.argoproj.io/sync-options", "")
            options = {s.strip() for s in sync.split(",")}
            required = {"Prune=false", "Delete=false"}
            conflicting = {s for s in options if s.startswith(("Prune=", "Delete="))} - required
            if not required <= options or conflicting:
                raise ContractError("retained PVC requires explicit Argo prune and application-deletion protection")
            if obj.get("spec", {}).get("volumeMode", "Filesystem") != "Filesystem":
                raise ContractError("workspace adapter requires filesystem PVCs")
            if obj.get("status", {}).get("phase") not in {"Pending", "Bound"}:
                raise ContractError("PVC is not available for binding")
        runtime = plan["runtimeClass"]
        if runtime["name"]:
            obj = self.read("runtimeclass", runtime["name"])
            meta = self._identity(obj, runtime["uid"])
            handler = obj.get("spec", {}).get("handler", "")
            if (meta.get("labels", {}).get("openshell.ai/sandbox-attachable") != "true"
                    or not re.fullmatch(r"kata(?:-[a-z0-9]+)*", handler)):
                raise ContractError("RuntimeClass has not been approved")

    def verify_workload(self, plan, workspace, sandbox_name, sandbox_id):
        """Verify the Ready workload Pod against its Sandbox and approved runtime."""
        namespace = plan["namespace"]
        kube_name = workspace + "--" + sandbox_name
        sandbox = self.read("sandbox", kube_name, namespace)
        if sandbox is None:
            return None
        sandbox_meta = sandbox.get("metadata", {})
        annotations = sandbox_meta.get("annotations", {})
        if (sandbox_meta.get("name") != kube_name or not sandbox_meta.get("uid")
                or sandbox_meta.get("deletionTimestamp")
                or annotations.get("openshell.ai/sandbox-id") != sandbox_id
                or annotations.get("openshell.ai/sandbox-name") != sandbox_name
                or annotations.get("openshell.ai/sandbox-workspace") != workspace):
            raise ContractError("Sandbox identity changed")
        pod_name = annotations.get("agents.x-k8s.io/pod-name") or kube_name
        if pod_name != kube_name:
            raise ContractError("Sandbox Pod name is outside the approved resource scope")
        pod = self.read("pod", pod_name, namespace)
        if pod is None:
            return None
        pod_meta = pod.get("metadata", {})
        if (pod_meta.get("name") != pod_name or not pod_meta.get("uid")
                or pod_meta.get("deletionTimestamp")):
            raise ContractError("workload Pod identity changed")
        owners = pod_meta.get("ownerReferences", [])
        if (len(owners) != 1 or owners[0].get("controller") is not True
                or owners[0].get("kind") != "Sandbox"
                or owners[0].get("apiVersion") not in {"agents.x-k8s.io/v1alpha1", "agents.x-k8s.io/v1beta1"}
                or owners[0].get("name") != kube_name
                or owners[0].get("uid") != sandbox_meta.get("uid")):
            raise ContractError("workload Pod is not owned by its Sandbox")
        if pod_meta.get("labels", {}).get("openshell.ai/boundary-role") != "workload":
            raise ContractError("workload Pod has the wrong boundary role")
        if pod_meta.get("annotations", {}).get("openshell.ai/sandbox-id") != sandbox_id:
            raise ContractError("workload Pod annotation does not match its Sandbox")
        conditions = pod.get("status", {}).get("conditions", [])
        if (pod.get("status", {}).get("phase") != "Running"
                or not any(c.get("type") == "Ready" and c.get("status") == "True" for c in conditions)):
            return None
        runtime = plan["runtimeClass"]["name"]
        actual = pod.get("spec", {}).get("runtimeClassName", "")
        if actual != runtime:
            raise ContractError("workload Pod runtime differs from the approved RuntimeClass")
        return sandbox_meta["uid"]
