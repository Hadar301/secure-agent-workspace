#!/usr/bin/env -S uv run --script
"""Test actual Pod-bound identity without scheduling a Pod or reading a Secret."""
import argparse
import copy
import importlib.util
import json
import re
import sys
import uuid
from pathlib import Path

SPEC = importlib.util.spec_from_file_location("lab_admission", Path(__file__).with_name("check-peerpod-storage-admission.py"))
CLIENT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CLIENT)
Error = CLIENT.CheckError


def check(api, registration):
    namespace = "saw-ppvc-" + registration
    guest = "saw-ppvc-probe-" + registration
    actor = "system:serviceaccount:" + guest + ":storage-guest"
    name = "bound-identity-" + uuid.uuid4().hex[:12]
    pods = "/api/v1/namespaces/" + guest + "/pods"
    records = "/apis/confidentialcontainers.org/v1alpha1/namespaces/" + namespace + "/peerpodvolumes"
    pod = {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name, "namespace": guest}, "spec": {"serviceAccountName": "storage-guest", "automountServiceAccountToken": False, "schedulingGates": [{"name": "saw.redhat.com/storage-lab-identity"}], "restartPolicy": "Never", "securityContext": {"runAsNonRoot": True, "runAsUser": 65532, "seccompProfile": {"type": "RuntimeDefault"}}, "containers": [{"name": "never-scheduled", "image": "registry.example.invalid/lab/identity:unused", "securityContext": {"allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]}}, "resources": {"requests": {"cpu": "5m", "memory": "16Mi"}, "limits": {"memory": "16Mi"}}}]}}
    for target in [namespace, guest]:
        labels = api.get("/api/v1/namespaces/" + target)["metadata"].get("labels", {})
        if labels.get("saw.redhat.com/peerpod-storage-lab") != registration:
            raise Error("LabNamespaceOwnershipRejected")
    created = []
    result = None
    try:
        status, admitted = api.request("POST", pods, pod)
        if status != 201:
            raise Error("LabIdentityPodRejected")
        pod_uid = admitted["metadata"]["uid"]
        created.append((pods + "/" + name, pod_uid))
        if admitted["spec"].get("nodeName") or admitted["spec"].get("runtimeClassName") or admitted["spec"].get("schedulingGates") != pod["spec"]["schedulingGates"]:
            raise Error("LabIdentityPodMustStayUnscheduled")
        token_request = {"apiVersion": "authentication.k8s.io/v1", "kind": "TokenRequest", "spec": {"audiences": [], "expirationSeconds": 600, "boundObjectRef": {"kind": "Pod", "apiVersion": "v1", "name": name, "uid": pod_uid}}}
        code, issued = api.request("POST", "/api/v1/namespaces/" + guest + "/serviceaccounts/storage-guest/token", token_request)
        if code != 201:
            raise Error("LabBoundTokenUnavailable")
        token = issued["status"]["token"]
        code, identity = api.request("POST", "/apis/authentication.k8s.io/v1/selfsubjectreviews", {"apiVersion": "authentication.k8s.io/v1", "kind": "SelfSubjectReview"}, bearer=token)
        user = identity.get("status", {}).get("userInfo", {})
        if code != 201 or user.get("username") != actor or user.get("extra", {}).get("authentication.kubernetes.io/pod-uid") != [pod_uid]:
            raise Error("LabActualBoundIdentityRejected")
        record = {"apiVersion": "confidentialcontainers.org/v1alpha1", "kind": "PeerpodVolume", "metadata": {"name": name, "namespace": namespace}, "spec": {"podUid": pod_uid, "podNamespace": guest, "volumeID": "identity-only", "vmID": "identity-only"}}
        code, record = api.request("POST", records, record)
        if code != 201:
            raise Error("LabIdentityRecordRejected")
        created.append((records + "/" + name, record["metadata"]["uid"]))
        changed = copy.deepcopy(record)
        changed["spec"]["podName"] = name
        code, _ = api.request("PUT", records + "/" + name, changed, dry_run=True, bearer=token)
        if code != 200:
            raise Error("LabOwnBoundUpdateRejected")
        changed["spec"]["vmID"] = "foreign-vm"
        code, denied = api.request("PUT", records + "/" + name, changed, dry_run=True, bearer=token)
        if code != 422 or "LabGuestVolumeMutationRejected" not in denied.get("message", ""):
            raise Error("LabForeignDiskUpdateNotDenied")
        if api.get(records + "/" + name)["spec"] != record["spec"]:
            raise Error("LabIdentityDryRunPersisted")
        final_pod = api.get(pods + "/" + name)
        if final_pod["spec"].get("nodeName"):
            raise Error("LabIdentityPodWasScheduled")
        foreign = copy.deepcopy(record)
        foreign["metadata"] = {"name": name + "-foreign", "namespace": namespace}
        foreign["spec"]["podUid"] = str(uuid.uuid4())
        code, foreign = api.request("POST", records, foreign)
        if code != 201:
            raise Error("LabForeignIdentityRecordRejected")
        created.append((records + "/" + name + "-foreign", foreign["metadata"]["uid"]))
        foreign["spec"]["podName"] = name
        code, denied = api.request("PUT", records + "/" + name + "-foreign", foreign, dry_run=True, bearer=token)
        if code != 422 or "LabBoundGuestIdentityRequired" not in denied.get("message", ""):
            raise Error("LabForeignPodUpdateNotDenied")
        result = {"foreignPodUpdateDenied": True, "realPodBoundIdentityVerified": True, "ownRecordDryRunPassed": True, "foreignDiskUpdateDenied": True, "podScheduled": False, "vmRequested": False, "guestNetworkTested": False, "tokenPrintedOrSaved": False, "credentialObjectsRead": False}
    finally:
        failed = False
        for path, uid in reversed(created):
            code, _ = api.request("DELETE", path, {"apiVersion": "v1", "kind": "DeleteOptions", "preconditions": {"uid": uid}})
            if code not in (200, 202):
                failed = True
        if failed:
            raise Error("LabIdentityCleanupFailed")
    for path, _ in created:
        code, _ = api.request("GET", path)
        if code != 404:
            raise Error("LabIdentityCleanupIncomplete")
    result["temporaryObjectsRemoved"] = True
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--context", required=True)
    parser.add_argument("--registration", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    try:
        if not re.fullmatch("[a-f0-9]{16}", args.registration):
            raise Error("LabRegistrationRejected")
        with CLIENT.Api(args.context) as api:
            result = check(api, args.registration)
        Path(args.output).write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result))
        return 0
    except (OSError, ValueError, KeyError, TypeError, Error):
        error = sys.exc_info()[1]
        print(str(error) if isinstance(error, Error) else "LabIdentityCheckRejected", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
