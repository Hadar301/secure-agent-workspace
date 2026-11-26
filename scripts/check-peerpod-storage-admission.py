#!/usr/bin/env -S uv run --script
"""Check the isolated lab admission rules. Never read a Secret.

The default mode is read-only. --exercise creates one public storage record,
uses server dry-run for all PVC/PV and update tests, then deletes its own record.
"""
import argparse
import json
import select
import sys
import subprocess
import time
import uuid
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import quote, unquote, urlsplit
from urllib.request import Request, urlopen

import yaml


class CheckError(Exception):
    pass


class Api:
    def __init__(self, context):
        self.context = context
        self.process = None
        self.base = None

    def __enter__(self):
        self.process = subprocess.Popen(
            ["oc", "--context=" + self.context, "proxy", "--address=127.0.0.1", "--port=0"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                self.close()
                raise CheckError("LabApiProxyUnavailable")
            ready, _, _ = select.select([self.process.stdout], [], [], 1)
            if ready:
                line = self.process.stdout.readline().strip()
                prefix = "Starting to serve on 127.0.0.1:"
                if line.startswith(prefix) and line[len(prefix):].isdigit():
                    self.base = "http://127.0.0.1:" + line[len(prefix):]
                    return self
        self.close()
        raise CheckError("LabApiProxyUnavailable")

    def close(self):
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)

        if self.process is not None:
            self.process.stdout.close()
            self.process.stderr.close()

    def __exit__(self, *_):
        self.close()

    def request(self, method, path, body=None, *, dry_run=False, actor=None, pod_uid=None, bearer=None):
        parsed = urlsplit(unquote(path))
        if (not path.startswith(("/api/v1/", "/apis/"))
                or parsed.netloc or parsed.fragment
                or "secrets" in parsed.path.lower()
                or ".." in parsed.path.split("/")
                or method not in {"GET", "POST", "PUT", "DELETE"}):
            raise CheckError("LabApiPathRejected")
        if dry_run:
            path += ("&" if "?" in path else "?") + "dryRun=All"
        if bearer and (actor or pod_uid):
            raise CheckError("LabMixedIdentityRejected")
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if bearer:
            headers["Authorization"] = "Bearer " + bearer
        if actor:
            headers["Impersonate-User"] = actor
        if pod_uid:
            key = quote("authentication.kubernetes.io/pod-uid", safe="")
            headers["Impersonate-Extra-" + key] = pod_uid
        payload = None if body is None else json.dumps(body).encode()
        request = Request(self.base + path, data=payload, headers=headers, method=method)
        try:
            with urlopen(request, timeout=20) as response:
                return response.status, json.load(response)
        except HTTPError as error:
            try:
                value = json.loads(error.read())
            except (ValueError, OSError):
                value = {}
            return error.code, value
        except OSError:
            raise CheckError("LabApiUnavailable") from None

    def get(self, path):
        status, value = self.request("GET", path)
        if status != 200:
            raise CheckError("LabRequiredResourceUnavailable")
        return value


def verify_inactive(api, namespace):
    namespace_obj = api.get("/api/v1/namespaces/" + namespace)
    registration = namespace.removeprefix("saw-ppvc-")
    if namespace_obj["metadata"].get("labels", {}).get("saw.redhat.com/peerpod-storage-lab") != registration:
        raise CheckError("LabNamespaceOwnershipRejected")
    deployment = api.get("/apis/apps/v1/namespaces/" + namespace + "/deployments/controller")
    daemon = api.get("/apis/apps/v1/namespaces/" + namespace + "/daemonsets/node")
    if deployment["spec"].get("replicas", 1) != 0 or daemon.get("status", {}).get("currentNumberScheduled", 0) != 0:
        raise CheckError("LabMustBeInactive")
    for suffix in ["claims", "volumes", "attachments", "guest-records"]:
        policy = api.get("/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicies/" + namespace + "-" + suffix)
        status = policy.get("status", {})
        if status.get("observedGeneration") != policy["metadata"]["generation"] or status.get("typeChecking", {}).get("expressionWarnings"):
            raise CheckError("LabAdmissionPolicyNotVerified")


def exercise(api, namespace):
    registration = namespace.removeprefix("saw-ppvc-")
    guest = "saw-ppvc-probe-" + registration
    driver = namespace + ".disk.csi.saw.redhat.com"
    controller = "system:serviceaccount:" + namespace + ":controller"
    guest_actor = "system:serviceaccount:" + guest + ":storage-guest"
    stem = "admission-" + uuid.uuid4().hex[:12]
    record_path = "/apis/confidentialcontainers.org/v1alpha1/namespaces/" + namespace + "/peerpodvolumes"
    pod_uid = str(uuid.uuid4())
    record = {"apiVersion": "confidentialcontainers.org/v1alpha1", "kind": "PeerpodVolume", "metadata": {"name": stem, "namespace": namespace}, "spec": {"podUid": pod_uid, "podNamespace": guest, "volumeID": "admission-only", "volumeName": stem, "vmID": "admission-only"}}
    status, created = api.request("POST", record_path, record)
    if status != 201:
        raise CheckError("LabAdmissionRecordCreateRejected")
    uid = created["metadata"]["uid"]
    results = []
    paths = []

    def case(name, method, path, body, allowed, reason=None, **identity):
        code, value = api.request(method, path, body, dry_run=True, **identity)
        matched = code in (200, 201) if allowed else code in (400, 403, 422) and reason in value.get("message", "")
        if not matched:
            raise CheckError("LabAdmissionCaseFailed:" + name)
        results.append({"case": name, "allowed": allowed, "status": code, "passed": True})

    try:
        for suffix in ["claims", "volumes", "attachments", "guest-records"]:
            api.get("/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicybindings/" + namespace + "-" + suffix)
        pvc = {"apiVersion": "v1", "kind": "PersistentVolumeClaim", "metadata": {"name": stem, "namespace": guest}, "spec": {"storageClassName": namespace, "accessModes": ["ReadWriteOnce"], "resources": {"requests": {"storage": "1Gi"}}}}
        pvc_path = "/api/v1/namespaces/" + guest + "/persistentvolumeclaims"
        case("own-claim", "POST", pvc_path, pvc, True)
        paths.append(pvc_path + "/" + stem)
        pvc["metadata"]["namespace"] = "default"
        case("foreign-claim", "POST", "/api/v1/namespaces/default/persistentvolumeclaims", pvc, False, "LabClaimNamespaceRejected")
        paths.append("/api/v1/namespaces/default/persistentvolumeclaims/" + stem)
        pv = {"apiVersion": "v1", "kind": "PersistentVolume", "metadata": {"name": stem}, "spec": {"capacity": {"storage": "1Gi"}, "accessModes": ["ReadWriteOnce"], "persistentVolumeReclaimPolicy": "Retain", "storageClassName": namespace, "claimRef": {"name": stem, "namespace": guest}, "csi": {"driver": driver, "volumeHandle": "admission-only"}}}
        case("own-volume", "POST", "/api/v1/persistentvolumes", pv, True, actor=controller)
        paths.append("/api/v1/persistentvolumes/" + stem)
        pv["spec"]["csi"]["driver"] = "other.example.test"
        case("foreign-volume", "POST", "/api/v1/persistentvolumes", pv, False, "LabForeignVolumeRejected", actor=controller)
        pv["spec"]["csi"]["driver"] = driver
        pv["spec"]["csi"]["nodeStageSecretRef"] = {"name": "unused-reference", "namespace": guest}
        case("secret-reference", "POST", "/api/v1/persistentvolumes", pv, False, "LabCsiSecretReferenceRejected", actor=controller)
        update_path = record_path + "/" + stem
        update = json.loads(json.dumps(created))
        update["spec"]["podName"] = "admission-probe"
        case("bound-guest", "PUT", update_path, update, True, actor=guest_actor, pod_uid=pod_uid)
        case("missing-bound-identity", "PUT", update_path, update, False, "LabBoundGuestIdentityRequired", actor=guest_actor)
        case("foreign-bound-identity", "PUT", update_path, update, False, "LabBoundGuestIdentityRequired", actor=guest_actor, pod_uid=str(uuid.uuid4()))
        update["spec"]["vmID"] = "foreign-vm"
        case("foreign-disk-record", "PUT", update_path, update, False, "LabGuestVolumeMutationRejected", actor=guest_actor, pod_uid=pod_uid)
        current = api.get(update_path)
        if current["spec"] != created["spec"] or current["metadata"]["resourceVersion"] != created["metadata"]["resourceVersion"]:
            raise CheckError("LabDryRunPersistedAnUpdate")
        for path in paths:
            code, _ = api.request("GET", path)
            if code != 404:
                raise CheckError("LabDryRunResourceExists")
    finally:
        code, _ = api.request("DELETE", record_path + "/" + stem, {"apiVersion": "v1", "kind": "DeleteOptions", "preconditions": {"uid": uid}})
        if code not in (200, 202):
            raise CheckError("LabAdmissionRecordCleanupFailed")
    code, _ = api.request("GET", record_path + "/" + stem)
    if code != 404:
        raise CheckError("LabAdmissionRecordCleanupIncomplete")
    return {"cases": results, "dryRunObjectsAbsent": True, "temporaryRecordRemoved": True, "credentialObjectsRead": False, "realGuestTokenTested": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--context", required=True)
    parser.add_argument("--values", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--exercise", action="store_true")
    args = parser.parse_args()
    try:
        config = yaml.safe_load(Path(args.values).read_text())
        registration = config["registration"]
        if not isinstance(registration, str) or len(registration) != 16 or any(x not in "0123456789abcdef" for x in registration) or config.get("activate") is not False:
            raise CheckError("LabConfigRejected")
        namespace = "saw-ppvc-" + registration
        with Api(args.context) as api:
            verify_inactive(api, namespace)
            result = exercise(api, namespace) if args.exercise else {"inactiveStageVerified": True}
        Path(args.output).write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result))
        return 0
    except (OSError, ValueError, KeyError, TypeError, CheckError):
        error = sys.exc_info()[1]
        print(str(error) if isinstance(error, CheckError) else "LabAdmissionCheckRejected", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
