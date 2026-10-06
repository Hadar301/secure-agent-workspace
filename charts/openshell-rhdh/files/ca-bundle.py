#!/usr/bin/env python3
"""Write the CA bundle the portal's pods verify TLS with: ca-bundle.py OUT.

Standard library only. The bundle holds, in this order:

  * the system CAs of this image (public certificates);
  * the cluster's trusted CA bundle, when mounted at TRUSTED_CA_FILE (a
    ConfigMap with config.openshift.io/inject-trusted-cabundle: the
    cluster proxy's additional CAs);
  * the Kubernetes API's CA and the service CA (this pod's service
    account): kubernetes.default.svc, and in-cluster services such as Vault;
  * the router's CA (openshift-config-managed/default-ingress-cert): routes
    such as Keycloak's, when the default ingress certificate is self-signed;
  * EXTRA_CA_FILE, when present (tls.extraCaBundle in the chart).

A source that is missing is skipped with a note: the bundle then just
trusts less, and a connection that needs it fails verification.
"""
import json
import os
import ssl
import sys
import urllib.request

SA = "/var/run/secrets/kubernetes.io/serviceaccount"
SYSTEM = ("/etc/pki/tls/certs/ca-bundle.crt", "/etc/ssl/certs/ca-certificates.crt",
          ssl.get_default_verify_paths().cafile or "")
INGRESS_CA = "/api/v1/namespaces/openshift-config-managed/configmaps/default-ingress-cert"


def read(path):
    try:
        with open(path, encoding="utf-8") as f:
            return f.read()
    except OSError:
        return ""


def ingress_ca():
    host, port = os.environ.get("KUBERNETES_SERVICE_HOST"), os.environ.get("KUBERNETES_SERVICE_PORT", "443")
    token = read(f"{SA}/token").strip()
    if not (host and token):
        return ""
    req = urllib.request.Request(f"https://{host}:{port}{INGRESS_CA}",
                                 headers={"Authorization": f"Bearer {token}", "Accept": "application/json"})
    ctx = ssl.create_default_context(cafile=f"{SA}/ca.crt")
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=15) as resp:
            return (json.load(resp).get("data") or {}).get("ca-bundle.crt", "")
    except Exception as exc:        # noqa: BLE001 (an optional source)
        print(f"note: no router CA ({exc})", flush=True)
        return ""


def main(out):
    parts = []
    system = next((p for p in SYSTEM if p and read(p)), "")
    for what, pem in (("system CAs", read(system) if system else ""),
                      ("cluster trusted CA bundle", read(os.environ.get("TRUSTED_CA_FILE", ""))),
                      ("Kubernetes API CA", read(f"{SA}/ca.crt")),
                      ("service CA", read(f"{SA}/service-ca.crt")),
                      ("router CA", ingress_ca()),
                      ("extra CAs", read(os.environ.get("EXTRA_CA_FILE", "")))):
        if "BEGIN CERTIFICATE" in pem:
            parts.append(pem.strip() + "\n")
            print(f"added: {what}", flush=True)
        else:
            print(f"note: no {what}", flush=True)
    with open(out, "w", encoding="utf-8") as f:
        f.write("".join(parts))
    print(f"wrote {out}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
