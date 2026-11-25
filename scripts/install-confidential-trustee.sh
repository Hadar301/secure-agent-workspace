#!/usr/bin/env bash
set -euo pipefail

namespace=trustee-operator-system
https_secret=saw-trustee-https
token_secret=saw-trustee-attestation-token
trustee_config=deploy/confidential/trustee-config.yaml
public_certificate=local-docs/trustee-server-ca.crt

oc get namespace "$namespace" -o name
oc get crd trusteeconfigs.confidentialcontainers.org -o name
[[ "$(oc auth can-i create secrets -n "$namespace")" == "yes" ]]
[[ "$(oc auth can-i create trusteeconfigs.confidentialcontainers.org -n "$namespace")" == "yes" ]]

existing_secrets="$(oc get secrets -n "$namespace" -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}')"
existing_configs="$(oc get trusteeconfigs.confidentialcontainers.org -n "$namespace" -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}')"
for name in "$https_secret" "$token_secret"; do
  if [[ "$existing_secrets" == *$'\n'"$name"$'\n'* || "$existing_secrets" == "$name" || "$existing_secrets" == "$name"$'\n'* ]]; then
    printf 'Refusing to replace existing Secret %s in %s.\n' "$name" "$namespace" >&2
    exit 1
  fi
done
if [[ "$existing_configs" == *$'\n'saw-trustee$'\n'* || "$existing_configs" == saw-trustee || "$existing_configs" == saw-trustee$'\n'* ]]; then
  printf 'Refusing to replace existing TrusteeConfig saw-trustee in %s.\n' "$namespace" >&2
  exit 1
fi
if [[ -e "$public_certificate" ]]; then
  printf 'Refusing to replace existing public certificate %s.\n' "$public_certificate" >&2
  exit 1
fi

cluster_domain="$(oc get ingress.config/cluster -o jsonpath='{.spec.domain}')"
if [[ -z "$cluster_domain" || "$cluster_domain" == *'/'* || "$cluster_domain" == *' '* ]]; then
  printf 'OpenShift ingress domain is unavailable or invalid.\n' >&2
  exit 1
fi

temporary_directory="$(mktemp -d "${TMPDIR:-/tmp}/saw-trustee.XXXXXX")"
trap 'rm -rf "$temporary_directory"' EXIT
umask 077

openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout "$temporary_directory/https.key" \
  -out "$temporary_directory/https.crt" \
  -subj "/CN=*.${cluster_domain}" \
  -addext "subjectAltName=DNS:*.${cluster_domain}"
openssl ecparam -name prime256v1 -genkey -noout -out "$temporary_directory/token.key"
openssl req -new -x509 -key "$temporary_directory/token.key" \
  -out "$temporary_directory/token.crt" -days 365 \
  -subj "/CN=saw-trustee-attestation-token"

oc create secret tls "$https_secret" -n "$namespace" \
  --cert="$temporary_directory/https.crt" \
  --key="$temporary_directory/https.key"
oc create secret tls "$token_secret" -n "$namespace" \
  --cert="$temporary_directory/token.crt" \
  --key="$temporary_directory/token.key"

mkdir -p "$(dirname "$public_certificate")"
cp "$temporary_directory/https.crt" "$public_certificate"
chmod 0644 "$public_certificate"
oc apply -f "$trustee_config"
oc rollout status deployment/trustee-deployment -n "$namespace" --timeout=300s
oc get trusteeconfig saw-trustee -n "$namespace" -o custom-columns=NAME:.metadata.name,PROFILE:.spec.profileType --no-headers
oc get routes -n "$namespace" -o custom-columns=NAME:.metadata.name,HOST:.spec.host,TO:.spec.to.name --no-headers
printf 'Public KBS certificate saved to %s.\n' "$public_certificate"
