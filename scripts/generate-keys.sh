#!/usr/bin/env bash
# Generate SSH keypair for sandbox provisioning.
# Keys are stored in ~/.generated-ssh-keys/ and referenced by path
# in values-secret.yaml (no content copying needed).

set -euo pipefail

KEYS_DIR="${KEYS_DIR:-${HOME}/.generated-ssh-keys}"
KEY_FILE="${KEYS_DIR}/sandbox-ssh"
VALUES_GLOBAL="values-global.yaml"
VALUES_SECRET="${VALUES_SECRET:-${HOME}/values-secret.yaml}"

# Generate keys if they don't exist
if [[ -f "${KEY_FILE}" ]]; then
  echo "SSH keypair already exists at ${KEY_FILE}"
else
  mkdir -p "${KEYS_DIR}"
  ssh-keygen -t ed25519 -f "${KEY_FILE}" -N "" -C "openshell-sandbox"
  echo "SSH keypair generated at ${KEY_FILE}"
fi

PUB_KEY=$(cat "${KEY_FILE}.pub")

# Update values-global.yaml with the public key
if [[ -f "${VALUES_GLOBAL}" ]]; then
  if grep -q "sshPublicKey:" "${VALUES_GLOBAL}"; then
    sed -i.bak "s|sshPublicKey:.*|sshPublicKey: \"${PUB_KEY}\"|" "${VALUES_GLOBAL}"
    rm -f "${VALUES_GLOBAL}.bak"
    echo "Updated ${VALUES_GLOBAL} with SSH public key."
  fi
fi

# Create values-secret.yaml from template if it doesn't exist
if [[ ! -f "${VALUES_SECRET}" ]]; then
  if [[ -f "values-secret.yaml.template" ]]; then
    cp values-secret.yaml.template "${VALUES_SECRET}"
    echo "Created ${VALUES_SECRET} from template."
  fi
fi

echo ""
echo "Done. Keys generated at:"
echo "  ${KEY_FILE} (private key)"
echo "  ${KEY_FILE}.pub (public key)"
echo ""
echo "The values-secret.yaml template references these paths automatically."
echo "No manual copying needed."
