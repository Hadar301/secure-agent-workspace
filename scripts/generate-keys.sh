#!/usr/bin/env bash
# Generate SSH keypair and auto-configure values-global.yaml + ~/values-secret.yaml.

set -euo pipefail

KEYS_DIR="${KEYS_DIR:-.generated-ssh-keys}"
KEY_FILE="${KEYS_DIR}/sandbox-ssh"
VALUES_GLOBAL="values-global.yaml"
VALUES_SECRET="${VALUES_SECRET:-${HOME}/values-secret.yaml}"

# Generate keys if they don't exist
if [[ -f "${KEY_FILE}" ]]; then
  echo "SSH keypair already exists at ${KEY_FILE}"
else
  mkdir -p "${KEYS_DIR}"
  ssh-keygen -t ed25519 -f "${KEY_FILE}" -N "" -C "openshell-saw"
  echo "SSH keypair generated at ${KEY_FILE}"
fi

PUB_KEY=$(cat "${KEY_FILE}.pub")
PRIV_KEY=$(cat "${KEY_FILE}")

# Update values-global.yaml with the public key
if [[ -f "${VALUES_GLOBAL}" ]]; then
  if grep -q "sshPublicKey:" "${VALUES_GLOBAL}"; then
    sed -i.bak "s|sshPublicKey:.*|sshPublicKey: \"${PUB_KEY}\"|" "${VALUES_GLOBAL}"
    rm -f "${VALUES_GLOBAL}.bak"
    echo "Updated ${VALUES_GLOBAL} with SSH public key."
  fi
fi

# Update or add SSH keys in ~/values-secret.yaml
if [[ ! -f "${VALUES_SECRET}" ]]; then
  if [[ -f "values-secret.yaml.template" ]]; then
    cp values-secret.yaml.template "${VALUES_SECRET}"
    echo "Created ${VALUES_SECRET} from template."
  else
    echo "WARNING: ${VALUES_SECRET} not found."
    exit 0
  fi
fi

if grep -q "name: ssh" "${VALUES_SECRET}"; then
  # SSH section exists — update the key values
  python3 -c "
import yaml
with open('${VALUES_SECRET}') as f:
    data = yaml.safe_load(f)
for s in data.get('secrets', []):
    if s['name'] == 'ssh':
        for field in s.get('fields', []):
            if field['name'] == 'private_key':
                field['value'] = open('${KEY_FILE}').read()
            elif field['name'] == 'public_key':
                field['value'] = open('${KEY_FILE}.pub').read().strip()
with open('${VALUES_SECRET}', 'w') as f:
    yaml.dump(data, f, default_flow_style=False, sort_keys=False)
" 2>/dev/null && echo "Updated SSH keys in ${VALUES_SECRET}." || \
  echo "WARNING: Could not auto-update ${VALUES_SECRET}. Update the ssh section manually."
else
  # No SSH section — append it
  cat >> "${VALUES_SECRET}" <<SSHEOF

  - name: ssh
    fields:
    - name: private_key
      value: |
$(echo "${PRIV_KEY}" | sed 's/^/        /')
    - name: public_key
      value: "${PUB_KEY}"
SSHEOF
  echo "Added SSH keys to ${VALUES_SECRET}."
fi

echo ""
echo "Done. Keys configured in:"
echo "  ${VALUES_GLOBAL} (public key)"
echo "  ${VALUES_SECRET} (private + public key)"
