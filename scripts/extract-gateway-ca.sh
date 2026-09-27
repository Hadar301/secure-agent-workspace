#!/usr/bin/env bash
# Extract the gateway CA certificate from the sandbox VM to the CLI config.
# The openshell CLI reads this CA (at ~/.config/openshell/gateways/<name>/mtls/ca.crt)
# to verify the gateway's TLS certificate, removing the need for --gateway-insecure.
# SSH goes through openshell-saw-vm-ssh.sh, which adds your key to the VM's
# accessCredentials Secret first.
# Expects: NS, VM_NAME, SSH_KEY_PATH, OUT_FILE
set -euo pipefail

NS="${NS:-openshell-agents}"
SSH_KEY_PATH="${SSH_KEY_PATH:-.generated-ssh-keys/sandbox-ssh}"
VM_NAME="${VM_NAME:?VM_NAME is required}"
OUT_FILE="${OUT_FILE:?OUT_FILE is required}"

echo "Extracting CA certificate from VM '${VM_NAME}'..."
mkdir -p "$(dirname "${OUT_FILE}")"

SAW_NS="${NS}" VM_NAME="${VM_NAME}" SSH_KEY_PATH="${SSH_KEY_PATH}" \
  "$(dirname "$0")/openshell-saw-vm-ssh.sh" \
  'cat $HOME/.local/state/openshell/tls/ca.crt' > "${OUT_FILE}"

if [[ ! -s "${OUT_FILE}" ]]; then
  echo "Error: CA certificate not found on VM. The gateway may not have started yet." >&2
  echo "  Run 'make openshell-saw-logs' to check, then re-run this target." >&2
  rm -f "${OUT_FILE}"
  exit 1
fi

echo "CA certificate installed."
