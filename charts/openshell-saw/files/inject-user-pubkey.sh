#!/usr/bin/env bash
set -euo pipefail

: "${SSH_PUBKEY:?}"
: "${SANDBOX_NAME:?}"

mkdir -p "${HOME}/.openshell-user-keys"
umask 077
printf '%s\n' "${SSH_PUBKEY}" > "${HOME}/.openshell-user-keys/${SANDBOX_NAME}.pub"
mkdir -p "${HOME}/.ssh"
chmod 700 "${HOME}/.ssh"
touch "${HOME}/.ssh/authorized_keys"
chmod 600 "${HOME}/.ssh/authorized_keys"
if ! grep -Fxq "${SSH_PUBKEY}" "${HOME}/.ssh/authorized_keys"; then
  printf '%s\n' "${SSH_PUBKEY}" >> "${HOME}/.ssh/authorized_keys"
fi
echo "pubkey_installed sandbox=${SANDBOX_NAME}"
