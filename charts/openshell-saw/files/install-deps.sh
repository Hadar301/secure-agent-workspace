#!/usr/bin/env bash
# Phase: install dependencies in the Job Pod (not the VM).
# Expects: VIRTCTL_VERSION

echo "Installing openssh-clients..."
dnf install -y --setopt=install_weak_deps=False openssh-clients jq openssl

echo "Installing kubectl..."
K8S_VERSION="$(curl -fsSL https://dl.k8s.io/release/stable.txt)"
curl -fsSL -o /usr/local/bin/kubectl "https://dl.k8s.io/release/${K8S_VERSION}/bin/linux/amd64/kubectl"
chmod +x /usr/local/bin/kubectl

echo "Downloading virtctl from cluster..."
VIRTCTL_URL="$(kubectl get ConsoleCLIDownload virtctl-clidownloads-kubevirt-hyperconverged \
  -o jsonpath='{.spec.links[?(@.text=="Download virtctl for Linux for x86_64")].href}' 2>/dev/null || true)"
if [[ -n "${VIRTCTL_URL}" ]]; then
  echo "  using cluster URL: ${VIRTCTL_URL}"
  curl -fsSL "${VIRTCTL_URL}" | tar xz -C /usr/local/bin virtctl
else
  echo "  ConsoleCLIDownload not found, falling back to GitHub ${VIRTCTL_VERSION}"
  curl -fsSL -o /usr/local/bin/virtctl \
    "https://github.com/kubevirt/kubevirt/releases/download/${VIRTCTL_VERSION}/virtctl-${VIRTCTL_VERSION}-linux-amd64"
fi
chmod +x /usr/local/bin/virtctl
