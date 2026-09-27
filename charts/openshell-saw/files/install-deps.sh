#!/usr/bin/env bash
# Phase: install tools in the prepare Job pod (not the VM).
echo "Installing jq and openssl..."
dnf install -y --setopt=install_weak_deps=False jq openssl

echo "Installing kubectl..."
K8S_VERSION="$(curl -fsSL https://dl.k8s.io/release/stable.txt)"
curl -fsSL -o /usr/local/bin/kubectl "https://dl.k8s.io/release/${K8S_VERSION}/bin/linux/amd64/kubectl"
chmod +x /usr/local/bin/kubectl
