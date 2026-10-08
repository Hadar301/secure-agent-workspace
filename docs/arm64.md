# Running on an arm64 cluster

OpenShift Virtualization runs only guests of the host's architecture, so on
an arm64 cluster (for example NVIDIA Grace / GB200 nodes) every image that
ends up in a workspace VM, and every pod the pattern runs, needs an arm64
build.

## What is multi-arch

| Image | Used by | arm64 |
|---|---|---|
| OpenShell cli, gateway, supervisor, sandbox (`quay.io/opendatahub/odh-openshell-*`, `v0.1.2-rhaiv.6`) | the installer inside the VM | yes: the InstallerBOM pins their multi-arch indexes; podman in the VM pulls its own architecture |
| AIPCC OpenClaw (`quay.io/aipcc/base-images/agentic/openclaw`) | the `notebook` sandbox | yes |
| The golden VM image (`openshell-gateway`) | every workspace VM's root disk | build it on the cluster (below); the prebuilt quay image is x86_64 |
| NemoClaw sandbox and CLI (`quay.io/rh-ai-quickstart/nemoclaw-sandbox`, `nemoclaw-cli`) | `type: nemoclaw` sandboxes (data-science `cuda-sandbox`, personal-assistant `assistant`) | not published for arm64 yet; see below |
| Governance interceptor (`ghcr.io/validatedpatterns-sandbox/governance-interceptor`) | admission for every gateway | build it on the cluster (below); the published image is x86_64 |

Check any image with `oc image info --show-multiarch <image>`.

## Steps on an arm64 cluster

1. **The internal image registry.** Bare-metal clusters often have it off
   (`managementState: Removed`). Turn it on with a storage class that can
   hold it, for example a ReadWriteMany one:

   ```bash
   oc get configs.imageregistry.operator.openshift.io cluster -o jsonpath='{.spec.managementState}{"\n"}'
   oc patch configs.imageregistry.operator.openshift.io cluster --type merge -p \
     '{"spec":{"managementState":"Managed","defaultRoute":true,"storage":{"pvc":{"claim":""}}}}'
   ```

2. **The golden VM image, built on the cluster.** The build runs on a node
   of the cluster's architecture and picks the Fedora Cloud image and cosign
   for it (`uname -m`). `PUSH=false` keeps the result in the internal
   registry, `openshell-agents/openshell-gateway:latest`, which is where
   workspace VMs import their root disk from by default:

   ```bash
   make -f Makefile-quickstart build-gateway-podman PUSH=false
   oc image info --show-multiarch image-registry.openshift-image-registry.svc:5000/openshell-agents/openshell-gateway:latest
   ```

   Do not run `make copy-images` on an arm64 cluster: it would replace that
   image with the x86_64 one from quay.

3. **The governance interceptor, built on the cluster**, and the pattern
   pointed at it (`charts/governance-interceptor` `image`):

   ```bash
   make -f Makefile-quickstart build-governance-interceptor-local
   ```

   Then set the interceptor's `image` to
   `image-registry.openshift-image-registry.svc:5000/openshell-agents/governance-interceptor:latest`
   (an override on the `governance-interceptor` application in your values
   file).

4. **NemoClaw images.** `make build-nemoclaw PUSH=false` and
   `make build-nemoclaw-cli PUSH=false` build arm64 images on the cluster,
   but the VM pulls them from quay (the profiles and the InstallerBOM name
   `quay.io/rh-ai-quickstart/...`). Until those quay tags are multi-arch,
   a NemoClaw sandbox does not start on arm64. To publish them, push the
   arm64 builds next to the existing amd64 ones and join the two in one tag,
   for example with podman on a workstation logged in to both registries:

   ```bash
   podman manifest create quay.io/rh-ai-quickstart/nemoclaw-sandbox:latest
   podman manifest add quay.io/rh-ai-quickstart/nemoclaw-sandbox:latest docker://quay.io/rh-ai-quickstart/nemoclaw-sandbox@<amd64 digest>
   podman manifest add quay.io/rh-ai-quickstart/nemoclaw-sandbox:latest docker://<arm64 build>
   podman manifest push --all quay.io/rh-ai-quickstart/nemoclaw-sandbox:latest
   ```

   The same for `nemoclaw-cli`.

   Until then, expect a NemoClaw sandbox to be slow rather than broken: the
   VM's podman runs an x86_64 image under qemu user-mode emulation (`uname -m`
   in the sandbox prints `x86_64`), so the sandbox starts, but every `node`
   and `openclaw` call is many times slower, `apply` can take several
   minutes on it, and CUDA in that image cannot use the node's GPUs.

5. **The rest of the install** is the same as on x86_64: `./pattern.sh make
   install` (it needs podman on the machine you run it from).

## Platform

The operators the pattern installs (OpenShift Virtualization, Red Hat build
of Keycloak, Red Hat Developer Hub, External Secrets, OpenShift Pipelines)
must support arm64 in your OpenShift version: check each one's support
matrix before planning a demo on arm64.
