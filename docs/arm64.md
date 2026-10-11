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
| NemoClaw sandbox and CLI (`quay.io/rh-ai-quickstart/nemoclaw-sandbox`, `nemoclaw-cli`) | `type: nemoclaw` sandboxes (data-science `cuda-sandbox`, personal-assistant `assistant`) | CI builds them for both (ghcr); `make nemoclaw-publish` copies them to quay. See below |
| Governance interceptor (`ghcr.io/validatedpatterns-sandbox/governance-interceptor`) | admission for every gateway | yes once CI has published it from a build with the multi-arch workflow; until then build it on the cluster (below) |

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
   make gateway-build-podman PUSH=false
   oc image info --show-multiarch image-registry.openshift-image-registry.svc:5000/openshell-agents/openshell-gateway:latest
   ```

   Do not run `make images-mirror` on an arm64 cluster: it would replace that
   image with the x86_64 one from quay.

3. **The governance interceptor, built on the cluster**, and the pattern
   pointed at it (`charts/governance-interceptor` `image`):

   ```bash
   make governance-interceptor-build-local
   ```

   Then set the interceptor's `image` to
   `image-registry.openshift-image-registry.svc:5000/openshell-agents/governance-interceptor:latest`
   (an override on the `governance-interceptor` application in your values
   file).

   The `build-governance-interceptor` workflow now builds amd64 and arm64
   and publishes one multi-arch tag (`:v0.1.2` and `:latest`). Once it has
   run on main, check with
   `oc image info --show-multiarch ghcr.io/validatedpatterns-sandbox/governance-interceptor:v0.1.2`
   and, if arm64 is listed, skip this step and drop the override.

4. **NemoClaw images.** The `build-nemoclaw-sandbox` and `build-nemoclaw-cli`
   workflows build each image natively on an amd64 and an arm64 runner and
   join them into one multi-arch tag in `ghcr.io/validatedpatterns-sandbox`
   (the upstream `sandbox-base` they build on is multi-arch too). The VM pulls
   them from quay, so copy them there, keeping both architectures, from a
   machine logged in to quay:

   ```bash
   make nemoclaw-publish
   oc image info --show-multiarch quay.io/rh-ai-quickstart/nemoclaw-sandbox:latest
   ```

   Do not push to quay with `make sandbox-build` (or `cli-build`)
   with `PUSH=true` afterwards: an in-cluster build is single-architecture and
   would replace the multi-arch tag. On a single arm64 cluster,
   `PUSH=false` builds an arm64 image into the internal registry instead
   (the in-cluster build no longer forces `TARGETARCH=amd64`).

   Until the quay tags are multi-arch, expect a NemoClaw sandbox to be slow rather than broken: the
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
