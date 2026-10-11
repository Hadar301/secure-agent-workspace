# Container images

Project CI publishes public images to `ghcr.io/<lowercase repository owner>/`.
The shipped defaults use the upstream project's public namespace,
`ghcr.io/validatedpatterns-sandbox`. Fork CI publishes under the fork owner;
consuming a fork requires overriding the Make and Helm image references.
These upstream deployment defaults are intentional: running CI in a fork does
not change the source of shipped images. Fork CI never publishes into the
upstream namespace. To test a fork's publications, set
`IMAGE_REPO=ghcr.io/<lowercase fork owner>` for mirror and build commands, and
override the gateway disk source, installer `bom.spec.nemoclaw.cliImage`,
interceptor `image`, and SAW-BOM profile image references listed below. Keep
those deployment overrides local when preparing changes for upstream.

| Image | CI tags | Consumers |
| --- | --- | --- |
| `openshell-gateway` | `latest`, `sha-<commit>` | Podman VM disk, `make images-mirror`, golden image import |
| `openshell-gateway-docker` | `latest`, `sha-<commit>` | Docker VM disk, `make gateway-build-docker` |
| `nemoclaw-cli` | `latest`, `sha-<commit>` | Installer BOM `spec.nemoclaw.cliImage` |
| `nemoclaw-sandbox` | `latest`, `sha-<commit>` | Data-science default and CUDA profiles |
| `governance-interceptor` | `latest`, `sha-<commit>`, OpenShell ref (currently `v0.1.2`) | Interceptor deployment and image builder |
| `saw-harness-<bundle>` | Bundle version, `sha-<commit>` | Optional digest-pinned `harnessRef.image` |

Pull requests build without registry credentials or pushing. Publishing is
restricted to `main`, including manual workflow dispatches. Every push verifies
the resulting digest with an empty Docker auth configuration: a private package
fails CI. CI adds the repository source label to associate its packages with the
repository. GHCR can create packages as private initially: a package administrator
must set each package's visibility to **Public** in its GitHub package settings,
including newly added harness bundles. Public pulls need no registry Secret.
Publishing uses `GITHUB_TOKEN` with `packages: write`.
The first publication of a new package can therefore fail its public-pull
check after the image is pushed. Set it to Public, then rerun the workflow.
GitHub's documented [package REST API](https://docs.github.com/en/rest/packages/packages)
does not expose a visibility-update endpoint; visibility is an administrator
setup step in [package settings](https://docs.github.com/en/packages/learn-github-packages/configuring-a-packages-access-control-and-visibility).
Harness images are signed before the public-pull check, so a visibility failure
does not skip signing an otherwise successfully published image.

```sh
# Exact selected tag; missing tags fail without falling back to latest.
make images-mirror IMAGE_TAG=sha-<commit>
# Select Docker's disk image explicitly when mirroring it.
make images-mirror MIRROR_IMAGES=openshell-gateway-docker
# Inspect without registry credentials.
skopeo inspect --no-creds docker://ghcr.io/validatedpatterns-sandbox/nemoclaw-cli:latest
```

`IMAGE_REPO` replaces the former `QUAY_REPO` option; `IMAGE_TAG` replaces the
former `OPENSHELL_VERSION` mirror/build tag option. These image tags do not select
the OpenShell release inside the VM: that is pinned separately by the installer
BOM. The default internal golden-image reference remains `:latest`; mirroring
stores the exact selected tag and adds this alias. Changing the disk source
only affects new VM disks. To roll back, select a previous `sha-<commit>` tag or
GHCR digest and recreate the VM disk using the documented workspace lifecycle.

Manual cluster builds push to `IMAGE_REPO`. Authenticate to GHCR with a token
that can write packages using `oc registry login --registry=ghcr.io`; the push
script uses the current containers auth file. For the interceptor BuildConfig,
create a Docker registry Secret named `ghcr-push-secret` in `BUILD_NS`, or override
`output.pushSecretName`. `governance-interceptor-build-local` uses the internal
registry and needs no GHCR push credentials. A fork interceptor build also needs
`charts/governance-interceptor`'s `image` override.

## Intentionally retained Quay dependencies

These images are supplied by other projects and are not built by this project's
CI. Rewriting their registry would point at unverified or nonexistent images.

| Quay path | Reason retained |
| --- | --- |
| `quay.io/opendatahub/odh-openshell-{cli,gateway,supervisor,sandbox}` | Versioned OpenShell component images; installer BOM and gateway-image builder pins. The CI-built `openshell-gateway` is a VM disk, not a replacement for the gateway component image. |
| `quay.io/aipcc/base-images/agentic/openclaw` | Digest-pinned standalone OpenClaw sandbox in the BOM profiles. |
| `quay.io/gkrumbach07/openshell-dashboard` | External dashboard running inside the VM. |
| `quay.io/oauth2-proxy/oauth2-proxy` | External dashboard and sandbox UI authentication proxy. |
| `quay.io/validatedpatterns/*` | External Validated Patterns tooling and framework images/charts, including `utility-container`, `patternizer`, `imperative-container`, `pattern-install`, and the operator UI catalog. |

The gateway builder's `registries.yaml` entry for `quay.io/opendatahub` supports
signature attachments for these retained upstream components. Historical signing
observations and registry-neutral test fixtures can also mention Quay.
Disconnected deployments must mirror both GHCR images and these dependencies.
