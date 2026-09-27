FROM quay.io/aipcc/base-images/agentic/openclaw@sha256:01b4def983e30a8e30e196d3f22ad3b759ade3af5e56dde89c306110162cb7bc

USER root

# OpenShell's sandbox supervisor isolates each sandbox in its own network
# namespace and needs nsenter (util-linux) for that, plus nftables for the
# proxy rules. The base image ships neither; fail the build if they are
# still missing rather than producing an image that exits at start.
RUN if command -v dnf >/dev/null 2>&1; then PM=dnf; \
    elif command -v microdnf >/dev/null 2>&1; then PM=microdnf; \
    else echo "no dnf/microdnf in the base image to install util-linux and nftables" >&2; exit 1; fi && \
    $PM install -y --setopt=install_weak_deps=0 util-linux-core nftables iproute || \
      $PM install -y --setopt=install_weak_deps=0 util-linux nftables iproute && \
    $PM clean all && \
    command -v nsenter && command -v nft && command -v ip

# The base image's sandbox user (1000:1000) owns /sandbox, its home.
RUN grep '^sandbox:[^:]*:1000:1000:' /etc/passwd && \
    mkdir -p /sandbox/.openclaw/state /run/secrets && \
    chown -R 1000:1000 /sandbox/.openclaw && \
    chmod 700 /sandbox/.openclaw /sandbox/.openclaw/state && \
    chmod 755 /run/secrets

ENV HOME=/sandbox \
    OPENCLAW_HOME=/sandbox \
    SQLITE_TMPDIR=/sandbox/.openclaw/state \
    TMPDIR=/sandbox/.openclaw/state

# Explicit group: OpenShell's supervisor refuses a numeric USER it cannot
# resolve to a primary group.
USER 1000:1000

RUN OPENCLAW_NIX_MODE=0 \
    openclaw plugins install @openclaw/openshell-sandbox
