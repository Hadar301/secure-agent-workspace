# Tools stage: the Hummingbird Node.js 26 builder, the same builder image the
# aipcc agentic OpenClaw base is built with, so nsenter and nft come from the
# same Red Hat Hummingbird package set. The base itself is distroless (no dnf).
FROM registry.access.redhat.com/hi/nodejs:26-builder@sha256:a8f5ef6d72222e139493128b122b691d04f1f830309e6b27918ef0b1656f2b92 AS tools
USER 0
RUN dnf install -y --setopt=install_weak_deps=0 util-linux-core nftables && dnf clean all
# Collect each tool with its shared libraries and the dynamic loader (listed by
# the loader itself, so ldd is not needed).
RUN set -e; mkdir -p /out/bin /out/lib; \
    LOADER=$(ls /usr/lib64/ld-linux-*.so.* /lib64/ld-linux-*.so.* 2>/dev/null | head -1); \
    cp -L "$LOADER" /out/lib/; \
    for bin in /usr/bin/nsenter /usr/sbin/nft; do \
      cp "$bin" /out/bin/; \
      "$LOADER" --list "$bin" | awk '$2 == "=>" && $3 ~ /^\// {print $3}' | \
        xargs -r -I{} cp -L {} /out/lib/; \
    done; \
    ls /out/bin /out/lib

FROM quay.io/aipcc/base-images/agentic/openclaw@sha256:01b4def983e30a8e30e196d3f22ad3b759ade3af5e56dde89c306110162cb7bc

USER root

# OpenShell's sandbox supervisor needs nsenter (util-linux) to enter the
# sandbox's network namespace, and nft (nftables) for the policy DNS and
# transparent proxy rules. The base image has neither and no package manager,
# so they come from the tools stage with their own libraries and dynamic
# loader (independent of the base image's glibc). Launchers sit where the
# supervisor looks for them. The build fails if they do not run.
COPY --from=tools /out /usr/local/lib/openshell-tools
RUN set -e; \
    LD=$(ls /usr/local/lib/openshell-tools/lib/ld-linux-*.so.*); \
    for tool in nsenter:/usr/bin/nsenter nft:/usr/sbin/nft; do \
      name=${tool%%:*}; target=${tool#*:}; \
      printf '#!/bin/sh\nexec %s --library-path /usr/local/lib/openshell-tools/lib /usr/local/lib/openshell-tools/bin/%s "$@"\n' \
        "$LD" "$name" > "$target"; \
      chmod 755 "$target"; \
    done; \
    nsenter --version && nft --version && command -v ip

# OpenShell's sandbox filesystem policy (its default and this repo's
# governance-policy) allows /usr, /lib, /app, /etc and /sandbox but not /opt,
# where the base image installs OpenClaw; inside a sandbox `openclaw` failed
# with "Permission denied". Move it under /usr and re-point the CLI.
RUN mv /opt/openclaw /usr/local/lib/openclaw && \
    ln -sfn /usr/local/lib/openclaw/node_modules/.bin/openclaw /usr/local/bin/openclaw && \
    case "$(readlink -f "$(command -v openclaw)")" in /usr/*) ;; *) echo "openclaw resolves outside /usr" >&2; exit 1;; esac && \
    openclaw --version

# The base image's sandbox user owns /sandbox, its home. Referenced by name:
# its UID differs between base image builds (1000, 1001).
RUN grep -q '^sandbox:' /etc/passwd && grep -q '^sandbox:' /etc/group && \
    mkdir -p /sandbox/.openclaw/state /run/secrets && \
    chown -R sandbox:sandbox /sandbox/.openclaw && \
    chmod 700 /sandbox/.openclaw /sandbox/.openclaw/state && \
    chmod 755 /run/secrets

ENV HOME=/sandbox \
    OPENCLAW_HOME=/sandbox \
    SQLITE_TMPDIR=/sandbox/.openclaw/state \
    TMPDIR=/sandbox/.openclaw/state

# Explicit group: OpenShell's supervisor resolves USER through /etc/passwd and
# /etc/group and refuses a user it cannot map to a primary group.
USER sandbox:sandbox

RUN OPENCLAW_NIX_MODE=0 \
    openclaw plugins install @openclaw/openshell-sandbox
