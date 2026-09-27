# Builder stage for nsenter and nft (see the note in the final stage).
FROM quay.io/fedora/fedora:43 AS tools
RUN dnf install -y --setopt=install_weak_deps=0 util-linux-core nftables && dnf clean all
RUN set -e; mkdir -p /out/bin /out/lib; \
    for bin in /usr/bin/nsenter /usr/sbin/nft; do \
      cp "$bin" /out/bin/; \
      ldd "$bin" | awk '$2 == "=>" && $3 ~ /^\// {print $3} $1 ~ /^\/.*ld-linux/ {print $1}' | \
        xargs -r -I{} cp -L {} /out/lib/; \
    done; \
    ls /out/lib/ld-linux-*.so.*

FROM quay.io/aipcc/base-images/agentic/openclaw@sha256:01b4def983e30a8e30e196d3f22ad3b759ade3af5e56dde89c306110162cb7bc

USER root

# OpenShell's sandbox supervisor needs nsenter (util-linux) to enter the
# sandbox's network namespace, and nft (nftables) for the policy DNS and
# transparent proxy rules. The base image has neither and no package manager,
# so they come from the tools stage with their own libraries and dynamic
# loader (independent of the base image's glibc). Launchers sit where the
# supervisor looks for them. The build fails if they do not run.
COPY --from=tools /out /opt/openshell-tools
RUN set -e; \
    LD=$(ls /opt/openshell-tools/lib/ld-linux-*.so.*); \
    for tool in nsenter:/usr/bin/nsenter nft:/usr/sbin/nft; do \
      name=${tool%%:*}; target=${tool#*:}; \
      printf '#!/bin/sh\nexec %s --library-path /opt/openshell-tools/lib /opt/openshell-tools/bin/%s "$@"\n' \
        "$LD" "$name" > "$target"; \
      chmod 755 "$target"; \
    done; \
    nsenter --version && nft --version && command -v ip

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
