FROM quay.io/redhat-et/openclaw:csb-openclaw-only-openclaw-v2026.7.2-beta.7

USER root

# OpenShell's supervisor resolves the image USER through /etc/passwd: a
# numeric UID with no passwd entry and no group is refused ("uses a numeric
# UID without an explicit group"). groupadd/useradd are missing in some base
# images, so fall back to writing the entries, and fail the build if they
# are still absent.
RUN (grep -q '^[^:]*:[^:]*:65532:' /etc/group || groupadd -g 65532 sandbox 2>/dev/null || \
      echo 'sandbox:x:65532:' >> /etc/group) && \
    (grep -q '^[^:]*:[^:]*:65532:' /etc/passwd || \
      useradd -u 65532 -g 65532 -M -d /sandbox -s /bin/sh sandbox 2>/dev/null || \
      echo 'sandbox:x:65532:65532::/sandbox:/bin/sh' >> /etc/passwd) && \
    grep '^[^:]*:[^:]*:65532:65532:' /etc/passwd && grep '^[^:]*:[^:]*:65532:' /etc/group

RUN mkdir -p /sandbox/.openclaw/state /run/secrets && \
    chown -R 65532:65532 /sandbox && \
    chmod 700 /sandbox/.openclaw /sandbox/.openclaw/state && \
    chmod 755 /run/secrets

RUN curl -fsSL "https://registry.npmjs.org/npm/-/npm-10.9.2.tgz" \
    | tar -xz -C /tmp && \
    mv /tmp/package /app/npm && \
    printf '#!/bin/sh\nexec node /app/npm/bin/npm-cli.js "$@"\n' \
      > /usr/sbin/npm && \
    chmod 755 /usr/sbin/npm

RUN if command -v dnf >/dev/null 2>&1; then \
      dnf install -y --setopt=install_weak_deps=False iproute nftables util-linux && \
      dnf clean all; \
    elif command -v apt-get >/dev/null 2>&1; then \
      apt-get update && \
      apt-get install -y iproute2 nftables util-linux && \
      rm -rf /var/lib/apt/lists/*; \
    elif command -v apk >/dev/null 2>&1; then \
      apk add --no-cache iproute2 nftables util-linux; \
    fi

RUN printf '#!/bin/sh\n\
umask 077\n\
unset OPENCLAW_NIX_MODE\n\
exec /app/entrypoint.sh "$@"\n' \
    > /app/entrypoint-wrapper.sh && \
    chmod 755 /app/entrypoint-wrapper.sh

ENV HOME=/sandbox \
    OPENCLAW_HOME=/sandbox \
    SQLITE_TMPDIR=/sandbox/.openclaw/state \
    TMPDIR=/sandbox/.openclaw/state

# Explicit group: see the passwd note above.
USER 65532:65532

RUN OPENCLAW_NIX_MODE=0 \
    openclaw plugins install @openclaw/openshell-sandbox

ENTRYPOINT ["/app/entrypoint-wrapper.sh"]
