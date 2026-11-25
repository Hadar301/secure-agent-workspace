# Supply digest-pinned build and supervisor images. Build from the SAW root.
ARG GO_BUILDER_IMAGE
ARG SUPERVISOR_IMAGE
FROM ${GO_BUILDER_IMAGE} AS builder
WORKDIR /src
COPY credential-proxy/go.mod ./
COPY credential-proxy/cmd ./cmd
COPY credential-proxy/internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /tmp/saw-credential-proxy ./cmd/saw-credential-proxy
FROM ${SUPERVISOR_IMAGE}
COPY --from=builder /tmp/saw-credential-proxy /usr/local/bin/saw-credential-proxy
