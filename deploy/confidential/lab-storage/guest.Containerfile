# SPDX-License-Identifier: Apache-2.0
# Pass approved digest references for both build arguments.
# A lab derivative. Not an official vendor image or a qualified guest helper.
ARG WRAPPER_IMAGE
ARG DRIVER_IMAGE
FROM ${WRAPPER_IMAGE} AS wrapper
FROM ${DRIVER_IMAGE}
COPY --from=wrapper /csi-podvm-wrapper /usr/local/bin/csi-podvm-wrapper
LABEL saw.redhat.com/component="peerpod-guest-storage-lab" \
      saw.redhat.com/qualification="experimental-unqualified"
