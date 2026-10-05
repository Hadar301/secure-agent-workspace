# OpenShell 0.1.x needs Rust 1.94 (rust-version in its Cargo.toml).
FROM --platform=linux/amd64 rust:1.94-bookworm AS builder

RUN apt-get update && apt-get install -y protobuf-compiler pkg-config libssl-dev git make cmake g++ && rm -rf /var/lib/apt/lists/*

WORKDIR /build
ARG OPENSHELL_REF=main
RUN git init . \
    && git remote add origin https://github.com/NVIDIA/OpenShell.git \
    && git fetch --depth 1 origin "${OPENSHELL_REF}" \
    && git checkout --detach FETCH_HEAD

WORKDIR /build/examples/governance-interceptor
# Workaround for NVIDIA/OpenShell#3929 (v0.1.2): the gateway hashes provider
# profile annotations in map order, so a profile with more than one annotation
# gives a different provider_env_revision on every call and no sandbox with a
# provider becomes ready ("Startup configuration did not stabilize"). Keep only
# the signature JWT, which already carries the hash (claim) and key id (header);
# the gateway treats the annotations as opaque. Drop this once #3929 is fixed.
RUN perl -0pi -e 's/\n    profile\n        \.annotations\n        \.insert\(PROFILE_HASH_ANNOTATION\.to_string\(\), profile_hash\);\n    profile\.annotations\.insert\(\n        PROFILE_SIGNATURE_KID_ANNOTATION\.to_string\(\),\n        policy_signer\.kid\(\)\.to_string\(\),\n    \);\n/\n/' src/main.rs \
    && ! grep -q 'insert(PROFILE_HASH_ANNOTATION' src/main.rs
# Harness driver-config guard. allow_driver_config is a
# fleet-wide switch, and OpenShell's resource admission never inspects who sent
# a driver_config envelope or what mount mode it asks for
# (crates/openshell-core/src/resource_admission.rs). The interceptor sees both,
# so the rules go here: only a platform admin may send driver config, and every
# mount in it must be read-only. CreateSandboxTemplate is bound too, because
# workload_template resolves after the interceptor seam.
RUN perl -0pi -e 's#                binding\(\n                    "govern-create-provider",#                binding(\n                    "govern-create-sandbox-template",\n                    "CreateSandboxTemplate",\n                    &[GatewayInterceptorPhase::Validate],\n                ),\n                binding(\n                    "govern-create-provider",#' src/main.rs \
    && grep -q '"govern-create-sandbox-template"' src/main.rs
RUN perl -0pi -e 's#            \("CreateSandbox", interceptor_evaluation::Phase::Validate\(_\)\) => \{\n                Ok\(validate_create_sandbox\(#            ("CreateSandboxTemplate", interceptor_evaluation::Phase::Validate(_)) => {\n                Ok(validate_driver_config(\n                    operation\n                        .pointer("/template/spec/driverConfig")\n                        .or_else(|| operation.pointer("/template/spec/driver_config")),\n                    &evaluation.principal,\n                ))\n            }\n            ("CreateSandbox", interceptor_evaluation::Phase::Validate(_)) => {\n                let gate = validate_driver_config(\n                    operation\n                        .pointer("/spec/template/driverConfig")\n                        .or_else(|| operation.pointer("/spec/template/driver_config")),\n                    &evaluation.principal,\n                );\n                if !gate.allowed {\n                    return Ok(gate);\n                }\n                Ok(validate_create_sandbox(#' src/main.rs \
    && grep -q 'let gate = validate_driver_config(' src/main.rs
RUN printf '%s\n' \
'' \
'const HARNESS_ADMIN_ROLE: &str = "openshell-admin";' \
'' \
'/// Reject caller-supplied driver config that is not an admin read-only mount.' \
'fn validate_driver_config(' \
'    driver_config: Option<&Value>,' \
'    principal: &HashMap<String, String>,' \
') -> InterceptorResult {' \
'    let Some(Value::Object(drivers)) = driver_config else {' \
'        return allow();' \
'    };' \
'    if drivers.is_empty() {' \
'        return allow();' \
'    }' \
'    let is_admin = principal.get("kind").map(String::as_str) == Some("user")' \
'        && principal.get("roles").is_some_and(|roles| {' \
'            roles.split(",").any(|role| role.trim() == HARNESS_ADMIN_ROLE)' \
'        });' \
'    if !is_admin {' \
'        return deny("driver config may only be submitted by a platform admin identity");' \
'    }' \
'    for block in drivers.values() {' \
'        let Some(mounts) = block.get("mounts") else {' \
'            continue;' \
'        };' \
'        let Some(mounts) = mounts.as_array() else {' \
'            return deny("driver config mounts must be an array");' \
'        };' \
'        if mounts' \
'            .iter()' \
'            .any(|mount| mount.get("read_only") != Some(&Value::Bool(true)))' \
'        {' \
'            return deny("driver config mounts must each set read_only: true");' \
'        }' \
'    }' \
'    allow()' \
'}' \
>> src/main.rs
RUN cargo build --release --target-dir /out

FROM --platform=linux/amd64 debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /out/release/governance-interceptor /usr/local/bin/governance-interceptor
ENTRYPOINT ["governance-interceptor"]
