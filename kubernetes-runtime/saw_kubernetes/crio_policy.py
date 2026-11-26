"""Explicit CRI-O 1.34 / OCI 1.2.1 adapter for the pinned OSC rules.

The adapter validates native identity and guest-pull metadata before it passes
an equivalent request to the vendor's unchanged process/Linux/storage checks.
It does not qualify an image, platform, Trustee binding, or release.
"""
import copy
import hashlib
import json
import re

PROFILE = "crio-1.34-oci-1.2.1-v1"
IMAGE = re.compile(r"[a-z0-9][a-z0-9.-]*(?::[0-9]+)?(?:/[a-z0-9]+(?:[._-]+[a-z0-9]+)*)+@sha256:[a-f0-9]{64}\Z")
MARKER = "__SAW_IDENTITY_JSON__"
VENDOR_RULES_SHA256 = "2655cbb7641829dd88e0647cac76407a6072cdd130c77fda436fa9af08f4b43e"
CAPS = ["CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FSETID", "CAP_FOWNER", "CAP_SETGID",
        "CAP_SETUID", "CAP_SETPCAP", "CAP_NET_BIND_SERVICE", "CAP_KILL"]
# Only the public entry point changes. The pinned vendor checks remain intact.
ENTRY = 'CreateContainerRequest := {"ops": ops, "allowed": true} if {'
RENAMED = 'saw_containerd_CreateContainerRequest := {"ops": ops, "allowed": true} if {'
RULES = r'''
# SAW CRI-O profile. Native fields are checked before normalization. The
# normalized request is used only by the pinned containerd-format validator.
# The pinned generator omits this newer telemetry request. Keep it denied
# with a defined decision instead of an agent policy evaluation error.
default GetMetricsRequest := false

CreateContainerRequest := result if {
    saw_crio_identity
    saw_crio_storage
    saw_crio_environment
    normalized := saw_crio_normalized
    result := saw_containerd_CreateContainerRequest with input as normalized
    result.allowed
}

# Duplicate entries with the same value are harmless runtime additions.
# Conflicting duplicates must not depend on an application's getenv behavior.
saw_crio_environment if {
    env := input.OCI.Process.Env
    every entry in env {
        name := split(entry, "=")[0]
        values := {other | other := env[_]; startswith(other, concat("", [name, "="]))}
        count(values) == 1
    }
    not saw_crio_bad_nss_env
}

saw_crio_bad_nss_env if {
    some entry in input.OCI.Process.Env
    startswith(entry, "NSS_SDB_USE_CACHE=")
    entry != "NSS_SDB_USE_CACHE=no"
}

saw_crio_identity if {
    a := input.OCI.Annotations
    c := policy_data.saw_crio
    input.OCI.Version == "1.2.1"
    a["io.container.manager"] == "cri-o"
    regex.match("^[a-f0-9]{64}$", input.container_id)
    input.exec_id == input.container_id
    a["io.kubernetes.cri-o.ContainerID"] == input.container_id
    regex.match("^[a-f0-9]{64}$", a["io.kubernetes.cri-o.SandboxID"])
    regex.match(c.namePattern, a["io.kubernetes.pod.name"])
    a["io.kubernetes.pod.namespace"] == c.namespace
    object.get(a, "io.kubernetes.cri-o.Namespace", c.namespace) == c.namespace
    regex.match("^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$", a["io.kubernetes.pod.uid"])
    object.get(a, "io.kubernetes.cri-o.RuntimeHandler", c.runtimeHandler) == c.runtimeHandler
    object.get(a, "io.kubernetes.cri-o.HostNetwork", "false") == "false"
    object.get(a, "io.kubernetes.cri-o.PrivilegedRuntime", "false") == "false"
    a["io.katacontainers.pkg.oci.bundle_path"] == concat("", ["/run/containers/storage/overlay-containers/", input.container_id, "/userdata"])
    input.OCI.Root.Path == concat("", ["/run/kata-containers/", input.container_id, "/rootfs"])
    saw_crio_image_hint(a)
    saw_crio_kind(a)
    # A second identity vocabulary must not change the interpretation.
    not saw_crio_conflicting_annotation
    labels := json.unmarshal(a["io.kubernetes.cri-o.Labels"])
    labels["io.kubernetes.pod.name"] == a["io.kubernetes.pod.name"]
    labels["io.kubernetes.pod.namespace"] == c.namespace
    labels["io.kubernetes.pod.uid"] == a["io.kubernetes.pod.uid"]
    labels["io.kubernetes.container.name"] == a["io.kubernetes.container.name"]
}

# The Image field can become the node's cached config ID. It does not
# select guest content. The pinned runtime uses ImageName as storage.source;
# both remain bound to the approved manifest in kind and storage checks.
saw_crio_image_hint(a) if {
    a["io.kubernetes.cri-o.Image"] == a["io.kubernetes.cri-o.ImageName"]
}

saw_crio_image_hint(a) if {
    a["io.kubernetes.cri-o.ContainerType"] == "container"
    regex.match("^(sha256:)?[a-f0-9]{64}$", a["io.kubernetes.cri-o.Image"])
}

saw_crio_conflicting_annotation if {
    some key in object.keys(input.OCI.Annotations)
    startswith(key, "io.kubernetes.cri.")
}

saw_crio_kind(a) if {
    a["io.kubernetes.cri-o.ContainerType"] == "sandbox"
    a["io.kubernetes.cri-o.Namespace"] == policy_data.saw_crio.namespace
    a["io.kubernetes.cri-o.RuntimeHandler"] == policy_data.saw_crio.runtimeHandler
    a["io.kubernetes.cri-o.HostNetwork"] == "false"
    a["io.kubernetes.cri-o.PrivilegedRuntime"] == "false"
    a["io.katacontainers.pkg.oci.container_type"] == "pod_sandbox"
    a["io.kubernetes.container.name"] == "POD"
    a["io.kubernetes.cri-o.ImageName"] == policy_data.saw_crio.pauseImage
    a["io.kubernetes.cri-o.SandboxID"] == input.container_id
    input.OCI.Process.Capabilities == policy_data.containers[0].OCI.Process.Capabilities
    input.OCI.Process.Env == policy_data.containers[0].OCI.Process.Env
    count(input.OCI.Mounts) == count(policy_data.containers[0].OCI.Mounts)
    a["io.kubernetes.cri-o.KubeName"] == a["io.kubernetes.pod.name"]
    a["io.kubernetes.cri-o.HostName"] == a["io.kubernetes.pod.name"]
    metadata := json.unmarshal(a["io.kubernetes.cri-o.Metadata"])
    metadata == {"name": a["io.kubernetes.pod.name"], "namespace": a["io.kubernetes.pod.namespace"], "uid": a["io.kubernetes.pod.uid"]}
}

saw_crio_kind(a) if {
    a["io.kubernetes.cri-o.ContainerType"] == "container"
    a["io.katacontainers.pkg.oci.container_type"] == "pod_container"
    name := a["io.kubernetes.container.name"]
    a["io.kubernetes.cri-o.ImageName"] == policy_data.saw_crio.images[name]
    input.OCI.Process.User.UID > 0
    input.OCI.Process.NoNewPrivileges == true
    metadata := json.unmarshal(a["io.kubernetes.cri-o.Metadata"])
    metadata.name == name
    object.keys(metadata) - {"name", "attempt"} == set()
    object.get(metadata, "attempt", 0) == 0
}

# The pinned guest handler uses storage.source for application image pulls.
# It uses the immutable guest's /pause_bundle for sandbox metadata. Bind both
# native metadata and source, so a host cannot switch these two paths.
saw_crio_storage if {
    pulls := [s | s := input.storages[_]; s.driver == "image_guest_pull"]
    count(pulls) == 1
    s := pulls[0]
    s.fstype == "overlay"
    s.fs_group == null
    s.shared == false
    s.options == []
    s.mount_point == input.OCI.Root.Path
    saw_crio_storage_source(s.source, input.OCI.Annotations)
    count(s.driver_options) == 1
    startswith(s.driver_options[0], "image_guest_pull=")
    raw := trim_prefix(s.driver_options[0], "image_guest_pull=")
    config := json.unmarshal(raw)
    object.keys(config) == {"metadata"}
    m := config.metadata
    a := input.OCI.Annotations
    every key in ["io.kubernetes.cri-o.Image", "io.kubernetes.cri-o.ImageName",
                   "io.kubernetes.cri-o.ContainerType", "io.kubernetes.cri-o.ContainerID",
                   "io.kubernetes.cri-o.SandboxID", "io.kubernetes.pod.name",
                   "io.kubernetes.pod.namespace", "io.kubernetes.pod.uid",
                   "io.kubernetes.container.name", "io.katacontainers.pkg.oci.container_type"] {
        m[key] == a[key]
    }
    not saw_crio_storage_conflict(m)
}

saw_crio_storage_source(source, a) if {
    a["io.kubernetes.cri-o.ContainerType"] == "sandbox"
    source == "pause"
}

saw_crio_storage_source(source, a) if {
    a["io.kubernetes.cri-o.ContainerType"] == "container"
    source == a["io.kubernetes.cri-o.ImageName"]
}

saw_crio_storage_conflict(m) if {
    some key in object.keys(m)
    startswith(key, "io.kubernetes.cri.")
}

saw_crio_normalized := object.union(object.remove(input, {"OCI"}), {"OCI": oci}) if {
    a := input.OCI.Annotations
    common := {
        "io.kubernetes.cri.container-type": a["io.kubernetes.cri-o.ContainerType"],
        "io.kubernetes.cri.sandbox-name": a["io.kubernetes.pod.name"],
        "io.kubernetes.cri.sandbox-namespace": a["io.kubernetes.pod.namespace"],
        "io.kubernetes.cri.sandbox-id": a["io.kubernetes.cri-o.SandboxID"],
        "io.kubernetes.cri.image-name": a["io.kubernetes.cri-o.ImageName"],
        "io.katacontainers.pkg.oci.bundle_path": a["io.katacontainers.pkg.oci.bundle_path"],
        "io.katacontainers.pkg.oci.container_type": a["io.katacontainers.pkg.oci.container_type"],
    }
    anno := object.union(common, saw_crio_kind_annotations(a))
    oci := object.union(object.remove(input.OCI, {"Annotations"}), {"Annotations": anno})
}

saw_crio_kind_annotations(a) := {
    "io.kubernetes.cri.sandbox-log-directory": concat("", ["/var/log/pods/", a["io.kubernetes.pod.namespace"], "_", a["io.kubernetes.pod.name"], "_", a["io.kubernetes.pod.uid"]]),
    "nerdctl/network-namespace": a["nerdctl/network-namespace"],
} if {
    a["io.kubernetes.cri-o.ContainerType"] == "sandbox"
    regex.match("^/var/run/netns/[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$", a["nerdctl/network-namespace"])
}

saw_crio_kind_annotations(a) := {"io.kubernetes.cri.container-name": a["io.kubernetes.container.name"]} if {
    a["io.kubernetes.cri-o.ContainerType"] == "container"
}
'''.strip()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def profile(value):
    if (not isinstance(value, dict) or set(value) != {"name", "pauseImage"}
            or value["name"] != PROFILE or not isinstance(value["pauseImage"], str)
            or not IMAGE.fullmatch(value["pauseImage"])):
        raise ValueError("LaunchRuntimeProfileRejected")
    return copy.deepcopy(value)


def adapted_prefix(prefix):
    if (hashlib.sha256(prefix.encode()).hexdigest() != VENDOR_RULES_SHA256
            or prefix.count(ENTRY) != 1 or 'saw_crio' in prefix):
        raise ValueError("LaunchRuntimeProfileRejected")
    return prefix.replace(ENTRY, RENAMED) + "\n\n" + RULES


def compile_policy(pod, template, runtime_profile):
    """Adapt a template only after the canonical generator checks pass."""
    config = profile(runtime_profile)
    prefix, encoded = template.split("\n\npolicy_data := ", 1)
    data = json.loads(encoded.replace(MARKER, 'null'))
    if data.pop("saw_identity") is not None:
        raise ValueError("LaunchRuntimeProfileRejected")
    original = copy.deepcopy(data)
    if any(key.startswith("saw_crio") for key in data):
        raise ValueError("LaunchRuntimeProfileRejected")
    pauses = [c for c in data["containers"] if c["OCI"]["Annotations"]["io.kubernetes.cri.container-type"] == "sandbox"]
    pause, = pauses
    if data["containers"][0] is not pause:
        raise ValueError("LaunchRuntimeProfileRejected")
    name_pattern = pause["OCI"]["Annotations"]["io.kubernetes.cri.sandbox-name"]
    data['saw_crio'] = {
        'name': config['name'], 'pauseImage': config['pauseImage'],
        'namePattern': name_pattern, 'namespace': pod['metadata']['namespace'],
        'runtimeHandler': pod['spec']['runtimeClassName'],
        'images': {c['name']: c['image'] for c in pod['spec']['containers'] + pod['spec'].get('initContainers', [])},
    }
    data['saw_crio_source'] = original
    # OpenShift's runtime sets this fixed public NSS cache option. It does
    # not permit another NSS value or a general environment wildcard.
    data['request_defaults']['CreateContainerRequest']['allow_env_regex'].append(
        '^NSS_SDB_USE_CACHE=no$')
    original_containers = {c['name']: c for c in pod['spec']['containers'] + pod['spec'].get('initContainers', [])}
    for container in data['containers']:
        oci = container['OCI']
        oci['Version'] = '1.2.1'
        oci['Annotations']['io.katacontainers.pkg.oci.bundle_path'] = '/run/containers/storage/overlay-containers/$(bundle-id)/userdata'
        if container is pause:
            continue
        name = oci['Annotations']['io.kubernetes.cri.container-name']
        declared = {m['mountPath'] for m in original_containers[name].get('volumeMounts', [])}
        if declared & {'/run/.containerenv', '/run/secrets', '/etc/hostname', '/etc/resolv.conf'}:
            raise ValueError('LaunchRuntimeProfileRejected')
        access = 'ro' if oci['Root']['Readonly'] else 'rw'
        mounts = []
        for mount in oci['Mounts']:
            destination = mount['destination']
            if destination in {'/var/run/secrets/kubernetes.io/serviceaccount', '/var/run/secrets/azure/tokens'} and destination not in declared:
                continue
            if destination == '/etc/resolv.conf':
                mount['options'] = [access, 'bind', 'nodev', 'nosuid', 'noexec']
            elif destination == '/etc/hostname':
                mount['options'] = [access, 'bind']
            elif mount['type_'] == 'bind' and (destination in declared or destination in {'/etc/hosts', '/dev/termination-log'}):
                if 'bind' in mount['options']:
                    raise ValueError('LaunchRuntimeProfileRejected')
                mount['options'] += ['bind']
            mounts.append(mount)
        mounts.append({'destination':'/run/.containerenv','type_':'bind',
            'source':'$(sfprefix).containerenv$','options':[access,'bind']})
        oci['Mounts'] = mounts
    oci = pause['OCI']
    oci['Annotations']['nerdctl/network-namespace'] = r'^/var/run/netns/[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$'
    oci['Annotations']['io.kubernetes.cri.image-name'] = config['pauseImage']
    oci['Process'].update(User={'UID': 0, 'GID': 0, 'AdditionalGids': [], 'Username': ''},
        Args=['/usr/bin/pod'], NoNewPrivileges=False,
        Capabilities={k: (CAPS[:] if k in {'Bounding', 'Effective', 'Permitted'} else [])
                      for k in ('Bounding','Effective','Permitted','Ambient','Inheritable')})
    oci['Process']['Env'] = ['PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', 'TERM=xterm']
    oci['Linux']['MaskedPaths'] = []
    oci['Linux']['ReadonlyPaths'] = []
    oci['Linux']['Sysctl'] = {'net.ipv4.ping_group_range': '0 2147483647'}
    mounts = oci['Mounts']
    if any(m['destination'] == '/etc/hostname' for m in mounts):
        raise ValueError('LaunchRuntimeProfileRejected')
    for mount in mounts:
        if mount['destination'] == '/etc/resolv.conf':
            mount['options'] = ['ro','bind','nodev','nosuid','noexec']
    mounts.append({'destination':'/etc/hostname', 'type_':'bind',
        'source':'$(sfprefix)hostname$', 'options':['ro','bind','nodev','nosuid','noexec']})
    data['saw_identity'] = MARKER
    result = canonical(data).replace(json.dumps(MARKER), MARKER)
    return adapted_prefix(prefix) + '\n\npolicy_data := ' + result + '\n'


def source_template(template):
    """Recover reviewed generator output for full enrollment revalidation."""
    prefix, encoded = template.split('\n\npolicy_data := ', 1)
    marker = '\n\n' + RULES
    if not prefix.endswith(marker):
        raise ValueError('LaunchRuntimeProfileRejected')
    base = prefix[:-len(marker)]
    if base.count(RENAMED) != 1:
        raise ValueError('LaunchRuntimeProfileRejected')
    base = base.replace(RENAMED, ENTRY)
    if adapted_prefix(base) != prefix:
        raise ValueError('LaunchRuntimeProfileRejected')
    data = json.loads(encoded.replace(MARKER, 'null'))
    if data.get('saw_identity', False) is not None:
        raise ValueError('LaunchRuntimeProfileRejected')
    original = data['saw_crio_source']
    if not isinstance(original, dict) or 'saw_identity' in original:
        raise ValueError('LaunchRuntimeProfileRejected')
    original['saw_identity'] = MARKER
    return base + '\n\npolicy_data := ' + canonical(original).replace(json.dumps(MARKER), MARKER) + '\n'
