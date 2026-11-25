"""Execute the pinned CRI-O policy against public request fixtures."""
import copy
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'kubernetes-runtime'))
from saw_kubernetes import attestation as a, crio_policy as crio

FIXTURES = ROOT / 'tests/fixtures/confidential'


@pytest.fixture
def artifacts():
    pod = json.loads((FIXTURES/'crio-pod.json').read_text())
    data = json.loads((FIXTURES/'crio-generator-data.json').read_text())
    request = json.loads((FIXTURES/'crio-pause-request.json').read_text())
    prefix = (FIXTURES/'osc-1.13-rules.rego').read_text().rstrip()
    assert hashlib.sha256(prefix.encode()).hexdigest() == a.GENPOLICY_RULES_SHA256
    profile = {'name': crio.PROFILE, 'pauseImage': request['OCI']['Annotations']['io.kubernetes.cri-o.ImageName']}
    generated = prefix+'\n\npolicy_data := '+a.canonical(data)+'\n'
    return pod, generated, profile, request


def evaluate(tmp_path, template, request, query='data.agent_policy.CreateContainerRequest'):
    opa = shutil.which('opa')
    if not opa:
        pytest.skip('OPA is required for executable policy tests')
    policy = tmp_path/'policy.rego'
    policy.write_text(template.replace(a.IDENTITY_MARKER, a.canonical({'owner':'alice','registration':'0123456789abcdef'})))
    input_file = tmp_path/'input.json'; input_file.write_text(a.canonical(request))
    state = tmp_path/'state.json'; state.write_text('{"pstate":{}}')
    result = subprocess.run([opa,'eval','--format=json','-d',str(policy),'-d',str(state),
        '-i',str(input_file),query],capture_output=True,text=True,timeout=15)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)['result'][0]['expressions'][0]['value'] if json.loads(result.stdout).get('result') else False


def test_native_pause_passes_exact_crio_profile(tmp_path, artifacts):
    pod, generated, profile, request = artifacts
    template = a.compile_launch_policy(pod, generated, profile)
    result = evaluate(tmp_path, template, request)
    assert isinstance(result, dict) and result['allowed'] is True
    assert any(op['value']=='qualification-agent' for op in result['ops'])
    assert crio.source_template(template) == a.compile_launch_policy(pod, generated)


def changed_request(request, change):
    request = copy.deepcopy(request)
    oci = request['OCI']; anno=oci['Annotations']; proc=oci['Process']
    if change=='image': anno['io.kubernetes.cri-o.ImageName']='registry.example.test/other@sha256:'+'c'*64
    elif change=='command': proc['Args']=['/bin/sh']
    elif change=='uid': proc['User']['UID']=1001
    elif change=='gid': proc['User']['GID']=1001
    elif change=='capability': proc['Capabilities']['Effective'].append('CAP_SYS_ADMIN')
    elif change=='removed-capability': proc['Capabilities']['Effective'].pop()
    elif change=='root-writable': oci['Root']['Readonly']=False
    elif change=='namespace': anno['io.kubernetes.pod.namespace']='saw-bob'
    elif change=='name': anno['io.kubernetes.pod.name']='other'
    elif change=='containerd-identity': anno['io.kubernetes.cri.sandbox-namespace']='saw-bob'
    elif change=='duplicate-identity': anno['io.kubernetes.cri-o.Namespace']='saw-bob'
    elif change=='labels':
        labels=json.loads(anno['io.kubernetes.cri-o.Labels']); labels['io.kubernetes.pod.namespace']='saw-bob'; anno['io.kubernetes.cri-o.Labels']=a.canonical(labels)
    elif change=='metadata':
        meta=json.loads(anno['io.kubernetes.cri-o.Metadata']); meta['namespace']='saw-bob'; anno['io.kubernetes.cri-o.Metadata']=a.canonical(meta)
    elif change=='runtime': anno['io.kubernetes.cri-o.RuntimeHandler']='runc'
    elif change=='privileged': anno['io.kubernetes.cri-o.PrivilegedRuntime']='true'
    elif change=='host-network': anno['io.kubernetes.cri-o.HostNetwork']='true'
    elif change=='oci': oci['Version']='1.1.0'
    elif change=='manager': anno['io.container.manager']='containerd'
    elif change=='root-path': oci['Root']['Path']='/run/kata-containers/'+'f'*64+'/rootfs'
    elif change=='mount-source': oci['Mounts'][-1]['source']='/etc/shadow'
    elif change=='mount-writable': oci['Mounts'][-1]['options'].remove('ro')
    elif change=='extra-mount': oci['Mounts'].append({'source':'/etc/shadow','destination':'/host-secret','type_':'bind','options':['ro']})
    elif change=='env': proc['Env'].append('LD_PRELOAD=/tmp/untrusted.so')
    elif change=='storage-image':
        value=json.loads(request['storages'][0]['driver_options'][0].split('=',1)[1]); value['metadata']['io.kubernetes.cri-o.ImageName']='registry.example.test/foreign@sha256:'+'d'*64; request['storages'][0]['driver_options']=['image_guest_pull='+a.canonical(value)]
    elif change=='storage-option': request['storages'][0]['driver_options'].append('other=unsafe')
    elif change=='storage-source': request['storages'][0]['source']='foreign'
    elif change=='storage-path': request['storages'][0]['mount_point']='/run/other/rootfs'
    elif change=='extra-storage': request['storages'].append(copy.deepcopy(request['storages'][0]))
    else: raise AssertionError(change)
    return request


@pytest.mark.parametrize('change',['image','command','uid','gid','capability','removed-capability','root-writable',
    'namespace','name','containerd-identity','duplicate-identity','labels','metadata',
    'runtime','privileged','host-network','oci','manager','root-path','mount-source',
    'mount-writable','extra-mount','env','storage-image','storage-option','storage-source','storage-path','extra-storage'])
def test_native_pause_rejects_changed_boundary(tmp_path, artifacts, change):
    pod, generated, profile, request=artifacts
    template=a.compile_launch_policy(pod,generated,profile)
    assert evaluate(tmp_path,template,changed_request(request,change)) is False


@pytest.mark.parametrize('request_name',['ExecProcessRequest','SetPolicyRequest','ReadStreamRequest',
    'WriteStreamRequest','GetDiagnosticDataRequest'])
def test_crio_keeps_host_access_denied(tmp_path,artifacts,request_name):
    pod,generated,profile,request=artifacts
    assert evaluate(tmp_path,a.compile_launch_policy(pod,generated,profile),request,
        'data.agent_policy.'+request_name) is False


@pytest.mark.parametrize('change',['profile','pause-tag','extra-profile-field','rules'])
def test_unknown_generation_inputs_fail_closed(artifacts,change):
    pod,generated,profile,_=artifacts
    if change=='profile': profile['name']='other'
    elif change=='pause-tag': profile['pauseImage']='registry.example.test/infra:latest'
    elif change=='extra-profile-field': profile['skipVerification']=True
    else: generated=generated.replace('default CreateContainerRequest := false','default CreateContainerRequest := true')
    with pytest.raises(a.AttestationError,match='^LaunchPolicyRejected$'):
        a.compile_launch_policy(pod,generated,profile)


def application_request(artifacts):
    # Independent runtime fixture. The canary configuration removes the
    # optional host subscription mount; every other native field stays.
    request = json.loads((FIXTURES / 'crio-application-request.json').read_text())
    request['OCI']['Mounts'] = [m for m in request['OCI']['Mounts']
                               if m['destination'] != '/run/secrets']
    return request


def test_native_application_keeps_exact_nonroot_process(tmp_path,artifacts):
    pod,generated,profile,_=artifacts
    result=evaluate(tmp_path,a.compile_launch_policy(pod,generated,profile),application_request(artifacts))
    assert isinstance(result,dict) and result['allowed'] is True


@pytest.mark.parametrize('change',['root','command','image','environment','capability','readonly','privilege','metadata'])
def test_application_rejects_changed_process(tmp_path,artifacts,change):
    pod,generated,profile,_=artifacts
    request=application_request(artifacts);oci=request['OCI']
    if change=='root': oci['Process']['User']['UID']=0
    elif change=='command': oci['Process']['Args']=['/bin/sh']
    elif change=='image': oci['Annotations']['io.kubernetes.cri-o.ImageName']=profile['pauseImage']
    elif change=='environment': oci['Process']['Env'].append('LD_PRELOAD=/tmp/foreign.so')
    elif change=='capability': oci['Process']['Capabilities']['Effective'].append('CAP_SYS_ADMIN')
    elif change=='readonly': oci['Root']['Readonly']=False
    elif change=='privilege': oci['Process']['NoNewPrivileges']=False
    else: oci['Annotations']['io.kubernetes.cri-o.Metadata']='{"name":"foreign"}'
    assert evaluate(tmp_path,a.compile_launch_policy(pod,generated,profile),request) is False


def crio_launch_bundle():
    """Use pinned generator output for both measured roles, without a cluster."""
    base=ROOT/'tests/fixtures/confidential'
    pod=json.loads((base/'crio-pod.json').read_text())
    data=json.loads((base/'crio-generator-data.json').read_text())
    prefix=(base/'osc-1.13-rules.rego').read_text().rstrip()
    runtime={'name':'crio-1.34-oci-1.2.1-v1','pauseImage':'registry.example.test/infra@sha256:'+'b'*64}
    entries={}
    for role in ('supervisor','workload'):
        p=copy.deepcopy(pod); d=copy.deepcopy(data)
        if role=='supervisor':
            c=p['spec']['containers'][0];c['name']='supervisor'
            c['command']=['/usr/local/bin/saw-credential-proxy','supervise','/openshell-supervisor',
                '--upstream-proxy','http://127.0.0.1:3128',
                '--upstream-proxy-ca-bundle','/run/openshell/saw-proxy-ca.pem']
            policy={'markerPrefix':'saw','allowHosts':['api.example.test'],
                'profiles':{'nvidia':['api.example.test']},
                'bindings':[{'secret':'inference','key':'api_key','providers':['nvidia']}]}
            bootstrap=a.supervisor_bootstrap(policy,'alice','0123456789abcdef')
            c['env']=[{'name':a.BOOTSTRAP_ENV,'value':bootstrap}]
            o=d['containers'][1]['OCI'];o['Annotations']['io.kubernetes.cri.container-name']='supervisor'
            o['Process']['Args']=c['command'];o['Process']['Env'].append(a.BOOTSTRAP_ENV+'='+bootstrap)
        generated=prefix+'\n\npolicy_data := '+a.canonical(d)
        entries[role]={'pod':p,'template':a.compile_launch_policy(p,generated,runtime),'runtimeProfile':copy.deepcopy(runtime)}
    return {'default/notebook':entries}


def test_crio_launch_bundle_revalidates_the_exact_profile():
    bundle=crio_launch_bundle()
    assert a.validate_launch_policies(bundle,a.digest(bundle))==a.digest(bundle)


@pytest.mark.parametrize('change',['rules','profile','source','adapted-command','extra-profile'])
def test_crio_launch_bundle_rejects_tampering(change):
    bundle=crio_launch_bundle(); entry=bundle['default/notebook']['workload']
    if change=='rules':entry['template']=entry['template'].replace('input.OCI.Version == "1.2.1"','true')
    elif change=='profile':entry['runtimeProfile']['pauseImage']='registry.example.test/foreign@sha256:'+'c'*64
    elif change=='source':entry['template']=entry['template'].replace('"saw_crio_source":{','"saw_crio_source":{"unexpected":true,')
    elif change=='adapted-command':entry['template']=entry['template'].replace('["/usr/bin/pod"]','["/bin/sh"]')
    else:entry['runtimeProfile']['permissive']=True
    with pytest.raises(a.AttestationError,match='^AttestationLaunchPolicyRejected$'):
        a.validate_launch_policies(bundle,a.digest(bundle))



def test_adapter_source_matches_the_reviewed_lock():
    import yaml
    lock = yaml.safe_load((ROOT / "deploy/confidential/source-lock.yaml").read_text())
    profile = lock["policyGenerator"]["runtimeProfiles"]["crio"]
    assert profile["name"] == crio.PROFILE
    assert hashlib.sha256((ROOT / profile["module"]).read_bytes()).hexdigest() == profile["moduleSHA256"]



def test_opaque_host_subscription_mount_is_denied(tmp_path, artifacts):
    pod, generated, profile, _ = artifacts
    request = json.loads((FIXTURES / 'crio-application-request.json').read_text())
    assert any(m['destination'] == '/run/secrets' for m in request['OCI']['Mounts'])
    assert evaluate(tmp_path, a.compile_launch_policy(pod, generated, profile), request) is False


@pytest.mark.parametrize('value', ['yes', 'false', '0'])
def test_runtime_nss_option_cannot_change(tmp_path, artifacts, value):
    pod, generated, profile, _ = artifacts
    request = application_request(artifacts)
    request['OCI']['Process']['Env'] = ['NSS_SDB_USE_CACHE='+value if item.startswith('NSS_SDB_USE_CACHE=') else item
                                       for item in request['OCI']['Process']['Env']]
    assert evaluate(tmp_path, a.compile_launch_policy(pod, generated, profile), request) is False


@pytest.mark.parametrize('entry', ['PATH=/tmp/foreign-bin', 'HOSTNAME=foreign'])
def test_conflicting_duplicate_environment_is_denied(tmp_path, artifacts, entry):
    pod, generated, profile, _ = artifacts
    request = application_request(artifacts)
    request['OCI']['Process']['Env'].append(entry)
    assert evaluate(tmp_path, a.compile_launch_policy(pod, generated, profile), request) is False



@pytest.mark.parametrize("cached", ["c"*64, "sha256:"+"c"*64])
def test_cached_config_id_does_not_select_guest_image(tmp_path, artifacts, cached):
    pod, generated, profile, _ = artifacts
    request = application_request(artifacts)
    annotations = request["OCI"]["Annotations"]
    approved = annotations["io.kubernetes.cri-o.ImageName"]
    annotations["io.kubernetes.cri-o.Image"] = cached
    storage = next(s for s in request["storages"] if s["driver"] == "image_guest_pull")
    metadata = json.loads(storage["driver_options"][0].split("=",1)[1])["metadata"]
    metadata["io.kubernetes.cri-o.Image"] = cached
    storage["driver_options"] = ["image_guest_pull="+a.canonical({"metadata":metadata})]
    template = a.compile_launch_policy(pod, generated, profile)
    result = evaluate(tmp_path, template, request)
    assert isinstance(result, dict) and result["allowed"] is True
    assert storage["source"] == approved
    storage["source"] = "registry.example.test/foreign@sha256:"+"d"*64
    assert evaluate(tmp_path, template, request) is False


@pytest.mark.parametrize("hint", ["registry.example.test/agent:latest",
    "registry.example.test/foreign@sha256:"+"d"*64, "unknown", "c"*63])
def test_unrecognized_or_conflicting_image_hint_is_denied(tmp_path, artifacts, hint):
    pod, generated, profile, _ = artifacts
    request = application_request(artifacts)
    request["OCI"]["Annotations"]["io.kubernetes.cri-o.Image"] = hint
    storage = next(s for s in request["storages"] if s["driver"] == "image_guest_pull")
    metadata = json.loads(storage["driver_options"][0].split("=",1)[1])["metadata"]
    metadata["io.kubernetes.cri-o.Image"] = hint
    storage["driver_options"] = ["image_guest_pull="+a.canonical({"metadata":metadata})]
    assert evaluate(tmp_path, a.compile_launch_policy(pod,generated,profile), request) is False
