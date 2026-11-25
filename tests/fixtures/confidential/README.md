# Confidential policy fixtures

`osc-1.13-rules.rego` is the unchanged Apache-2.0 vendor rule code from
`openshift/kata-containers` revision
`b17f640901e87e620ab74db428e8e0883cb91b81`.
`deploy/confidential/source-lock.yaml` pins its digest.

The JSON fixtures use reserved example registry names, generic owner and Pod
identities, fixed nonsecret IDs, and a representative nonroot UID. They model
the CRI-O 1.34 / OCI 1.2.1 request format and locked generator output. They
contain no cluster hostname, provider key, token, or live attestation report.
The executable tests also exercise application requests, storage source
binding, denied host access, and full enrollment revalidation.
