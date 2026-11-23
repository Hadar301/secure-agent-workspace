package agent_policy

import future.keywords.in
import future.keywords.if

default AddARPNeighborsRequest := true
default AddSwapRequest := true
default CloseStdinRequest := true
default CreateSandboxRequest := true
default DestroySandboxRequest := true
default GetMetricsRequest := true
default GetOOMEventRequest := true
default GuestDetailsRequest := true
default ListInterfacesRequest := true
default ListRoutesRequest := true
default MemHotplugByProbeRequest := true
default OnlineCPUMemRequest := true
default PauseContainerRequest := true
default PullImageRequest := true
default RemoveContainerRequest := true
default RemoveStaleVirtiofsShareMountsRequest := true
default ReseedRandomDevRequest := true
default ResumeContainerRequest := true
default SetGuestDateTimeRequest := true
default SignalProcessRequest := true
default StartContainerRequest := true
default StartTracingRequest := true
default StatsContainerRequest := true
default StopTracingRequest := true
default TtyWinResizeRequest := true
default UpdateContainerRequest := true
default UpdateEphemeralMountsRequest := true
default UpdateInterfaceRequest := true
default UpdateRoutesRequest := true
default WaitProcessRequest := true
default WriteStreamRequest := true
default CreateContainerRequest := true
default ReadStreamRequest := false
default CopyFileRequest := false
default SetPolicyRequest := false
default ExecProcessRequest := false

CopyFileRequest if {
    allow_copy_file
}

allow_copy_file if {
    input.file_type == "Regular"
    allow_copy_file_path(input.path, "")
}

allow_copy_file if {
    input.file_type == "Directory"
    allow_copy_file_path(input.path, "")
}

allow_copy_file if {
    input.file_type == "Symlink"
    allow_copy_file_path(input.path, ".*/.+")
    check_directory_traversal(input.symlink_target)
    not startswith(input.symlink_target, "/")
}

allow_copy_file_path(path, regex_suffix) if {
    check_directory_traversal(path)
    some regex1 in policy_data.request_defaults.CopyFileRequest
    regex2 := replace(regex1, "$(sfprefix)", policy_data.common.sfprefix)
    regex3 := replace(regex2, "$(cpath)", policy_data.common.cpath)
    regex4 := replace(regex3, "$(bundle-id)", "[a-z0-9]{64}")
    regex5 := concat("", [regex4, regex_suffix])
    regex.match(regex5, path)
}

check_directory_traversal(i_path) if {
    not regex.match("(^|/)\\.\\.($|/)", i_path)
}

policy_data := {
    "saw_identity": __SAW_IDENTITY_JSON__,
    "common": {
        "cpath": "/run/kata-containers/shared/containers(?:/passthrough)?",
        "sfprefix": "^$(cpath)/(watchable/)?$(bundle-id)-[a-z0-9]{16}-"
    },
    "request_defaults": {
        "CopyFileRequest": ["$(sfprefix)"]
    }
}
