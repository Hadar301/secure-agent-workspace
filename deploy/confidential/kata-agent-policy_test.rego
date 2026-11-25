package agent_policy_test

import data.agent_policy

test_lifecycle_requests_are_allowed if {
  agent_policy.CreateContainerRequest
  agent_policy.CreateSandboxRequest
}

test_exec_is_denied if {
  not agent_policy.ExecProcessRequest
}

test_policy_replacement_is_denied if {
  not agent_policy.SetPolicyRequest
}

test_stream_read_is_denied if {
  not agent_policy.ReadStreamRequest
}

test_regular_copy_in_shared_path_is_allowed if {
  agent_policy.CopyFileRequest with input as {
    "file_type": "Regular",
    "path": "/run/kata-containers/shared/containers/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-payload.txt",
  }
}

test_copy_outside_shared_path_is_denied if {
  not agent_policy.CopyFileRequest with input as {
    "file_type": "Regular",
    "path": "/etc/passwd",
  }
}

test_copy_traversal_is_denied if {
  not agent_policy.CopyFileRequest with input as {
    "file_type": "Regular",
    "path": "/run/kata-containers/shared/containers/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-payload/../outside",
  }
}

test_relative_symlink_is_allowed if {
  agent_policy.CopyFileRequest with input as {
    "file_type": "Symlink",
    "path": "/run/kata-containers/shared/containers/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-link/child",
    "symlink_target": "payload",
  }
}

test_absolute_symlink_is_denied if {
  not agent_policy.CopyFileRequest with input as {
    "file_type": "Symlink",
    "path": "/run/kata-containers/shared/containers/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-link/child",
    "symlink_target": "/etc/passwd",
  }
}
