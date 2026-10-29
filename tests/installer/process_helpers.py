"""Limit real process scans to one test's simulated sandbox.

The production script runs in a sandbox PID namespace. Pytest workers share
the host PID namespace, so filter its /proc scan by the test's private path.
Keep the production command-line matching and sh -c exclusion unchanged.
"""
import shlex


def isolate_process_scan(script, root):
    read_command = 'c=$(tr "\\000" " " < "$d/cmdline" 2>/dev/null) || continue; '
    assert read_command in script, "gateway /proc reader changed; review test isolation"
    within_test = f'case "$c" in *{shlex.quote(str(root))}*) ;; *) continue;; esac; '
    return script.replace(read_command, read_command + within_test)
