#!/usr/bin/env python3
"""Bound the uninstall playbook and its Argo cleanup watcher."""
import os
import signal
import subprocess
import sys
import time


def main():
    timeout = int(os.environ.get('UNINSTALL_TIMEOUT_SECONDS', '600'))
    if timeout <= 0 or len(sys.argv) < 2:
        raise SystemExit('Positive timeout and uninstall command required')
    deadline = time.monotonic() + timeout
    child = subprocess.Popen(sys.argv[1:], start_new_session=True)

    def oc(*args):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError
        return subprocess.run(['oc', '--request-timeout=10s', *args],
                              capture_output=True, text=True,
                              timeout=min(10, remaining))

    try:
        while time.monotonic() < deadline:
            code = child.poll()
            if code is not None:
                if code:
                    return code
                result = oc('get', 'patterns', 'secure-agent-workspace', '-n',
                            'patterns-operator', '--ignore-not-found', '-o', 'name')
                if result.returncode:
                    print(result.stderr, file=sys.stderr)
                    return 1
                if not result.stdout.strip():
                    return 0
            result = oc('get', 'applications.argoproj.io', '-n', 'vp-gitops', '-o', 'name')
            if result.returncode == 0:
                for app in result.stdout.split():
                    oc('patch', app, '-n', 'vp-gitops', '--type=json',
                       '-p=[{"op":"remove","path":"/metadata/finalizers"}]')
                    oc('delete', app, '-n', 'vp-gitops', '--wait=false', '--ignore-not-found')
            time.sleep(min(5, max(0, deadline - time.monotonic())))
        raise TimeoutError
    except (TimeoutError, subprocess.TimeoutExpired):
        print('Uninstall timed out; inspect Pattern secure-agent-workspace in '
              'patterns-operator and Applications in vp-gitops. Further cleanup stopped.', file=sys.stderr)
        return 124
    finally:
        # Also terminate descendants if the playbook exited but left helpers behind.
        try:
            os.killpg(child.pid, signal.SIGTERM)
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        child.wait()


if __name__ == '__main__':
    sys.exit(main())
