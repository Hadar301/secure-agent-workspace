"""Per-worker cache for successful local Helm renders.

Keep command results private to each caller. Render helpers parse the returned
text into new documents, so a test cannot change another test's documents.
"""
import copy
import hashlib
from pathlib import Path
import subprocess

_renders = {}


def _contents(path):
    path = Path(path)
    if path.is_dir():
        digest = hashlib.sha256()
        for child in sorted(path.rglob("*")):
            if child.is_file():
                digest.update(str(child.relative_to(path)).encode())
                digest.update(b"\0")
                digest.update(child.read_bytes())
        return digest.digest()
    return path.read_bytes()


def run_helm(command, *, capture_output=True, text=True, check=False):
    """Cache only local template calls with all file inputs in the key.

    Release, namespace and flags are part of command. Re-read charts and values
    on each call: tests can rewrite files at the same path between renders.
    """
    command = list(map(str, command))
    if len(command) < 4 or command[1] != "template" or not Path(command[3]).exists():
        return subprocess.run(command, capture_output=capture_output, text=text, check=check)
    # A post-renderer can read arbitrary files or external state.
    if any(arg.startswith("--post-renderer") for arg in command):
        return subprocess.run(command, capture_output=capture_output, text=text, check=check)
    inputs = [(command[3], _contents(command[3]))]
    for index, arg in enumerate(command[4:], 4):
        if arg in ("-f", "--values", "--set-file"):
            if index + 1 == len(command):
                return subprocess.run(command, capture_output=capture_output, text=text, check=check)
            value = command[index + 1]
        elif arg.startswith(("--values=", "--set-file=")):
            value = arg.split("=", 1)[1]
        elif arg.startswith("-f"):
            value = arg[2:].removeprefix("=")
        else:
            continue
        # Unsupported file syntax bypasses caching; Helm still reports errors.
        paths = value.split(",")
        if arg.startswith("--set-file"):
            paths = [entry.split("=", 1)[-1] for entry in paths]
        if any(not Path(path).is_file() for path in paths):
            return subprocess.run(command, capture_output=capture_output, text=text, check=check)
        inputs.extend((path, _contents(path)) for path in paths)
    key = (str(Path.cwd()), tuple(command), tuple(inputs), capture_output, text)
    if key not in _renders:
        result = subprocess.run(command, capture_output=capture_output, text=text, check=check)
        if result.returncode:
            return result
        _renders[key] = copy.deepcopy(result)
    return copy.deepcopy(_renders[key])
