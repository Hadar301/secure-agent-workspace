#!/usr/bin/env python3
"""Write one private E2E config from a manual GitHub Actions event."""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys

import yaml


REQUIRED = (
    "cluster_api_url",
    "cluster_username",
    "cluster_password",
    "nvidia_api_key",
)


def private_write(path: Path, value: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(value)


def write_config(path: Path, inputs: dict[str, str]) -> None:
    missing = [name for name in REQUIRED if not inputs.get(name)]
    if missing:
        raise ValueError("missing required CI inputs: " + ", ".join(missing))
    if not path.is_absolute():
        raise ValueError("CI config path must be absolute")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    config = {
        "cluster": {
            "apiURL": inputs["cluster_api_url"],
            "username": inputs["cluster_username"],
            "password": inputs["cluster_password"],
        },
        "inference": {
            "provider": "nvidia",
            "model": "nvidia/nemotron-3-super-120b-a12b",
            "apiKey": inputs["nvidia_api_key"],
        },
        "cleanup": "always",
    }
    private_write(path, yaml.safe_dump(config, sort_keys=False).encode())


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: saw-tp-e2e-ci-config.py ABSOLUTE_CONFIG_PATH", file=sys.stderr)
        return 2
    try:
        event_path = os.environ.get("GITHUB_EVENT_PATH")
        if not event_path:
            raise ValueError("GITHUB_EVENT_PATH is required")
        event = json.loads(Path(event_path).read_text(encoding="utf-8"))
        inputs = event.get("inputs")
        if not isinstance(inputs, dict):
            raise ValueError("manual workflow inputs are absent")
        write_config(Path(sys.argv[1]), inputs)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print("CI input error: " + str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
