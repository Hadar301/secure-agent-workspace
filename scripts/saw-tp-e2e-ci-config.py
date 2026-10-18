#!/usr/bin/env python3
"""Write one private E2E config from GitHub Actions secret variables."""

from __future__ import annotations

import os
from pathlib import Path
import sys

import yaml


REQUIRED = (
    "SAW_E2E_API_URL",
    "SAW_E2E_USERNAME",
    "SAW_E2E_PASSWORD",
    "SAW_E2E_NVIDIA_API_KEY",
)


def private_write(path: Path, value: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(value)


def write_config(path: Path, environ: dict[str, str]) -> None:
    missing = [name for name in REQUIRED if not environ.get(name)]
    if missing:
        raise ValueError("missing required CI inputs: " + ", ".join(missing))
    if not path.is_absolute():
        raise ValueError("CI config path must be absolute")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    config = {
        "cluster": {
            "apiURL": environ["SAW_E2E_API_URL"],
            "username": environ["SAW_E2E_USERNAME"],
            "password": environ["SAW_E2E_PASSWORD"],
        },
        "inference": {
            "provider": "nvidia",
            "model": environ.get("SAW_E2E_MODEL") or "nvidia/nemotron-3-super-120b-a12b",
            "apiKey": environ["SAW_E2E_NVIDIA_API_KEY"],
        },
        "cleanup": "always",
    }
    for variable, section, key, filename in (
        ("SAW_E2E_API_CA_PEM", "cluster", "caFile", "api-ca.pem"),
        ("SAW_E2E_INGRESS_CA_PEM", "oidc", "caFile", "ingress-ca.pem"),
    ):
        value = environ.get(variable)
        if value:
            certificate = path.parent / filename
            private_write(certificate, value.encode())
            config.setdefault(section, {})[key] = str(certificate)
    private_write(path, yaml.safe_dump(config, sort_keys=False).encode())


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: saw-tp-e2e-ci-config.py ABSOLUTE_CONFIG_PATH", file=sys.stderr)
        return 2
    try:
        write_config(Path(sys.argv[1]), dict(os.environ))
    except (OSError, ValueError) as exc:
        print("CI input error: " + str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
