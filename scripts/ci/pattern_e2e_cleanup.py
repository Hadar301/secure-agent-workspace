#!/usr/bin/env python3
"""Clean resources from a completed or interrupted Pattern E2E run."""

from __future__ import annotations

import signal
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.ci.pattern_e2e import E2EError, Runner


def main() -> int:
    try:
        runner = Runner(recovery=True)
    except E2EError as exc:
        print(f"Pattern E2E cleanup setup failed: {exc}", file=sys.stderr)
        return 1

    def cancelled(_signal, _frame):
        runner.cancelled = True
        raise KeyboardInterrupt("cleanup cancelled")

    signal.signal(signal.SIGINT, cancelled)
    signal.signal(signal.SIGTERM, cancelled)
    return runner.recover_cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
