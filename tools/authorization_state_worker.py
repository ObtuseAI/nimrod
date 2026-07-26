from __future__ import annotations

import argparse
import json
import os
import time
from collections.abc import Callable
from pathlib import Path

from nimrod_simulator.errors import LeaseReplayError
from nimrod_simulator.jsonio import canonical_json_bytes
from nimrod_simulator.model import JsonObject
from nimrod_simulator.state_journal import FileLeaseStateStore


CRASH_EXIT_CODE = 91
VALID_FAILURE_POINTS = (
    "none",
    "prepared_durable",
    "owner_created",
    "owner_durable",
    "commit_prepared",
    "commit_published",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Process-level authorization-state validation worker.")
    parser.add_argument("--state-root", required=True, type=Path)
    parser.add_argument("--lease-id", required=True)
    parser.add_argument("--nonce", required=True)
    parser.add_argument("--claimed-at", required=True)
    parser.add_argument("--start-gate", required=True, type=Path)
    parser.add_argument("--result", required=True, type=Path)
    parser.add_argument("--failure-injection-point", required=True, choices=VALID_FAILURE_POINTS)
    return parser.parse_args()


def await_start_gate(path: Path, timeout_seconds: float) -> None:
    deadline = time.monotonic() + timeout_seconds
    while not path.is_file():
        if time.monotonic() >= deadline:
            raise TimeoutError(f"Authorization-state worker start gate was not released: '{path}'.")
        time.sleep(0.005)


def build_failure_injector(failure_point: str) -> Callable[[str], None]:
    def inject(phase: str) -> None:
        if failure_point == phase:
            os._exit(CRASH_EXIT_CODE)

    return inject


def write_result(path: Path, result: JsonObject) -> None:
    path.write_bytes(canonical_json_bytes(result) + b"\n")


def main() -> None:
    args = parse_args()
    await_start_gate(args.start_gate, 30.0)
    store = FileLeaseStateStore(args.state_root, build_failure_injector(args.failure_injection_point))
    try:
        committed_path = store.claim(args.lease_id, args.nonce, args.claimed_at)
        result: JsonObject = {
            "status": "claimed",
            "process_id": os.getpid(),
            "committed_path": str(committed_path),
        }
    except LeaseReplayError as error:
        result = {
            "status": "replay_denied",
            "process_id": os.getpid(),
            "error": str(error),
        }
    write_result(args.result, result)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
