"""CLI for one caller-scoped, read-only Windows Edge process observation."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from nimrod_edge.live_observation import collect_live_process_observation
from nimrod_simulator.authorization import parse_timestamp
from nimrod_simulator.errors import SimulatorError
from nimrod_simulator.jsonio import canonical_json_bytes, validate_contract


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nimrod-edge-observe",
        description="Collect one read-only hashed Windows process identity without policy or action authority.",
    )
    parser.add_argument("--project-root", type=Path, required=True)
    parser.add_argument("--process-id", type=int, required=True)
    parser.add_argument("--collected-at", type=str, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main() -> None:
    arguments = build_parser().parse_args()
    try:
        observation = collect_live_process_observation(
            arguments.process_id,
            parse_timestamp(arguments.collected_at, "--collected-at"),
        )
        validate_contract(
            observation,
            arguments.project_root / "specs" / "edge-live-process-observation.schema.json",
            "live Edge process observation",
        )
        arguments.output.parent.mkdir(parents=True, exist_ok=True)
        arguments.output.write_bytes(canonical_json_bytes(observation) + b"\n")
    except SimulatorError as error:
        print(
            json.dumps(
                {
                    "status": "DENIED_FAIL_CLOSED",
                    "error_type": type(error).__name__,
                    "message": str(error),
                },
                sort_keys=True,
            )
        )
        raise SystemExit(2) from error
    print(json.dumps(observation, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
