"""CLI for the unprivileged nimrod Edge replay preview."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from nimrod_edge.runtime import run_edge_preview
from nimrod_simulator.authorization import parse_timestamp
from nimrod_simulator.errors import SimulatorError
from nimrod_simulator.jsonio import read_json_object


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nimrod-edge-replay",
        description="Run one deterministic replay-to-proposal-to-proof Edge preview without endpoint authority.",
    )
    parser.add_argument("--project-root", type=Path, required=True)
    parser.add_argument("--scenario", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--now", type=str, required=True)
    return parser


def main() -> None:
    parser = build_parser()
    arguments = parser.parse_args()
    try:
        result = run_edge_preview(
            arguments.project_root,
            read_json_object(arguments.scenario),
            arguments.output,
            parse_timestamp(arguments.now, "--now"),
        )
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
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
