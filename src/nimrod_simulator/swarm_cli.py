"""Command-line entry point for the governed proposal-only swarm."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from nimrod_simulator.authorization import parse_timestamp
from nimrod_simulator.errors import SimulatorError
from nimrod_simulator.jsonio import read_json_object
from nimrod_simulator.swarm import run_swarm_review


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nimrod-swarm",
        description="Run a simulated proposal-only Red, Blue, Purple, Evidence, Recovery, Verification, and Safety swarm.",
    )
    parser.add_argument("--project-root", type=Path, required=True)
    parser.add_argument("--lease", type=Path, required=True)
    parser.add_argument("--campaign", type=Path, required=True)
    parser.add_argument("--mission", type=Path, required=True)
    parser.add_argument("--authorization-proof", type=Path, required=True)
    parser.add_argument("--trust-policy", type=Path, required=True)
    parser.add_argument("--control-state", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--now", type=str, required=True)
    return parser


def main() -> None:
    arguments = build_parser().parse_args()
    try:
        result = run_swarm_review(
            arguments.project_root,
            read_json_object(arguments.lease),
            read_json_object(arguments.campaign),
            read_json_object(arguments.mission),
            read_json_object(arguments.authorization_proof),
            read_json_object(arguments.trust_policy),
            read_json_object(arguments.control_state),
            arguments.output,
            parse_timestamp(arguments.now, "--now"),
        )
    except SimulatorError as error:
        print(json.dumps({"status": "SWARM_BLOCKED_FAIL_CLOSED", "error_type": type(error).__name__, "message": str(error)}))
        raise SystemExit(2) from error
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
