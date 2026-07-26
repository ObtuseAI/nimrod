"""Command-line entry point for the no-execution simulator."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from nimrod_simulator.authorization import parse_timestamp
from nimrod_simulator.errors import SimulatorError
from nimrod_simulator.jsonio import read_json_object
from nimrod_simulator.runtime import run_simulation


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nimrod-simulate",
        description="Compile and witness a simulated Crucible campaign without target execution.",
    )
    parser.add_argument("--project-root", type=Path, required=True)
    parser.add_argument("--lease", type=Path, required=True)
    parser.add_argument("--campaign", type=Path, required=True)
    parser.add_argument("--authorization-proof", type=Path, required=True)
    parser.add_argument("--trust-policy", type=Path, required=True)
    parser.add_argument("--control-state", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--state-root", type=Path, required=True)
    parser.add_argument("--now", type=str, required=True)
    return parser


def main() -> None:
    parser = build_parser()
    arguments = parser.parse_args()
    try:
        lease = read_json_object(arguments.lease)
        campaign = read_json_object(arguments.campaign)
        proof_bundle = read_json_object(arguments.authorization_proof)
        trust_policy = read_json_object(arguments.trust_policy)
        control_state = read_json_object(arguments.control_state)
        now = parse_timestamp(arguments.now, "--now")
        result = run_simulation(
            arguments.project_root,
            lease,
            campaign,
            proof_bundle,
            trust_policy,
            control_state,
            arguments.output,
            arguments.state_root,
            now,
        )
    except SimulatorError as error:
        print(json.dumps({"status": "DENIED_FAIL_CLOSED", "error_type": type(error).__name__, "message": str(error)}))
        raise SystemExit(2) from error
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
