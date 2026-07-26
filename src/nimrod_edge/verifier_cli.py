"""JSON-stdin process boundary for Edge proposal verification."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import cast

from nimrod_edge.verifier import verify_edge_proposal
from nimrod_simulator.authorization import parse_timestamp
from nimrod_simulator.errors import SimulatorError
from nimrod_simulator.model import JsonObject


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nimrod-edge-verifier",
        description="Independently verify a replayed Edge proposal without endpoint or execution access.",
    )
    parser.add_argument("--project-root", type=Path, required=True)
    parser.add_argument("--verified-at", type=str, required=True)
    return parser


def read_bundle() -> tuple[JsonObject, JsonObject]:
    value: object = json.loads(sys.stdin.read())
    if not isinstance(value, dict):
        raise TypeError("Edge verifier input must be a JSON object.")
    scenario = value.get("scenario")
    action = value.get("action")
    if not isinstance(scenario, dict) or not isinstance(action, dict):
        raise TypeError("Edge verifier input requires scenario and action objects.")
    return cast(JsonObject, scenario), cast(JsonObject, action)


def main() -> None:
    parser = build_parser()
    arguments = parser.parse_args()
    try:
        scenario, action = read_bundle()
        result = verify_edge_proposal(
            arguments.project_root,
            scenario,
            action,
            parse_timestamp(arguments.verified_at, "--verified-at"),
        )
    except (SimulatorError, TypeError, json.JSONDecodeError) as error:
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
