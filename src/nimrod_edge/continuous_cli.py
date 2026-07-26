"""CLI for bounded, read-only continuous Windows defensive observation."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from nimrod_edge.continuous_observation import collect_live_continuous_observation
from nimrod_simulator.authorization import parse_timestamp
from nimrod_simulator.errors import SimulatorError
from nimrod_simulator.jsonio import canonical_json_bytes


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nimrod-edge-observe-continuous",
        description="Collect bounded read-only PowerShell, optional Sysmon, and DNS event metadata without policy or action authority.",
    )
    parser.add_argument("--started-at", type=str, required=True)
    parser.add_argument("--poll-cycles", type=int, required=True)
    parser.add_argument("--poll-interval-seconds", type=float, required=True)
    parser.add_argument("--maximum-events-per-source", type=int, required=True)
    parser.add_argument("--query-timeout-seconds", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main() -> None:
    arguments = build_parser().parse_args()
    try:
        observation = collect_live_continuous_observation(
            arguments.poll_cycles,
            arguments.poll_interval_seconds,
            arguments.maximum_events_per_source,
            parse_timestamp(arguments.started_at, "--started-at"),
            arguments.query_timeout_seconds,
        )
        arguments.output.parent.mkdir(parents=True, exist_ok=True)
        arguments.output.write_bytes(canonical_json_bytes(observation) + b"\n")
    except SimulatorError as error:
        print(json.dumps({"status": "DENIED_FAIL_CLOSED", "error_type": type(error).__name__, "message": str(error)}, sort_keys=True))
        raise SystemExit(2) from error
    print(json.dumps(observation, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
