"""Exit abruptly after the resource meter has durably published an observation."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import cast

from nimrod_platform_assurance.resource_meter import run_resource_measurement_until_observation
from nimrod_simulator.errors import InjectedResourceMeterCrashError
from nimrod_simulator.model import JsonObject


EXPECTED_ABRUPT_EXIT_CODE = 86


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True, type=Path)
    return parser.parse_args()


def read_config(path: Path) -> JsonObject:
    value: object = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise TypeError(f"Resource meter abrupt-crash config must be an object: '{path}'.")
    return cast(JsonObject, value)


def main() -> None:
    args = parse_args()
    config = read_config(args.config)
    command = config.get("command")
    if not isinstance(command, list) or not all(isinstance(item, str) for item in command):
        raise TypeError("Resource meter abrupt-crash command must be a string list.")
    try:
        run_resource_measurement_until_observation(
            Path(str(config["state_root"])),
            str(config["meter_id"]),
            str(config["candidate_digest"]),
            str(config["resource_lease_digest"]),
            cast(list[str], command),
            Path(str(config["output_root"])),
            int(config["memory_limit_bytes"]),
            int(config["timeout_seconds"]),
            str(config["prepared_at"]),
            str(config["started_at"]),
            str(config["completed_at"]),
        )
    except InjectedResourceMeterCrashError:
        os._exit(EXPECTED_ABRUPT_EXIT_CODE)
    raise RuntimeError("Resource meter abrupt-crash boundary did not activate.")


if __name__ == "__main__":
    main()
