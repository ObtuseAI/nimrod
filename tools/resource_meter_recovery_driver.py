"""Recover a durable resource-meter observation in a separate process."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from nimrod_platform_assurance.resource_meter import recover_resource_measurement


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--state-root", required=True, type=Path)
    parser.add_argument("--meter-id", required=True)
    parser.add_argument("--recovered-at", required=True)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    receipt = recover_resource_measurement(args.state_root, args.meter_id, args.recovered_at)
    sys.stdout.write(json.dumps(receipt, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
