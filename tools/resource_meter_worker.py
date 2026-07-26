"""Benign bounded workload used to validate OS resource metering."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--allocation-megabytes", required=True, type=int)
    parser.add_argument("--iterations", required=True, type=int)
    parser.add_argument("--output-bytes", required=True, type=int)
    return parser.parse_args()


def execute_workload(
    output_path: Path,
    allocation_megabytes: int,
    iterations: int,
    output_bytes: int,
) -> None:
    if allocation_megabytes <= 0 or iterations <= 0 or output_bytes <= 0:
        raise ValueError("Resource meter workload arguments must be positive.")
    allocation = bytearray(allocation_megabytes * 1024 * 1024)
    digest = hashlib.sha256()
    for index in range(iterations):
        offset = index % len(allocation)
        allocation[offset] = (allocation[offset] + index) % 256
        digest.update(allocation[offset : offset + 1])
    block = digest.digest()
    payload = (block * ((output_bytes // len(block)) + 1))[:output_bytes]
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(payload)


def main() -> None:
    args = parse_args()
    execute_workload(args.output, args.allocation_megabytes, args.iterations, args.output_bytes)


if __name__ == "__main__":
    main()
