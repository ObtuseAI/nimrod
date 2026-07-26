"""Benign long-running process used to validate read-only Windows isolation collection."""

from __future__ import annotations

import argparse
import time
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ready-file", required=True, type=Path)
    parser.add_argument("--lifetime-seconds", required=True, type=int)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.lifetime_seconds <= 0:
        raise ValueError("lifetime-seconds must be positive")
    args.ready_file.write_text("ready\n", encoding="utf-8", newline="\n")
    time.sleep(args.lifetime_seconds)


if __name__ == "__main__":
    main()
