from __future__ import annotations

import argparse
import json
import os
from collections.abc import Callable
from datetime import datetime
from pathlib import Path

from nimrod_simulator.errors import RangeKillConflictError, RangeKillReplayError
from nimrod_simulator.jsonio import read_json_object
from nimrod_simulator.range_kill import RangeKillStateStore, no_range_kill_failure


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def build_failure_injector(failure_point: str) -> Callable[[str], None]:
    if failure_point == "none":
        return no_range_kill_failure

    def inject(phase: str) -> None:
        if phase == failure_point:
            os._exit(91 if phase == "temporary_durable" else 92)

    return inject


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--state-root", type=Path, required=True)
    parser.add_argument("--topology", type=Path, required=True)
    parser.add_argument("--command", type=Path, required=True)
    parser.add_argument("--governance", type=Path, required=True)
    parser.add_argument("--now", required=True)
    parser.add_argument("--maximum-lifetime-seconds", type=int, required=True)
    parser.add_argument("--failure-point", choices=("none", "temporary_durable", "state_published"), required=True)
    args = parser.parse_args()
    store = RangeKillStateStore(args.state_root, build_failure_injector(args.failure_point))
    try:
        state = store.engage(
            read_json_object(args.command),
            read_json_object(args.topology),
            read_json_object(args.governance),
            parse_time(args.now),
            args.maximum_lifetime_seconds,
        )
        result = {"status": "accepted", "command_digest": state["command_digest"]}
    except RangeKillReplayError as error:
        result = {"status": "replay_denied", "error": str(error)}
    except RangeKillConflictError as error:
        result = {"status": "conflict_denied", "error": str(error)}
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
