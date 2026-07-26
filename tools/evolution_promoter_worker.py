from __future__ import annotations

import argparse
import json
import os
from collections.abc import Callable
from datetime import datetime
from pathlib import Path

from nimrod_simulator.errors import EvolutionTransitionConflictError, EvolutionTransitionReplayError
from nimrod_simulator.evolution_transition import EvolutionTransitionStore, no_transition_failure
from nimrod_simulator.jsonio import read_json_object


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def build_failure_injector(failure_point: str) -> Callable[[str], None]:
    if failure_point == "none":
        return no_transition_failure

    def inject(phase: str) -> None:
        if phase == failure_point:
            os._exit(101 if phase == "temporary_durable" else 102)

    return inject


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--state-root", type=Path, required=True)
    parser.add_argument("--envelope", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--evaluation", type=Path, required=True)
    parser.add_argument("--capability-report", type=Path, required=True)
    parser.add_argument("--constitution", type=Path, required=True)
    parser.add_argument("--governance", type=Path, required=True)
    parser.add_argument("--now", required=True)
    parser.add_argument("--maximum-constitution-lifetime-seconds", type=int, required=True)
    parser.add_argument("--maximum-transition-lifetime-seconds", type=int, required=True)
    parser.add_argument("--failure-point", choices=("none", "temporary_durable", "state_published"), required=True)
    args = parser.parse_args()
    store = EvolutionTransitionStore(args.state_root, build_failure_injector(args.failure_point))
    try:
        receipt = store.apply(
            read_json_object(args.envelope),
            read_json_object(args.candidate),
            read_json_object(args.evaluation),
            read_json_object(args.capability_report),
            read_json_object(args.constitution),
            read_json_object(args.governance),
            parse_time(args.now),
            args.maximum_constitution_lifetime_seconds,
            args.maximum_transition_lifetime_seconds,
        )
        result = {"process_id": os.getpid(), "status": "accepted", "receipt": receipt}
    except EvolutionTransitionReplayError as error:
        result = {"process_id": os.getpid(), "status": "replay_denied", "error": str(error)}
    except EvolutionTransitionConflictError as error:
        result = {"process_id": os.getpid(), "status": "conflict_denied", "error": str(error)}
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
