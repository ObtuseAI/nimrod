"""Separate-process autonomous threshold promotion and regression-demotion worker."""

from __future__ import annotations

import argparse
import json
import os
from collections.abc import Callable
from datetime import datetime
from pathlib import Path

from nimrod_simulator.autonomous_promotion import (
    apply_autonomous_regression_demotion,
    apply_autonomous_shadow_promotion,
)
from nimrod_simulator.errors import EvolutionTransitionConflictError, EvolutionTransitionReplayError
from nimrod_simulator.evolution_transition import EvolutionTransitionStore, no_transition_failure
from nimrod_simulator.jsonio import read_json_object, require_object, require_string


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def build_failure_injector(failure_point: str) -> Callable[[str], None]:
    if failure_point == "none":
        return no_transition_failure

    def inject(phase: str) -> None:
        if phase == failure_point:
            os._exit(111 if phase == "temporary_durable" else 112)

    return inject


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--state-root", type=Path, required=True)
    parser.add_argument("--job", type=Path, required=True)
    parser.add_argument("--now", required=True)
    parser.add_argument("--maximum-constitution-lifetime-seconds", type=int, required=True)
    parser.add_argument("--maximum-transition-lifetime-seconds", type=int, required=True)
    parser.add_argument(
        "--failure-point",
        choices=("none", "temporary_durable", "state_published"),
        required=True,
    )
    arguments = parser.parse_args()
    job = read_json_object(arguments.job)
    envelope = require_object(job.get("transition_envelope"), "job.transition_envelope")
    action = require_string(envelope.get("action"), "transition_envelope.action")
    store = EvolutionTransitionStore(
        arguments.state_root,
        build_failure_injector(arguments.failure_point),
    )
    try:
        if action == "register_shadow":
            result = apply_autonomous_shadow_promotion(
                store,
                job,
                parse_time(arguments.now),
                arguments.maximum_constitution_lifetime_seconds,
                arguments.maximum_transition_lifetime_seconds,
            )
        elif action == "demote":
            result = apply_autonomous_regression_demotion(
                store,
                job,
                parse_time(arguments.now),
                arguments.maximum_constitution_lifetime_seconds,
                arguments.maximum_transition_lifetime_seconds,
            )
        else:
            raise ValueError(f"Autonomous promotion worker does not support action '{action}'.")
        output = {"process_id": os.getpid(), "status": "accepted", **result}
    except EvolutionTransitionReplayError as error:
        output = {"process_id": os.getpid(), "status": "replay_denied", "error": str(error)}
    except EvolutionTransitionConflictError as error:
        output = {"process_id": os.getpid(), "status": "conflict_denied", "error": str(error)}
    print(json.dumps(output, sort_keys=True))


if __name__ == "__main__":
    main()
