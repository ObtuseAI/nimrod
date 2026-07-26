"""Validate the caller-scoped Windows Edge observation adapter with live evidence."""

from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import TypeVar

from nimrod_edge.live_observation import (
    COLLECTION_INTERFACES,
    collect_live_process_observation,
    validate_live_process_observation,
)
from nimrod_simulator.errors import EdgeLiveObservationError, SimulatorError
from nimrod_simulator.jsonio import read_json_object, validate_contract
from nimrod_simulator.model import JsonObject


TError = TypeVar("TError", bound=Exception)


def require_condition(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def expect_error(
    error_type: type[TError],
    operation: Callable[[], object],
    label: str,
) -> None:
    try:
        operation()
    except error_type:
        return
    raise RuntimeError(f"Expected {error_type.__name__} for {label}.")


def wait_for_file(path: Path, timeout_seconds: int) -> None:
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if path.is_file():
            return
        time.sleep(0.02)
    raise RuntimeError(f"Worker readiness file was not created within {timeout_seconds} seconds.")


def validate_edge_live_observation(project_root: Path) -> JsonObject:
    schema_path = project_root / "specs" / "edge-live-process-observation.schema.json"
    collected_at = datetime.now(timezone.utc).replace(microsecond=0)
    with tempfile.TemporaryDirectory(prefix="nimrod-edge-live-observation-") as temporary_directory:
        temporary_root = Path(temporary_directory)
        ready_file = temporary_root / "ready.txt"
        output_file = temporary_root / "edge-live-observation.json"
        worker = subprocess.Popen(
            [
                sys.executable,
                str(project_root / "tools" / "windows_isolation_target_worker.py"),
                "--ready-file",
                str(ready_file),
                "--lifetime-seconds",
                "30",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            wait_for_file(ready_file, 5)
            api_observation = collect_live_process_observation(worker.pid, collected_at)
            validate_contract(api_observation, schema_path, "live Edge API observation")
            command = [
                sys.executable,
                "-m",
                "nimrod_edge.live_cli",
                "--project-root",
                str(project_root),
                "--process-id",
                str(worker.pid),
                "--collected-at",
                collected_at.isoformat().replace("+00:00", "Z"),
                "--output",
                str(output_file),
            ]
            completed = subprocess.run(
                command,
                cwd=project_root,
                capture_output=True,
                check=False,
                text=True,
                timeout=20,
            )
            require_condition(
                completed.returncode == 0,
                f"Live Edge CLI failed: command={command!r} returncode={completed.returncode} "
                f"stdout={completed.stdout!r} stderr={completed.stderr!r}",
            )
            cli_observation = read_json_object(output_file)
            validate_contract(cli_observation, schema_path, "live Edge CLI observation")
            require_condition(
                api_observation["process"] == cli_observation["process"],
                "API and CLI live observations did not bind the same process identity.",
            )
            rendered = json.dumps(cli_observation, sort_keys=True).casefold()
            require_condition(
                str(Path(sys.executable).resolve()).casefold() not in rendered,
                "Live Edge observation retained the raw executable path.",
            )
            require_condition(
                api_observation["collector"]["active_network_probe_performed"] is False,
                "Live Edge observation performed an active network probe.",
            )
            require_condition(
                api_observation["policy_input"]["ready_for_egress_policy"] is False,
                "Live process identity was laundered into a ready egress policy input.",
            )

            adversarial_count = 0
            expect_error(
                EdgeLiveObservationError,
                lambda: collect_live_process_observation(0, collected_at),
                "zero process ID",
            )
            adversarial_count += 1
            expect_error(
                SimulatorError,
                lambda: collect_live_process_observation(2_147_483_647, collected_at),
                "unavailable process ID",
            )
            adversarial_count += 1
            widened_authority = copy.deepcopy(api_observation)
            widened_authority["authority"]["can_execute"] = True
            expect_error(
                EdgeLiveObservationError,
                lambda: validate_live_process_observation(widened_authority),
                "execution authority widening",
            )
            adversarial_count += 1
            missing_blocker = copy.deepcopy(api_observation)
            missing_blocker["blockers"].pop()
            expect_error(
                EdgeLiveObservationError,
                lambda: validate_live_process_observation(missing_blocker),
                "missing policy blocker",
            )
            adversarial_count += 1
            false_policy_readiness = copy.deepcopy(api_observation)
            false_policy_readiness["policy_input"]["ready_for_egress_policy"] = True
            expect_error(
                EdgeLiveObservationError,
                lambda: validate_live_process_observation(false_policy_readiness),
                "false policy readiness",
            )
            adversarial_count += 1
            origin_substitution = copy.deepcopy(api_observation)
            origin_substitution["origin"] = "replayed"
            expect_error(
                EdgeLiveObservationError,
                lambda: validate_live_process_observation(origin_substitution),
                "origin substitution",
            )
            adversarial_count += 1
            raw_path_field = copy.deepcopy(api_observation)
            raw_path_field["process"]["executable_path"] = str(Path(sys.executable).resolve())
            expect_error(
                SimulatorError,
                lambda: validate_contract(raw_path_field, schema_path, "raw path mutation"),
                "raw path contract field",
            )
            adversarial_count += 1
        finally:
            worker.terminate()
            try:
                worker.wait(timeout=5)
            except subprocess.TimeoutExpired:
                worker.kill()
                worker.wait(timeout=5)
    return {
        "status": "EDGE_LIVE_PROCESS_OBSERVATION_VALID_POLICY_AND_ACTION_BLOCKED",
        "origin": "live",
        "platform": "windows",
        "live_target_process_count": 1,
        "api_observation_count": 1,
        "cli_observation_count": 1,
        "supported_interface_count": len(COLLECTION_INTERFACES),
        "negative_fail_closed_case_count": adversarial_count,
        "requested_process_only": True,
        "raw_executable_path_retained": False,
        "raw_account_sid_retained": False,
        "active_network_probe_performed": False,
        "writes_performed": False,
        "policy_input_ready": False,
        "action_proposed": False,
        "execution_authorized": False,
        "execution_performed": False,
        "target_state_changed": False,
    }


def main() -> None:
    project_root = Path(__file__).resolve().parents[1]
    result = validate_edge_live_observation(project_root)
    report_path = project_root / "reports" / "EDGE_LIVE_OBSERVATION_VALIDATION.json"
    report_path.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
