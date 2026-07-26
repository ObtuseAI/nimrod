"""Validate read-only live Windows isolation measurement without claiming production readiness."""

from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, TypeVar

from jsonschema import Draft202012Validator, FormatChecker

from nimrod_simulator.errors import IsolationBoundaryError, WindowsIsolationCollectionError
from nimrod_simulator.isolation_boundary import REQUIRED_ISOLATION_CONTROLS, verify_isolation_attestation
from nimrod_simulator.model import JsonObject
from nimrod_platform_assurance.windows_isolation_collector import (
    build_signed_windows_isolation_attestation,
    collect_process_identity,
    collect_windows_isolation_measurement,
)
from validate_evolution_assurance import governance_connectors, governance_state


TError = TypeVar("TError", bound=Exception)
MAXIMUM_ATTESTATION_LIFETIME_SECONDS = 900


def require_condition(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def expect_error(error_type: type[TError], operation: Callable[[], object], label: str) -> None:
    try:
        operation()
    except error_type:
        return
    raise RuntimeError(f"Expected {error_type.__name__} for {label}.")


def validate_contract(value: JsonObject, schema_path: Path, label: str) -> None:
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors = sorted(validator.iter_errors(value), key=lambda item: list(item.absolute_path))
    if errors:
        rendered = "; ".join(error.message for error in errors)
        raise RuntimeError(f"{label} failed schema validation: {rendered}")


def wait_for_file(path: Path, timeout_seconds: int) -> None:
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if path.is_file():
            return
        time.sleep(0.02)
    raise RuntimeError(f"Worker readiness file was not created within {timeout_seconds} seconds.")


def validate_windows_isolation(project_root: Path) -> JsonObject:
    signers = governance_connectors()
    governance = governance_state(signers, "live")
    started_at = datetime.now(timezone.utc).replace(microsecond=0)
    with tempfile.TemporaryDirectory(prefix="nimrod-windows-isolation-") as temporary_directory:
        temporary_root = Path(temporary_directory)
        ready_file = temporary_root / "input" / "ready.txt"
        ready_file.parent.mkdir(parents=True)
        output_directory = temporary_root / "output"
        output_directory.mkdir()
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
            target_identity = collect_process_identity(worker.pid)
            collected_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
            measurement = collect_windows_isolation_measurement(
                worker.pid,
                ready_file,
                output_directory,
                str(target_identity["os_account_sid"]),
                collected_at,
                10,
                2,
            )
            validate_contract(
                measurement,
                project_root / "specs" / "windows-isolation-measurement.schema.json",
                "live Windows isolation measurement",
            )
            issued_at = datetime.now(timezone.utc).replace(microsecond=0)
            attestation = build_signed_windows_isolation_attestation(
                measurement,
                "evaluator:windows-reference",
                "principal:windows-reference",
                governance,
                signers[:2],
                issued_at,
                300,
            )
            validate_contract(
                attestation,
                project_root / "specs" / "os-isolation-attestation.schema.json",
                "signed live-observed isolation attestation",
            )
            verification = verify_isolation_attestation(
                attestation,
                governance,
                issued_at + timedelta(seconds=1),
                MAXIMUM_ATTESTATION_LIFETIME_SECONDS,
            )
            require_condition(measurement["origin"] == "live", "Windows measurement did not preserve live origin.")
            require_condition(measurement["collector"]["independent_process"] is True, "Collector did not run outside the target process.")
            require_condition(measurement["environment"]["credential_value_accessed"] is False, "Collector accessed credential values.")
            require_condition(measurement["filesystem"]["acl_modified"] is False, "Collector modified an ACL.")
            require_condition(
                measurement["filesystem"]["effective_rights_computed"] is True,
                "Collector did not compute effective ACL rights.",
            )
            require_condition(measurement["network"]["active_probe_performed"] is False, "Collector performed an active network probe.")
            require_condition(
                measurement["network"]["target_inspection_method"] == "powershell_netsecurity_read_only",
                "Collector did not perform target-specific firewall inspection.",
            )
            require_condition(measurement["network"]["firewall_modified"] is False, "Collector modified firewall state.")
            require_condition(set(measurement["blockers"]), "Desktop measurement unexpectedly claimed a complete production boundary.")
            require_condition(verification["production_eligible"] is False, "Desktop live observation claimed production eligibility.")
            require_condition(verification["boundary_verified"] is False, "Desktop live observation claimed a verified isolation boundary.")

            adversarial_count = 0
            tampered_attestation = copy.deepcopy(attestation)
            tampered_attestation["collector"]["raw_evidence_digest"] = "sha256:" + "0" * 64
            expect_error(
                IsolationBoundaryError,
                lambda: verify_isolation_attestation(tampered_attestation, governance, issued_at + timedelta(seconds=1), MAXIMUM_ATTESTATION_LIFETIME_SECONDS),
                "measurement digest substitution",
            )
            adversarial_count += 1
            missing_control = copy.deepcopy(attestation)
            missing_control["controls"].pop()
            expect_error(
                IsolationBoundaryError,
                lambda: verify_isolation_attestation(missing_control, governance, issued_at + timedelta(seconds=1), MAXIMUM_ATTESTATION_LIFETIME_SECONDS),
                "missing isolation control",
            )
            adversarial_count += 1
            forged_status = copy.deepcopy(attestation)
            forged_status["status"] = "verified"
            forged_status["blockers"] = []
            expect_error(
                IsolationBoundaryError,
                lambda: verify_isolation_attestation(forged_status, governance, issued_at + timedelta(seconds=1), MAXIMUM_ATTESTATION_LIFETIME_SECONDS),
                "boundary status laundering",
            )
            adversarial_count += 1
            expired_time = issued_at + timedelta(seconds=301)
            expect_error(
                IsolationBoundaryError,
                lambda: verify_isolation_attestation(attestation, governance, expired_time, MAXIMUM_ATTESTATION_LIFETIME_SECONDS),
                "expired live observation",
            )
            adversarial_count += 1
            same_process_identity = collect_process_identity(worker.pid)
            require_condition(
                same_process_identity["executable_digest"] == measurement["target"]["executable_digest"],
                "Repeated process identity measurement drifted.",
            )
            adversarial_count += 1
            expect_error(
                WindowsIsolationCollectionError,
                lambda: collect_windows_isolation_measurement(worker.pid, ready_file, output_directory, "", collected_at, 10, 1),
                "empty expected account SID",
            )
            adversarial_count += 1
        finally:
            worker.terminate()
            try:
                worker.wait(timeout=5)
            except subprocess.TimeoutExpired:
                worker.kill()
                worker.wait(timeout=5)
    elapsed_milliseconds = int((datetime.now(timezone.utc) - started_at).total_seconds() * 1000)
    return {
        "status": "WINDOWS_ISOLATION_LIVE_OBSERVED_BOUNDARY_INCOMPLETE_PRODUCTION_BLOCKED",
        "origin": "live",
        "platform": "windows",
        "collector_kind": "windows_access_check",
        "independent_collector_process": True,
        "control_count": len(REQUIRED_ISOLATION_CONTROLS),
        "verified_control_count": len(REQUIRED_ISOLATION_CONTROLS) - len(measurement["blockers"]),
        "blocker_count": len(measurement["blockers"]),
        "blockers": measurement["blockers"],
        "signed_attestation_verified": True,
        "boundary_verified": False,
        "production_eligible": False,
        "acl_modified": False,
        "effective_acl_rights_computed": True,
        "input_write_allowed": measurement["filesystem"]["input"]["target_effective_access"]["write_allowed"],
        "output_target_write_allowed": measurement["filesystem"]["output"]["target_effective_access"]["write_allowed"],
        "output_collector_write_allowed": measurement["filesystem"]["output"]["collector_effective_access"]["write_allowed"],
        "firewall_modified": False,
        "target_specific_firewall_inspection": measurement["network"]["target_inspection_succeeded"],
        "matching_target_block_rule_count": measurement["network"]["matching_block_rule_count"],
        "all_traffic_target_block_rule_count": measurement["network"]["all_traffic_block_rule_count"],
        "active_network_probe_performed": False,
        "credential_values_accessed": False,
        "adversarial_case_count": adversarial_count,
        "validation_elapsed_milliseconds": elapsed_milliseconds,
        "candidate_executed": False,
        "production_promotion_authorized": False,
    }


def main() -> None:
    project_root = Path(__file__).resolve().parent.parent
    result = validate_windows_isolation(project_root)
    report_path = project_root / "reports" / "WINDOWS_ISOLATION_VALIDATION.json"
    report_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
