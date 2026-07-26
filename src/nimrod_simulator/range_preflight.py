"""Fail-closed disposable-range connection preflight evaluation."""

from __future__ import annotations

from datetime import datetime

from nimrod_simulator.authorization import parse_timestamp
from nimrod_simulator.errors import ControlStateValidationError, RangePreflightError
from nimrod_simulator.jsonio import require_list, require_object, require_string, sha256_digest
from nimrod_simulator.model import JsonObject
from nimrod_simulator.range_policy import verify_range_adapter_policy_envelope


REQUIRED_CONTROLS = {
    "CLEANUP_CONTRACT",
    "DEDICATED_CREDENTIALS",
    "DEFAULT_DENY_EGRESS",
    "DISPOSABLE_TARGET",
    "INDEPENDENT_VERIFIER",
    "OUT_OF_BAND_KILL",
    "RESTORABLE_SNAPSHOT",
    "TELEMETRY_SEPARATION",
    "TRUSTED_TIME",
}


def evaluate_disposable_range_preflight(
    preflight: JsonObject,
    policy: JsonObject,
    policy_envelope: JsonObject,
    governance_state: JsonObject,
    corpus_report: JsonObject,
    evaluated_at: datetime,
    maximum_policy_lifetime_seconds: int,
    maximum_preflight_age_seconds: int,
) -> JsonObject:
    if evaluated_at.utcoffset() is None:
        raise RangePreflightError("Disposable-range preflight evaluation time must be timezone-aware.")
    if maximum_preflight_age_seconds <= 0:
        raise RangePreflightError("Disposable-range maximum preflight age must be positive.")
    policy_verification = verify_range_adapter_policy_envelope(
        policy_envelope,
        policy,
        governance_state,
        evaluated_at,
        maximum_policy_lifetime_seconds,
    )
    if preflight.get("preflight_version") != "0.1.0" or preflight.get("origin") != "simulated":
        raise RangePreflightError("Disposable-range preflight must be version 0.1.0 and simulated.")
    if preflight.get("environment_class") != "isolated_range":
        raise RangePreflightError("Disposable-range preflight environment must be isolated_range.")
    try:
        captured_at = parse_timestamp(preflight.get("captured_at"), "preflight.captured_at")
    except ControlStateValidationError as error:
        raise RangePreflightError(f"Disposable-range preflight captured_at is invalid: {error}.") from error
    age_seconds = int((evaluated_at - captured_at).total_seconds())
    if age_seconds < 0:
        raise RangePreflightError("Disposable-range preflight cannot be captured in the future.")
    if age_seconds > maximum_preflight_age_seconds:
        raise RangePreflightError(
            f"Disposable-range preflight age {age_seconds}s exceeds {maximum_preflight_age_seconds}s."
        )
    authority = require_object(preflight.get("authority"), "preflight.authority")
    if authority != {"can_connect": False, "can_execute": False}:
        raise RangePreflightError("Disposable-range preflight cannot grant connection or execution authority.")
    if preflight.get("policy_envelope_digest") != policy_verification.get("envelope_digest"):
        raise RangePreflightError("Disposable-range preflight policy-envelope digest mismatch.")
    if preflight.get("corpus_report_digest") != sha256_digest(corpus_report):
        raise RangePreflightError("Disposable-range preflight corpus-report digest mismatch.")
    if corpus_report.get("origin") != "simulated" or corpus_report.get("report_version") != "0.1.0":
        raise RangePreflightError("Disposable-range corpus report version or origin mismatch.")
    report_authority = require_object(corpus_report.get("authority"), "corpus_report.authority")
    if report_authority != {"can_connect": False, "can_compile": False, "can_execute": False}:
        raise RangePreflightError("Disposable-range corpus report cannot grant authority.")
    for field in (
        "compilation_performed",
        "source_tool_contacted",
        "network_access_performed",
        "live_execution_performed",
    ):
        if corpus_report.get(field) is not False:
            raise RangePreflightError(f"Disposable-range corpus report must keep '{field}' false.")
    controls = require_list(preflight.get("controls"), "preflight.controls")
    control_objects: list[JsonObject] = []
    control_ids: list[str] = []
    for index, value in enumerate(controls):
        control = require_object(value, f"preflight.controls[{index}]")
        control_id = require_string(control.get("control_id"), f"preflight.controls[{index}].control_id")
        evidence = require_list(control.get("evidence"), f"preflight.controls[{index}].evidence")
        status = require_string(control.get("status"), f"preflight.controls[{index}].status")
        if status not in {"proven", "unproven", "failed"}:
            raise RangePreflightError(f"Preflight control '{control_id}' has unsupported status '{status}'.")
        if status == "proven" and not evidence:
            raise RangePreflightError(f"Proven preflight control '{control_id}' lacks evidence.")
        control_ids.append(control_id)
        control_objects.append(control)
    if len(control_ids) != len(set(control_ids)) or set(control_ids) != REQUIRED_CONTROLS:
        raise RangePreflightError("Disposable-range preflight must contain each required control exactly once.")
    blocked_controls = sorted(
        require_string(control.get("control_id"), "control.control_id")
        for control in control_objects
        if control.get("status") != "proven"
    )
    if corpus_report.get("status") != "compatible_no_execution":
        blocked_controls.append("CORPUS_COMPATIBILITY")
    blocked_controls = sorted(set(blocked_controls))
    gate_satisfied = not blocked_controls
    status = "ready_for_separately_authorized_range_connection" if gate_satisfied else "blocked"
    return {
        "result_version": "0.1.0",
        "origin": "simulated",
        "status": status,
        "preflight_id": preflight["preflight_id"],
        "range_id": preflight["range_id"],
        "policy_envelope_digest": policy_verification["envelope_digest"],
        "corpus_report_digest": sha256_digest(corpus_report),
        "connection_gate_satisfied": gate_satisfied,
        "blocked_controls": blocked_controls,
        "tool_installation_authorized": False,
        "range_connection_authorized": False,
        "execution_authorized": False,
        "authority": {"can_connect": False, "can_execute": False},
    }
