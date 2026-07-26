"""Threshold-certified OS isolation evidence for verifier and evaluator processes."""

from __future__ import annotations

from datetime import datetime

from nimrod_simulator.authorization import parse_timestamp
from nimrod_simulator.errors import ControlStateValidationError, IsolationBoundaryError
from nimrod_simulator.jsonio import require_list, require_object, require_string, sha256_digest
from nimrod_simulator.key_governance import SigningConnector
from nimrod_simulator.model import JsonObject
from nimrod_simulator.threshold_signing import sign_threshold_document, verify_threshold_signatures


ISOLATION_ATTESTATION_DOMAIN = b"nimrod.os-isolation-attestation.v0.1\x00"
REQUIRED_ISOLATION_CONTROLS = {
    "CREDENTIAL_ISOLATION",
    "DEDICATED_OS_ACCOUNT",
    "DISTINCT_PROCESS",
    "EXECUTABLE_IDENTITY",
    "NETWORK_EGRESS_DENIED",
    "READ_ONLY_INPUT_ACL",
    "SEPARATE_OUTPUT_ACL",
}
ISOLATION_AUTHORITY = {
    "can_authorize": False,
    "can_execute": False,
    "can_modify_acl": False,
    "can_grant_credentials": False,
}


def sign_isolation_attestation(
    unsigned_attestation: JsonObject,
    connectors: list[SigningConnector],
) -> JsonObject:
    return sign_threshold_document(
        unsigned_attestation,
        connectors,
        ISOLATION_ATTESTATION_DOMAIN,
        "OS isolation attestation",
        IsolationBoundaryError,
    )


def _attestation_time(value: object, field: str) -> datetime:
    try:
        return parse_timestamp(value, field)
    except ControlStateValidationError as error:
        raise IsolationBoundaryError(f"OS isolation attestation time '{field}' is invalid: {error}.") from error


def _validate_time_window(
    attestation: JsonObject,
    now: datetime,
    maximum_lifetime_seconds: int,
) -> datetime:
    if now.tzinfo is None:
        raise IsolationBoundaryError("OS isolation verification time must include a UTC offset.")
    if maximum_lifetime_seconds <= 0:
        raise IsolationBoundaryError("OS isolation maximum lifetime must be positive.")
    captured_at = _attestation_time(attestation.get("captured_at"), "attestation.captured_at")
    issued_at = _attestation_time(attestation.get("issued_at"), "attestation.issued_at")
    not_before = _attestation_time(attestation.get("not_before"), "attestation.not_before")
    expires_at = _attestation_time(attestation.get("expires_at"), "attestation.expires_at")
    if captured_at > issued_at:
        raise IsolationBoundaryError("OS isolation evidence was captured after attestation issuance.")
    if issued_at < not_before or issued_at >= expires_at:
        raise IsolationBoundaryError("OS isolation issuance is outside its validity window.")
    if now < not_before or now >= expires_at:
        raise IsolationBoundaryError("OS isolation attestation is not active at verification time.")
    if (expires_at - not_before).total_seconds() > maximum_lifetime_seconds:
        raise IsolationBoundaryError(
            f"OS isolation attestation lifetime exceeds {maximum_lifetime_seconds} seconds."
        )
    return issued_at


def _validate_controls(attestation: JsonObject) -> tuple[list[str], bool]:
    values = require_list(attestation.get("controls"), "attestation.controls")
    controls: dict[str, JsonObject] = {}
    violated = False
    for index, value in enumerate(values):
        control = require_object(value, f"attestation.controls[{index}]")
        control_id = require_string(control.get("control_id"), f"attestation.controls[{index}].control_id")
        if control_id in controls:
            raise IsolationBoundaryError(f"OS isolation attestation repeats control '{control_id}'.")
        status = require_string(control.get("status"), f"attestation.controls[{index}].status")
        if status not in {"verified", "unproven", "violated"}:
            raise IsolationBoundaryError(f"OS isolation control '{control_id}' has unsupported status '{status}'.")
        evidence = require_list(control.get("evidence"), f"attestation.controls[{index}].evidence")
        if status == "verified" and not evidence:
            raise IsolationBoundaryError(f"Verified OS isolation control '{control_id}' lacks evidence.")
        violated = violated or status == "violated"
        controls[control_id] = control
    if set(controls) != REQUIRED_ISOLATION_CONTROLS:
        missing = sorted(REQUIRED_ISOLATION_CONTROLS - set(controls))
        unexpected = sorted(set(controls) - REQUIRED_ISOLATION_CONTROLS)
        raise IsolationBoundaryError(
            "OS isolation controls must match the constitutional set exactly: "
            f"missing={missing}, unexpected={unexpected}."
        )
    blockers = sorted(control_id for control_id, control in controls.items() if control.get("status") != "verified")
    expected_status = "verified" if not blockers else ("violated" if violated else "boundary_unproven")
    actual_status = require_string(attestation.get("status"), "attestation.status")
    if actual_status != expected_status:
        raise IsolationBoundaryError(
            f"OS isolation status '{actual_status}' does not match derived status '{expected_status}'."
        )
    declared_blockers = [require_string(value, "attestation.blockers[]") for value in require_list(attestation.get("blockers"), "attestation.blockers")]
    if declared_blockers != blockers:
        raise IsolationBoundaryError(
            f"OS isolation blockers do not match control evidence: expected={blockers}, received={declared_blockers}."
        )
    return blockers, not blockers


def verify_isolation_attestation(
    attestation: JsonObject,
    governance_state: JsonObject,
    now: datetime,
    maximum_lifetime_seconds: int,
) -> JsonObject:
    if require_string(attestation.get("attestation_version"), "attestation.attestation_version") != "0.1.0":
        raise IsolationBoundaryError("OS isolation attestation_version must be '0.1.0'.")
    origin = require_string(attestation.get("origin"), "attestation.origin")
    if origin not in {"simulated", "range", "sacrificial_replica", "live"}:
        raise IsolationBoundaryError(f"OS isolation attestation origin '{origin}' is unsupported.")
    component_kind = require_string(attestation.get("component_kind"), "attestation.component_kind")
    if component_kind not in {"verifier", "evaluator"}:
        raise IsolationBoundaryError(f"OS isolation component kind '{component_kind}' is unsupported.")
    component_id = require_string(attestation.get("component_id"), "attestation.component_id")
    logical_principal = require_string(attestation.get("logical_principal"), "attestation.logical_principal")
    process = require_object(attestation.get("process"), "attestation.process")
    process_id = process.get("process_id")
    if not isinstance(process_id, int) or isinstance(process_id, bool) or process_id <= 0:
        raise IsolationBoundaryError("OS isolation process_id must be a positive integer.")
    account_identifier = require_string(process.get("os_account_identifier"), "attestation.process.os_account_identifier")
    account_sid = require_string(process.get("os_account_sid"), "attestation.process.os_account_sid")
    collector = require_object(attestation.get("collector"), "attestation.collector")
    collector_kind = require_string(collector.get("kind"), "attestation.collector.kind")
    if collector_kind not in {"fixture", "windows_access_check", "linux_access_check", "macos_access_check"}:
        raise IsolationBoundaryError(f"OS isolation collector kind '{collector_kind}' is unsupported.")
    if origin == "live" and collector_kind == "fixture":
        raise IsolationBoundaryError("Live OS isolation evidence cannot originate from a fixture collector.")
    if attestation.get("governance_state_digest") != sha256_digest(governance_state):
        raise IsolationBoundaryError("OS isolation attestation governance-state digest mismatch.")
    if require_object(attestation.get("authority"), "attestation.authority") != ISOLATION_AUTHORITY:
        raise IsolationBoundaryError("OS isolation attestation exposes prohibited authority.")
    issued_at = _validate_time_window(attestation, now, maximum_lifetime_seconds)
    blockers, boundary_verified = _validate_controls(attestation)
    verified_signers, verified_roles = verify_threshold_signatures(
        attestation,
        governance_state,
        issued_at,
        ISOLATION_ATTESTATION_DOMAIN,
        "OS isolation attestation",
        IsolationBoundaryError,
    )
    production_eligible = boundary_verified and origin == "live" and collector_kind != "fixture"
    return {
        "verification_version": "0.1.0",
        "attestation_digest": sha256_digest(attestation),
        "origin": origin,
        "component_kind": component_kind,
        "component_id": component_id,
        "logical_principal": logical_principal,
        "process_id": process_id,
        "os_account_identifier": account_identifier,
        "os_account_sid": account_sid,
        "collector_kind": collector_kind,
        "boundary_verified": boundary_verified,
        "production_eligible": production_eligible,
        "read_only_acl_verified": "READ_ONLY_INPUT_ACL" not in blockers,
        "verified_signer_ids": verified_signers,
        "verified_roles": verified_roles,
        "blockers": blockers,
        "authority": ISOLATION_AUTHORITY,
    }
