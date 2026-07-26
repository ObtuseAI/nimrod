"""Threshold-authorized range evidence completion without connection or execution authority."""

from __future__ import annotations

import copy
from datetime import datetime

from nimrod_simulator.authorization import parse_timestamp
from nimrod_simulator.compiler import deterministic_uuid, format_timestamp
from nimrod_simulator.errors import (
    ControlStateValidationError,
    RangeEvidenceCompletionAuthorizationError,
    RangeEvidenceCompletionError,
    RangeEvidenceCompletionPolicyError,
)
from nimrod_simulator.jsonio import (
    require_boolean,
    require_integer,
    require_list,
    require_object,
    require_string,
    require_string_list,
    sha256_digest,
)
from nimrod_simulator.key_governance import SigningConnector, validate_governance_state
from nimrod_simulator.model import JsonObject
from nimrod_simulator.range_evidence_admission import REAL_OBSERVATION_ORIGINS
from nimrod_simulator.range_evidence_acceptance import ACCEPTANCE_ACTIVITY, ACCEPTANCE_AUTHORITY
from nimrod_simulator.range_execution_gate import REQUIRED_ENVIRONMENT_ATTESTATIONS
from nimrod_simulator.threshold_signing import sign_threshold_document, verify_threshold_signatures


COMPLETION_POLICY_DOMAIN = b"nimrod.range-evidence-completion-policy.v0.1\x00"
COMPLETION_AUTHORIZATION_DOMAIN = b"nimrod.range-evidence-completion-authorization.v0.1\x00"
COMPLETION_OUTCOMES = {"authorize_completion", "deny_completion"}
COMPLETABLE_ACCEPTANCE_STATUS = "accepted_controls_pending_separate_evidence_completion_authority"
COMPLETION_POLICY_AUTHORITY = {
    "can_collect": False,
    "can_install": False,
    "can_provision": False,
    "can_change_policy": False,
    "can_access_credentials": False,
    "can_connect": False,
    "can_execute": False,
    "can_mark_evidence_complete": False,
    "can_authorize_action": False,
}
COMPLETION_ACTIVITY = copy.deepcopy(ACCEPTANCE_ACTIVITY)
COMPLETION_RECEIPT_AUTHORITY = copy.deepcopy(COMPLETION_POLICY_AUTHORITY)


def _timestamp(
    value: object,
    field: str,
    error_type: type[Exception],
) -> datetime:
    try:
        return parse_timestamp(value, field)
    except ControlStateValidationError as error:
        raise error_type(f"Timestamp '{field}' is invalid: {error}.") from error


def _verify_window(
    document: JsonObject,
    evaluated_at: datetime,
    maximum_lifetime_seconds: int,
    label: str,
    error_type: type[Exception],
) -> datetime:
    if evaluated_at.utcoffset() is None:
        raise error_type(f"{label.capitalize()} evaluation time must be timezone-aware.")
    if maximum_lifetime_seconds <= 0:
        raise error_type(f"{label.capitalize()} maximum lifetime must be positive.")
    issued_at = _timestamp(document.get("issued_at"), f"{label}.issued_at", error_type)
    not_before = _timestamp(document.get("not_before"), f"{label}.not_before", error_type)
    expires_at = _timestamp(document.get("expires_at"), f"{label}.expires_at", error_type)
    if issued_at > not_before or not_before >= expires_at:
        raise error_type(f"{label.capitalize()} validity window is inconsistent.")
    if int((expires_at - issued_at).total_seconds()) > maximum_lifetime_seconds:
        raise error_type(f"{label.capitalize()} lifetime exceeds the configured maximum.")
    if evaluated_at < not_before or evaluated_at > expires_at:
        raise error_type(f"{label.capitalize()} is outside its active validity window.")
    return issued_at


def _expected_policy_blockers(origin: str) -> set[str]:
    blockers = {"EVIDENCE_COMPLETION_AUTHORIZATION_MISSING"}
    if origin == "simulated":
        blockers.update(
            {
                "OWNER_NAMED_SACRIFICIAL_RANGE_MISSING",
                "REAL_INDEPENDENT_VERIFIER_ACCEPTANCE_MISSING",
                "REAL_READ_ONLY_OBSERVATIONS_MISSING",
            }
        )
    return blockers


def sign_range_evidence_completion_policy(
    unsigned_policy: JsonObject,
    connectors: list[SigningConnector],
) -> JsonObject:
    return sign_threshold_document(
        unsigned_policy,
        connectors,
        COMPLETION_POLICY_DOMAIN,
        "range evidence completion policy",
        RangeEvidenceCompletionPolicyError,
    )


def verify_range_evidence_completion_policy(
    policy: JsonObject,
    governance_state: JsonObject,
    acceptance_report: JsonObject,
    evaluated_at: datetime,
    maximum_lifetime_seconds: int,
) -> JsonObject:
    validate_governance_state(governance_state)
    if policy.get("policy_version") != "0.1.0":
        raise RangeEvidenceCompletionPolicyError("Range evidence completion policy must use version 0.1.0.")
    if policy.get("governance_state_digest") != sha256_digest(governance_state):
        raise RangeEvidenceCompletionPolicyError("Completion policy governance-state digest mismatch.")
    bindings = {
        "acceptance_report_id": acceptance_report.get("report_id"),
        "acceptance_report_digest": sha256_digest(acceptance_report),
        "origin": acceptance_report.get("origin"),
        "scope_digest": acceptance_report.get("scope_digest"),
        "environment_id": acceptance_report.get("environment_id"),
    }
    for field, expected in bindings.items():
        if policy.get(field) != expected:
            raise RangeEvidenceCompletionPolicyError(f"Completion policy {field} binding mismatch.")
    origin = require_string(policy.get("origin"), "policy.origin")
    if origin not in {"simulated", *REAL_OBSERVATION_ORIGINS}:
        raise RangeEvidenceCompletionPolicyError(f"Completion policy origin '{origin}' is unsupported.")
    issued_at = _verify_window(
        policy,
        evaluated_at,
        maximum_lifetime_seconds,
        "completion policy",
        RangeEvidenceCompletionPolicyError,
    )
    required_controls = require_string_list(policy.get("required_controls"), "policy.required_controls")
    if set(required_controls) != REQUIRED_ENVIRONMENT_ATTESTATIONS or len(required_controls) != len(
        REQUIRED_ENVIRONMENT_ATTESTATIONS
    ):
        raise RangeEvidenceCompletionPolicyError("Completion policy must require every range control exactly once.")
    expected_count = len(REQUIRED_ENVIRONMENT_ATTESTATIONS)
    exact_counts = {
        "required_accepted_control_count": expected_count,
        "required_verified_attestation_count": expected_count,
        "required_real_independent_verifier_count": 2,
    }
    for field, expected in exact_counts.items():
        if require_integer(policy.get(field), f"policy.{field}") != expected:
            raise RangeEvidenceCompletionPolicyError(f"Completion policy {field} is weakened or widened.")
    if policy.get("required_acceptance_status") != COMPLETABLE_ACCEPTANCE_STATUS:
        raise RangeEvidenceCompletionPolicyError("Completion policy acceptance status is weakened or widened.")
    if set(require_string_list(policy.get("allowed_outcomes"), "policy.allowed_outcomes")) != COMPLETION_OUTCOMES:
        raise RangeEvidenceCompletionPolicyError("Completion policy outcome vocabulary is widened or incomplete.")
    if require_list(policy.get("network_destinations"), "policy.network_destinations"):
        raise RangeEvidenceCompletionPolicyError("Completion policy cannot declare network destinations.")
    if require_list(policy.get("secret_references"), "policy.secret_references"):
        raise RangeEvidenceCompletionPolicyError("Completion policy cannot declare secret references.")
    expected_status = "fixture_policy_non_completing" if origin == "simulated" else "external_completion_policy"
    if policy.get("status") != expected_status:
        raise RangeEvidenceCompletionPolicyError("Completion policy status is inconsistent with its origin.")
    blockers = set(require_string_list(policy.get("blockers"), "policy.blockers"))
    if blockers != _expected_policy_blockers(origin):
        raise RangeEvidenceCompletionPolicyError("Completion policy blockers are incomplete or laundered.")
    if require_object(policy.get("authority"), "policy.authority") != COMPLETION_POLICY_AUTHORITY:
        raise RangeEvidenceCompletionPolicyError("Completion policy exposes prohibited authority.")
    verified_signers, verified_roles = verify_threshold_signatures(
        policy,
        governance_state,
        issued_at,
        COMPLETION_POLICY_DOMAIN,
        "range evidence completion policy",
        RangeEvidenceCompletionPolicyError,
    )
    return {
        "policy_id": require_string(policy.get("policy_id"), "policy.policy_id"),
        "policy_digest": sha256_digest(policy),
        "origin": origin,
        "verified_signer_ids": verified_signers,
        "verified_roles": verified_roles,
    }


def _completion_prerequisites_satisfied(acceptance_report: JsonObject) -> bool:
    controls = require_list(acceptance_report.get("control_results"), "acceptance_report.control_results")
    control_objects = [
        require_object(value, f"acceptance_report.control_results[{index}]")
        for index, value in enumerate(controls)
    ]
    control_ids = {
        require_string(value.get("control_id"), "acceptance_report.control_result.control_id")
        for value in control_objects
    }
    resolutions = require_object(acceptance_report.get("resolution_counts"), "acceptance_report.resolution_counts")
    expected_count = len(REQUIRED_ENVIRONMENT_ATTESTATIONS)
    return (
        acceptance_report.get("origin") in REAL_OBSERVATION_ORIGINS
        and acceptance_report.get("status") == COMPLETABLE_ACCEPTANCE_STATUS
        and require_boolean(acceptance_report.get("owner_named_environment"), "owner_named_environment") is True
        and isinstance(acceptance_report.get("environment_name"), str)
        and bool(acceptance_report.get("environment_name"))
        and require_integer(acceptance_report.get("required_control_count"), "required_control_count") == expected_count
        and require_integer(acceptance_report.get("accepted_control_count"), "accepted_control_count") == expected_count
        and require_integer(acceptance_report.get("verified_attestation_count"), "verified_attestation_count") == expected_count
        and require_integer(
            acceptance_report.get("real_independent_verifier_count"), "real_independent_verifier_count"
        )
        >= 2
        and control_ids == REQUIRED_ENVIRONMENT_ATTESTATIONS
        and len(control_objects) == expected_count
        and all(value.get("resolution") == "accepted" for value in control_objects)
        and resolutions
        == {"accepted": expected_count, "rejected": 0, "abstained": 0, "disagreement": 0, "timeout": 0}
        and acceptance_report.get("evidence_complete") is False
        and require_object(acceptance_report.get("activity"), "acceptance_report.activity") == ACCEPTANCE_ACTIVITY
        and require_object(acceptance_report.get("authority"), "acceptance_report.authority") == ACCEPTANCE_AUTHORITY
    )


def sign_range_evidence_completion_authorization(
    unsigned_authorization: JsonObject,
    connectors: list[SigningConnector],
) -> JsonObject:
    return sign_threshold_document(
        unsigned_authorization,
        connectors,
        COMPLETION_AUTHORIZATION_DOMAIN,
        "range evidence completion authorization",
        RangeEvidenceCompletionAuthorizationError,
    )


def verify_range_evidence_completion_authorization(
    authorization: JsonObject,
    policy: JsonObject,
    governance_state: JsonObject,
    acceptance_report: JsonObject,
    evaluated_at: datetime,
    maximum_lifetime_seconds: int,
) -> JsonObject:
    if authorization.get("authorization_version") != "0.1.0":
        raise RangeEvidenceCompletionAuthorizationError(
            "Range evidence completion authorization must use version 0.1.0."
        )
    bindings = {
        "policy_id": policy.get("policy_id"),
        "policy_digest": sha256_digest(policy),
        "acceptance_report_id": acceptance_report.get("report_id"),
        "acceptance_report_digest": sha256_digest(acceptance_report),
        "origin": acceptance_report.get("origin"),
        "scope_digest": acceptance_report.get("scope_digest"),
        "environment_id": acceptance_report.get("environment_id"),
    }
    for field, expected in bindings.items():
        if authorization.get(field) != expected:
            raise RangeEvidenceCompletionAuthorizationError(f"Completion authorization {field} binding mismatch.")
    issued_at = _verify_window(
        authorization,
        evaluated_at,
        maximum_lifetime_seconds,
        "completion authorization",
        RangeEvidenceCompletionAuthorizationError,
    )
    outcome = require_string(authorization.get("outcome"), "authorization.outcome")
    if outcome not in COMPLETION_OUTCOMES:
        raise RangeEvidenceCompletionAuthorizationError(f"Completion outcome '{outcome}' is unsupported.")
    prerequisites_satisfied = _completion_prerequisites_satisfied(acceptance_report)
    expected_reason = (
        "all_completion_prerequisites_satisfied"
        if outcome == "authorize_completion"
        else "completion_denied_or_prerequisites_unsatisfied"
    )
    if authorization.get("reason") != expected_reason:
        raise RangeEvidenceCompletionAuthorizationError("Completion authorization reason is inconsistent with outcome.")
    if outcome == "authorize_completion" and not prerequisites_satisfied:
        raise RangeEvidenceCompletionAuthorizationError(
            "Completion cannot be authorized until every real evidence prerequisite is satisfied."
        )
    if authorization.get("origin") == "simulated" and outcome != "deny_completion":
        raise RangeEvidenceCompletionAuthorizationError("Simulated evidence completion must remain denied.")
    expected_status = "external_completion_authorized" if outcome == "authorize_completion" else "completion_denied"
    if authorization.get("status") != expected_status:
        raise RangeEvidenceCompletionAuthorizationError("Completion authorization status is inconsistent with outcome.")
    authority = require_object(authorization.get("authority"), "authorization.authority")
    expected_authority = copy.deepcopy(COMPLETION_POLICY_AUTHORITY)
    expected_authority["can_mark_evidence_complete"] = outcome == "authorize_completion"
    if authority != expected_authority:
        raise RangeEvidenceCompletionAuthorizationError("Completion authorization exposes widened or inconsistent authority.")
    verified_signers, verified_roles = verify_threshold_signatures(
        authorization,
        governance_state,
        issued_at,
        COMPLETION_AUTHORIZATION_DOMAIN,
        "range evidence completion authorization",
        RangeEvidenceCompletionAuthorizationError,
    )
    return {
        "authorization_id": require_string(authorization.get("authorization_id"), "authorization.authorization_id"),
        "authorization_digest": sha256_digest(authorization),
        "outcome": outcome,
        "prerequisites_satisfied": prerequisites_satisfied,
        "verified_signer_ids": verified_signers,
        "verified_roles": verified_roles,
    }


def build_range_evidence_completion_receipt(
    policy: JsonObject,
    authorization: JsonObject,
    governance_state: JsonObject,
    acceptance_report: JsonObject,
    completed_at: datetime,
    maximum_policy_lifetime_seconds: int,
    maximum_authorization_lifetime_seconds: int,
) -> JsonObject:
    policy_verification = verify_range_evidence_completion_policy(
        policy,
        governance_state,
        acceptance_report,
        completed_at,
        maximum_policy_lifetime_seconds,
    )
    authorization_verification = verify_range_evidence_completion_authorization(
        authorization,
        policy,
        governance_state,
        acceptance_report,
        completed_at,
        maximum_authorization_lifetime_seconds,
    )
    completed = authorization_verification.get("outcome") == "authorize_completion"
    origin = require_string(policy_verification.get("origin"), "policy_verification.origin")
    if completed:
        status = "evidence_complete_pending_separate_connection_authorization"
        blockers = ["EXECUTION_AUTHORIZATION_MISSING", "RANGE_CONNECTION_AUTHORIZATION_MISSING"]
    elif origin == "simulated":
        status = "blocked_fixture_acceptance_non_completing"
        blockers = sorted(
            {
                *require_string_list(acceptance_report.get("blockers"), "acceptance_report.blockers"),
                "EVIDENCE_COMPLETION_AUTHORIZATION_DENIED",
            }
        )
    else:
        status = "evidence_completion_denied"
        blockers = sorted(
            {
                *require_string_list(acceptance_report.get("blockers"), "acceptance_report.blockers"),
                "EVIDENCE_COMPLETION_AUTHORIZATION_DENIED",
            }
        )
    policy_id = require_string(policy_verification.get("policy_id"), "policy_verification.policy_id")
    authorization_id = require_string(
        authorization_verification.get("authorization_id"), "authorization_verification.authorization_id"
    )
    return {
        "receipt_version": "0.1.0",
        "receipt_id": deterministic_uuid(policy_id, authorization_id, sha256_digest(acceptance_report)),
        "origin": origin,
        "status": status,
        "completed_at": format_timestamp(completed_at),
        "policy_id": policy_id,
        "policy_digest": policy_verification["policy_digest"],
        "authorization_id": authorization_id,
        "authorization_digest": authorization_verification["authorization_digest"],
        "acceptance_report_id": acceptance_report.get("report_id"),
        "acceptance_report_digest": sha256_digest(acceptance_report),
        "scope_digest": acceptance_report.get("scope_digest"),
        "environment_id": acceptance_report.get("environment_id"),
        "environment_name": acceptance_report.get("environment_name"),
        "owner_named_environment": acceptance_report.get("owner_named_environment"),
        "required_control_count": acceptance_report.get("required_control_count"),
        "accepted_control_count": acceptance_report.get("accepted_control_count"),
        "verified_attestation_count": acceptance_report.get("verified_attestation_count"),
        "real_independent_verifier_count": acceptance_report.get("real_independent_verifier_count"),
        "completion_prerequisites_satisfied": authorization_verification["prerequisites_satisfied"],
        "completion_authorized": completed,
        "evidence_complete": completed,
        "range_connection_authorized": False,
        "execution_authorized": False,
        "verified_authorization_signer_ids": authorization_verification["verified_signer_ids"],
        "verified_authorization_roles": authorization_verification["verified_roles"],
        "blockers": blockers,
        "activity": copy.deepcopy(COMPLETION_ACTIVITY),
        "authority": copy.deepcopy(COMPLETION_RECEIPT_AUTHORITY),
    }


def validate_range_evidence_completion_receipt(
    receipt: JsonObject,
    policy: JsonObject,
    authorization: JsonObject,
    governance_state: JsonObject,
    acceptance_report: JsonObject,
    completed_at: datetime,
    maximum_policy_lifetime_seconds: int,
    maximum_authorization_lifetime_seconds: int,
) -> None:
    expected = build_range_evidence_completion_receipt(
        policy,
        authorization,
        governance_state,
        acceptance_report,
        completed_at,
        maximum_policy_lifetime_seconds,
        maximum_authorization_lifetime_seconds,
    )
    if receipt != expected:
        raise RangeEvidenceCompletionError(
            "Range evidence completion receipt differs from the deterministic authorization projection."
        )
