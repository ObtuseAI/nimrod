"""Fail-closed projection of supervised-verifier evidence for the control board."""

from __future__ import annotations

from datetime import datetime

from nimrod_simulator.errors import ControlBoardProjectionError, IsolationBoundaryError
from nimrod_simulator.isolation_boundary import verify_isolation_attestation
from nimrod_simulator.jsonio import require_boolean, require_integer, require_object, require_string, sha256_digest
from nimrod_simulator.model import JsonObject


CONSENSUS_STATES = {
    "agreed_valid",
    "agreed_valid_boundary_unproven",
    "agreed_invalid",
    "disagreement",
    "verifier_timeout",
    "verifier_unavailable",
}
OBSERVATION_STATES = {"valid", "invalid", "timeout", "unavailable"}
OPERATOR_STATE_BY_CONSENSUS = {
    "agreed_valid": "verified",
    "agreed_valid_boundary_unproven": "boundary_unproven",
    "agreed_invalid": "invalid",
    "disagreement": "disagreement",
    "verifier_timeout": "timeout",
    "verifier_unavailable": "unavailable",
}
SUMMARY_BY_OPERATOR_STATE = {
    "verified": "Independent verification is accepted under the complete production boundary.",
    "boundary_unproven": "Verifier agreement exists, but the production isolation boundary is incomplete.",
    "invalid": "Both independent verifiers rejected the same evidence subject.",
    "disagreement": "Verifier observations disagree; dissent is preserved and success is blocked.",
    "timeout": "At least one required verifier exceeded its deadline; success is blocked.",
    "unavailable": "At least one required verifier is unavailable; success is blocked.",
}
BLOCKER_MESSAGES = {
    "CONSENSUS_NOT_ACCEPTED": "Verifier consensus is not accepted.",
    "DEDICATED_OS_IDENTITY_UNPROVEN": "A dedicated verifier OS identity has not been proven for both services.",
    "OS_READ_ONLY_ACL_UNPROVEN": "OS-enforced read-only ACL evidence is missing.",
    "VERIFIER_HEALTH_INCOMPLETE": "Both required verifier health reports are not production-ready.",
    "VERIFIER_DISAGREEMENT": "Verifier observations disagree and cannot be collapsed into a majority result.",
    "VERIFIER_TIMEOUT": "A required verifier exceeded its deadline.",
    "VERIFIER_UNAVAILABLE": "A required verifier did not return an observation.",
    "EVIDENCE_INVALID": "Both verifiers rejected the same evidence subject.",
}


def _require_two_observations(observations: list[JsonObject]) -> None:
    if len(observations) != 2:
        raise ControlBoardProjectionError(
            f"Control-board projection requires exactly two verifier observations; received {len(observations)}."
        )
    service_ids = [require_string(value.get("service_id"), "observation.service_id") for value in observations]
    principals = [
        require_string(value.get("logical_principal"), "observation.logical_principal") for value in observations
    ]
    if len(set(service_ids)) != 2:
        raise ControlBoardProjectionError("Control-board projection requires two distinct verifier service identities.")
    if len(set(principals)) != 2:
        raise ControlBoardProjectionError("Control-board projection requires two distinct verifier principals.")
    process_ids = [value.get("process_id") for value in observations if isinstance(value.get("process_id"), int)]
    if len(process_ids) == 2 and process_ids[0] == process_ids[1]:
        raise ControlBoardProjectionError("Control-board projection cannot represent two verifiers from one process.")
    for index, observation in enumerate(observations):
        status = require_string(observation.get("status"), f"observations[{index}].status")
        if status not in OBSERVATION_STATES:
            raise ControlBoardProjectionError(f"Unsupported verifier observation status '{status}'.")


def _validate_evidence_binding(
    health_reports: list[JsonObject], observations: list[JsonObject], consensus: JsonObject
) -> str:
    _require_two_observations(observations)
    if len(health_reports) > 2:
        raise ControlBoardProjectionError(
            f"Control-board projection accepts at most two verifier health reports; received {len(health_reports)}."
        )
    observation_services = {
        require_string(value.get("service_id"), "observation.service_id") for value in observations
    }
    health_services = [require_string(value.get("service_id"), "health.service_id") for value in health_reports]
    if len(health_services) != len(set(health_services)):
        raise ControlBoardProjectionError("Control-board projection received duplicate verifier health identities.")
    unknown_health = sorted(set(health_services) - observation_services)
    if unknown_health:
        raise ControlBoardProjectionError(
            f"Verifier health reports do not bind to the observations: {', '.join(unknown_health)}."
        )
    origin = require_string(consensus.get("origin"), "consensus.origin")
    evidence = [*health_reports, *observations]
    for index, value in enumerate(evidence):
        if value.get("origin") != origin:
            raise ControlBoardProjectionError(
                f"Verifier evidence origin mismatch at evidence index {index}: expected '{origin}'."
            )
    expected_digests = {
        require_string(consensus.get("primary_observation_digest"), "consensus.primary_observation_digest"),
        require_string(consensus.get("secondary_observation_digest"), "consensus.secondary_observation_digest"),
    }
    observed_digests = {sha256_digest(value) for value in observations}
    if expected_digests != observed_digests:
        raise ControlBoardProjectionError("Verifier consensus digests do not bind the supplied observations.")
    state = require_string(consensus.get("state"), "consensus.state")
    if state not in CONSENSUS_STATES:
        raise ControlBoardProjectionError(f"Unsupported verifier consensus state '{state}'.")
    accepted = require_boolean(consensus.get("verification_accepted"), "consensus.verification_accepted")
    if accepted != (state == "agreed_valid"):
        raise ControlBoardProjectionError("Only an agreed_valid consensus may claim verification acceptance.")
    return origin


def _project_health(report: JsonObject | None, observation: JsonObject) -> JsonObject:
    if report is None:
        return {
            "service_id": require_string(observation.get("service_id"), "observation.service_id"),
            "logical_principal": require_string(
                observation.get("logical_principal"), "observation.logical_principal"
            ),
            "process_id": observation.get("process_id"),
            "os_account_identifier": observation.get("os_account_identifier"),
            "status": "unavailable",
            "os_account_boundary_verified": False,
            "production_ready": False,
        }
    report_service = require_string(report.get("service_id"), "health.service_id")
    observation_service = require_string(observation.get("service_id"), "observation.service_id")
    if report_service != observation_service:
        raise ControlBoardProjectionError(
            f"Health service '{report_service}' does not match observation service '{observation_service}'."
        )
    health_pid = require_integer(report.get("process_id"), "health.process_id")
    observation_pid = observation.get("process_id")
    if isinstance(observation_pid, int) and observation_pid != health_pid:
        raise ControlBoardProjectionError(
            f"Health and observation process IDs differ for verifier '{report_service}'."
        )
    health_principal = require_string(report.get("logical_principal"), "health.logical_principal")
    observation_principal = require_string(observation.get("logical_principal"), "observation.logical_principal")
    if health_principal != observation_principal:
        raise ControlBoardProjectionError(
            f"Health and observation principals differ for verifier '{report_service}'."
        )
    return {
        "service_id": report_service,
        "logical_principal": health_principal,
        "process_id": health_pid,
        "os_account_identifier": require_string(
            report.get("os_account_identifier"), "health.os_account_identifier"
        ),
        "status": require_string(report.get("status"), "health.status"),
        "os_account_boundary_verified": require_boolean(
            report.get("os_account_boundary_verified"), "health.os_account_boundary_verified"
        ),
        "production_ready": require_boolean(report.get("production_ready"), "health.production_ready"),
    }


def _project_observation(observation: JsonObject) -> JsonObject:
    details = require_object(observation.get("details"), "observation.details")
    message = details.get("message")
    if message is not None and not isinstance(message, str):
        raise ControlBoardProjectionError("Verifier observation details.message must be a string or null.")
    return {
        "service_id": require_string(observation.get("service_id"), "observation.service_id"),
        "status": require_string(observation.get("status"), "observation.status"),
        "observed_at": require_string(observation.get("observed_at"), "observation.observed_at"),
        "subject_digest": observation.get("subject_digest"),
        "read_only_behavior_verified": require_boolean(
            observation.get("read_only_behavior_verified"), "observation.read_only_behavior_verified"
        ),
        "detail": message or "No verifier error reported.",
    }


def _verify_isolation_evidence(
    isolation_attestations: list[JsonObject],
    observations: list[JsonObject],
    governance_state: JsonObject,
    captured_at: datetime,
    maximum_attestation_lifetime_seconds: int,
) -> list[JsonObject]:
    if len(isolation_attestations) != 2:
        raise ControlBoardProjectionError(
            f"Control-board projection requires exactly two signed isolation attestations; received {len(isolation_attestations)}."
        )
    observation_by_service = {
        require_string(value.get("service_id"), "observation.service_id"): value for value in observations
    }
    verifications: list[JsonObject] = []
    for attestation in isolation_attestations:
        try:
            verification = verify_isolation_attestation(
                attestation,
                governance_state,
                captured_at,
                maximum_attestation_lifetime_seconds,
            )
        except IsolationBoundaryError as error:
            raise ControlBoardProjectionError(f"Verifier OS isolation evidence is invalid: {error}") from error
        if verification.get("component_kind") != "verifier":
            raise ControlBoardProjectionError("Verifier projection received non-verifier isolation evidence.")
        component_id = require_string(verification.get("component_id"), "isolation.component_id")
        observation = observation_by_service.get(component_id)
        if observation is None:
            raise ControlBoardProjectionError(
                f"Verifier isolation component '{component_id}' does not bind a supplied observation."
            )
        expected = {
            "logical_principal": observation.get("logical_principal"),
            "process_id": observation.get("process_id"),
            "os_account_identifier": observation.get("os_account_identifier"),
        }
        for field, value in expected.items():
            if verification.get(field) != value:
                raise ControlBoardProjectionError(
                    f"Verifier isolation field '{field}' does not bind observation '{component_id}'."
                )
        verifications.append(verification)
    if len({str(value["component_id"]) for value in verifications}) != 2:
        raise ControlBoardProjectionError("Verifier projection received duplicate isolation component identities.")
    return sorted(verifications, key=lambda value: str(value["component_id"]))


def _blocker_codes(
    consensus_state: str,
    consensus_accepted: bool,
    health_complete: bool,
    os_identity_verified: bool,
    os_read_only_acl_verified: bool,
) -> list[str]:
    result: list[str] = []
    state_blockers = {
        "agreed_invalid": "EVIDENCE_INVALID",
        "disagreement": "VERIFIER_DISAGREEMENT",
        "verifier_timeout": "VERIFIER_TIMEOUT",
        "verifier_unavailable": "VERIFIER_UNAVAILABLE",
    }
    state_blocker = state_blockers.get(consensus_state)
    if state_blocker is not None:
        result.append(state_blocker)
    if not consensus_accepted:
        result.append("CONSENSUS_NOT_ACCEPTED")
    if not health_complete:
        result.append("VERIFIER_HEALTH_INCOMPLETE")
    if not os_identity_verified:
        result.append("DEDICATED_OS_IDENTITY_UNPROVEN")
    if not os_read_only_acl_verified:
        result.append("OS_READ_ONLY_ACL_UNPROVEN")
    return result


def project_verifier_control_board(
    health_reports: list[JsonObject],
    observations: list[JsonObject],
    consensus: JsonObject,
    isolation_attestations: list[JsonObject],
    governance_state: JsonObject,
    captured_at: str,
    maximum_attestation_lifetime_seconds: int,
) -> JsonObject:
    """Create a display-only verifier projection from cryptographically bound evidence."""
    origin = _validate_evidence_binding(health_reports, observations, consensus)
    try:
        captured_at_value = datetime.fromisoformat(captured_at.replace("Z", "+00:00"))
    except ValueError as error:
        raise ControlBoardProjectionError(
            f"Control-board projection captured_at is invalid: '{captured_at}'."
        ) from error
    if captured_at_value.tzinfo is None:
        raise ControlBoardProjectionError("Control-board projection captured_at must include a UTC offset.")
    isolation_verifications = _verify_isolation_evidence(
        isolation_attestations,
        observations,
        governance_state,
        captured_at_value,
        maximum_attestation_lifetime_seconds,
    )
    if any(value.get("origin") != origin for value in isolation_verifications):
        raise ControlBoardProjectionError("Verifier isolation evidence origin does not match the consensus origin.")
    health_by_service = {
        require_string(report.get("service_id"), "health.service_id"): report for report in health_reports
    }
    ordered_observations = sorted(
        observations, key=lambda value: require_string(value.get("service_id"), "observation.service_id")
    )
    projected_health = [
        _project_health(
            health_by_service.get(require_string(observation.get("service_id"), "observation.service_id")),
            observation,
        )
        for observation in ordered_observations
    ]
    health_complete = len(health_reports) == 2 and all(
        value.get("status") == "healthy_reference_boundary" for value in projected_health
    )
    isolation_evidence_verified = all(
        value.get("boundary_verified") is True for value in isolation_verifications
    )
    live_os_enforcement_verified = isolation_evidence_verified and all(
        value.get("production_eligible") is True for value in isolation_verifications
    )
    os_identity_verified = health_complete and live_os_enforcement_verified and all(
        value.get("os_account_boundary_verified") is True and value.get("production_ready") is True
        for value in projected_health
    )
    os_read_only_acl_verified = live_os_enforcement_verified and all(
        value.get("read_only_acl_verified") is True for value in isolation_verifications
    )
    consensus_state = require_string(consensus.get("state"), "consensus.state")
    consensus_accepted = require_boolean(
        consensus.get("verification_accepted"), "consensus.verification_accepted"
    )
    production_ready = (
        consensus_state == "agreed_valid"
        and consensus_accepted
        and health_complete
        and os_identity_verified
        and os_read_only_acl_verified
    )
    operator_state = OPERATOR_STATE_BY_CONSENSUS[consensus_state]
    if operator_state == "verified" and not production_ready:
        operator_state = "boundary_unproven"
    blocker_codes = _blocker_codes(
        consensus_state,
        consensus_accepted,
        health_complete,
        os_identity_verified,
        os_read_only_acl_verified,
    )
    dissent = [
        {"code": code, "source": "supervised_verifier", "message": BLOCKER_MESSAGES[code]}
        for code in blocker_codes
    ]
    return {
        "projection_version": "0.2.0",
        "origin": origin,
        "captured_at": captured_at,
        "operator_state": operator_state,
        "severity": "verified" if production_ready else "blocked",
        "summary": SUMMARY_BY_OPERATOR_STATE[operator_state],
        "consensus": {
            "consensus_id": require_string(consensus.get("consensus_id"), "consensus.consensus_id"),
            "observed_at": require_string(consensus.get("observed_at"), "consensus.observed_at"),
            "state": consensus_state,
            "verification_accepted": consensus_accepted,
            "reason": require_string(consensus.get("reason"), "consensus.reason"),
            "primary_observation_digest": require_string(
                consensus.get("primary_observation_digest"), "consensus.primary_observation_digest"
            ),
            "secondary_observation_digest": require_string(
                consensus.get("secondary_observation_digest"), "consensus.secondary_observation_digest"
            ),
        },
        "service_health": projected_health,
        "observations": [_project_observation(value) for value in ordered_observations],
        "boundary": {
            "production_ready": production_ready,
            "health_complete": health_complete,
            "isolation_evidence_verified": isolation_evidence_verified,
            "live_os_enforcement_verified": live_os_enforcement_verified,
            "dedicated_os_identity_verified": os_identity_verified,
            "os_read_only_acl_verified": os_read_only_acl_verified,
            "isolation_attestation_digests": [
                value["attestation_digest"] for value in isolation_verifications
            ],
            "missing_controls": blocker_codes,
        },
        "dissent": dissent,
        "authority": {
            "can_authorize": False,
            "can_execute": False,
            "may_mark_verification_accepted": production_ready,
        },
    }
