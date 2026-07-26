"""Contract-only snapshot restoration and cleanup evidence evaluation."""

from __future__ import annotations

from datetime import datetime

from nimrod_simulator.authorization import parse_timestamp
from nimrod_simulator.errors import ControlStateValidationError, RangeRecoveryError
from nimrod_simulator.jsonio import require_integer, require_list, require_object, require_string, sha256_digest
from nimrod_simulator.model import JsonObject
from nimrod_simulator.range_topology import validate_range_topology


REQUIRED_CLEANUP_OBLIGATIONS = {
    "AGENT_ABSENCE",
    "CREDENTIAL_DISPOSITION",
    "ROUTE_CLOSURE",
    "TARGET_RESTORED",
    "TELEMETRY_FINALIZED",
    "TOOL_ARTIFACT_REMOVAL",
}


def range_cleanup_subject(evidence: JsonObject) -> JsonObject:
    return {
        "evidence_id": evidence.get("evidence_id"),
        "captured_at": evidence.get("captured_at"),
        "topology_digest": evidence.get("topology_digest"),
        "kill_state_digest": evidence.get("kill_state_digest"),
        "baseline_snapshot_digest": evidence.get("baseline_snapshot_digest"),
        "observed_post_cleanup_snapshot_digest": evidence.get("observed_post_cleanup_snapshot_digest"),
        "cleanup_obligations": evidence.get("cleanup_obligations"),
    }


def range_cleanup_subject_digest(evidence: JsonObject) -> str:
    return sha256_digest(range_cleanup_subject(evidence))


def evaluate_range_recovery(
    evidence: JsonObject,
    topology: JsonObject,
    kill_state: JsonObject,
    evaluated_at: datetime,
    maximum_evidence_age_seconds: int,
) -> JsonObject:
    if evaluated_at.utcoffset() is None:
        raise RangeRecoveryError("Range recovery evaluation time must be timezone-aware.")
    if maximum_evidence_age_seconds <= 0:
        raise RangeRecoveryError("Range recovery maximum evidence age must be positive.")
    topology_verdict = validate_range_topology(topology)
    if evidence.get("evidence_version") != "0.1.0" or evidence.get("origin") != "simulated":
        raise RangeRecoveryError("Range recovery evidence must be version 0.1.0 and simulated.")
    if evidence.get("topology_digest") != topology_verdict.get("topology_digest"):
        raise RangeRecoveryError("Range recovery topology digest mismatch.")
    if kill_state.get("state_version") != "0.1.0" or kill_state.get("origin") != "simulated":
        raise RangeRecoveryError("Range recovery kill state version or origin mismatch.")
    if kill_state.get("state") != "engaged" or kill_state.get("kill_remains_engaged") is not True:
        raise RangeRecoveryError("Range recovery requires an engaged irreversible kill state.")
    if kill_state.get("topology_digest") != topology_verdict.get("topology_digest"):
        raise RangeRecoveryError("Range recovery kill state is bound to another topology.")
    if kill_state.get("topology_id") != topology.get("topology_id") or kill_state.get("generation") != topology.get("generation"):
        raise RangeRecoveryError("Range recovery kill state identity mismatch.")
    kill_authority = require_object(kill_state.get("authority"), "kill_state.authority")
    if kill_authority != {"can_disengage": False, "can_connect": False, "can_execute": False}:
        raise RangeRecoveryError("Range recovery kill state contains authority.")
    if evidence.get("kill_state_digest") != sha256_digest(kill_state):
        raise RangeRecoveryError("Range recovery kill-state digest mismatch.")
    evidence_authority = require_object(evidence.get("authority"), "evidence.authority")
    if evidence_authority != {"can_reset_kill": False, "can_reuse_range": False, "can_execute": False}:
        raise RangeRecoveryError("Range recovery evidence cannot reset, reuse, or execute.")
    try:
        captured_at = parse_timestamp(evidence.get("captured_at"), "evidence.captured_at")
    except ControlStateValidationError as error:
        raise RangeRecoveryError(f"Range recovery captured_at is invalid: {error}.") from error
    age_seconds = int((evaluated_at - captured_at).total_seconds())
    if age_seconds < 0:
        raise RangeRecoveryError("Range recovery evidence cannot be captured in the future.")
    if age_seconds > maximum_evidence_age_seconds:
        raise RangeRecoveryError(
            f"Range recovery evidence age {age_seconds}s exceeds {maximum_evidence_age_seconds}s."
        )
    expected_subject_digest = range_cleanup_subject_digest(evidence)
    if evidence.get("cleanup_subject_digest") != expected_subject_digest:
        raise RangeRecoveryError("Range recovery cleanup subject digest mismatch.")

    obligation_values = require_list(evidence.get("cleanup_obligations"), "evidence.cleanup_obligations")
    obligations: list[JsonObject] = [
        require_object(value, f"evidence.cleanup_obligations[{index}]")
        for index, value in enumerate(obligation_values)
    ]
    obligation_ids: list[str] = []
    blockers: list[str] = []
    for obligation in obligations:
        obligation_id = require_string(obligation.get("obligation_id"), "obligation.obligation_id")
        status = require_string(obligation.get("status"), "obligation.status")
        if status not in {"verified", "unproven", "failed"}:
            raise RangeRecoveryError(f"Cleanup obligation '{obligation_id}' has unsupported status '{status}'.")
        references = require_list(obligation.get("evidence"), "obligation.evidence")
        if status == "verified" and not references:
            raise RangeRecoveryError(f"Verified cleanup obligation '{obligation_id}' lacks evidence.")
        if status != "verified":
            blockers.append(obligation_id)
        obligation_ids.append(obligation_id)
    if len(obligation_ids) != len(set(obligation_ids)) or set(obligation_ids) != REQUIRED_CLEANUP_OBLIGATIONS:
        raise RangeRecoveryError("Range recovery must contain each cleanup obligation exactly once.")

    observations_values = require_list(evidence.get("verifier_observations"), "evidence.verifier_observations")
    observations: list[JsonObject] = [
        require_object(value, f"evidence.verifier_observations[{index}]")
        for index, value in enumerate(observations_values)
    ]
    if len(observations) != 2:
        raise RangeRecoveryError("Range recovery requires exactly two independent verifier observations.")
    verifier_ids = [require_string(value.get("verifier_id"), "verifier.verifier_id") for value in observations]
    principals = [require_string(value.get("logical_principal"), "verifier.logical_principal") for value in observations]
    process_ids = [require_integer(value.get("process_id"), "verifier.process_id") for value in observations]
    if len(set(verifier_ids)) != 2 or len(set(principals)) != 2 or len(set(process_ids)) != 2:
        raise RangeRecoveryError("Range recovery requires distinct verifier identities, principals, and processes.")
    verified_verifier_count = 0
    for observation in observations:
        if observation.get("subject_digest") != expected_subject_digest:
            raise RangeRecoveryError("Range recovery verifier observation subject digest mismatch.")
        status = require_string(observation.get("status"), "verifier.status")
        if status not in {"verified", "rejected"}:
            raise RangeRecoveryError(f"Range recovery verifier status '{status}' is unsupported.")
        if status == "verified":
            verified_verifier_count += 1
        else:
            blockers.append("VERIFIER_REJECTED")

    baseline_digest = require_string(evidence.get("baseline_snapshot_digest"), "evidence.baseline_snapshot_digest")
    observed_digest = require_string(
        evidence.get("observed_post_cleanup_snapshot_digest"),
        "evidence.observed_post_cleanup_snapshot_digest",
    )
    snapshot_restored = baseline_digest == observed_digest
    if not snapshot_restored:
        blockers.append("SNAPSHOT_STATE_MISMATCH")
    blockers = sorted(set(blockers))
    cleanup_verified = not blockers and verified_verifier_count == 2
    return {
        "receipt_version": "0.1.0",
        "origin": "simulated",
        "status": "verified_contract_only" if cleanup_verified else "blocked",
        "evidence_id": evidence["evidence_id"],
        "evidence_digest": sha256_digest(evidence),
        "topology_digest": topology_verdict["topology_digest"],
        "kill_state_digest": sha256_digest(kill_state),
        "cleanup_subject_digest": expected_subject_digest,
        "snapshot_restored": snapshot_restored,
        "cleanup_verified": cleanup_verified,
        "cleanup_obligation_count": len(obligations),
        "verified_verifier_count": verified_verifier_count,
        "blockers": blockers,
        "kill_remains_engaged": True,
        "range_reuse_authorized": False,
        "range_connection_authorized": False,
        "execution_authorized": False,
        "authority": {"can_reset_kill": False, "can_reuse_range": False, "can_execute": False},
    }
