"""Independent range-evidence decisions with no collection or execution capability."""

from __future__ import annotations

import base64
import binascii
import copy
from datetime import datetime

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from nimrod_simulator.authorization import parse_timestamp
from nimrod_simulator.compiler import deterministic_uuid, format_timestamp
from nimrod_simulator.errors import (
    ControlStateValidationError,
    RangeEvidenceAcceptanceError,
    RangeVerifierDecisionError,
    RangeVerifierPolicyError,
)
from nimrod_simulator.jsonio import (
    canonical_json_bytes,
    require_boolean,
    require_integer,
    require_list,
    require_object,
    require_string,
    require_string_list,
    sha256_digest,
)
from nimrod_simulator.key_governance import (
    SigningConnector,
    decode_public_key,
    validate_governance_state,
)
from nimrod_simulator.model import JsonObject
from nimrod_simulator.range_evidence_admission import REAL_OBSERVATION_ORIGINS
from nimrod_simulator.range_execution_gate import REQUIRED_ENVIRONMENT_ATTESTATIONS
from nimrod_simulator.threshold_signing import (
    sign_threshold_document,
    verify_threshold_signatures,
)


RANGE_VERIFIER_POLICY_DOMAIN = b"nimrod.range-verifier-policy.v0.1\x00"
RANGE_VERIFIER_DECISION_DOMAIN = b"nimrod.range-verifier-decision.v0.1\x00"
VERIFIER_OPERATIONS = {"emit_decision", "inspect_retained_observation"}
VERIFIER_DECISIONS = {"accept", "abstain", "reject", "timeout"}
DECISION_REASON_BY_VALUE = {
    "accept": "evidence_supports_control",
    "abstain": "insufficient_or_fixture_evidence",
    "reject": "evidence_contradicts_control",
    "timeout": "verification_deadline_exceeded",
}
VERIFIER_POLICY_AUTHORITY = {
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
VERIFIER_DECISION_ACTIVITY = {
    "environment_contact_performed_by_nimrod": False,
    "collection_performed": False,
    "policy_mutation_performed": False,
    "credential_access_performed": False,
    "tool_installation_performed": False,
    "network_contact_performed": False,
    "range_connection_performed": False,
    "campaign_execution_performed": False,
}
VERIFIER_DECISION_AUTHORITY = copy.deepcopy(VERIFIER_POLICY_AUTHORITY)
ACCEPTANCE_ACTIVITY = {
    "environment_contact_performed": False,
    "collection_performed": False,
    "infrastructure_provisioned": False,
    "host_or_network_policy_changed": False,
    "credentials_handled": False,
    "tools_installed": False,
    "network_contact_performed": False,
    "range_connected": False,
    "campaign_executed": False,
}
ACCEPTANCE_AUTHORITY = copy.deepcopy(VERIFIER_POLICY_AUTHORITY)


def _timestamp(
    value: object,
    field: str,
    error_type: type[Exception],
) -> datetime:
    try:
        return parse_timestamp(value, field)
    except ControlStateValidationError as error:
        raise error_type(f"Timestamp '{field}' is invalid: {error}.") from error


def _decode_base64(
    value: str,
    field: str,
    error_type: type[Exception],
) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as error:
        raise error_type(f"Field '{field}' is not canonical base64.") from error


def sign_range_verifier_policy(
    unsigned_policy: JsonObject,
    connectors: list[SigningConnector],
) -> JsonObject:
    return sign_threshold_document(
        unsigned_policy,
        connectors,
        RANGE_VERIFIER_POLICY_DOMAIN,
        "range verifier policy",
        RangeVerifierPolicyError,
    )


def _verifier_index(policy: JsonObject) -> dict[str, JsonObject]:
    verifiers = require_list(policy.get("verifiers"), "policy.verifiers")
    return {
        require_string(
            require_object(value, f"policy.verifiers[{index}]").get("verifier_id"),
            f"policy.verifiers[{index}].verifier_id",
        ): require_object(value, f"policy.verifiers[{index}]")
        for index, value in enumerate(verifiers)
    }


def verify_range_verifier_policy(
    policy: JsonObject,
    governance_state: JsonObject,
    admission_report: JsonObject,
    evaluated_at: datetime,
    maximum_lifetime_seconds: int,
) -> JsonObject:
    if evaluated_at.utcoffset() is None:
        raise RangeVerifierPolicyError("Verifier policy evaluation time must be timezone-aware.")
    if maximum_lifetime_seconds <= 0:
        raise RangeVerifierPolicyError("Verifier policy maximum lifetime must be positive.")
    validate_governance_state(governance_state)
    if policy.get("policy_version") != "0.1.0":
        raise RangeVerifierPolicyError("Range verifier policy must use version 0.1.0.")
    if policy.get("governance_state_digest") != sha256_digest(governance_state):
        raise RangeVerifierPolicyError("Range verifier policy governance-state digest mismatch.")
    if policy.get("admission_report_id") != admission_report.get("report_id"):
        raise RangeVerifierPolicyError("Range verifier policy admission-report identity mismatch.")
    if policy.get("admission_report_digest") != sha256_digest(admission_report):
        raise RangeVerifierPolicyError("Range verifier policy admission-report digest mismatch.")
    for field in ("origin", "scope_digest", "environment_id"):
        if policy.get(field) != admission_report.get(field):
            raise RangeVerifierPolicyError(f"Range verifier policy {field} binding mismatch.")
    issued_at = _timestamp(policy.get("issued_at"), "policy.issued_at", RangeVerifierPolicyError)
    not_before = _timestamp(policy.get("not_before"), "policy.not_before", RangeVerifierPolicyError)
    expires_at = _timestamp(policy.get("expires_at"), "policy.expires_at", RangeVerifierPolicyError)
    if issued_at > not_before or not_before >= expires_at:
        raise RangeVerifierPolicyError("Range verifier policy validity window is inconsistent.")
    if int((expires_at - issued_at).total_seconds()) > maximum_lifetime_seconds:
        raise RangeVerifierPolicyError("Range verifier policy lifetime exceeds the configured maximum.")
    if evaluated_at < not_before or evaluated_at > expires_at:
        raise RangeVerifierPolicyError("Range verifier policy is outside its active validity window.")
    if require_integer(policy.get("minimum_decisions_per_observation"), "minimum_decisions_per_observation") != 2:
        raise RangeVerifierPolicyError("Range verifier policy requires exactly two decisions per observation.")
    if set(require_string_list(policy.get("allowed_decisions"), "allowed_decisions")) != VERIFIER_DECISIONS:
        raise RangeVerifierPolicyError("Range verifier policy decision vocabulary is widened or incomplete.")
    verifiers = [
        require_object(value, f"policy.verifiers[{index}]")
        for index, value in enumerate(require_list(policy.get("verifiers"), "policy.verifiers"))
    ]
    if len(verifiers) != 3:
        raise RangeVerifierPolicyError("Range verifier policy requires exactly three independently identified verifiers.")
    verifier_ids: set[str] = set()
    principals: set[str] = set()
    process_ids: set[int] = set()
    public_keys: set[str] = set()
    origin = require_string(policy.get("origin"), "policy.origin")
    for index, verifier in enumerate(verifiers):
        verifier_id = require_string(verifier.get("verifier_id"), f"verifiers[{index}].verifier_id")
        principal = require_string(verifier.get("logical_principal"), f"verifiers[{index}].logical_principal")
        process_id = require_integer(verifier.get("process_id"), f"verifiers[{index}].process_id")
        public_key = require_string(verifier.get("public_key_base64"), f"verifiers[{index}].public_key_base64")
        if process_id <= 0:
            raise RangeVerifierPolicyError(f"Verifier '{verifier_id}' process ID must be positive.")
        if require_boolean(verifier.get("read_only"), f"verifiers[{index}].read_only") is not True:
            raise RangeVerifierPolicyError(f"Verifier '{verifier_id}' must be read-only.")
        if set(require_string_list(verifier.get("operation_allowlist"), "verifier.operation_allowlist")) != VERIFIER_OPERATIONS:
            raise RangeVerifierPolicyError(f"Verifier '{verifier_id}' operation allowlist is widened or incomplete.")
        if require_list(verifier.get("network_destinations"), "verifier.network_destinations"):
            raise RangeVerifierPolicyError(f"Verifier '{verifier_id}' cannot declare network destinations.")
        if require_list(verifier.get("secret_references"), "verifier.secret_references"):
            raise RangeVerifierPolicyError(f"Verifier '{verifier_id}' cannot declare secret references.")
        if require_boolean(verifier.get("collector_identity_shared"), "verifier.collector_identity_shared"):
            raise RangeVerifierPolicyError(f"Verifier '{verifier_id}' cannot share a collector identity.")
        enforcement = require_string(verifier.get("identity_enforcement"), "verifier.identity_enforcement")
        independence_digest = verifier.get("independence_evidence_digest")
        if origin == "simulated":
            if enforcement != "fixture_logical_only" or independence_digest is not None:
                raise RangeVerifierPolicyError("Simulated verifier identities must remain fixture-only and unproven.")
        elif origin in REAL_OBSERVATION_ORIGINS:
            if enforcement != "externally_attested" or not isinstance(independence_digest, str):
                raise RangeVerifierPolicyError("Real verifier identities require external independence evidence.")
        else:
            raise RangeVerifierPolicyError(f"Range verifier policy origin '{origin}' is unsupported.")
        decode_public_key(public_key, verifier_id)
        verifier_ids.add(verifier_id)
        principals.add(principal)
        process_ids.add(process_id)
        public_keys.add(public_key)
    if any(len(values) != 3 for values in (verifier_ids, principals, process_ids, public_keys)):
        raise RangeVerifierPolicyError("Verifier identities, principals, processes, and public keys must be distinct.")
    expected_status = "fixture_policy_non_accepting" if origin == "simulated" else "external_evidence_decisions_allowed"
    if policy.get("status") != expected_status:
        raise RangeVerifierPolicyError("Range verifier policy status is inconsistent with its origin.")
    blockers = set(require_string_list(policy.get("blockers"), "policy.blockers"))
    expected_blockers = {"EVIDENCE_COMPLETION_AUTHORITY_MISSING"}
    if origin == "simulated":
        expected_blockers.add("REAL_INDEPENDENT_VERIFIER_ACCEPTANCE_MISSING")
    if blockers != expected_blockers:
        raise RangeVerifierPolicyError("Range verifier policy blockers are incomplete or laundered.")
    if require_object(policy.get("authority"), "policy.authority") != VERIFIER_POLICY_AUTHORITY:
        raise RangeVerifierPolicyError("Range verifier policy exposes prohibited authority.")
    verified_signers, verified_roles = verify_threshold_signatures(
        policy,
        governance_state,
        issued_at,
        RANGE_VERIFIER_POLICY_DOMAIN,
        "range verifier policy",
        RangeVerifierPolicyError,
    )
    return {
        "policy_id": require_string(policy.get("policy_id"), "policy.policy_id"),
        "policy_digest": sha256_digest(policy),
        "origin": origin,
        "verified_signer_ids": verified_signers,
        "verified_roles": verified_roles,
        "verifier_count": len(verifiers),
    }


def _decision_message(decision: JsonObject) -> bytes:
    unsigned: JsonObject = {key: value for key, value in decision.items() if key != "signature"}
    return RANGE_VERIFIER_DECISION_DOMAIN + canonical_json_bytes(unsigned)


def sign_range_verifier_decision(
    unsigned_decision: JsonObject,
    connector: SigningConnector,
) -> JsonObject:
    if "signature" in unsigned_decision:
        raise RangeVerifierDecisionError("Unsigned range verifier decision contains a signature.")
    return {
        **unsigned_decision,
        "signature": {
            "signer_id": connector.key_id,
            "algorithm": "Ed25519",
            "signature_base64": base64.b64encode(connector.sign(_decision_message(unsigned_decision))).decode("ascii"),
        },
    }


def _retained_observation_index(admission_report: JsonObject) -> dict[str, JsonObject]:
    retained = require_list(admission_report.get("retained_observations"), "admission_report.retained_observations")
    return {
        require_string(
            require_object(value, f"retained_observations[{index}]").get("observation_id"),
            f"retained_observations[{index}].observation_id",
        ): require_object(value, f"retained_observations[{index}]")
        for index, value in enumerate(retained)
    }


def verify_range_verifier_decision(
    decision: JsonObject,
    policy: JsonObject,
    admission_report: JsonObject,
    evaluated_at: datetime,
    maximum_age_seconds: int,
) -> JsonObject:
    if evaluated_at.utcoffset() is None:
        raise RangeVerifierDecisionError("Verifier decision evaluation time must be timezone-aware.")
    if maximum_age_seconds <= 0:
        raise RangeVerifierDecisionError("Verifier decision maximum age must be positive.")
    if decision.get("decision_version") != "0.1.0":
        raise RangeVerifierDecisionError("Range verifier decision must use version 0.1.0.")
    origin = require_string(decision.get("origin"), "decision.origin")
    if origin != policy.get("origin") or origin != admission_report.get("origin"):
        raise RangeVerifierDecisionError("Range verifier decision origin binding mismatch.")
    expected_status = "fixture_decision_non_accepting" if origin == "simulated" else "externally_supplied_pending_acceptance"
    if decision.get("status") != expected_status:
        raise RangeVerifierDecisionError("Range verifier decision status is inconsistent with its origin.")
    bindings = {
        "policy_id": policy.get("policy_id"),
        "policy_digest": sha256_digest(policy),
        "admission_report_id": admission_report.get("report_id"),
        "admission_report_digest": sha256_digest(admission_report),
        "environment_id": admission_report.get("environment_id"),
        "scope_digest": admission_report.get("scope_digest"),
    }
    for field, expected in bindings.items():
        if decision.get(field) != expected:
            raise RangeVerifierDecisionError(f"Range verifier decision {field} binding mismatch.")
    decided_at = _timestamp(decision.get("decided_at"), "decision.decided_at", RangeVerifierDecisionError)
    age_seconds = int((evaluated_at - decided_at).total_seconds())
    if age_seconds < 0:
        raise RangeVerifierDecisionError("Range verifier decision is from the future.")
    if age_seconds > maximum_age_seconds:
        raise RangeVerifierDecisionError("Range verifier decision is stale.")
    observation_id = require_string(decision.get("observation_id"), "decision.observation_id")
    retained = _retained_observation_index(admission_report).get(observation_id)
    if retained is None:
        raise RangeVerifierDecisionError("Range verifier decision references an unretained observation.")
    for field in ("observation_digest", "raw_evidence_digest", "control_id"):
        if decision.get(field) != retained.get(field):
            raise RangeVerifierDecisionError(f"Range verifier decision {field} binding mismatch.")
    verifier_identity = require_object(decision.get("verifier"), "decision.verifier")
    verifier_id = require_string(verifier_identity.get("verifier_id"), "decision.verifier.verifier_id")
    verifier = _verifier_index(policy).get(verifier_id)
    if verifier is None:
        raise RangeVerifierDecisionError(f"Range verifier '{verifier_id}' is not policy-pinned.")
    expected_identity = {
        "verifier_id": verifier_id,
        "logical_principal": verifier.get("logical_principal"),
        "process_id": verifier.get("process_id"),
        "identity_enforcement": verifier.get("identity_enforcement"),
        "independence_evidence_digest": verifier.get("independence_evidence_digest"),
    }
    if verifier_identity != expected_identity:
        raise RangeVerifierDecisionError("Range verifier decision identity differs from policy.")
    decision_value = require_string(decision.get("decision"), "decision.decision")
    if decision_value not in VERIFIER_DECISIONS:
        raise RangeVerifierDecisionError(f"Range verifier decision '{decision_value}' is unsupported.")
    if origin == "simulated" and decision_value == "accept":
        raise RangeVerifierDecisionError("Simulated evidence cannot receive an accepting verifier decision.")
    if decision.get("reason") != DECISION_REASON_BY_VALUE[decision_value]:
        raise RangeVerifierDecisionError("Range verifier decision reason does not match the decision.")
    if require_boolean(decision.get("evidence_read_only"), "decision.evidence_read_only") is not True:
        raise RangeVerifierDecisionError("Range verifier decision must preserve read-only evidence access.")
    if require_object(decision.get("activity"), "decision.activity") != VERIFIER_DECISION_ACTIVITY:
        raise RangeVerifierDecisionError("Range verifier decision claims prohibited activity.")
    if require_object(decision.get("authority"), "decision.authority") != VERIFIER_DECISION_AUTHORITY:
        raise RangeVerifierDecisionError("Range verifier decision exposes prohibited authority.")
    signature = require_object(decision.get("signature"), "decision.signature")
    if signature.get("signer_id") != verifier_id or signature.get("algorithm") != "Ed25519":
        raise RangeVerifierDecisionError("Range verifier decision signature identity or algorithm mismatch.")
    signature_bytes = _decode_base64(
        require_string(signature.get("signature_base64"), "decision.signature.signature_base64"),
        "decision.signature.signature_base64",
        RangeVerifierDecisionError,
    )
    if len(signature_bytes) != 64:
        raise RangeVerifierDecisionError("Range verifier decision Ed25519 signature must be 64 bytes.")
    public_key = decode_public_key(
        require_string(verifier.get("public_key_base64"), "verifier.public_key_base64"),
        verifier_id,
    )
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature_bytes, _decision_message(decision))
    except (InvalidSignature, ValueError) as error:
        raise RangeVerifierDecisionError(
            f"Range verifier decision signature verification failed for '{verifier_id}'."
        ) from error
    return {
        "decision_id": require_string(decision.get("decision_id"), "decision.decision_id"),
        "decision_digest": sha256_digest(decision),
        "observation_id": observation_id,
        "observation_digest": retained.get("observation_digest"),
        "raw_evidence_digest": retained.get("raw_evidence_digest"),
        "control_id": retained.get("control_id"),
        "verifier_id": verifier_id,
        "identity_enforcement": verifier.get("identity_enforcement"),
        "decision": decision_value,
        "reason": decision.get("reason"),
        "decided_at": format_timestamp(decided_at),
    }


def resolve_range_verifier_decisions(
    origin: str,
    decision_values: list[str],
) -> str:
    if len(decision_values) != 2:
        raise RangeEvidenceAcceptanceError("Exactly two verifier decisions are required per observation.")
    if any(value not in VERIFIER_DECISIONS for value in decision_values):
        raise RangeEvidenceAcceptanceError("Verifier decision resolution received an unsupported value.")
    if "timeout" in decision_values:
        return "timeout"
    unique_values = set(decision_values)
    if len(unique_values) != 1:
        return "disagreement"
    value = decision_values[0]
    if value == "accept":
        if origin not in REAL_OBSERVATION_ORIGINS:
            raise RangeEvidenceAcceptanceError("Simulated evidence cannot resolve to accepted.")
        return "accepted"
    if value == "reject":
        return "rejected"
    if value == "abstain":
        return "abstained"
    raise RangeEvidenceAcceptanceError(f"Verifier decision value '{value}' cannot be resolved.")


def build_range_evidence_acceptance_report(
    policy: JsonObject,
    governance_state: JsonObject,
    admission_report: JsonObject,
    decisions: list[object],
    assembled_at: datetime,
    maximum_policy_lifetime_seconds: int,
    maximum_decision_age_seconds: int,
) -> JsonObject:
    policy_verification = verify_range_verifier_policy(
        policy,
        governance_state,
        admission_report,
        assembled_at,
        maximum_policy_lifetime_seconds,
    )
    decision_objects = [
        require_object(value, f"decisions[{index}]")
        for index, value in enumerate(decisions)
    ]
    expected_decision_count = len(REQUIRED_ENVIRONMENT_ATTESTATIONS) * 2
    if len(decision_objects) != expected_decision_count:
        raise RangeEvidenceAcceptanceError("Range evidence acceptance requires exactly two decisions per control.")
    verified = [
        verify_range_verifier_decision(
            decision,
            policy,
            admission_report,
            assembled_at,
            maximum_decision_age_seconds,
        )
        for decision in decision_objects
    ]
    decisions_by_control: dict[str, list[JsonObject]] = {
        control_id: [] for control_id in REQUIRED_ENVIRONMENT_ATTESTATIONS
    }
    decision_ids: set[str] = set()
    for item in verified:
        control_id = require_string(item.get("control_id"), "verified.control_id")
        decisions_by_control[control_id].append(item)
        decision_id = require_string(item.get("decision_id"), "verified.decision_id")
        if decision_id in decision_ids:
            raise RangeEvidenceAcceptanceError("Range verifier decision IDs must be unique.")
        decision_ids.add(decision_id)
    control_results: list[JsonObject] = []
    for control_id in sorted(REQUIRED_ENVIRONMENT_ATTESTATIONS):
        control_decisions = decisions_by_control[control_id]
        if len(control_decisions) != 2:
            raise RangeEvidenceAcceptanceError(f"Control '{control_id}' does not have exactly two decisions.")
        observation_ids = {str(item.get("observation_id")) for item in control_decisions}
        verifier_ids = {str(item.get("verifier_id")) for item in control_decisions}
        if len(observation_ids) != 1:
            raise RangeEvidenceAcceptanceError(f"Control '{control_id}' decisions bind different observations.")
        if len(verifier_ids) != 2:
            raise RangeEvidenceAcceptanceError(f"Control '{control_id}' decisions require distinct verifiers.")
        resolution = resolve_range_verifier_decisions(
            require_string(policy_verification.get("origin"), "policy_verification.origin"),
            [require_string(item.get("decision"), "verified.decision") for item in control_decisions],
        )
        control_results.append(
            {
                "control_id": control_id,
                "observation_id": control_decisions[0]["observation_id"],
                "observation_digest": control_decisions[0]["observation_digest"],
                "raw_evidence_digest": control_decisions[0]["raw_evidence_digest"],
                "resolution": resolution,
                "decision_ids": sorted(str(item["decision_id"]) for item in control_decisions),
                "verifier_ids": sorted(str(item["verifier_id"]) for item in control_decisions),
            }
        )
    retained_decisions = sorted(
        [
            {
                "decision_id": item["decision_id"],
                "decision_digest": item["decision_digest"],
                "observation_id": item["observation_id"],
                "control_id": item["control_id"],
                "verifier_id": item["verifier_id"],
                "decision": item["decision"],
                "reason": item["reason"],
                "decided_at": item["decided_at"],
            }
            for item in verified
        ],
        key=lambda item: (str(item["control_id"]), str(item["verifier_id"])),
    )
    resolution_counts = {
        status: sum(1 for item in control_results if item.get("resolution") == status)
        for status in ("accepted", "rejected", "abstained", "disagreement", "timeout")
    }
    origin = require_string(policy_verification.get("origin"), "policy_verification.origin")
    used_verifier_ids = {str(item.get("verifier_id")) for item in verified}
    external_verifier_ids = {
        str(item.get("verifier_id"))
        for item in verified
        if item.get("identity_enforcement") == "externally_attested"
    }
    accepted_count = resolution_counts["accepted"]
    if origin == "simulated":
        status = "blocked_fixture_verifier_decisions_non_accepting"
    elif accepted_count == len(REQUIRED_ENVIRONMENT_ATTESTATIONS):
        status = "accepted_controls_pending_separate_evidence_completion_authority"
    else:
        status = "blocked_unresolved_or_negative_verifier_decisions"
    blockers = {
        "EVIDENCE_COMPLETION_AUTHORITY_MISSING",
        "RANGE_CONNECTION_AUTHORIZATION_MISSING",
        "EXECUTION_AUTHORIZATION_MISSING",
    }
    if origin == "simulated":
        blockers.update(
            {
                "OWNER_NAMED_SACRIFICIAL_RANGE_MISSING",
                "REAL_READ_ONLY_OBSERVATIONS_MISSING",
                "REAL_INDEPENDENT_VERIFIER_ACCEPTANCE_MISSING",
            }
        )
    elif accepted_count != len(REQUIRED_ENVIRONMENT_ATTESTATIONS):
        blockers.add("ALL_REQUIRED_CONTROLS_NOT_ACCEPTED")
    policy_id = require_string(policy_verification.get("policy_id"), "policy_verification.policy_id")
    report_id = deterministic_uuid(policy_id, sha256_digest(retained_decisions), "range-evidence-acceptance")
    return {
        "report_version": "0.1.0",
        "report_id": report_id,
        "origin": origin,
        "status": status,
        "assembled_at": format_timestamp(assembled_at),
        "policy_id": policy_id,
        "policy_digest": policy_verification["policy_digest"],
        "admission_report_id": admission_report.get("report_id"),
        "admission_report_digest": sha256_digest(admission_report),
        "scope_digest": admission_report.get("scope_digest"),
        "environment_id": admission_report.get("environment_id"),
        "environment_name": admission_report.get("environment_name"),
        "owner_named_environment": admission_report.get("owner_named_environment"),
        "required_control_count": len(REQUIRED_ENVIRONMENT_ATTESTATIONS),
        "verified_decision_count": len(verified),
        "distinct_signed_verifier_count": len(used_verifier_ids),
        "real_independent_verifier_count": len(external_verifier_ids),
        "retained_decisions": retained_decisions,
        "control_results": control_results,
        "resolution_counts": resolution_counts,
        "accepted_control_count": accepted_count,
        "verified_attestation_count": 0,
        "evidence_complete": False,
        "blockers": sorted(blockers),
        "activity": copy.deepcopy(ACCEPTANCE_ACTIVITY),
        "authority": copy.deepcopy(ACCEPTANCE_AUTHORITY),
    }


def validate_range_evidence_acceptance_report(
    report: JsonObject,
    policy: JsonObject,
    governance_state: JsonObject,
    admission_report: JsonObject,
    decisions: list[object],
    assembled_at: datetime,
    maximum_policy_lifetime_seconds: int,
    maximum_decision_age_seconds: int,
) -> None:
    expected = build_range_evidence_acceptance_report(
        policy,
        governance_state,
        admission_report,
        decisions,
        assembled_at,
        maximum_policy_lifetime_seconds,
        maximum_decision_age_seconds,
    )
    if report != expected:
        raise RangeEvidenceAcceptanceError(
            "Range evidence acceptance report differs from the deterministic decision projection."
        )
