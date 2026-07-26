"""Signed evaluator policy, observations, and assurance-gated Foundry evaluation."""

from __future__ import annotations

import base64
import binascii
from datetime import datetime

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from nimrod_simulator.authorization import parse_timestamp
from nimrod_simulator.errors import (
    ControlStateValidationError,
    EvaluatorObservationError,
    EvaluatorTrustPolicyError,
)
from nimrod_simulator.evolution_foundry import (
    REQUIRED_EVALUATOR_ROLES,
    evaluate_cognitive_candidate,
)
from nimrod_simulator.isolation_boundary import verify_isolation_attestation
from nimrod_simulator.jsonio import canonical_json_bytes, require_list, require_object, require_string, sha256_digest
from nimrod_simulator.key_governance import SigningConnector
from nimrod_simulator.model import JsonObject
from nimrod_simulator.resource_ledger import verify_lineage_resource_ledger
from nimrod_simulator.threshold_signing import sign_threshold_document, verify_threshold_signatures


EVALUATOR_POLICY_DOMAIN = b"nimrod.evaluator-trust-policy.v0.1\x00"
EVALUATOR_OBSERVATION_DOMAIN = b"nimrod.evaluator-observation.v0.1\x00"
EVALUATOR_POLICY_AUTHORITY = {
    "can_select_itself": False,
    "can_modify_constitution": False,
    "can_grant_credentials": False,
    "can_execute": False,
}
EVALUATOR_OBSERVATION_AUTHORITY = {
    "can_promote": False,
    "can_execute": False,
    "can_modify_evaluators": False,
    "can_allocate_resources": False,
}
EVALUATOR_ASSURANCE_AUTHORITY = {
    "can_promote": False,
    "can_execute": False,
    "can_modify_evaluators": False,
    "can_expand_resources": False,
}


def sign_evaluator_trust_policy(
    unsigned_policy: JsonObject,
    connectors: list[SigningConnector],
) -> JsonObject:
    return sign_threshold_document(
        unsigned_policy,
        connectors,
        EVALUATOR_POLICY_DOMAIN,
        "evaluator trust policy",
        EvaluatorTrustPolicyError,
    )


def _policy_time(value: object, field: str) -> datetime:
    try:
        return parse_timestamp(value, field)
    except ControlStateValidationError as error:
        raise EvaluatorTrustPolicyError(f"Evaluator trust-policy time '{field}' is invalid: {error}.") from error


def _observation_time(value: object, field: str) -> datetime:
    try:
        return parse_timestamp(value, field)
    except ControlStateValidationError as error:
        raise EvaluatorObservationError(f"Evaluator observation time '{field}' is invalid: {error}.") from error


def verify_evaluator_trust_policy(
    policy: JsonObject,
    constitution: JsonObject,
    governance_state: JsonObject,
    now: datetime,
    maximum_lifetime_seconds: int,
) -> JsonObject:
    if policy.get("policy_version") != "0.1.0":
        raise EvaluatorTrustPolicyError("Evaluator trust policy_version must be '0.1.0'.")
    if now.tzinfo is None or maximum_lifetime_seconds <= 0:
        raise EvaluatorTrustPolicyError("Evaluator trust-policy verification requires an aware time and positive lifetime.")
    issued_at = _policy_time(policy.get("issued_at"), "policy.issued_at")
    not_before = _policy_time(policy.get("not_before"), "policy.not_before")
    expires_at = _policy_time(policy.get("expires_at"), "policy.expires_at")
    if issued_at < not_before or issued_at >= expires_at or now < not_before or now >= expires_at:
        raise EvaluatorTrustPolicyError("Evaluator trust policy is outside its active validity window.")
    if (expires_at - not_before).total_seconds() > maximum_lifetime_seconds:
        raise EvaluatorTrustPolicyError(
            f"Evaluator trust-policy lifetime exceeds {maximum_lifetime_seconds} seconds."
        )
    origin = require_string(policy.get("origin"), "policy.origin")
    if origin != constitution.get("origin") or origin != governance_state.get("origin"):
        raise EvaluatorTrustPolicyError("Evaluator trust policy origin does not match its roots.")
    if policy.get("constitution_digest") != sha256_digest(constitution):
        raise EvaluatorTrustPolicyError("Evaluator trust policy constitution digest mismatch.")
    if policy.get("governance_state_digest") != sha256_digest(governance_state):
        raise EvaluatorTrustPolicyError("Evaluator trust policy governance-state digest mismatch.")
    if require_object(policy.get("authority"), "policy.authority") != EVALUATOR_POLICY_AUTHORITY:
        raise EvaluatorTrustPolicyError("Evaluator trust policy exposes prohibited authority.")
    evaluators = require_list(policy.get("evaluators"), "policy.evaluators")
    if len(evaluators) != len(REQUIRED_EVALUATOR_ROLES):
        raise EvaluatorTrustPolicyError("Evaluator trust policy requires exactly four evaluator identities.")
    identities: set[str] = set()
    principals: set[str] = set()
    accounts: set[str] = set()
    sids: set[str] = set()
    roles: set[str] = set()
    for index, value in enumerate(evaluators):
        evaluator = require_object(value, f"policy.evaluators[{index}]")
        evaluator_id = require_string(evaluator.get("evaluator_id"), f"policy.evaluators[{index}].evaluator_id")
        principal = require_string(
            evaluator.get("logical_principal"), f"policy.evaluators[{index}].logical_principal"
        )
        account = require_string(
            evaluator.get("expected_os_account_identifier"),
            f"policy.evaluators[{index}].expected_os_account_identifier",
        )
        sid = require_string(
            evaluator.get("expected_os_account_sid"), f"policy.evaluators[{index}].expected_os_account_sid"
        )
        role = require_string(evaluator.get("role"), f"policy.evaluators[{index}].role")
        public_key = require_string(
            evaluator.get("public_key_base64"), f"policy.evaluators[{index}].public_key_base64"
        )
        try:
            public_key_bytes = base64.b64decode(public_key, validate=True)
        except (binascii.Error, ValueError) as error:
            raise EvaluatorTrustPolicyError(
                f"Evaluator '{evaluator_id}' public key is not canonical base64."
            ) from error
        if len(public_key_bytes) != 32:
            raise EvaluatorTrustPolicyError(f"Evaluator '{evaluator_id}' public key must be 32 bytes.")
        if (
            evaluator_id in identities
            or principal in principals
            or account.casefold() in accounts
            or sid.casefold() in sids
            or role in roles
        ):
            raise EvaluatorTrustPolicyError("Evaluator trust policy collapses an identity, principal, account, SID, or role.")
        identities.add(evaluator_id)
        principals.add(principal)
        accounts.add(account.casefold())
        sids.add(sid.casefold())
        roles.add(role)
    if roles != REQUIRED_EVALUATOR_ROLES:
        raise EvaluatorTrustPolicyError("Evaluator trust policy must bind every constitutional evaluator role.")
    verified_signers, verified_roles = verify_threshold_signatures(
        policy,
        governance_state,
        issued_at,
        EVALUATOR_POLICY_DOMAIN,
        "evaluator trust policy",
        EvaluatorTrustPolicyError,
    )
    return {
        "verification_version": "0.1.0",
        "policy_digest": sha256_digest(policy),
        "origin": origin,
        "evaluator_count": len(evaluators),
        "roles": sorted(roles),
        "verified_signer_ids": verified_signers,
        "verified_roles": verified_roles,
        "authority": EVALUATOR_POLICY_AUTHORITY,
    }


def evaluator_observation_message(envelope: JsonObject) -> bytes:
    unsigned = {key: value for key, value in envelope.items() if key != "signature"}
    return EVALUATOR_OBSERVATION_DOMAIN + canonical_json_bytes(unsigned)


def sign_evaluator_observation(
    unsigned_envelope: JsonObject,
    connector: SigningConnector,
) -> JsonObject:
    if "signature" in unsigned_envelope:
        raise EvaluatorObservationError("Unsigned evaluator observation contains a signature.")
    signature = base64.b64encode(
        connector.sign(EVALUATOR_OBSERVATION_DOMAIN + canonical_json_bytes(unsigned_envelope))
    ).decode("ascii")
    return {
        **unsigned_envelope,
        "signature": {
            "signer_id": connector.key_id,
            "algorithm": "Ed25519",
            "signature_base64": signature,
        },
    }


def evaluation_input_digest(
    capability_report: JsonObject,
    hard_gate_results: list[JsonObject],
    champion_floor_results: list[JsonObject],
    metrics: list[JsonObject],
) -> str:
    return sha256_digest(
        {
            "capability_report_digest": sha256_digest(capability_report),
            "hard_gate_results": hard_gate_results,
            "champion_floor_results": champion_floor_results,
            "metrics": metrics,
        }
    )


def _policy_evaluator(policy: JsonObject, evaluator_id: str) -> JsonObject:
    matches = [
        require_object(value, "policy.evaluators[]")
        for value in require_list(policy.get("evaluators"), "policy.evaluators")
        if isinstance(value, dict) and value.get("evaluator_id") == evaluator_id
    ]
    if len(matches) != 1:
        raise EvaluatorObservationError(f"Evaluator observation signer '{evaluator_id}' is not uniquely trusted.")
    return matches[0]


def verify_evaluator_observation(
    envelope: JsonObject,
    policy: JsonObject,
    policy_verification: JsonObject,
    isolation_attestation: JsonObject,
    isolation_verification: JsonObject,
    expected_candidate_digest: str,
    expected_constitution_digest: str,
    expected_capability_report_digest: str,
    expected_evaluation_input_digest: str,
    expected_resource_ledger_digest: str,
    now: datetime,
) -> tuple[JsonObject, JsonObject]:
    if envelope.get("envelope_version") != "0.1.0":
        raise EvaluatorObservationError("Evaluator observation envelope_version must be '0.1.0'.")
    if now.tzinfo is None:
        raise EvaluatorObservationError("Evaluator observation verification time must include a UTC offset.")
    observed_at = _observation_time(envelope.get("observed_at"), "envelope.observed_at")
    expires_at = _observation_time(envelope.get("expires_at"), "envelope.expires_at")
    if observed_at > now or now >= expires_at or observed_at >= expires_at:
        raise EvaluatorObservationError("Evaluator observation is future-dated, expired, or has an invalid window.")
    if envelope.get("origin") != policy_verification.get("origin"):
        raise EvaluatorObservationError("Evaluator observation origin does not match the verified trust policy.")
    expected_bindings = {
        "evaluator_policy_digest": policy_verification.get("policy_digest"),
        "subject_digest": expected_candidate_digest,
        "constitution_digest": expected_constitution_digest,
        "capability_report_digest": expected_capability_report_digest,
        "evaluation_input_digest": expected_evaluation_input_digest,
        "resource_ledger_digest": expected_resource_ledger_digest,
        "isolation_attestation_digest": isolation_verification.get("attestation_digest"),
    }
    for field, expected in expected_bindings.items():
        if envelope.get(field) != expected:
            raise EvaluatorObservationError(
                f"Evaluator observation binding '{field}' mismatch: expected '{expected}', received '{envelope.get(field)}'."
            )
    if sha256_digest(isolation_attestation) != isolation_verification.get("attestation_digest"):
        raise EvaluatorObservationError("Evaluator isolation attestation and verification receipt diverge.")
    if isolation_verification.get("boundary_verified") is not True:
        raise EvaluatorObservationError("Evaluator observation lacks complete OS-isolation control evidence.")
    evaluator_id = require_string(envelope.get("evaluator_id"), "envelope.evaluator_id")
    trusted = _policy_evaluator(policy, evaluator_id)
    identity_bindings = {
        "role": trusted.get("role"),
        "logical_principal": trusted.get("logical_principal"),
        "os_account_identifier": trusted.get("expected_os_account_identifier"),
        "os_account_sid": trusted.get("expected_os_account_sid"),
    }
    for field, expected in identity_bindings.items():
        if envelope.get(field) != expected:
            raise EvaluatorObservationError(
                f"Evaluator observation identity '{field}' mismatch for '{evaluator_id}'."
            )
    isolation_bindings = {
        "component_kind": "evaluator",
        "component_id": evaluator_id,
        "logical_principal": envelope.get("logical_principal"),
        "process_id": envelope.get("process_id"),
        "os_account_identifier": envelope.get("os_account_identifier"),
        "os_account_sid": envelope.get("os_account_sid"),
    }
    for field, expected in isolation_bindings.items():
        if isolation_verification.get(field) != expected:
            raise EvaluatorObservationError(
                f"Evaluator isolation identity '{field}' does not bind observation '{evaluator_id}'."
            )
    status = require_string(envelope.get("status"), "envelope.status")
    if status not in {"pass", "fail", "inconclusive"}:
        raise EvaluatorObservationError(f"Evaluator observation status '{status}' is unsupported.")
    evidence = [
        require_object(value, f"envelope.evidence[{index}]")
        for index, value in enumerate(require_list(envelope.get("evidence"), "envelope.evidence"))
    ]
    if status == "pass" and not evidence:
        raise EvaluatorObservationError("Passing evaluator observation requires evidence.")
    if require_object(envelope.get("authority"), "envelope.authority") != EVALUATOR_OBSERVATION_AUTHORITY:
        raise EvaluatorObservationError("Evaluator observation exposes prohibited authority.")
    signature = require_object(envelope.get("signature"), "envelope.signature")
    signer_id = require_string(signature.get("signer_id"), "envelope.signature.signer_id")
    if signer_id != evaluator_id or signature.get("algorithm") != "Ed25519":
        raise EvaluatorObservationError("Evaluator observation signature identity or algorithm mismatch.")
    try:
        public_key = base64.b64decode(
            require_string(trusted.get("public_key_base64"), "trusted.public_key_base64"), validate=True
        )
        signature_bytes = base64.b64decode(
            require_string(signature.get("signature_base64"), "envelope.signature.signature_base64"),
            validate=True,
        )
    except (binascii.Error, ValueError) as error:
        raise EvaluatorObservationError("Evaluator observation key or signature is not canonical base64.") from error
    if len(public_key) != 32 or len(signature_bytes) != 64:
        raise EvaluatorObservationError("Evaluator observation key or signature has an invalid length.")
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature_bytes, evaluator_observation_message(envelope))
    except (InvalidSignature, ValueError) as error:
        raise EvaluatorObservationError(f"Evaluator observation signature failed for '{evaluator_id}'.") from error
    envelope_digest = sha256_digest(envelope)
    projected_observation: JsonObject = {
        "evaluator_id": evaluator_id,
        "logical_principal": envelope["logical_principal"],
        "process_id": envelope["process_id"],
        "role": envelope["role"],
        "subject_digest": envelope["subject_digest"],
        "status": status,
        "evidence": [
            *evidence,
            {"id": f"signed-envelope:{envelope['envelope_id']}", "digest": envelope_digest},
            {"id": f"os-isolation:{isolation_attestation['attestation_id']}", "digest": isolation_verification["attestation_digest"]},
            {"id": "lineage-resource-ledger", "digest": expected_resource_ledger_digest},
        ],
    }
    verification: JsonObject = {
        "verification_version": "0.1.0",
        "envelope_id": envelope["envelope_id"],
        "envelope_digest": envelope_digest,
        "origin": envelope["origin"],
        "evaluator_id": evaluator_id,
        "logical_principal": envelope["logical_principal"],
        "process_id": envelope["process_id"],
        "role": envelope["role"],
        "signature_verified": True,
        "isolation_boundary_verified": True,
        "production_isolation_verified": isolation_verification["production_eligible"],
        "isolation_attestation_digest": isolation_verification["attestation_digest"],
        "resource_ledger_digest": expected_resource_ledger_digest,
        "status": status,
        "authority": EVALUATOR_OBSERVATION_AUTHORITY,
    }
    return projected_observation, verification


def evaluate_signed_cognitive_candidate(
    candidate: JsonObject,
    constitution: JsonObject,
    governance_state: JsonObject,
    capability_report: JsonObject,
    evaluator_policy: JsonObject,
    evaluator_envelopes: list[JsonObject],
    isolation_attestations: list[JsonObject],
    resource_ledger: JsonObject,
    hard_gate_results: list[JsonObject],
    champion_floor_results: list[JsonObject],
    metrics: list[JsonObject],
    evaluated_at: datetime,
    maximum_policy_lifetime_seconds: int,
    maximum_attestation_lifetime_seconds: int,
    maximum_ledger_lifetime_seconds: int,
) -> tuple[JsonObject, JsonObject]:
    policy_verification = verify_evaluator_trust_policy(
        evaluator_policy,
        constitution,
        governance_state,
        evaluated_at,
        maximum_policy_lifetime_seconds,
    )
    ledger_verification = verify_lineage_resource_ledger(
        resource_ledger,
        constitution,
        governance_state,
        evaluated_at,
        maximum_ledger_lifetime_seconds,
    )
    candidate_digest = sha256_digest(candidate)
    if ledger_verification.get("root_candidate_digest") != candidate_digest:
        raise EvaluatorObservationError("Resource ledger root does not bind the evaluated candidate.")
    isolation_by_digest: dict[str, tuple[JsonObject, JsonObject]] = {}
    for attestation in isolation_attestations:
        verification = verify_isolation_attestation(
            attestation,
            governance_state,
            evaluated_at,
            maximum_attestation_lifetime_seconds,
        )
        digest = require_string(verification.get("attestation_digest"), "isolation.attestation_digest")
        if digest in isolation_by_digest:
            raise EvaluatorObservationError(f"Evaluator assurance repeats isolation attestation '{digest}'.")
        isolation_by_digest[digest] = (attestation, verification)
    expected_input_digest = evaluation_input_digest(
        capability_report,
        hard_gate_results,
        champion_floor_results,
        metrics,
    )
    projected_observations: list[JsonObject] = []
    evaluator_verifications: list[JsonObject] = []
    for envelope in evaluator_envelopes:
        isolation_digest = require_string(
            envelope.get("isolation_attestation_digest"), "envelope.isolation_attestation_digest"
        )
        isolation_pair = isolation_by_digest.get(isolation_digest)
        if isolation_pair is None:
            raise EvaluatorObservationError(
                f"Evaluator observation references absent isolation attestation '{isolation_digest}'."
            )
        projected, verification = verify_evaluator_observation(
            envelope,
            evaluator_policy,
            policy_verification,
            isolation_pair[0],
            isolation_pair[1],
            candidate_digest,
            sha256_digest(constitution),
            sha256_digest(capability_report),
            expected_input_digest,
            require_string(ledger_verification.get("ledger_digest"), "ledger.ledger_digest"),
            evaluated_at,
        )
        projected_observations.append(projected)
        evaluator_verifications.append(verification)
    evaluation = evaluate_cognitive_candidate(
        candidate,
        constitution,
        capability_report,
        projected_observations,
        hard_gate_results,
        champion_floor_results,
        metrics,
        evaluated_at,
    )
    if ledger_verification.get("within_constitution") is not True:
        blockers = sorted(
            set(require_list(evaluation.get("blockers"), "evaluation.blockers"))
            | {"LINEAGE_RESOURCE_LEDGER_BLOCKED"}
        )
        evaluation = {**evaluation, "status": "blocked", "blockers": blockers}
    contract_boundary_verified = (
        len(evaluator_verifications) == len(REQUIRED_EVALUATOR_ROLES)
        and all(value.get("signature_verified") is True for value in evaluator_verifications)
        and all(value.get("isolation_boundary_verified") is True for value in evaluator_verifications)
        and ledger_verification.get("within_constitution") is True
    )
    live_os_enforcement_verified = contract_boundary_verified and all(
        value.get("production_isolation_verified") is True for value in evaluator_verifications
    )
    assurance: JsonObject = {
        "assurance_version": "0.1.0",
        "origin": candidate["origin"],
        "candidate_digest": candidate_digest,
        "constitution_digest": sha256_digest(constitution),
        "evaluator_policy_digest": policy_verification["policy_digest"],
        "evaluation_input_digest": expected_input_digest,
        "resource_ledger_digest": ledger_verification["ledger_digest"],
        "evaluator_verifications": sorted(evaluator_verifications, key=lambda value: str(value["role"])),
        "resource_ledger_verification": ledger_verification,
        "contract_boundary_verified": contract_boundary_verified,
        "live_os_enforcement_verified": live_os_enforcement_verified,
        "shadow_evaluation_eligible": evaluation["status"] == "eligible_for_shadow" and contract_boundary_verified,
        "production_promotion_authorized": False,
        "authority": EVALUATOR_ASSURANCE_AUTHORITY,
    }
    return evaluation, assurance
