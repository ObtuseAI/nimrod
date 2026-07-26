"""Read-only range observation admission with no collection or execution capability."""

from __future__ import annotations

import base64
import binascii
import copy
import hashlib
from datetime import datetime

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from nimrod_simulator.authorization import parse_timestamp
from nimrod_simulator.compiler import deterministic_uuid, format_timestamp
from nimrod_simulator.errors import (
    ControlStateValidationError,
    RangeCollectorPolicyError,
    RangeEnvironmentObservationError,
    RangeEvidenceAdmissionError,
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
from nimrod_simulator.key_governance import SigningConnector, decode_public_key, validate_governance_state
from nimrod_simulator.model import JsonObject
from nimrod_simulator.range_execution_gate import REQUIRED_ENVIRONMENT_ATTESTATIONS
from nimrod_simulator.threshold_signing import sign_threshold_document, verify_threshold_signatures


RANGE_COLLECTOR_POLICY_DOMAIN = b"nimrod.range-collector-policy.v0.1\x00"
RANGE_ENVIRONMENT_OBSERVATION_DOMAIN = b"nimrod.range-environment-observation.v0.1\x00"
COLLECTOR_OPERATIONS = {"digest", "emit_attestation", "observe"}
OBSERVATION_ORIGINS = {"simulated", "range", "sacrificial_replica"}
REAL_OBSERVATION_ORIGINS = {"range", "sacrificial_replica"}
COLLECTOR_POLICY_AUTHORITY = {
    "can_install": False,
    "can_provision": False,
    "can_change_policy": False,
    "can_access_credentials": False,
    "can_contact_source_tools": False,
    "can_open_network_connection": False,
    "can_execute": False,
}
OBSERVATION_ACTIVITY = {
    "environment_contact_performed_by_nimrod": False,
    "policy_mutation_performed": False,
    "credential_access_performed": False,
    "tool_installation_performed": False,
    "source_tool_contact_performed": False,
    "network_contact_performed": False,
    "campaign_execution_performed": False,
}
OBSERVATION_AUTHORITY = {
    "can_install": False,
    "can_provision": False,
    "can_change_policy": False,
    "can_access_credentials": False,
    "can_connect": False,
    "can_execute": False,
    "can_verify_attestation": False,
}
ADMISSION_ACTIVITY = {
    "infrastructure_provisioned": False,
    "host_or_network_policy_changed": False,
    "credentials_handled": False,
    "tools_installed": False,
    "source_tools_contacted": False,
    "network_contact_performed": False,
    "range_connected": False,
    "campaign_executed": False,
}
ADMISSION_AUTHORITY = {
    "can_install": False,
    "can_provision": False,
    "can_change_policy": False,
    "can_access_credentials": False,
    "can_connect": False,
    "can_execute": False,
    "can_mark_evidence_complete": False,
    "can_verify_attestation": False,
}


def _timestamp(value: object, field: str, error_type: type[Exception]) -> datetime:
    try:
        return parse_timestamp(value, field)
    except ControlStateValidationError as error:
        raise error_type(f"Timestamp '{field}' is invalid: {error}.") from error


def _nullable_string(value: object, field: str) -> str | None:
    if value is None:
        return None
    return require_string(value, field)


def _decode_base64(value: str, field: str, error_type: type[Exception]) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as error:
        raise error_type(f"Field '{field}' is not canonical base64.") from error


def _raw_sha256_digest(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def sign_range_collector_policy(
    unsigned_policy: JsonObject,
    connectors: list[SigningConnector],
) -> JsonObject:
    return sign_threshold_document(
        unsigned_policy,
        connectors,
        RANGE_COLLECTOR_POLICY_DOMAIN,
        "range collector policy",
        RangeCollectorPolicyError,
    )


def _validate_policy_environment(policy: JsonObject) -> tuple[JsonObject, str]:
    environment = require_object(policy.get("environment"), "policy.environment")
    owner_named = require_boolean(environment.get("owner_named"), "policy.environment.owner_named")
    environment_name = _nullable_string(environment.get("environment_name"), "policy.environment.environment_name")
    environment_class = require_string(environment.get("environment_class"), "policy.environment.environment_class")
    expected_origin = require_string(
        environment.get("expected_observation_origin"),
        "policy.environment.expected_observation_origin",
    )
    if expected_origin not in OBSERVATION_ORIGINS:
        raise RangeCollectorPolicyError(f"Collector policy observation origin '{expected_origin}' is unsupported.")
    blockers = require_string_list(policy.get("blockers"), "policy.blockers")
    if owner_named:
        if environment_name is None:
            raise RangeCollectorPolicyError("Owner-named collector policy requires an environment name.")
        if environment_class not in {"isolated_range", "sacrificial_replica"}:
            raise RangeCollectorPolicyError("Owner-named collector policy requires an isolated range class.")
        if expected_origin not in REAL_OBSERVATION_ORIGINS:
            raise RangeCollectorPolicyError("Owner-named collector policy requires a real range observation origin.")
        if policy.get("status") != "external_read_only_observations_allowed" or blockers:
            raise RangeCollectorPolicyError("Owner-named collector policy status or blockers are inconsistent.")
    else:
        if environment_name is not None:
            raise RangeCollectorPolicyError("Unnamed collector policy cannot contain an environment name.")
        if environment_class != "sacrificial_range_candidate" or expected_origin != "simulated":
            raise RangeCollectorPolicyError("Unnamed collector policy must remain a simulated range candidate.")
        if policy.get("origin") != "simulated":
            raise RangeCollectorPolicyError("Unnamed collector policy cannot claim a real origin.")
        if policy.get("status") != "blocked_owner_named_environment_missing":
            raise RangeCollectorPolicyError("Unnamed collector policy must preserve its blocked status.")
        if blockers != ["OWNER_NAMED_SACRIFICIAL_RANGE_MISSING"]:
            raise RangeCollectorPolicyError("Unnamed collector policy must preserve the owner-name blocker.")
    return environment, expected_origin


def verify_range_collector_policy(
    policy: JsonObject,
    governance_state: JsonObject,
    evaluated_at: datetime,
    maximum_lifetime_seconds: int,
) -> JsonObject:
    if evaluated_at.utcoffset() is None:
        raise RangeCollectorPolicyError("Collector policy evaluation time must be timezone-aware.")
    if maximum_lifetime_seconds <= 0:
        raise RangeCollectorPolicyError("Collector policy maximum lifetime must be positive.")
    validate_governance_state(governance_state)
    if policy.get("policy_version") != "0.1.0":
        raise RangeCollectorPolicyError("Collector policy must use version 0.1.0.")
    if policy.get("origin") not in OBSERVATION_ORIGINS:
        raise RangeCollectorPolicyError("Collector policy origin is unsupported.")
    if policy.get("governance_state_digest") != sha256_digest(governance_state):
        raise RangeCollectorPolicyError("Collector policy governance-state digest mismatch.")
    issued_at = _timestamp(policy.get("issued_at"), "policy.issued_at", RangeCollectorPolicyError)
    not_before = _timestamp(policy.get("not_before"), "policy.not_before", RangeCollectorPolicyError)
    expires_at = _timestamp(policy.get("expires_at"), "policy.expires_at", RangeCollectorPolicyError)
    if issued_at > not_before or not_before >= expires_at:
        raise RangeCollectorPolicyError("Collector policy validity window is inconsistent.")
    if int((expires_at - issued_at).total_seconds()) > maximum_lifetime_seconds:
        raise RangeCollectorPolicyError("Collector policy lifetime exceeds the configured maximum.")
    if evaluated_at < not_before or evaluated_at > expires_at:
        raise RangeCollectorPolicyError("Collector policy is outside its active validity window.")
    required_controls = set(require_string_list(policy.get("required_controls"), "policy.required_controls"))
    if required_controls != REQUIRED_ENVIRONMENT_ATTESTATIONS:
        raise RangeCollectorPolicyError("Collector policy must bind the exact nine environment controls.")
    environment, expected_origin = _validate_policy_environment(policy)
    collectors = [
        require_object(value, f"policy.collectors[{index}]")
        for index, value in enumerate(require_list(policy.get("collectors"), "policy.collectors"))
    ]
    if len(collectors) != len(REQUIRED_ENVIRONMENT_ATTESTATIONS):
        raise RangeCollectorPolicyError("Collector policy requires one independently identified collector per control.")
    collector_ids: set[str] = set()
    principals: set[str] = set()
    process_ids: set[int] = set()
    public_keys: set[str] = set()
    controls: set[str] = set()
    for index, collector in enumerate(collectors):
        collector_id = require_string(collector.get("collector_id"), f"policy.collectors[{index}].collector_id")
        principal = require_string(
            collector.get("logical_principal"),
            f"policy.collectors[{index}].logical_principal",
        )
        process_id = require_integer(collector.get("process_id"), f"policy.collectors[{index}].process_id")
        public_key = require_string(
            collector.get("public_key_base64"),
            f"policy.collectors[{index}].public_key_base64",
        )
        control_id = require_string(
            collector.get("allowed_control_id"),
            f"policy.collectors[{index}].allowed_control_id",
        )
        if process_id <= 0:
            raise RangeCollectorPolicyError(f"Collector '{collector_id}' process ID must be positive.")
        if require_boolean(collector.get("read_only"), f"policy.collectors[{index}].read_only") is not True:
            raise RangeCollectorPolicyError(f"Collector '{collector_id}' must be read-only.")
        if set(require_string_list(collector.get("operation_allowlist"), "collector.operation_allowlist")) != COLLECTOR_OPERATIONS:
            raise RangeCollectorPolicyError(f"Collector '{collector_id}' operation allowlist is widened or incomplete.")
        if require_list(collector.get("network_destinations"), "collector.network_destinations"):
            raise RangeCollectorPolicyError(f"Collector '{collector_id}' cannot declare network destinations.")
        if require_list(collector.get("secret_references"), "collector.secret_references"):
            raise RangeCollectorPolicyError(f"Collector '{collector_id}' cannot declare secret references.")
        decode_public_key(public_key, collector_id)
        collector_ids.add(collector_id)
        principals.add(principal)
        process_ids.add(process_id)
        public_keys.add(public_key)
        controls.add(control_id)
    expected_count = len(REQUIRED_ENVIRONMENT_ATTESTATIONS)
    if any(len(values) != expected_count for values in (collector_ids, principals, process_ids, public_keys)):
        raise RangeCollectorPolicyError("Collector identities, principals, processes, and public keys must be distinct.")
    if controls != REQUIRED_ENVIRONMENT_ATTESTATIONS:
        raise RangeCollectorPolicyError("Collector policy must assign every required control exactly once.")
    if require_object(policy.get("authority"), "policy.authority") != COLLECTOR_POLICY_AUTHORITY:
        raise RangeCollectorPolicyError("Collector policy exposes prohibited authority.")
    verified_signers, verified_roles = verify_threshold_signatures(
        policy,
        governance_state,
        issued_at,
        RANGE_COLLECTOR_POLICY_DOMAIN,
        "range collector policy",
        RangeCollectorPolicyError,
    )
    return {
        "policy_id": require_string(policy.get("policy_id"), "policy.policy_id"),
        "policy_digest": sha256_digest(policy),
        "environment_id": require_string(environment.get("environment_id"), "policy.environment.environment_id"),
        "environment_name": environment.get("environment_name"),
        "owner_named": environment.get("owner_named"),
        "expected_observation_origin": expected_origin,
        "verified_signer_ids": verified_signers,
        "verified_roles": verified_roles,
        "collector_count": len(collectors),
    }


def _observation_message(observation: JsonObject) -> bytes:
    unsigned: JsonObject = {key: value for key, value in observation.items() if key != "signature"}
    return RANGE_ENVIRONMENT_OBSERVATION_DOMAIN + canonical_json_bytes(unsigned)


def sign_range_environment_observation(
    unsigned_observation: JsonObject,
    connector: SigningConnector,
) -> JsonObject:
    if "signature" in unsigned_observation:
        raise RangeEnvironmentObservationError("Unsigned range observation contains a signature.")
    signature = {
        "signer_id": connector.key_id,
        "algorithm": "Ed25519",
        "signature_base64": base64.b64encode(connector.sign(_observation_message(unsigned_observation))).decode("ascii"),
    }
    return {**unsigned_observation, "signature": signature}


def _collector_index(policy: JsonObject) -> dict[str, JsonObject]:
    collectors = require_list(policy.get("collectors"), "policy.collectors")
    return {
        require_string(require_object(value, f"policy.collectors[{index}]").get("collector_id"), "collector_id"):
        require_object(value, f"policy.collectors[{index}]")
        for index, value in enumerate(collectors)
    }


def verify_range_environment_observation(
    observation: JsonObject,
    policy: JsonObject,
    evaluated_at: datetime,
    maximum_age_seconds: int,
) -> JsonObject:
    if evaluated_at.utcoffset() is None:
        raise RangeEnvironmentObservationError("Observation evaluation time must be timezone-aware.")
    if maximum_age_seconds <= 0:
        raise RangeEnvironmentObservationError("Observation maximum age must be positive.")
    if observation.get("observation_version") != "0.1.0":
        raise RangeEnvironmentObservationError("Range observation must use version 0.1.0.")
    origin = require_string(observation.get("origin"), "observation.origin")
    environment = require_object(policy.get("environment"), "policy.environment")
    if origin != environment.get("expected_observation_origin"):
        raise RangeEnvironmentObservationError("Range observation origin differs from collector policy.")
    if observation.get("environment_id") != environment.get("environment_id"):
        raise RangeEnvironmentObservationError("Range observation environment identity mismatch.")
    if observation.get("environment_name") != environment.get("environment_name"):
        raise RangeEnvironmentObservationError("Range observation environment name mismatch.")
    if observation.get("policy_id") != policy.get("policy_id") or observation.get("policy_digest") != sha256_digest(policy):
        raise RangeEnvironmentObservationError("Range observation collector-policy binding mismatch.")
    if observation.get("scope_digest") != policy.get("scope_digest"):
        raise RangeEnvironmentObservationError("Range observation scope digest mismatch.")
    status = require_string(observation.get("status"), "observation.status")
    owner_named = require_boolean(environment.get("owner_named"), "policy.environment.owner_named")
    expected_status = "externally_supplied_unverified" if owner_named else "fixture_only_unproven"
    if status != expected_status:
        raise RangeEnvironmentObservationError("Range observation status is inconsistent with environment naming state.")
    collected_at = _timestamp(
        observation.get("collected_at"),
        "observation.collected_at",
        RangeEnvironmentObservationError,
    )
    age_seconds = int((evaluated_at - collected_at).total_seconds())
    if age_seconds < 0:
        raise RangeEnvironmentObservationError("Range observation is from the future.")
    if age_seconds > maximum_age_seconds:
        raise RangeEnvironmentObservationError("Range observation is stale.")
    collector_identity = require_object(observation.get("collector"), "observation.collector")
    collector_id = require_string(collector_identity.get("collector_id"), "observation.collector.collector_id")
    collector = _collector_index(policy).get(collector_id)
    if collector is None:
        raise RangeEnvironmentObservationError(f"Range observation collector '{collector_id}' is not policy-pinned.")
    if collector_identity != {
        "collector_id": collector_id,
        "logical_principal": collector.get("logical_principal"),
        "process_id": collector.get("process_id"),
    }:
        raise RangeEnvironmentObservationError("Range observation collector identity differs from policy.")
    control_id = require_string(observation.get("control_id"), "observation.control_id")
    if control_id != collector.get("allowed_control_id"):
        raise RangeEnvironmentObservationError("Range observation control is outside collector scope.")
    raw_evidence = require_object(observation.get("raw_evidence"), "observation.raw_evidence")
    if raw_evidence.get("content_type") != "application/json" or raw_evidence.get("encoding") != "base64":
        raise RangeEnvironmentObservationError("Raw range evidence must be base64-encoded application/json.")
    payload = _decode_base64(
        require_string(raw_evidence.get("payload_base64"), "observation.raw_evidence.payload_base64"),
        "observation.raw_evidence.payload_base64",
        RangeEnvironmentObservationError,
    )
    if require_integer(raw_evidence.get("byte_length"), "observation.raw_evidence.byte_length") != len(payload):
        raise RangeEnvironmentObservationError("Raw range evidence byte length mismatch.")
    if raw_evidence.get("digest") != _raw_sha256_digest(payload):
        raise RangeEnvironmentObservationError("Raw range evidence content digest mismatch.")
    if raw_evidence.get("retention_mode") != "inline_content_addressed":
        raise RangeEnvironmentObservationError("Raw range evidence must remain inline and content-addressed.")
    if require_boolean(raw_evidence.get("contains_credentials"), "raw_evidence.contains_credentials"):
        raise RangeEnvironmentObservationError("Range observation cannot contain credentials.")
    if require_boolean(raw_evidence.get("contains_secrets"), "raw_evidence.contains_secrets"):
        raise RangeEnvironmentObservationError("Range observation cannot contain secrets.")
    if require_object(observation.get("activity"), "observation.activity") != OBSERVATION_ACTIVITY:
        raise RangeEnvironmentObservationError("Range observation claims prohibited nimrod activity.")
    if require_object(observation.get("authority"), "observation.authority") != OBSERVATION_AUTHORITY:
        raise RangeEnvironmentObservationError("Range observation exposes prohibited authority.")
    signature = require_object(observation.get("signature"), "observation.signature")
    if signature.get("signer_id") != collector_id or signature.get("algorithm") != "Ed25519":
        raise RangeEnvironmentObservationError("Range observation signature identity or algorithm mismatch.")
    signature_bytes = _decode_base64(
        require_string(signature.get("signature_base64"), "observation.signature.signature_base64"),
        "observation.signature.signature_base64",
        RangeEnvironmentObservationError,
    )
    if len(signature_bytes) != 64:
        raise RangeEnvironmentObservationError("Range observation Ed25519 signature must be 64 bytes.")
    public_key = decode_public_key(
        require_string(collector.get("public_key_base64"), "collector.public_key_base64"),
        collector_id,
    )
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature_bytes, _observation_message(observation))
    except (InvalidSignature, ValueError) as error:
        raise RangeEnvironmentObservationError(
            f"Range observation signature verification failed for collector '{collector_id}'."
        ) from error
    return {
        "observation_id": require_string(observation.get("observation_id"), "observation.observation_id"),
        "observation_digest": sha256_digest(observation),
        "raw_evidence_digest": raw_evidence.get("digest"),
        "control_id": control_id,
        "origin": origin,
        "collector_id": collector_id,
        "logical_principal": collector.get("logical_principal"),
        "process_id": collector.get("process_id"),
        "collected_at": format_timestamp(collected_at),
    }


def build_range_evidence_admission_report(
    policy: JsonObject,
    governance_state: JsonObject,
    observations: list[object],
    assembled_at: datetime,
    maximum_policy_lifetime_seconds: int,
    maximum_observation_age_seconds: int,
) -> JsonObject:
    policy_verification = verify_range_collector_policy(
        policy,
        governance_state,
        assembled_at,
        maximum_policy_lifetime_seconds,
    )
    observation_objects = [
        require_object(value, f"observations[{index}]")
        for index, value in enumerate(observations)
    ]
    if len(observation_objects) != len(REQUIRED_ENVIRONMENT_ATTESTATIONS):
        raise RangeEvidenceAdmissionError("Evidence admission requires exactly nine observation envelopes.")
    verified = [
        verify_range_environment_observation(
            observation,
            policy,
            assembled_at,
            maximum_observation_age_seconds,
        )
        for observation in observation_objects
    ]
    controls = [require_string(item.get("control_id"), "verified.control_id") for item in verified]
    if len(controls) != len(set(controls)) or set(controls) != REQUIRED_ENVIRONMENT_ATTESTATIONS:
        raise RangeEvidenceAdmissionError("Evidence admission requires every control exactly once.")
    collector_ids = {require_string(item.get("collector_id"), "verified.collector_id") for item in verified}
    principals = {require_string(item.get("logical_principal"), "verified.logical_principal") for item in verified}
    process_ids = {require_integer(item.get("process_id"), "verified.process_id") for item in verified}
    required_count = len(REQUIRED_ENVIRONMENT_ATTESTATIONS)
    if any(len(values) != required_count for values in (collector_ids, principals, process_ids)):
        raise RangeEvidenceAdmissionError("Evidence admission requires independently identified collectors per control.")
    retained_observations = sorted(
        [
            {
                "observation_id": item["observation_id"],
                "observation_digest": item["observation_digest"],
                "raw_evidence_digest": item["raw_evidence_digest"],
                "control_id": item["control_id"],
                "collector_id": item["collector_id"],
            }
            for item in verified
        ],
        key=lambda item: str(item["control_id"]),
    )
    attestations = sorted(
        [
            {
                "control_id": item["control_id"],
                "origin": item["origin"],
                "status": "unproven",
                "observed_at": item["collected_at"],
                "evidence": [
                    {
                        "id": item["observation_id"],
                        "digest": item["raw_evidence_digest"],
                    }
                ],
                "verifier": None,
            }
            for item in verified
        ],
        key=lambda item: str(item["control_id"]),
    )
    real_controls = sorted(
        require_string(item.get("control_id"), "verified.control_id")
        for item in verified
        if item.get("origin") in REAL_OBSERVATION_ORIGINS
    )
    missing_real_controls = sorted(REQUIRED_ENVIRONMENT_ATTESTATIONS.difference(real_controls))
    owner_named = require_boolean(policy_verification.get("owner_named"), "policy_verification.owner_named")
    blockers = {
        "INDEPENDENT_VERIFIER_ATTESTATIONS_MISSING",
        "EVIDENCE_COMPLETION_AUTHORITY_MISSING",
        "RANGE_CONNECTION_AUTHORIZATION_MISSING",
        "EXECUTION_AUTHORIZATION_MISSING",
    }
    if not owner_named:
        blockers.add("OWNER_NAMED_SACRIFICIAL_RANGE_MISSING")
    if missing_real_controls:
        blockers.add("REAL_READ_ONLY_OBSERVATIONS_MISSING")
    status = (
        "blocked_independent_verification_missing"
        if owner_named and not missing_real_controls
        else "blocked_owner_named_environment_and_real_observations_missing"
    )
    policy_id = require_string(policy_verification.get("policy_id"), "policy_verification.policy_id")
    report_id = deterministic_uuid(policy_id, sha256_digest(retained_observations), "range-evidence-admission")
    return {
        "report_version": "0.1.0",
        "report_id": report_id,
        "origin": policy.get("origin"),
        "status": status,
        "assembled_at": format_timestamp(assembled_at),
        "policy_id": policy_id,
        "policy_digest": policy_verification["policy_digest"],
        "scope_digest": policy.get("scope_digest"),
        "environment_id": policy_verification["environment_id"],
        "environment_name": policy_verification["environment_name"],
        "owner_named_environment": owner_named,
        "policy_verified_signer_count": len(require_string_list(policy_verification.get("verified_signer_ids"), "verified_signer_ids")),
        "required_control_count": required_count,
        "signed_observation_count": len(verified),
        "content_addressed_observation_count": len(retained_observations),
        "distinct_collector_count": min(len(collector_ids), len(principals), len(process_ids)),
        "real_observation_count": len(real_controls),
        "missing_real_observation_controls": missing_real_controls,
        "retained_observations": retained_observations,
        "emitted_attestations": attestations,
        "emitted_attestation_count": len(attestations),
        "verified_attestation_count": 0,
        "independent_verifier_count": 0,
        "evidence_complete": False,
        "blockers": sorted(blockers),
        "activity": copy.deepcopy(ADMISSION_ACTIVITY),
        "authority": copy.deepcopy(ADMISSION_AUTHORITY),
    }


def validate_range_evidence_admission_report(
    report: JsonObject,
    policy: JsonObject,
    governance_state: JsonObject,
    observations: list[object],
    assembled_at: datetime,
    maximum_policy_lifetime_seconds: int,
    maximum_observation_age_seconds: int,
) -> None:
    expected = build_range_evidence_admission_report(
        policy,
        governance_state,
        observations,
        assembled_at,
        maximum_policy_lifetime_seconds,
        maximum_observation_age_seconds,
    )
    if report != expected:
        raise RangeEvidenceAdmissionError(
            "Range evidence admission report differs from the deterministic attestation-only projection."
        )
