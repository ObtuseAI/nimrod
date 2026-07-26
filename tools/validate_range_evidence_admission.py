"""Validate signed read-only range observation admission without environment contact."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TypeVar

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jsonschema import Draft202012Validator, FormatChecker

from nimrod_simulator.compiler import deterministic_uuid
from nimrod_simulator.errors import (
    RangeCollectorPolicyError,
    RangeEnvironmentObservationError,
    RangeEvidenceAdmissionError,
)
from nimrod_simulator.jsonio import canonical_json_bytes, read_json_object, sha256_digest
from nimrod_simulator.key_governance import EphemeralEd25519SigningConnector, governance_key
from nimrod_simulator.model import JsonObject
from nimrod_simulator.range_evidence_admission import (
    ADMISSION_ACTIVITY,
    ADMISSION_AUTHORITY,
    COLLECTOR_OPERATIONS,
    COLLECTOR_POLICY_AUTHORITY,
    OBSERVATION_ACTIVITY,
    OBSERVATION_AUTHORITY,
    build_range_evidence_admission_report,
    sign_range_collector_policy,
    sign_range_environment_observation,
    validate_range_evidence_admission_report,
    verify_range_collector_policy,
    verify_range_environment_observation,
)
from nimrod_simulator.range_execution_gate import (
    REQUIRED_ENVIRONMENT_ATTESTATIONS,
    build_preexecution_evidence_packet,
)


TError = TypeVar("TError", bound=Exception)
PROJECT_ROOT = Path(__file__).resolve().parents[1]
VALIDATION_TIME = datetime(2026, 7, 13, 16, 30, 0, tzinfo=timezone.utc)
POLICY_LIFETIME_SECONDS = 900
OBSERVATION_AGE_SECONDS = 180


def require_condition(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def expect_error(error_type: type[TError], operation: Callable[[], object], label: str) -> None:
    try:
        operation()
    except error_type:
        return
    except Exception as error:
        raise AssertionError(
            f"{label} raised {type(error).__name__}; expected {error_type.__name__}: {error}"
        ) from error
    raise AssertionError(f"Expected {error_type.__name__} for {label}.")


def validate_contract(value: JsonObject, schema_path: Path, label: str) -> None:
    schema = read_json_object(schema_path)
    errors = sorted(
        Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(value),
        key=lambda item: list(item.absolute_path),
    )
    if errors:
        rendered = "; ".join(error.message for error in errors)
        raise AssertionError(f"{label} failed schema validation: {rendered}")


def governance_connectors() -> list[EphemeralEd25519SigningConnector]:
    identities = (
        ("key:range-owner", "customer_authority", 1),
        ("key:range-safety", "safety_officer", 2),
        ("key:range-recovery", "recovery_officer", 3),
    )
    return [
        EphemeralEd25519SigningConnector(
            key_id,
            role,
            Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32),
        )
        for key_id, role, seed in identities
    ]


def governance_state(connectors: list[EphemeralEd25519SigningConnector]) -> JsonObject:
    issued_at = "2026-07-13T16:20:00Z"
    return {
        "state_version": "0.1.0",
        "governance_id": "30cf9c4f-39ca-4692-a37f-8ebfa309ec85",
        "origin": "simulated",
        "epoch": 1,
        "issued_at": issued_at,
        "previous_state_digest": None,
        "threshold": 2,
        "ceremony_key_count": 3,
        "minimum_distinct_roles": 2,
        "keys": [
            governance_key(
                connector,
                "active",
                issued_at,
                None,
                "test_ephemeral",
                f"connector:custody:{connector.key_id}",
                f"memory:{connector.key_id}",
                False,
                None,
            )
            for connector in connectors
        ],
    }


def collector_connectors() -> list[EphemeralEd25519SigningConnector]:
    return [
        EphemeralEd25519SigningConnector(
            f"collector:{control_id.lower()}",
            "read_only_environment_collector",
            Ed25519PrivateKey.from_private_bytes(bytes([21 + index]) * 32),
        )
        for index, control_id in enumerate(sorted(REQUIRED_ENVIRONMENT_ATTESTATIONS))
    ]


def public_key_base64(connector: EphemeralEd25519SigningConnector) -> str:
    return connector.public_key_base64


def signed_collector_policy(
    governance: JsonObject,
    governance_signers: list[EphemeralEd25519SigningConnector],
    collectors: list[EphemeralEd25519SigningConnector],
    scope_digest: str,
) -> JsonObject:
    unsigned: JsonObject = {
        "policy_version": "0.1.0",
        "policy_id": "6ee3f239-303d-42e2-bb4d-4cd5a0c418d1",
        "origin": "simulated",
        "status": "blocked_owner_named_environment_missing",
        "governance_state_digest": sha256_digest(governance),
        "scope_digest": scope_digest,
        "issued_at": "2026-07-13T16:25:00Z",
        "not_before": "2026-07-13T16:25:00Z",
        "expires_at": "2026-07-13T16:35:00Z",
        "environment": {
            "environment_id": "range-environment:owner-name-required",
            "environment_name": None,
            "environment_class": "sacrificial_range_candidate",
            "owner_named": False,
            "expected_observation_origin": "simulated",
        },
        "required_controls": sorted(REQUIRED_ENVIRONMENT_ATTESTATIONS),
        "collectors": [
            {
                "collector_id": connector.key_id,
                "logical_principal": f"principal:{control_id.lower()}",
                "process_id": 4100 + index,
                "public_key_base64": public_key_base64(connector),
                "allowed_control_id": control_id,
                "read_only": True,
                "operation_allowlist": sorted(COLLECTOR_OPERATIONS),
                "network_destinations": [],
                "secret_references": [],
            }
            for index, (control_id, connector) in enumerate(
                zip(sorted(REQUIRED_ENVIRONMENT_ATTESTATIONS), collectors, strict=True)
            )
        ],
        "blockers": ["OWNER_NAMED_SACRIFICIAL_RANGE_MISSING"],
        "authority": copy.deepcopy(COLLECTOR_POLICY_AUTHORITY),
    }
    return sign_range_collector_policy(unsigned, governance_signers[:2])


def raw_evidence(control_id: str) -> JsonObject:
    payload = canonical_json_bytes(
        {
            "control_id": control_id,
            "fixture": True,
            "result": "unproven",
            "source": "deterministic_contract_validation",
        }
    )
    return {
        "content_type": "application/json",
        "encoding": "base64",
        "byte_length": len(payload),
        "digest": f"sha256:{hashlib.sha256(payload).hexdigest()}",
        "payload_base64": base64.b64encode(payload).decode("ascii"),
        "retention_mode": "inline_content_addressed",
        "contains_credentials": False,
        "contains_secrets": False,
    }


def signed_observations(
    policy: JsonObject,
    collectors: list[EphemeralEd25519SigningConnector],
) -> list[JsonObject]:
    policy_collectors = policy.get("collectors")
    if not isinstance(policy_collectors, list):
        raise TypeError("Collector policy must contain collector definitions.")
    result: list[JsonObject] = []
    for index, connector in enumerate(collectors):
        collector = policy_collectors[index]
        if not isinstance(collector, dict):
            raise TypeError(f"Collector policy entry {index} must be an object.")
        control_id = str(collector["allowed_control_id"])
        unsigned: JsonObject = {
            "observation_version": "0.1.0",
            "observation_id": deterministic_uuid(str(policy["policy_id"]), control_id, "environment-observation"),
            "origin": "simulated",
            "status": "fixture_only_unproven",
            "environment_id": "range-environment:owner-name-required",
            "environment_name": None,
            "policy_id": policy["policy_id"],
            "policy_digest": sha256_digest(policy),
            "scope_digest": policy["scope_digest"],
            "control_id": control_id,
            "collector": {
                "collector_id": collector["collector_id"],
                "logical_principal": collector["logical_principal"],
                "process_id": collector["process_id"],
            },
            "collected_at": "2026-07-13T16:29:00Z",
            "raw_evidence": raw_evidence(control_id),
            "activity": copy.deepcopy(OBSERVATION_ACTIVITY),
            "authority": copy.deepcopy(OBSERVATION_AUTHORITY),
        }
        result.append(sign_range_environment_observation(unsigned, connector))
    return result


def resigned_policy(
    policy: JsonObject,
    connectors: list[EphemeralEd25519SigningConnector],
) -> JsonObject:
    unsigned = {key: copy.deepcopy(value) for key, value in policy.items() if key != "signatures"}
    return sign_range_collector_policy(unsigned, connectors[:2])


def write_or_compare_example(path: Path, value: JsonObject) -> None:
    rendered = json.dumps(value, indent=2, ensure_ascii=False) + "\n"
    if path.exists() and path.read_text(encoding="utf-8") != rendered:
        raise AssertionError(f"Canonical example drifted from deterministic regeneration: {path}")
    if not path.exists():
        path.write_bytes(rendered.encode("utf-8"))


def main() -> None:
    schemas = PROJECT_ROOT / "specs"
    examples = schemas / "examples"
    scope = read_json_object(examples / "range-lease-topology-scope.example.json")
    governance_signers = governance_connectors()
    governance = governance_state(governance_signers)
    collectors = collector_connectors()
    policy = signed_collector_policy(governance, governance_signers, collectors, sha256_digest(scope))
    observations = signed_observations(policy, collectors)
    report = build_range_evidence_admission_report(
        policy,
        governance,
        observations,
        VALIDATION_TIME,
        POLICY_LIFETIME_SECONDS,
        OBSERVATION_AGE_SECONDS,
    )

    validate_contract(policy, schemas / "range-collector-policy.schema.json", "collector policy")
    validate_contract(
        observations[0],
        schemas / "range-environment-observation.schema.json",
        "environment observation",
    )
    validate_contract(
        report,
        schemas / "range-evidence-admission-report.schema.json",
        "evidence admission report",
    )
    verify_range_collector_policy(policy, governance, VALIDATION_TIME, POLICY_LIFETIME_SECONDS)
    for observation in observations:
        verify_range_environment_observation(
            observation,
            policy,
            VALIDATION_TIME,
            OBSERVATION_AGE_SECONDS,
        )
    validate_range_evidence_admission_report(
        report,
        policy,
        governance,
        observations,
        VALIDATION_TIME,
        POLICY_LIFETIME_SECONDS,
        OBSERVATION_AGE_SECONDS,
    )

    preexecution = build_preexecution_evidence_packet(
        scope,
        read_json_object(examples / "range-connector-capability-manifest.example.json"),
        read_json_object(examples / "range-topology-verdict.example.json"),
        read_json_object(examples / "disposable-range-preflight-result.example.json"),
        list(report["emitted_attestations"]),
        VALIDATION_TIME,
        OBSERVATION_AGE_SECONDS,
    )
    require_condition(preexecution["real_environment_attestation_count"] == 0, "Admission cannot verify attestations.")
    require_condition(preexecution["evidence_complete"] is False, "Admission cannot complete the evidence gate.")
    require_condition(preexecution["execution_authorized"] is False, "Admission cannot authorize execution.")

    adversarial_cases: list[tuple[str, type[Exception], Callable[[], object]]] = []

    def policy_case(label: str, mutation: Callable[[JsonObject], None], resign: bool) -> None:
        altered = copy.deepcopy(policy)
        mutation(altered)
        candidate = resigned_policy(altered, governance_signers) if resign else altered
        adversarial_cases.append(
            (
                label,
                RangeCollectorPolicyError,
                lambda candidate=candidate: verify_range_collector_policy(
                    candidate,
                    governance,
                    VALIDATION_TIME,
                    POLICY_LIFETIME_SECONDS,
                ),
            )
        )

    policy_case("policy_signature_tamper", lambda value: value["signatures"][0].update(signature_base64="A" * 86 + "=="), False)
    policy_case("policy_threshold_underflow", lambda value: value.update(signatures=value["signatures"][:1]), False)
    policy_case("policy_governance_substitution", lambda value: value.update(governance_state_digest="sha256:" + "0" * 64), True)
    policy_case("policy_lifetime_widening", lambda value: value.update(expires_at="2026-07-13T17:00:00Z"), True)
    policy_case("owner_name_laundering", lambda value: value["environment"].update(environment_name="unnamed-laundered"), True)
    policy_case("policy_status_laundering", lambda value: value.update(status="external_read_only_observations_allowed"), True)
    policy_case("collector_id_capture", lambda value: value["collectors"][1].update(collector_id=value["collectors"][0]["collector_id"]), True)
    policy_case("collector_principal_capture", lambda value: value["collectors"][1].update(logical_principal=value["collectors"][0]["logical_principal"]), True)
    policy_case("collector_process_capture", lambda value: value["collectors"][1].update(process_id=value["collectors"][0]["process_id"]), True)
    policy_case("collector_key_capture", lambda value: value["collectors"][1].update(public_key_base64=value["collectors"][0]["public_key_base64"]), True)
    policy_case("collector_control_duplication", lambda value: value["collectors"][1].update(allowed_control_id=value["collectors"][0]["allowed_control_id"]), True)
    policy_case("collector_write_authority", lambda value: value["collectors"][0].update(read_only=False), True)
    policy_case("collector_operation_widening", lambda value: value["collectors"][0]["operation_allowlist"].append("execute"), True)
    policy_case("collector_network_destination", lambda value: value["collectors"][0]["network_destinations"].append("https://range.invalid"), True)
    policy_case("collector_secret_reference", lambda value: value["collectors"][0]["secret_references"].append("secret:range"), True)
    policy_case("collector_policy_authority", lambda value: value["authority"].update(can_connect=True), True)

    def observation_case(label: str, mutation: Callable[[JsonObject], None]) -> None:
        altered = copy.deepcopy(observations[0])
        mutation(altered)
        adversarial_cases.append(
            (
                label,
                RangeEnvironmentObservationError,
                lambda altered=altered: verify_range_environment_observation(
                    altered,
                    policy,
                    VALIDATION_TIME,
                    OBSERVATION_AGE_SECONDS,
                ),
            )
        )

    observation_case("observation_signature_tamper", lambda value: value["signature"].update(signature_base64="A" * 86 + "=="))
    observation_case("observation_origin_laundering", lambda value: value.update(origin="range"))
    observation_case("observation_environment_substitution", lambda value: value.update(environment_id="range-environment:other"))
    observation_case("observation_policy_substitution", lambda value: value.update(policy_digest="sha256:" + "0" * 64))
    observation_case("observation_scope_substitution", lambda value: value.update(scope_digest="sha256:" + "0" * 64))
    observation_case("observation_control_widening", lambda value: value.update(control_id="TRUSTED_TIME"))
    observation_case("observation_collector_substitution", lambda value: value["collector"].update(logical_principal="principal:captured"))
    observation_case("observation_stale", lambda value: value.update(collected_at="2026-07-13T16:00:00Z"))
    observation_case("observation_future", lambda value: value.update(collected_at="2026-07-13T16:31:00Z"))
    observation_case("raw_payload_tamper", lambda value: value["raw_evidence"].update(payload_base64=base64.b64encode(b"{}").decode("ascii")))
    observation_case("raw_digest_tamper", lambda value: value["raw_evidence"].update(digest="sha256:" + "0" * 64))
    observation_case("raw_length_tamper", lambda value: value["raw_evidence"].update(byte_length=2))
    observation_case("credential_presence", lambda value: value["raw_evidence"].update(contains_credentials=True))
    observation_case("secret_presence", lambda value: value["raw_evidence"].update(contains_secrets=True))
    observation_case("observation_activity_laundering", lambda value: value["activity"].update(network_contact_performed=True))
    observation_case("observation_authority_laundering", lambda value: value["authority"].update(can_connect=True))
    observation_case("observation_signer_substitution", lambda value: value["signature"].update(signer_id="collector:other"))

    adversarial_cases.append(
        (
            "observation_omission",
            RangeEvidenceAdmissionError,
            lambda: build_range_evidence_admission_report(
                policy,
                governance,
                observations[:-1],
                VALIDATION_TIME,
                POLICY_LIFETIME_SECONDS,
                OBSERVATION_AGE_SECONDS,
            ),
        )
    )
    duplicated = copy.deepcopy(observations)
    duplicated[-1] = copy.deepcopy(duplicated[0])
    adversarial_cases.append(
        (
            "observation_duplication",
            RangeEvidenceAdmissionError,
            lambda: build_range_evidence_admission_report(
                policy,
                governance,
                duplicated,
                VALIDATION_TIME,
                POLICY_LIFETIME_SECONDS,
                OBSERVATION_AGE_SECONDS,
            ),
        )
    )

    def report_case(label: str, mutation: Callable[[JsonObject], None]) -> None:
        altered = copy.deepcopy(report)
        mutation(altered)
        adversarial_cases.append(
            (
                label,
                RangeEvidenceAdmissionError,
                lambda altered=altered: validate_range_evidence_admission_report(
                    altered,
                    policy,
                    governance,
                    observations,
                    VALIDATION_TIME,
                    POLICY_LIFETIME_SECONDS,
                    OBSERVATION_AGE_SECONDS,
                ),
            )
        )

    report_case("report_status_laundering", lambda value: value.update(status="blocked_independent_verification_missing"))
    report_case("report_completion_laundering", lambda value: value.update(evidence_complete=True))
    report_case("report_verification_laundering", lambda value: value.update(verified_attestation_count=9))
    report_case("report_authority_laundering", lambda value: value["authority"].update(can_execute=True))
    report_case("report_activity_laundering", lambda value: value["activity"].update(range_connected=True))
    report_case("report_retention_substitution", lambda value: value["retained_observations"][0].update(raw_evidence_digest="sha256:" + "0" * 64))

    for label, error_type, operation in adversarial_cases:
        expect_error(error_type, operation, label)

    write_or_compare_example(examples / "range-collector-policy.example.json", policy)
    write_or_compare_example(examples / "range-environment-observation.example.json", observations[0])
    write_or_compare_example(examples / "range-evidence-admission-report.example.json", report)

    validation_report: JsonObject = {
        "status": "RANGE_EVIDENCE_ADMISSION_SIGNED_FIXTURES_RETAINED_OWNER_RANGE_AND_INDEPENDENT_VERIFICATION_BLOCKED",
        "origin": "simulated",
        "collector_policy_status": policy["status"],
        "collector_policy_signer_count": len(policy["signatures"]),
        "required_control_count": report["required_control_count"],
        "signed_observation_count": report["signed_observation_count"],
        "content_addressed_observation_count": report["content_addressed_observation_count"],
        "distinct_collector_count": report["distinct_collector_count"],
        "owner_named_environment": report["owner_named_environment"],
        "real_observation_count": report["real_observation_count"],
        "emitted_attestation_count": report["emitted_attestation_count"],
        "verified_attestation_count": report["verified_attestation_count"],
        "independent_verifier_count": report["independent_verifier_count"],
        "evidence_complete": report["evidence_complete"],
        "blockers": report["blockers"],
        "adversarial_case_count": len(adversarial_cases),
        "fixture_independent_document_api": True,
        "preexecution_packet_real_attestation_count": preexecution["real_environment_attestation_count"],
        "preexecution_packet_evidence_complete": preexecution["evidence_complete"],
        "preexecution_packet_execution_authorized": preexecution["execution_authorized"],
        "activity": copy.deepcopy(ADMISSION_ACTIVITY),
        "authority": copy.deepcopy(ADMISSION_AUTHORITY),
    }
    report_path = PROJECT_ROOT / "reports" / "RANGE_EVIDENCE_ADMISSION_VALIDATION.json"
    report_path.write_text(
        json.dumps(validation_report, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(json.dumps(validation_report, indent=2))


if __name__ == "__main__":
    main()
