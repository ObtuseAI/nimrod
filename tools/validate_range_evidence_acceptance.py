"""Validate independent range-evidence decisions without collection or execution."""

from __future__ import annotations

import copy
import json
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import TypeVar

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jsonschema import Draft202012Validator, FormatChecker

from nimrod_simulator.compiler import deterministic_uuid
from nimrod_simulator.errors import (
    RangeEvidenceAcceptanceError,
    RangeVerifierDecisionError,
    RangeVerifierPolicyError,
)
from nimrod_simulator.jsonio import read_json_object, sha256_digest
from nimrod_simulator.key_governance import EphemeralEd25519SigningConnector
from nimrod_simulator.model import JsonObject
from nimrod_simulator.range_evidence_acceptance import (
    ACCEPTANCE_ACTIVITY,
    ACCEPTANCE_AUTHORITY,
    DECISION_REASON_BY_VALUE,
    VERIFIER_DECISION_ACTIVITY,
    VERIFIER_DECISION_AUTHORITY,
    VERIFIER_OPERATIONS,
    VERIFIER_POLICY_AUTHORITY,
    build_range_evidence_acceptance_report,
    resolve_range_verifier_decisions,
    sign_range_verifier_decision,
    sign_range_verifier_policy,
    validate_range_evidence_acceptance_report,
    verify_range_verifier_decision,
    verify_range_verifier_policy,
)
from nimrod_simulator.range_evidence_admission import build_range_evidence_admission_report
from validate_range_evidence_admission import (
    OBSERVATION_AGE_SECONDS,
    POLICY_LIFETIME_SECONDS as COLLECTOR_POLICY_LIFETIME_SECONDS,
    collector_connectors,
    governance_connectors,
    governance_state,
    signed_collector_policy,
    signed_observations,
)


TError = TypeVar("TError", bound=Exception)
PROJECT_ROOT = Path(__file__).resolve().parents[1]
ADMISSION_TIME = datetime(2026, 7, 13, 16, 30, 0, tzinfo=timezone.utc)
VALIDATION_TIME = datetime(2026, 7, 13, 16, 32, 0, tzinfo=timezone.utc)
VERIFIER_POLICY_LIFETIME_SECONDS = 900
DECISION_AGE_SECONDS = 180


def require_condition(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def expect_error(
    error_type: type[TError],
    operation: Callable[[], object],
    label: str,
) -> None:
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


def verifier_connectors() -> list[EphemeralEd25519SigningConnector]:
    return [
        EphemeralEd25519SigningConnector(
            f"range-verifier:{index + 1}",
            "independent_range_evidence_verifier",
            Ed25519PrivateKey.from_private_bytes(bytes([41 + index]) * 32),
        )
        for index in range(3)
    ]


def signed_verifier_policy(
    governance: JsonObject,
    governance_signers: list[EphemeralEd25519SigningConnector],
    admission_report: JsonObject,
    verifiers: list[EphemeralEd25519SigningConnector],
) -> JsonObject:
    unsigned: JsonObject = {
        "policy_version": "0.1.0",
        "policy_id": "51eb728b-c4ad-442a-9706-52728b4d46bb",
        "origin": "simulated",
        "status": "fixture_policy_non_accepting",
        "governance_state_digest": sha256_digest(governance),
        "admission_report_id": admission_report["report_id"],
        "admission_report_digest": sha256_digest(admission_report),
        "scope_digest": admission_report["scope_digest"],
        "environment_id": admission_report["environment_id"],
        "issued_at": "2026-07-13T16:30:00Z",
        "not_before": "2026-07-13T16:30:00Z",
        "expires_at": "2026-07-13T16:40:00Z",
        "minimum_decisions_per_observation": 2,
        "allowed_decisions": ["abstain", "accept", "reject", "timeout"],
        "verifiers": [
            {
                "verifier_id": connector.key_id,
                "logical_principal": f"principal:range-verifier-{index + 1}",
                "process_id": 5201 + index,
                "public_key_base64": connector.public_key_base64,
                "read_only": True,
                "operation_allowlist": sorted(VERIFIER_OPERATIONS),
                "identity_enforcement": "fixture_logical_only",
                "independence_evidence_digest": None,
                "collector_identity_shared": False,
                "network_destinations": [],
                "secret_references": [],
            }
            for index, connector in enumerate(verifiers)
        ],
        "blockers": [
            "EVIDENCE_COMPLETION_AUTHORITY_MISSING",
            "REAL_INDEPENDENT_VERIFIER_ACCEPTANCE_MISSING",
        ],
        "authority": copy.deepcopy(VERIFIER_POLICY_AUTHORITY),
    }
    return sign_range_verifier_policy(unsigned, governance_signers[:2])


def resigned_policy(
    policy: JsonObject,
    governance_signers: list[EphemeralEd25519SigningConnector],
) -> JsonObject:
    unsigned = copy.deepcopy(policy)
    unsigned.pop("signatures", None)
    return sign_range_verifier_policy(unsigned, governance_signers[:2])


def canonical_decision_pairs() -> tuple[tuple[str, str], ...]:
    return (
        ("reject", "reject"),
        ("reject", "reject"),
        ("abstain", "abstain"),
        ("abstain", "abstain"),
        ("reject", "abstain"),
        ("abstain", "reject"),
        ("timeout", "abstain"),
        ("abstain", "timeout"),
        ("timeout", "abstain"),
    )


def signed_decisions(
    policy: JsonObject,
    admission_report: JsonObject,
    verifiers: list[EphemeralEd25519SigningConnector],
) -> list[JsonObject]:
    retained = admission_report.get("retained_observations")
    policy_verifiers = policy.get("verifiers")
    if not isinstance(retained, list) or not isinstance(policy_verifiers, list):
        raise TypeError("Admission report and verifier policy must contain lists.")
    results: list[JsonObject] = []
    for observation, decision_pair in zip(retained, canonical_decision_pairs(), strict=True):
        if not isinstance(observation, dict):
            raise TypeError("Retained observation must be an object.")
        for verifier_index, decision_value in enumerate(decision_pair):
            verifier = policy_verifiers[verifier_index]
            if not isinstance(verifier, dict):
                raise TypeError("Verifier policy entry must be an object.")
            unsigned: JsonObject = {
                "decision_version": "0.1.0",
                "decision_id": deterministic_uuid(
                    str(policy["policy_id"]),
                    str(observation["observation_id"]),
                    str(verifier["verifier_id"]),
                ),
                "origin": "simulated",
                "status": "fixture_decision_non_accepting",
                "policy_id": policy["policy_id"],
                "policy_digest": sha256_digest(policy),
                "admission_report_id": admission_report["report_id"],
                "admission_report_digest": sha256_digest(admission_report),
                "environment_id": admission_report["environment_id"],
                "scope_digest": admission_report["scope_digest"],
                "observation_id": observation["observation_id"],
                "observation_digest": observation["observation_digest"],
                "raw_evidence_digest": observation["raw_evidence_digest"],
                "control_id": observation["control_id"],
                "verifier": {
                    "verifier_id": verifier["verifier_id"],
                    "logical_principal": verifier["logical_principal"],
                    "process_id": verifier["process_id"],
                    "identity_enforcement": verifier["identity_enforcement"],
                    "independence_evidence_digest": verifier["independence_evidence_digest"],
                },
                "decision": decision_value,
                "reason": DECISION_REASON_BY_VALUE[decision_value],
                "decided_at": "2026-07-13T16:31:00Z",
                "evidence_read_only": True,
                "activity": copy.deepcopy(VERIFIER_DECISION_ACTIVITY),
                "authority": copy.deepcopy(VERIFIER_DECISION_AUTHORITY),
            }
            results.append(sign_range_verifier_decision(unsigned, verifiers[verifier_index]))
    return results


def resigned_decision(
    decision: JsonObject,
    connector: EphemeralEd25519SigningConnector,
) -> JsonObject:
    unsigned = copy.deepcopy(decision)
    unsigned.pop("signature", None)
    return sign_range_verifier_decision(unsigned, connector)


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
    collector_policy = signed_collector_policy(
        governance,
        governance_signers,
        collectors,
        sha256_digest(scope),
    )
    observations = signed_observations(collector_policy, collectors)
    admission_report = build_range_evidence_admission_report(
        collector_policy,
        governance,
        observations,
        ADMISSION_TIME,
        COLLECTOR_POLICY_LIFETIME_SECONDS,
        OBSERVATION_AGE_SECONDS,
    )
    verifiers = verifier_connectors()
    policy = signed_verifier_policy(governance, governance_signers, admission_report, verifiers)
    decisions = signed_decisions(policy, admission_report, verifiers)
    report = build_range_evidence_acceptance_report(
        policy,
        governance,
        admission_report,
        decisions,
        VALIDATION_TIME,
        VERIFIER_POLICY_LIFETIME_SECONDS,
        DECISION_AGE_SECONDS,
    )

    validate_contract(policy, schemas / "range-verifier-policy.schema.json", "verifier policy")
    validate_contract(decisions[0], schemas / "range-verifier-decision.schema.json", "verifier decision")
    validate_contract(
        report,
        schemas / "range-evidence-acceptance-report.schema.json",
        "evidence acceptance report",
    )
    verify_range_verifier_policy(
        policy,
        governance,
        admission_report,
        VALIDATION_TIME,
        VERIFIER_POLICY_LIFETIME_SECONDS,
    )
    for decision in decisions:
        verify_range_verifier_decision(
            decision,
            policy,
            admission_report,
            VALIDATION_TIME,
            DECISION_AGE_SECONDS,
        )
    validate_range_evidence_acceptance_report(
        report,
        policy,
        governance,
        admission_report,
        decisions,
        VALIDATION_TIME,
        VERIFIER_POLICY_LIFETIME_SECONDS,
        DECISION_AGE_SECONDS,
    )

    require_condition(
        resolve_range_verifier_decisions("range", ["accept", "accept"]) == "accepted",
        "Two real accepting decisions must resolve to accepted.",
    )
    require_condition(
        resolve_range_verifier_decisions("range", ["reject", "reject"]) == "rejected",
        "Two rejecting decisions must resolve to rejected.",
    )
    require_condition(
        resolve_range_verifier_decisions("range", ["abstain", "abstain"]) == "abstained",
        "Two abstaining decisions must resolve to abstained.",
    )
    require_condition(
        resolve_range_verifier_decisions("range", ["accept", "reject"]) == "disagreement",
        "Conflicting decisions must preserve disagreement.",
    )
    require_condition(
        resolve_range_verifier_decisions("range", ["accept", "timeout"]) == "timeout",
        "A timeout must remain literal.",
    )
    expect_error(
        RangeEvidenceAcceptanceError,
        lambda: resolve_range_verifier_decisions("simulated", ["accept", "accept"]),
        "simulated_acceptance",
    )

    require_condition(report["verified_decision_count"] == 18, "Acceptance report must retain 18 decisions.")
    require_condition(report["distinct_signed_verifier_count"] == 2, "Canonical report must use two fixture verifiers.")
    require_condition(report["real_independent_verifier_count"] == 0, "Fixture verifiers are not real independent verifiers.")
    require_condition(
        report["resolution_counts"]
        == {"accepted": 0, "rejected": 2, "abstained": 2, "disagreement": 2, "timeout": 3},
        "Canonical report must preserve every non-success resolution class.",
    )
    require_condition(report["accepted_control_count"] == 0, "Fixture evidence cannot accept a control.")
    require_condition(report["verified_attestation_count"] == 0, "Acceptance decisions cannot verify attestations.")
    require_condition(report["evidence_complete"] is False, "Acceptance decisions cannot complete evidence.")
    require_condition(report["activity"] == ACCEPTANCE_ACTIVITY, "Acceptance activity must remain false.")
    require_condition(report["authority"] == ACCEPTANCE_AUTHORITY, "Acceptance authority must remain false.")

    adversarial_cases: list[tuple[str, type[Exception], Callable[[], object]]] = []

    def policy_case(label: str, mutation: Callable[[JsonObject], None], resign: bool) -> None:
        altered = copy.deepcopy(policy)
        mutation(altered)
        candidate = resigned_policy(altered, governance_signers) if resign else altered
        adversarial_cases.append(
            (
                label,
                RangeVerifierPolicyError,
                lambda candidate=candidate: verify_range_verifier_policy(
                    candidate,
                    governance,
                    admission_report,
                    VALIDATION_TIME,
                    VERIFIER_POLICY_LIFETIME_SECONDS,
                ),
            )
        )

    policy_case("policy_signature_tamper", lambda value: value["signatures"][0].update(signature_base64="A" * 86 + "=="), False)
    policy_case("policy_threshold_underflow", lambda value: value.update(signatures=value["signatures"][:1]), False)
    policy_case("policy_governance_substitution", lambda value: value.update(governance_state_digest="sha256:" + "0" * 64), True)
    policy_case("policy_admission_substitution", lambda value: value.update(admission_report_digest="sha256:" + "0" * 64), True)
    policy_case("policy_scope_substitution", lambda value: value.update(scope_digest="sha256:" + "0" * 64), True)
    policy_case("policy_lifetime_widening", lambda value: value.update(expires_at="2026-07-13T17:00:00Z"), True)
    policy_case("policy_status_laundering", lambda value: value.update(status="external_evidence_decisions_allowed"), True)
    policy_case("policy_decision_vocabulary_widening", lambda value: value.update(allowed_decisions=["accept"]), True)
    policy_case("verifier_id_capture", lambda value: value["verifiers"][1].update(verifier_id=value["verifiers"][0]["verifier_id"]), True)
    policy_case("verifier_principal_capture", lambda value: value["verifiers"][1].update(logical_principal=value["verifiers"][0]["logical_principal"]), True)
    policy_case("verifier_process_capture", lambda value: value["verifiers"][1].update(process_id=value["verifiers"][0]["process_id"]), True)
    policy_case("verifier_key_capture", lambda value: value["verifiers"][1].update(public_key_base64=value["verifiers"][0]["public_key_base64"]), True)
    policy_case("verifier_network_destination", lambda value: value["verifiers"][0].update(network_destinations=["https://invalid.example"]), True)
    policy_case("verifier_identity_laundering", lambda value: value["verifiers"][0].update(identity_enforcement="externally_attested"), True)
    policy_case("collector_identity_sharing", lambda value: value["verifiers"][0].update(collector_identity_shared=True), True)
    policy_case("policy_authority_laundering", lambda value: value["authority"].update(can_execute=True), True)

    def decision_case(label: str, mutation: Callable[[JsonObject], None], resign: bool) -> None:
        altered = copy.deepcopy(decisions[0])
        mutation(altered)
        candidate = resigned_decision(altered, verifiers[0]) if resign else altered
        adversarial_cases.append(
            (
                label,
                RangeVerifierDecisionError,
                lambda candidate=candidate: verify_range_verifier_decision(
                    candidate,
                    policy,
                    admission_report,
                    VALIDATION_TIME,
                    DECISION_AGE_SECONDS,
                ),
            )
        )

    decision_case("decision_signature_tamper", lambda value: value["signature"].update(signature_base64="A" * 86 + "=="), False)
    decision_case("decision_policy_substitution", lambda value: value.update(policy_digest="sha256:" + "0" * 64), True)
    decision_case("decision_admission_substitution", lambda value: value.update(admission_report_digest="sha256:" + "0" * 64), True)
    decision_case("decision_environment_substitution", lambda value: value.update(environment_id="range-environment:other"), True)
    decision_case("decision_scope_substitution", lambda value: value.update(scope_digest="sha256:" + "0" * 64), True)
    decision_case("decision_observation_substitution", lambda value: value.update(observation_id="00000000-0000-4000-8000-000000000000"), True)
    decision_case("decision_observation_digest_tamper", lambda value: value.update(observation_digest="sha256:" + "0" * 64), True)
    decision_case("decision_raw_digest_tamper", lambda value: value.update(raw_evidence_digest="sha256:" + "0" * 64), True)
    decision_case("decision_control_tamper", lambda value: value.update(control_id="TRUSTED_TIME"), True)
    decision_case("decision_verifier_substitution", lambda value: value["verifier"].update(verifier_id="range-verifier:3"), True)
    decision_case("decision_principal_substitution", lambda value: value["verifier"].update(logical_principal="principal:captured"), True)
    decision_case("decision_stale", lambda value: value.update(decided_at="2026-07-13T16:20:00Z"), True)
    decision_case("decision_future", lambda value: value.update(decided_at="2026-07-13T16:33:00Z"), True)
    decision_case("fixture_accept_laundering", lambda value: value.update(decision="accept", reason="evidence_supports_control"), True)
    decision_case("decision_reason_laundering", lambda value: value.update(reason="evidence_supports_control"), True)
    decision_case("decision_read_only_laundering", lambda value: value.update(evidence_read_only=False), True)
    decision_case("decision_activity_laundering", lambda value: value["activity"].update(collection_performed=True), True)
    decision_case("decision_authority_laundering", lambda value: value["authority"].update(can_mark_evidence_complete=True), True)
    decision_case("decision_signer_substitution", lambda value: value["signature"].update(signer_id="range-verifier:3"), False)

    adversarial_cases.append(
        (
            "decision_omission",
            RangeEvidenceAcceptanceError,
            lambda: build_range_evidence_acceptance_report(
                policy,
                governance,
                admission_report,
                decisions[:-1],
                VALIDATION_TIME,
                VERIFIER_POLICY_LIFETIME_SECONDS,
                DECISION_AGE_SECONDS,
            ),
        )
    )
    duplicated = copy.deepcopy(decisions)
    duplicated[-1] = copy.deepcopy(duplicated[0])
    adversarial_cases.append(
        (
            "decision_duplication",
            RangeEvidenceAcceptanceError,
            lambda: build_range_evidence_acceptance_report(
                policy,
                governance,
                admission_report,
                duplicated,
                VALIDATION_TIME,
                VERIFIER_POLICY_LIFETIME_SECONDS,
                DECISION_AGE_SECONDS,
            ),
        )
    )

    def report_case(label: str, mutation: Callable[[JsonObject], None]) -> None:
        altered = copy.deepcopy(report)
        mutation(altered)
        adversarial_cases.append(
            (
                label,
                RangeEvidenceAcceptanceError,
                lambda altered=altered: validate_range_evidence_acceptance_report(
                    altered,
                    policy,
                    governance,
                    admission_report,
                    decisions,
                    VALIDATION_TIME,
                    VERIFIER_POLICY_LIFETIME_SECONDS,
                    DECISION_AGE_SECONDS,
                ),
            )
        )

    report_case("report_status_laundering", lambda value: value.update(status="accepted_controls_pending_separate_evidence_completion_authority"))
    report_case("report_acceptance_laundering", lambda value: value.update(accepted_control_count=9))
    report_case("report_completion_laundering", lambda value: value.update(evidence_complete=True))
    report_case("report_attestation_laundering", lambda value: value.update(verified_attestation_count=9))
    report_case("report_resolution_collapse", lambda value: value["resolution_counts"].update(disagreement=0))
    report_case("report_decision_substitution", lambda value: value["retained_decisions"][0].update(decision_digest="sha256:" + "0" * 64))
    report_case("report_authority_laundering", lambda value: value["authority"].update(can_connect=True))
    report_case("report_activity_laundering", lambda value: value["activity"].update(range_connected=True))

    for label, error_type, operation in adversarial_cases:
        expect_error(error_type, operation, label)

    write_or_compare_example(examples / "range-verifier-policy.example.json", policy)
    write_or_compare_example(examples / "range-verifier-decision.example.json", decisions[0])
    write_or_compare_example(examples / "range-evidence-acceptance-report.example.json", report)

    validation_report: JsonObject = {
        "status": "RANGE_EVIDENCE_ACCEPTANCE_SIGNED_FIXTURE_DECISIONS_RETAINED_REAL_INDEPENDENT_ACCEPTANCE_BLOCKED",
        "origin": "simulated",
        "verifier_policy_status": policy["status"],
        "verifier_policy_signer_count": len(policy["signatures"]),
        "configured_verifier_count": len(policy["verifiers"]),
        "required_control_count": report["required_control_count"],
        "verified_decision_count": report["verified_decision_count"],
        "distinct_signed_verifier_count": report["distinct_signed_verifier_count"],
        "real_independent_verifier_count": report["real_independent_verifier_count"],
        "resolution_counts": report["resolution_counts"],
        "accepted_control_count": report["accepted_control_count"],
        "verified_attestation_count": report["verified_attestation_count"],
        "evidence_complete": report["evidence_complete"],
        "blockers": report["blockers"],
        "adversarial_case_count": len(adversarial_cases) + 1,
        "pure_real_acceptance_resolution_validated": True,
        "simulated_acceptance_denied": True,
        "activity": copy.deepcopy(ACCEPTANCE_ACTIVITY),
        "authority": copy.deepcopy(ACCEPTANCE_AUTHORITY),
    }
    report_path = PROJECT_ROOT / "reports" / "RANGE_EVIDENCE_ACCEPTANCE_VALIDATION.json"
    report_path.write_text(
        json.dumps(validation_report, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(json.dumps(validation_report, indent=2))


if __name__ == "__main__":
    main()
