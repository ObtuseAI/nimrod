"""Validate threshold-authorized evidence completion without connection or execution."""

from __future__ import annotations

import copy
import json
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import TypeVar

from jsonschema import Draft202012Validator, FormatChecker

from nimrod_simulator.errors import (
    RangeEvidenceCompletionAuthorizationError,
    RangeEvidenceCompletionError,
    RangeEvidenceCompletionPolicyError,
)
from nimrod_simulator.jsonio import read_json_object, sha256_digest
from nimrod_simulator.key_governance import EphemeralEd25519SigningConnector
from nimrod_simulator.model import JsonObject
from nimrod_simulator.range_evidence_completion import (
    COMPLETABLE_ACCEPTANCE_STATUS,
    COMPLETION_ACTIVITY,
    COMPLETION_OUTCOMES,
    COMPLETION_POLICY_AUTHORITY,
    COMPLETION_RECEIPT_AUTHORITY,
    build_range_evidence_completion_receipt,
    sign_range_evidence_completion_authorization,
    sign_range_evidence_completion_policy,
    validate_range_evidence_completion_receipt,
    verify_range_evidence_completion_authorization,
    verify_range_evidence_completion_policy,
)
from nimrod_simulator.range_execution_gate import REQUIRED_ENVIRONMENT_ATTESTATIONS
from validate_range_evidence_admission import governance_connectors, governance_state


TError = TypeVar("TError", bound=Exception)
PROJECT_ROOT = Path(__file__).resolve().parents[1]
COMPLETION_TIME = datetime(2026, 7, 13, 16, 34, 0, tzinfo=timezone.utc)
POLICY_LIFETIME_SECONDS = 900
AUTHORIZATION_LIFETIME_SECONDS = 300


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


def completion_policy(
    acceptance_report: JsonObject,
    governance: JsonObject,
    signers: list[EphemeralEd25519SigningConnector],
) -> JsonObject:
    origin = str(acceptance_report["origin"])
    blockers = ["EVIDENCE_COMPLETION_AUTHORIZATION_MISSING"]
    if origin == "simulated":
        blockers.extend(
            [
                "OWNER_NAMED_SACRIFICIAL_RANGE_MISSING",
                "REAL_INDEPENDENT_VERIFIER_ACCEPTANCE_MISSING",
                "REAL_READ_ONLY_OBSERVATIONS_MISSING",
            ]
        )
    unsigned: JsonObject = {
        "policy_version": "0.1.0",
        "policy_id": "d47cc48a-dcf2-4db2-83bc-d19385a22347",
        "origin": origin,
        "status": "fixture_policy_non_completing" if origin == "simulated" else "external_completion_policy",
        "governance_state_digest": sha256_digest(governance),
        "acceptance_report_id": acceptance_report["report_id"],
        "acceptance_report_digest": sha256_digest(acceptance_report),
        "scope_digest": acceptance_report["scope_digest"],
        "environment_id": acceptance_report["environment_id"],
        "issued_at": "2026-07-13T16:32:30Z",
        "not_before": "2026-07-13T16:32:30Z",
        "expires_at": "2026-07-13T16:40:00Z",
        "required_controls": sorted(REQUIRED_ENVIRONMENT_ATTESTATIONS),
        "required_accepted_control_count": 9,
        "required_verified_attestation_count": 9,
        "required_real_independent_verifier_count": 2,
        "required_acceptance_status": COMPLETABLE_ACCEPTANCE_STATUS,
        "allowed_outcomes": sorted(COMPLETION_OUTCOMES),
        "network_destinations": [],
        "secret_references": [],
        "blockers": sorted(blockers),
        "authority": copy.deepcopy(COMPLETION_POLICY_AUTHORITY),
    }
    return sign_range_evidence_completion_policy(unsigned, signers[:2])


def completion_authorization(
    policy: JsonObject,
    acceptance_report: JsonObject,
    signers: list[EphemeralEd25519SigningConnector],
    outcome: str,
) -> JsonObject:
    authority = copy.deepcopy(COMPLETION_POLICY_AUTHORITY)
    authority["can_mark_evidence_complete"] = outcome == "authorize_completion"
    unsigned: JsonObject = {
        "authorization_version": "0.1.0",
        "authorization_id": "700175a4-a1fd-4db7-b25a-9a2cc0f65046",
        "origin": acceptance_report["origin"],
        "status": "external_completion_authorized" if outcome == "authorize_completion" else "completion_denied",
        "policy_id": policy["policy_id"],
        "policy_digest": sha256_digest(policy),
        "acceptance_report_id": acceptance_report["report_id"],
        "acceptance_report_digest": sha256_digest(acceptance_report),
        "scope_digest": acceptance_report["scope_digest"],
        "environment_id": acceptance_report["environment_id"],
        "issued_at": "2026-07-13T16:33:00Z",
        "not_before": "2026-07-13T16:33:00Z",
        "expires_at": "2026-07-13T16:36:00Z",
        "outcome": outcome,
        "reason": (
            "all_completion_prerequisites_satisfied"
            if outcome == "authorize_completion"
            else "completion_denied_or_prerequisites_unsatisfied"
        ),
        "authority": authority,
    }
    return sign_range_evidence_completion_authorization(unsigned, [signers[0], signers[2]])


def resign_policy(
    policy: JsonObject,
    signers: list[EphemeralEd25519SigningConnector],
) -> JsonObject:
    unsigned = copy.deepcopy(policy)
    unsigned.pop("signatures", None)
    return sign_range_evidence_completion_policy(unsigned, signers[:2])


def resign_authorization(
    authorization: JsonObject,
    signers: list[EphemeralEd25519SigningConnector],
) -> JsonObject:
    unsigned = copy.deepcopy(authorization)
    unsigned.pop("signatures", None)
    return sign_range_evidence_completion_authorization(unsigned, [signers[0], signers[2]])


def real_accepted_report(fixture: JsonObject) -> JsonObject:
    report = copy.deepcopy(fixture)
    report["report_id"] = "9bb9864c-9a4f-475e-b8dd-2b4519bbb99d"
    report["origin"] = "sacrificial_replica"
    report["status"] = COMPLETABLE_ACCEPTANCE_STATUS
    report["environment_id"] = "range-environment:owner-named-sacrificial-01"
    report["environment_name"] = "owner-named-sacrificial-01"
    report["owner_named_environment"] = True
    report["real_independent_verifier_count"] = 2
    report["accepted_control_count"] = 9
    report["verified_attestation_count"] = 9
    report["resolution_counts"] = {
        "accepted": 9,
        "rejected": 0,
        "abstained": 0,
        "disagreement": 0,
        "timeout": 0,
    }
    for result in report["control_results"]:
        if not isinstance(result, dict):
            raise TypeError("Control result must be an object.")
        result["resolution"] = "accepted"
    report["blockers"] = [
        "EVIDENCE_COMPLETION_AUTHORITY_MISSING",
        "EXECUTION_AUTHORIZATION_MISSING",
        "RANGE_CONNECTION_AUTHORIZATION_MISSING",
    ]
    return report


def write_or_compare_example(path: Path, value: JsonObject) -> None:
    rendered = json.dumps(value, indent=2, ensure_ascii=False) + "\n"
    if path.exists() and path.read_text(encoding="utf-8") != rendered:
        raise AssertionError(f"Canonical example drifted from deterministic regeneration: {path}")
    if not path.exists():
        path.write_bytes(rendered.encode("utf-8"))


def main() -> None:
    schemas = PROJECT_ROOT / "specs"
    examples = schemas / "examples"
    acceptance_report = read_json_object(examples / "range-evidence-acceptance-report.example.json")
    signers = governance_connectors()
    governance = governance_state(signers)
    policy = completion_policy(acceptance_report, governance, signers)
    authorization = completion_authorization(policy, acceptance_report, signers, "deny_completion")
    receipt = build_range_evidence_completion_receipt(
        policy,
        authorization,
        governance,
        acceptance_report,
        COMPLETION_TIME,
        POLICY_LIFETIME_SECONDS,
        AUTHORIZATION_LIFETIME_SECONDS,
    )
    validate_range_evidence_completion_receipt(
        receipt,
        policy,
        authorization,
        governance,
        acceptance_report,
        COMPLETION_TIME,
        POLICY_LIFETIME_SECONDS,
        AUTHORIZATION_LIFETIME_SECONDS,
    )
    write_or_compare_example(examples / "range-evidence-completion-policy.example.json", policy)
    write_or_compare_example(
        examples / "range-evidence-completion-authorization.example.json", authorization
    )
    write_or_compare_example(examples / "range-evidence-completion-receipt.example.json", receipt)
    validate_contract(policy, schemas / "range-evidence-completion-policy.schema.json", "completion policy")
    validate_contract(
        authorization,
        schemas / "range-evidence-completion-authorization.schema.json",
        "completion authorization",
    )
    validate_contract(receipt, schemas / "range-evidence-completion-receipt.schema.json", "completion receipt")

    policy_cases: list[tuple[str, Callable[[JsonObject], None]]] = [
        ("missing signatures", lambda value: value.__setitem__("signatures", [])),
        ("acceptance digest substitution", lambda value: value.__setitem__("acceptance_report_digest", "sha256:" + "0" * 64)),
        ("scope substitution", lambda value: value.__setitem__("scope_digest", "sha256:" + "1" * 64)),
        ("environment substitution", lambda value: value.__setitem__("environment_id", "range-environment:other")),
        ("accepted-count weakening", lambda value: value.__setitem__("required_accepted_control_count", 8)),
        ("attestation-count weakening", lambda value: value.__setitem__("required_verified_attestation_count", 8)),
        ("verifier-count weakening", lambda value: value.__setitem__("required_real_independent_verifier_count", 1)),
        ("control omission", lambda value: value.__setitem__("required_controls", value["required_controls"][:-1])),
        ("status widening", lambda value: value.__setitem__("required_acceptance_status", "blocked_fixture_verifier_decisions_non_accepting")),
        ("outcome widening", lambda value: value.__setitem__("allowed_outcomes", ["authorize_completion", "deny_completion", "connect"])),
        ("network destination", lambda value: value.__setitem__("network_destinations", ["https://range.invalid"])),
        ("secret reference", lambda value: value.__setitem__("secret_references", ["secret:range"])),
        ("policy authority", lambda value: value["authority"].__setitem__("can_connect", True)),
    ]
    adversarial_count = 0
    for label, mutate in policy_cases:
        candidate = copy.deepcopy(policy)
        mutate(candidate)
        if label != "missing signatures":
            candidate = resign_policy(candidate, signers)
        expect_error(
            RangeEvidenceCompletionPolicyError,
            lambda candidate=candidate: verify_range_evidence_completion_policy(
                candidate,
                governance,
                acceptance_report,
                COMPLETION_TIME,
                POLICY_LIFETIME_SECONDS,
            ),
            label,
        )
        adversarial_count += 1

    authorization_cases: list[tuple[str, Callable[[JsonObject], None]]] = [
        ("authorization signatures missing", lambda value: value.__setitem__("signatures", [])),
        ("authorization policy substitution", lambda value: value.__setitem__("policy_digest", "sha256:" + "2" * 64)),
        ("authorization report substitution", lambda value: value.__setitem__("acceptance_report_digest", "sha256:" + "3" * 64)),
        ("authorization scope substitution", lambda value: value.__setitem__("scope_digest", "sha256:" + "4" * 64)),
        ("authorization environment substitution", lambda value: value.__setitem__("environment_id", "range-environment:other")),
        ("simulated completion laundering", lambda value: value.__setitem__("outcome", "authorize_completion")),
        ("authorization reason laundering", lambda value: value.__setitem__("reason", "all_completion_prerequisites_satisfied")),
        ("authorization status laundering", lambda value: value.__setitem__("status", "external_completion_authorized")),
        ("completion authority laundering", lambda value: value["authority"].__setitem__("can_mark_evidence_complete", True)),
        ("connection authority widening", lambda value: value["authority"].__setitem__("can_connect", True)),
        ("execution authority widening", lambda value: value["authority"].__setitem__("can_execute", True)),
    ]
    for label, mutate in authorization_cases:
        candidate = copy.deepcopy(authorization)
        mutate(candidate)
        if label != "authorization signatures missing":
            candidate = resign_authorization(candidate, signers)
        expect_error(
            RangeEvidenceCompletionAuthorizationError,
            lambda candidate=candidate: verify_range_evidence_completion_authorization(
                candidate,
                policy,
                governance,
                acceptance_report,
                COMPLETION_TIME,
                AUTHORIZATION_LIFETIME_SECONDS,
            ),
            label,
        )
        adversarial_count += 1

    receipt_cases: list[tuple[str, Callable[[JsonObject], None]]] = [
        ("receipt status laundering", lambda value: value.__setitem__("status", "evidence_complete_pending_separate_connection_authorization")),
        ("receipt prerequisite laundering", lambda value: value.__setitem__("completion_prerequisites_satisfied", True)),
        ("receipt completion laundering", lambda value: value.__setitem__("evidence_complete", True)),
        ("receipt authorization laundering", lambda value: value.__setitem__("completion_authorized", True)),
        ("receipt connection widening", lambda value: value.__setitem__("range_connection_authorized", True)),
        ("receipt execution widening", lambda value: value.__setitem__("execution_authorized", True)),
        ("receipt count laundering", lambda value: value.__setitem__("accepted_control_count", 9)),
        ("receipt signer omission", lambda value: value.__setitem__("verified_authorization_signer_ids", [])),
        ("receipt blocker omission", lambda value: value.__setitem__("blockers", [])),
        ("receipt activity laundering", lambda value: value["activity"].__setitem__("range_connected", True)),
        ("receipt authority laundering", lambda value: value["authority"].__setitem__("can_connect", True)),
    ]
    for label, mutate in receipt_cases:
        candidate = copy.deepcopy(receipt)
        mutate(candidate)
        expect_error(
            RangeEvidenceCompletionError,
            lambda candidate=candidate: validate_range_evidence_completion_receipt(
                candidate,
                policy,
                authorization,
                governance,
                acceptance_report,
                COMPLETION_TIME,
                POLICY_LIFETIME_SECONDS,
                AUTHORIZATION_LIFETIME_SECONDS,
            ),
            label,
        )
        adversarial_count += 1

    real_report = real_accepted_report(acceptance_report)
    real_policy = completion_policy(real_report, governance, signers)
    real_authorization = completion_authorization(
        real_policy, real_report, signers, "authorize_completion"
    )
    real_receipt = build_range_evidence_completion_receipt(
        real_policy,
        real_authorization,
        governance,
        real_report,
        COMPLETION_TIME,
        POLICY_LIFETIME_SECONDS,
        AUTHORIZATION_LIFETIME_SECONDS,
    )
    require_condition(real_receipt["evidence_complete"] is True, "Real completion path did not complete evidence.")
    require_condition(
        real_receipt["range_connection_authorized"] is False
        and real_receipt["execution_authorized"] is False,
        "Evidence completion widened connection or execution authority.",
    )
    incomplete_real_report = copy.deepcopy(real_report)
    incomplete_real_report["accepted_control_count"] = 8
    incomplete_policy = completion_policy(incomplete_real_report, governance, signers)
    incomplete_authorization = completion_authorization(
        incomplete_policy,
        incomplete_real_report,
        signers,
        "authorize_completion",
    )
    expect_error(
        RangeEvidenceCompletionAuthorizationError,
        lambda: verify_range_evidence_completion_authorization(
            incomplete_authorization,
            incomplete_policy,
            governance,
            incomplete_real_report,
            COMPLETION_TIME,
            AUTHORIZATION_LIFETIME_SECONDS,
        ),
        "incomplete real acceptance completion",
    )
    adversarial_count += 1

    validation_report: JsonObject = {
        "status": "RANGE_EVIDENCE_COMPLETION_SIGNED_DENIAL_RETAINED_REAL_COMPLETION_BLOCKED",
        "origin": receipt["origin"],
        "completion_policy_status": policy["status"],
        "completion_policy_signer_count": len(policy["signatures"]),
        "completion_authorization_status": authorization["status"],
        "completion_authorization_signer_count": len(authorization["signatures"]),
        "completion_prerequisites_satisfied": receipt["completion_prerequisites_satisfied"],
        "completion_authorized": receipt["completion_authorized"],
        "accepted_control_count": receipt["accepted_control_count"],
        "verified_attestation_count": receipt["verified_attestation_count"],
        "real_independent_verifier_count": receipt["real_independent_verifier_count"],
        "evidence_complete": receipt["evidence_complete"],
        "range_connection_authorized": receipt["range_connection_authorized"],
        "execution_authorized": receipt["execution_authorized"],
        "blockers": receipt["blockers"],
        "adversarial_case_count": adversarial_count,
        "pure_real_completion_path_validated": True,
        "incomplete_real_completion_denied": True,
        "activity": copy.deepcopy(COMPLETION_ACTIVITY),
        "authority": copy.deepcopy(COMPLETION_RECEIPT_AUTHORITY),
    }
    report_path = PROJECT_ROOT / "reports" / "RANGE_EVIDENCE_COMPLETION_VALIDATION.json"
    report_path.write_text(
        json.dumps(validation_report, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(json.dumps(validation_report, indent=2))


if __name__ == "__main__":
    main()
