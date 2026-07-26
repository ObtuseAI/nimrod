"""Validate signed construction-zone provisioning denial and attestation planning."""

from __future__ import annotations

import copy
import json
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import TypeVar

from jsonschema import Draft202012Validator, FormatChecker

from nimrod_simulator.construction_zone_preflight import build_construction_zone_preflight_result
from nimrod_simulator.construction_zone_provisioning_gate import (
    ATTESTATION_EVIDENCE_REQUIREMENTS,
    ATTESTATION_PLAN_ACTIVITY,
    ATTESTATION_PLAN_AUTHORITY,
    EXPECTED_ATTESTATION_PLAN_BLOCKERS,
    EXPECTED_PROVISIONING_BLOCKERS,
    PROVISIONING_ACTIVITY,
    PROVISIONING_AUTHORITY,
    PROVISIONING_OPERATIONS,
    build_construction_zone_provisioning_gate_result,
    sign_construction_zone_provisioning_authorization,
    validate_construction_zone_attestation_plan,
    validate_construction_zone_provisioning_gate_result,
    verify_construction_zone_provisioning_authorization,
)
from nimrod_simulator.errors import (
    ConstructionZoneAttestationPlanError,
    ConstructionZoneProvisioningAuthorizationError,
    ConstructionZoneProvisioningGateError,
)
from nimrod_simulator.jsonio import read_json_object, sha256_digest
from nimrod_simulator.key_governance import EphemeralEd25519SigningConnector
from nimrod_simulator.model import JsonObject
from validate_construction_zone_preflight import construction_zone, quarantine_receipt
from validate_public_sacrificial_corpus import public_source_registry, replica_plan
from validate_range_evidence_admission import governance_connectors, governance_state
from validate_source_staging_gate import owner_scope_registry, staging_authorization


TError = TypeVar("TError", bound=Exception)
PROJECT_ROOT = Path(__file__).resolve().parents[1]
PREFLIGHT_TIME = datetime(2026, 7, 13, 19, 12, 0, tzinfo=timezone.utc)
ASSESSMENT_TIME = datetime(2026, 7, 13, 19, 14, 0, tzinfo=timezone.utc)
MAXIMUM_LIFETIME_SECONDS = 600


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
        raise AssertionError(f"{label} failed schema validation: {'; '.join(error.message for error in errors)}")


def attestation_plan(zone: JsonObject, preflight_result: JsonObject) -> JsonObject:
    return {
        "plan_version": "0.1.0",
        "plan_id": "68d5bb0d-56d5-4b24-a946-f6ce4570a99e",
        "origin": "simulated",
        "status": "independent_attestors_unassigned",
        "declared_at": "2026-07-13T19:12:30Z",
        "zone_id": zone["zone_id"],
        "zone_digest": sha256_digest(zone),
        "preflight_result_id": preflight_result["result_id"],
        "preflight_result_digest": sha256_digest(preflight_result),
        "evidence_origin_requirement": "live",
        "minimum_distinct_principals_per_control": 2,
        "minimum_distinct_processes_per_control": 2,
        "controls": [
            {
                "control_id": control_id,
                "required_evidence_kinds": list(required_evidence_kinds),
                "collector_id": None,
                "collector_principal": None,
                "collector_process_id": None,
                "verifier_id": None,
                "verifier_principal": None,
                "verifier_process_id": None,
                "status": "unassigned",
                "evidence": [],
            }
            for control_id, required_evidence_kinds in ATTESTATION_EVIDENCE_REQUIREMENTS.items()
        ],
        "blockers": sorted(EXPECTED_ATTESTATION_PLAN_BLOCKERS),
        "activity": copy.deepcopy(ATTESTATION_PLAN_ACTIVITY),
        "authority": copy.deepcopy(ATTESTATION_PLAN_AUTHORITY),
    }


def provisioning_authorization(
    governance: JsonObject,
    zone: JsonObject,
    preflight_result: JsonObject,
    plan: JsonObject,
    signers: list[EphemeralEd25519SigningConnector],
) -> JsonObject:
    unsigned: JsonObject = {
        "authorization_version": "0.1.0",
        "authorization_id": "d59ab7b6-ab34-47ac-ac1d-c1c5ae6897d0",
        "origin": "simulated",
        "status": "signed_denial_environment_and_attestors_unassigned",
        "governance_state_digest": sha256_digest(governance),
        "zone_id": zone["zone_id"],
        "zone_digest": sha256_digest(zone),
        "preflight_result_id": preflight_result["result_id"],
        "preflight_result_digest": sha256_digest(preflight_result),
        "attestation_plan_id": plan["plan_id"],
        "attestation_plan_digest": sha256_digest(plan),
        "issued_at": "2026-07-13T19:13:00Z",
        "not_before": "2026-07-13T19:13:00Z",
        "expires_at": "2026-07-13T19:18:00Z",
        "outcome": "deny_provisioning",
        "requested_operations": list(PROVISIONING_OPERATIONS),
        "authorized_operations": [],
        "operator_approval_reference": None,
        "provider_id": None,
        "credential_references": [],
        "blockers": sorted(EXPECTED_PROVISIONING_BLOCKERS),
        "authority": copy.deepcopy(PROVISIONING_AUTHORITY),
    }
    return sign_construction_zone_provisioning_authorization(unsigned, [signers[0], signers[2]])


def write_or_compare_example(path: Path, value: JsonObject) -> None:
    rendered = json.dumps(value, indent=2, ensure_ascii=False) + "\n"
    if path.exists() and path.read_text(encoding="utf-8") != rendered:
        raise AssertionError(f"Canonical example drifted from deterministic regeneration: {path}")
    if not path.exists():
        path.write_bytes(rendered.encode("utf-8"))


def main() -> None:
    schemas = PROJECT_ROOT / "specs"
    examples = schemas / "examples"
    public_registry = public_source_registry()
    replica = replica_plan(public_registry)
    owner_registry = owner_scope_registry()
    signers = governance_connectors()
    governance = governance_state(signers)
    staging = staging_authorization(governance, owner_registry, public_registry, replica, signers)
    zone = construction_zone(staging)
    receipt = quarantine_receipt(zone, staging)
    preflight = build_construction_zone_preflight_result(
        zone,
        receipt,
        staging,
        governance,
        owner_registry,
        public_registry,
        replica,
        PREFLIGHT_TIME,
        MAXIMUM_LIFETIME_SECONDS,
    )
    plan = attestation_plan(zone, preflight)
    authorization = provisioning_authorization(governance, zone, preflight, plan, signers)
    result = build_construction_zone_provisioning_gate_result(
        authorization,
        governance,
        plan,
        zone,
        preflight,
        receipt,
        staging,
        owner_registry,
        public_registry,
        replica,
        ASSESSMENT_TIME,
        MAXIMUM_LIFETIME_SECONDS,
    )
    validate_construction_zone_attestation_plan(plan, zone, preflight, staging)
    verify_construction_zone_provisioning_authorization(
        authorization,
        governance,
        plan,
        zone,
        preflight,
        receipt,
        staging,
        owner_registry,
        public_registry,
        replica,
        ASSESSMENT_TIME,
        MAXIMUM_LIFETIME_SECONDS,
    )
    validate_construction_zone_provisioning_gate_result(
        result,
        authorization,
        governance,
        plan,
        zone,
        preflight,
        receipt,
        staging,
        owner_registry,
        public_registry,
        replica,
        ASSESSMENT_TIME,
        MAXIMUM_LIFETIME_SECONDS,
    )
    write_or_compare_example(examples / "construction-zone-isolation-attestation-plan.example.json", plan)
    write_or_compare_example(examples / "construction-zone-provisioning-authorization.example.json", authorization)
    write_or_compare_example(examples / "construction-zone-provisioning-gate-result.example.json", result)
    validate_contract(plan, schemas / "construction-zone-isolation-attestation-plan.schema.json", "attestation plan")
    validate_contract(
        authorization,
        schemas / "construction-zone-provisioning-authorization.schema.json",
        "provisioning authorization",
    )
    validate_contract(
        result,
        schemas / "construction-zone-provisioning-gate-result.schema.json",
        "provisioning gate result",
    )

    adversarial_count = 0
    plan_cases: list[tuple[str, Callable[[JsonObject], None]]] = [
        ("plan status laundering", lambda value: value.__setitem__("status", "complete")),
        ("plan origin laundering", lambda value: value.__setitem__("origin", "live")),
        ("zone ID substitution", lambda value: value.__setitem__("zone_id", "00000000-0000-4000-8000-000000000000")),
        ("zone digest substitution", lambda value: value.__setitem__("zone_digest", "sha256:" + "0" * 64)),
        ("preflight ID substitution", lambda value: value.__setitem__("preflight_result_id", "00000000-0000-4000-8000-000000000000")),
        ("preflight digest substitution", lambda value: value.__setitem__("preflight_result_digest", "sha256:" + "0" * 64)),
        ("fixture evidence origin", lambda value: value.__setitem__("evidence_origin_requirement", "simulated")),
        ("single principal", lambda value: value.__setitem__("minimum_distinct_principals_per_control", 1)),
        ("single process", lambda value: value.__setitem__("minimum_distinct_processes_per_control", 1)),
        ("control omission", lambda value: value.__setitem__("controls", value["controls"][:-1])),
        ("evidence-contract weakening", lambda value: value["controls"][0].__setitem__("required_evidence_kinds", ["BASE_IMAGE_DIGEST"])),
        ("collector identity fabrication", lambda value: value["controls"][0].__setitem__("collector_id", "collector-a")),
        ("verifier identity fabrication", lambda value: value["controls"][0].__setitem__("verifier_id", "verifier-a")),
        ("evidence fabrication", lambda value: value["controls"][0].__setitem__("evidence", ["fixture:fake"])),
        ("plan activity laundering", lambda value: value["activity"].__setitem__("observation_collected", True)),
        ("plan authority laundering", lambda value: value["authority"].__setitem__("can_verify", True)),
    ]
    for label, mutate in plan_cases:
        candidate = copy.deepcopy(plan)
        mutate(candidate)
        expect_error(
            ConstructionZoneAttestationPlanError,
            lambda candidate=candidate: validate_construction_zone_attestation_plan(candidate, zone, preflight, staging),
            label,
        )
        adversarial_count += 1

    authorization_cases: list[tuple[str, Callable[[JsonObject], None]]] = [
        ("authorization status laundering", lambda value: value.__setitem__("status", "authorized")),
        ("authorization outcome laundering", lambda value: value.__setitem__("outcome", "authorize_provisioning")),
        ("governance substitution", lambda value: value.__setitem__("governance_state_digest", "sha256:" + "0" * 64)),
        ("authorization zone substitution", lambda value: value.__setitem__("zone_digest", "sha256:" + "0" * 64)),
        ("authorization preflight substitution", lambda value: value.__setitem__("preflight_result_digest", "sha256:" + "0" * 64)),
        ("authorization plan substitution", lambda value: value.__setitem__("attestation_plan_digest", "sha256:" + "0" * 64)),
        ("inconsistent validity", lambda value: value.__setitem__("not_before", "2026-07-13T19:19:00Z")),
        ("excess lifetime", lambda value: value.__setitem__("expires_at", "2026-07-13T19:25:00Z")),
        ("stale authorization", lambda value: value.__setitem__("expires_at", "2026-07-13T19:13:30Z")),
        ("operation omission", lambda value: value.__setitem__("requested_operations", value["requested_operations"][:-1])),
        ("operation authorization laundering", lambda value: value.__setitem__("authorized_operations", ["CREATE_DISPOSABLE_WORKSPACE"])),
        ("operator approval fabrication", lambda value: value.__setitem__("operator_approval_reference", "approval:fake")),
        ("provider selection fabrication", lambda value: value.__setitem__("provider_id", "provider:fake")),
        ("credential insertion", lambda value: value.__setitem__("credential_references", ["secret:fake"])),
        ("blocker omission", lambda value: value.__setitem__("blockers", value["blockers"][:-1])),
        ("authorization authority laundering", lambda value: value["authority"].__setitem__("can_provision", True)),
        ("signature threshold failure", lambda value: value.__setitem__("signatures", value["signatures"][:1])),
    ]
    for label, mutate in authorization_cases:
        candidate = copy.deepcopy(authorization)
        mutate(candidate)
        expect_error(
            ConstructionZoneProvisioningAuthorizationError,
            lambda candidate=candidate: verify_construction_zone_provisioning_authorization(
                candidate,
                governance,
                plan,
                zone,
                preflight,
                receipt,
                staging,
                owner_registry,
                public_registry,
                replica,
                ASSESSMENT_TIME,
                MAXIMUM_LIFETIME_SECONDS,
            ),
            label,
        )
        adversarial_count += 1

    result_cases: list[tuple[str, Callable[[JsonObject], None]]] = [
        ("result status laundering", lambda value: value.__setitem__("status", "ready")),
        ("result zone substitution", lambda value: value.__setitem__("zone_digest", "sha256:" + "0" * 64)),
        ("result preflight substitution", lambda value: value.__setitem__("preflight_result_digest", "sha256:" + "0" * 64)),
        ("result plan substitution", lambda value: value.__setitem__("attestation_plan_digest", "sha256:" + "0" * 64)),
        ("result authorization substitution", lambda value: value.__setitem__("authorization_digest", "sha256:" + "0" * 64)),
        ("verified signer omission", lambda value: value.__setitem__("verified_signer_ids", value["verified_signer_ids"][:1])),
        ("control count drift", lambda value: value.__setitem__("required_control_count", 9)),
        ("collector assignment laundering", lambda value: value.__setitem__("assigned_collector_count", 10)),
        ("verifier assignment laundering", lambda value: value.__setitem__("assigned_verifier_count", 10)),
        ("control verification laundering", lambda value: value.__setitem__("verified_control_count", 10)),
        ("plan completion laundering", lambda value: value.__setitem__("attestation_plan_complete", True)),
        ("operator approval laundering", lambda value: value.__setitem__("operator_approval_present", True)),
        ("provider selection laundering", lambda value: value.__setitem__("provider_selected", True)),
        ("provisioning authority laundering", lambda value: value.__setitem__("provisioning_authorized", True)),
        ("provisioning activity laundering", lambda value: value.__setitem__("provisioning_performed", True)),
        ("staging laundering", lambda value: value.__setitem__("staging_authorized", True)),
        ("build laundering", lambda value: value.__setitem__("build_authorized", True)),
        ("connection laundering", lambda value: value.__setitem__("range_connection_authorized", True)),
        ("execution laundering", lambda value: value.__setitem__("execution_authorized", True)),
        ("result blocker omission", lambda value: value.__setitem__("blockers", value["blockers"][:-1])),
        ("result activity laundering", lambda value: value["activity"].__setitem__("identity_created", True)),
        ("result authority laundering", lambda value: value["authority"].__setitem__("can_create_identity", True)),
    ]
    for label, mutate in result_cases:
        candidate = copy.deepcopy(result)
        mutate(candidate)
        expect_error(
            ConstructionZoneProvisioningGateError,
            lambda candidate=candidate: validate_construction_zone_provisioning_gate_result(
                candidate,
                authorization,
                governance,
                plan,
                zone,
                preflight,
                receipt,
                staging,
                owner_registry,
                public_registry,
                replica,
                ASSESSMENT_TIME,
                MAXIMUM_LIFETIME_SECONDS,
            ),
            label,
        )
        adversarial_count += 1

    validation_report: JsonObject = {
        "status": result["status"],
        "origin": result["origin"],
        "verified_signer_count": len(result["verified_signer_ids"]),
        "verified_role_count": len(result["verified_roles"]),
        "required_control_count": result["required_control_count"],
        "assigned_collector_count": result["assigned_collector_count"],
        "assigned_verifier_count": result["assigned_verifier_count"],
        "verified_control_count": result["verified_control_count"],
        "attestation_plan_complete": result["attestation_plan_complete"],
        "operator_approval_present": result["operator_approval_present"],
        "provider_selected": result["provider_selected"],
        "provisioning_authorized": result["provisioning_authorized"],
        "provisioning_performed": result["provisioning_performed"],
        "staging_authorized": result["staging_authorized"],
        "build_authorized": result["build_authorized"],
        "range_connection_authorized": result["range_connection_authorized"],
        "execution_authorized": result["execution_authorized"],
        "adversarial_case_count": adversarial_count,
        "blockers": result["blockers"],
        "activity": copy.deepcopy(PROVISIONING_ACTIVITY),
        "authority": copy.deepcopy(PROVISIONING_AUTHORITY),
    }
    report_path = PROJECT_ROOT / "reports" / "CONSTRUCTION_ZONE_PROVISIONING_GATE_VALIDATION.json"
    report_path.write_text(json.dumps(validation_report, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps(validation_report, indent=2))


if __name__ == "__main__":
    main()
