"""Validate declaration-only construction-zone and quarantine evidence preflight."""

from __future__ import annotations

import copy
import json
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import TypeVar

from jsonschema import Draft202012Validator, FormatChecker

from nimrod_simulator.construction_zone_preflight import (
    CONSTRUCTION_ZONE_CONTROLS,
    EXPECTED_PREFLIGHT_BLOCKERS,
    PREFLIGHT_ACTIVITY,
    PREFLIGHT_AUTHORITY,
    QUARANTINE_ACTIVITY,
    QUARANTINE_AUTHORITY,
    ZONE_ACTIVITY,
    ZONE_AUTHORITY,
    build_construction_zone_preflight_result,
    validate_construction_zone_declaration,
    validate_construction_zone_preflight_result,
    validate_quarantine_evidence_receipt,
)
from nimrod_simulator.errors import (
    ConstructionZoneDeclarationError,
    ConstructionZonePreflightError,
    QuarantineEvidenceReceiptError,
)
from nimrod_simulator.jsonio import read_json_object, sha256_digest
from nimrod_simulator.model import JsonObject
from nimrod_simulator.source_staging_gate import QUARANTINE_REQUIREMENTS
from validate_public_sacrificial_corpus import public_source_registry, replica_plan
from validate_range_evidence_admission import governance_connectors, governance_state
from validate_source_staging_gate import owner_scope_registry, staging_authorization


TError = TypeVar("TError", bound=Exception)
PROJECT_ROOT = Path(__file__).resolve().parents[1]
ASSESSMENT_TIME = datetime(2026, 7, 13, 19, 12, 0, tzinfo=timezone.utc)
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


def construction_zone(authorization: JsonObject) -> JsonObject:
    return {
        "zone_version": "0.1.0",
        "zone_id": "46295d08-2990-4f04-a207-e9cc298b99c5",
        "origin": "simulated",
        "status": "declared_not_provisioned",
        "declared_at": "2026-07-13T19:11:15Z",
        "staging_authorization_id": authorization["authorization_id"],
        "staging_authorization_digest": sha256_digest(authorization),
        "environment_class": "isolated_construction_zone_candidate",
        "generation": 1,
        "controls": [
            {"control_id": control_id, "status": "unproven", "evidence": []}
            for control_id in CONSTRUCTION_ZONE_CONTROLS
        ],
        "network": {
            "mode": "offline_default_deny_declaration",
            "internet_egress": False,
            "public_ingress": False,
            "github_access": False,
            "registry_access": False,
            "external_dns_resolution": False,
            "policy_applied": False,
        },
        "storage": {
            "workspace_kind": "disposable_ephemeral",
            "source_ingress_read_only": True,
            "separate_output_store_required": True,
            "workspace_created": False,
            "source_ingress_mounted": False,
            "output_store_created": False,
            "baseline_snapshot_digest": None,
        },
        "activity": copy.deepcopy(ZONE_ACTIVITY),
        "authority": copy.deepcopy(ZONE_AUTHORITY),
    }


def quarantine_receipt(zone: JsonObject, authorization: JsonObject) -> JsonObject:
    requested_source_ids = authorization.get("requested_source_ids")
    if not isinstance(requested_source_ids, list):
        raise TypeError("Staging authorization requested_source_ids must be a list.")
    return {
        "receipt_version": "0.1.0",
        "receipt_id": "00cffec9-4ccc-4077-9292-1d0aff7f29b6",
        "origin": "simulated",
        "status": "evidence_missing",
        "recorded_at": "2026-07-13T19:11:30Z",
        "zone_id": zone["zone_id"],
        "zone_digest": sha256_digest(zone),
        "staging_authorization_id": authorization["authorization_id"],
        "staging_authorization_digest": sha256_digest(authorization),
        "requested_source_ids": copy.deepcopy(requested_source_ids),
        "source_archive_count": 0,
        "source_archive_digests": [],
        "results": [
            {
                "requirement_id": requirement_id,
                "status": "missing",
                "performed": False,
                "evidence_digest": None,
                "evidence": [],
            }
            for requirement_id in QUARANTINE_REQUIREMENTS
        ],
        "activity": copy.deepcopy(QUARANTINE_ACTIVITY),
        "authority": copy.deepcopy(QUARANTINE_AUTHORITY),
    }


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
    plan = replica_plan(public_registry)
    owner_registry = owner_scope_registry()
    signers = governance_connectors()
    governance = governance_state(signers)
    authorization = staging_authorization(governance, owner_registry, public_registry, plan, signers)
    zone = construction_zone(authorization)
    receipt = quarantine_receipt(zone, authorization)
    result = build_construction_zone_preflight_result(
        zone,
        receipt,
        authorization,
        governance,
        owner_registry,
        public_registry,
        plan,
        ASSESSMENT_TIME,
        MAXIMUM_LIFETIME_SECONDS,
    )
    validate_construction_zone_declaration(zone, authorization)
    validate_quarantine_evidence_receipt(receipt, zone, authorization)
    validate_construction_zone_preflight_result(
        result,
        zone,
        receipt,
        authorization,
        governance,
        owner_registry,
        public_registry,
        plan,
        ASSESSMENT_TIME,
        MAXIMUM_LIFETIME_SECONDS,
    )
    write_or_compare_example(examples / "isolated-construction-zone.example.json", zone)
    write_or_compare_example(examples / "source-quarantine-evidence-receipt.example.json", receipt)
    write_or_compare_example(examples / "construction-zone-preflight-result.example.json", result)
    validate_contract(zone, schemas / "isolated-construction-zone.schema.json", "construction zone")
    validate_contract(receipt, schemas / "source-quarantine-evidence-receipt.schema.json", "quarantine receipt")
    validate_contract(result, schemas / "construction-zone-preflight-result.schema.json", "construction preflight")

    adversarial_count = 0
    zone_cases: list[tuple[str, Callable[[JsonObject], None]]] = [
        ("zone provisioning laundering", lambda value: value.__setitem__("status", "provisioned")),
        ("authorization ID substitution", lambda value: value.__setitem__("staging_authorization_id", "00000000-0000-4000-8000-000000000000")),
        ("authorization digest substitution", lambda value: value.__setitem__("staging_authorization_digest", "sha256:" + "0" * 64)),
        ("generation widening", lambda value: value.__setitem__("generation", 2)),
        ("control omission", lambda value: value.__setitem__("controls", value["controls"][:-1])),
        ("control evidence laundering", lambda value: value["controls"][0].__setitem__("evidence", ["fixture:fake"])),
        ("internet egress", lambda value: value["network"].__setitem__("internet_egress", True)),
        ("GitHub access", lambda value: value["network"].__setitem__("github_access", True)),
        ("network enforcement laundering", lambda value: value["network"].__setitem__("policy_applied", True)),
        ("writable source ingress", lambda value: value["storage"].__setitem__("source_ingress_read_only", False)),
        ("workspace creation laundering", lambda value: value["storage"].__setitem__("workspace_created", True)),
        ("snapshot laundering", lambda value: value["storage"].__setitem__("baseline_snapshot_digest", "sha256:" + "1" * 64)),
        ("zone activity laundering", lambda value: value["activity"].__setitem__("construction_zone_provisioned", True)),
        ("zone authority laundering", lambda value: value["authority"].__setitem__("can_provision", True)),
    ]
    for label, mutate in zone_cases:
        candidate = copy.deepcopy(zone)
        mutate(candidate)
        expect_error(
            ConstructionZoneDeclarationError,
            lambda candidate=candidate: validate_construction_zone_declaration(candidate, authorization),
            label,
        )
        adversarial_count += 1

    receipt_cases: list[tuple[str, Callable[[JsonObject], None]]] = [
        ("receipt completion laundering", lambda value: value.__setitem__("status", "complete")),
        ("zone ID substitution", lambda value: value.__setitem__("zone_id", "00000000-0000-4000-8000-000000000000")),
        ("zone digest substitution", lambda value: value.__setitem__("zone_digest", "sha256:" + "0" * 64)),
        ("receipt authorization substitution", lambda value: value.__setitem__("staging_authorization_digest", "sha256:" + "0" * 64)),
        ("source omission", lambda value: value.__setitem__("requested_source_ids", value["requested_source_ids"][:-1])),
        ("archive count laundering", lambda value: value.__setitem__("source_archive_count", 5)),
        ("archive digest laundering", lambda value: value.__setitem__("source_archive_digests", ["sha256:" + "2" * 64])),
        ("requirement omission", lambda value: value.__setitem__("results", value["results"][:-1])),
        ("scanner completion laundering", lambda value: value["results"][0].__setitem__("status", "pass")),
        ("performed laundering", lambda value: value["results"][0].__setitem__("performed", True)),
        ("evidence digest laundering", lambda value: value["results"][0].__setitem__("evidence_digest", "sha256:" + "3" * 64)),
        ("scanner activity laundering", lambda value: value["activity"].__setitem__("scanner_executed", True)),
        ("quarantine authority laundering", lambda value: value["authority"].__setitem__("can_extract_source", True)),
    ]
    for label, mutate in receipt_cases:
        candidate = copy.deepcopy(receipt)
        mutate(candidate)
        expect_error(
            QuarantineEvidenceReceiptError,
            lambda candidate=candidate: validate_quarantine_evidence_receipt(candidate, zone, authorization),
            label,
        )
        adversarial_count += 1

    result_cases: list[tuple[str, Callable[[JsonObject], None]]] = [
        ("verified zone laundering", lambda value: value.__setitem__("verified_zone_control_count", 10)),
        ("verified quarantine laundering", lambda value: value.__setitem__("verified_quarantine_requirement_count", 8)),
        ("zone provisioning result laundering", lambda value: value.__setitem__("construction_zone_provisioned", True)),
        ("quarantine completion result laundering", lambda value: value.__setitem__("quarantine_evidence_complete", True)),
        ("staging result laundering", lambda value: value.__setitem__("staging_authorized", True)),
        ("build result laundering", lambda value: value.__setitem__("build_authorized", True)),
        ("connection result laundering", lambda value: value.__setitem__("range_connection_authorized", True)),
        ("execution result laundering", lambda value: value.__setitem__("execution_authorized", True)),
        ("preflight blocker omission", lambda value: value.__setitem__("blockers", value["blockers"][:-1])),
        ("preflight activity laundering", lambda value: value["activity"].__setitem__("source_archive_staged", True)),
        ("preflight authority laundering", lambda value: value["authority"].__setitem__("can_build_replica", True)),
        ("receipt digest substitution", lambda value: value.__setitem__("receipt_digest", "sha256:" + "0" * 64)),
        ("result status laundering", lambda value: value.__setitem__("status", "ready")),
    ]
    for label, mutate in result_cases:
        candidate = copy.deepcopy(result)
        mutate(candidate)
        expect_error(
            ConstructionZonePreflightError,
            lambda candidate=candidate: validate_construction_zone_preflight_result(
                candidate,
                zone,
                receipt,
                authorization,
                governance,
                owner_registry,
                public_registry,
                plan,
                ASSESSMENT_TIME,
                MAXIMUM_LIFETIME_SECONDS,
            ),
            label,
        )
        adversarial_count += 1

    validation_report: JsonObject = {
        "status": result["status"],
        "origin": result["origin"],
        "zone_control_count": result["zone_control_count"],
        "verified_zone_control_count": result["verified_zone_control_count"],
        "quarantine_requirement_count": result["quarantine_requirement_count"],
        "verified_quarantine_requirement_count": result["verified_quarantine_requirement_count"],
        "source_archive_count": result["source_archive_count"],
        "construction_zone_provisioned": result["construction_zone_provisioned"],
        "quarantine_evidence_complete": result["quarantine_evidence_complete"],
        "staging_authorized": result["staging_authorized"],
        "build_authorized": result["build_authorized"],
        "range_connection_authorized": result["range_connection_authorized"],
        "execution_authorized": result["execution_authorized"],
        "adversarial_case_count": adversarial_count,
        "blockers": result["blockers"],
        "activity": copy.deepcopy(PREFLIGHT_ACTIVITY),
        "authority": copy.deepcopy(PREFLIGHT_AUTHORITY),
    }
    report_path = PROJECT_ROOT / "reports" / "CONSTRUCTION_ZONE_PREFLIGHT_VALIDATION.json"
    report_path.write_text(json.dumps(validation_report, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps(validation_report, indent=2))


if __name__ == "__main__":
    main()
