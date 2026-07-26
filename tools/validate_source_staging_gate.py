"""Validate owner-scope and threshold-signed source-staging denial contracts."""

from __future__ import annotations

import copy
import json
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import TypeVar

from jsonschema import Draft202012Validator, FormatChecker

from nimrod_simulator.errors import (
    OwnerScopeRegistryError,
    SourceStagingAuthorizationError,
    SourceStagingGateError,
)
from nimrod_simulator.jsonio import read_json_object, sha256_digest
from nimrod_simulator.key_governance import EphemeralEd25519SigningConnector
from nimrod_simulator.model import JsonObject
from nimrod_simulator.source_staging_gate import (
    EXPECTED_OWNER_BLOCKERS,
    EXPECTED_STAGING_BLOCKERS,
    OWNER_REGISTRY_AUTHORITY,
    QUARANTINE_REQUIREMENTS,
    STAGING_ACTIVITY,
    STAGING_AUTHORITY,
    build_source_staging_gate_report,
    sign_source_staging_authorization,
    validate_owner_scope_registry,
    validate_source_staging_gate_report,
    verify_source_staging_authorization,
)
from validate_public_sacrificial_corpus import public_source_registry, replica_plan
from validate_range_evidence_admission import governance_connectors, governance_state


TError = TypeVar("TError", bound=Exception)
PROJECT_ROOT = Path(__file__).resolve().parents[1]
ASSESSMENT_TIME = datetime(2026, 7, 13, 19, 11, 0, tzinfo=timezone.utc)
MAXIMUM_LIFETIME_SECONDS = 600


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


def owner_scope_registry() -> JsonObject:
    return {
        "registry_version": "0.1.0",
        "registry_id": "f738d581-922c-45f2-b389-72aa025c92b6",
        "origin": "simulated",
        "status": "incomplete_owner_attestation_required",
        "recorded_at": "2026-07-13T19:09:00Z",
        "registry_complete": False,
        "owner_attestation_present": False,
        "unknown_ownership_action": "deny",
        "excluded_organizations": ["obtuseai"],
        "excluded_repositories": ["obtuseai/nimrod"],
        "ownership_proof_digests": [],
        "blockers": sorted(EXPECTED_OWNER_BLOCKERS),
        "authority": copy.deepcopy(OWNER_REGISTRY_AUTHORITY),
    }


def staging_authorization(
    governance: JsonObject,
    owner_registry: JsonObject,
    public_registry: JsonObject,
    plan: JsonObject,
    signers: list[EphemeralEd25519SigningConnector],
) -> JsonObject:
    sources = public_registry.get("sources")
    if not isinstance(sources, list):
        raise TypeError("Public source registry sources must be a list.")
    requested_source_ids = sorted(
        str(source["source_id"])
        for source in sources
        if isinstance(source, dict)
    )
    unsigned: JsonObject = {
        "authorization_version": "0.1.0",
        "authorization_id": "c0ef9fcc-126e-4aab-98aa-2273fd2178aa",
        "origin": "simulated",
        "status": "signed_denial_owner_scope_incomplete",
        "governance_state_digest": sha256_digest(governance),
        "owner_registry_id": owner_registry["registry_id"],
        "owner_registry_digest": sha256_digest(owner_registry),
        "public_registry_id": public_registry["registry_id"],
        "public_registry_digest": sha256_digest(public_registry),
        "replica_plan_id": plan["plan_id"],
        "replica_plan_digest": sha256_digest(plan),
        "issued_at": "2026-07-13T19:10:00Z",
        "not_before": "2026-07-13T19:10:00Z",
        "expires_at": "2026-07-13T19:15:00Z",
        "outcome": "deny_staging",
        "requested_source_ids": requested_source_ids,
        "authorized_source_ids": [],
        "authorized_content_digests": [],
        "construction_zone_id": None,
        "quarantine_requirements": list(QUARANTINE_REQUIREMENTS),
        "network": {
            "mode": "offline_default_deny",
            "internet_egress": False,
            "public_ingress": False,
            "github_access": False,
            "registry_access": False,
            "external_dns_resolution": False,
        },
        "blockers": sorted(EXPECTED_STAGING_BLOCKERS),
        "authority": copy.deepcopy(STAGING_AUTHORITY),
    }
    return sign_source_staging_authorization(unsigned, [signers[0], signers[2]])


def resign_authorization(
    authorization: JsonObject,
    signers: list[EphemeralEd25519SigningConnector],
) -> JsonObject:
    unsigned = copy.deepcopy(authorization)
    unsigned.pop("signatures", None)
    return sign_source_staging_authorization(unsigned, [signers[0], signers[2]])


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
    report = build_source_staging_gate_report(
        authorization,
        governance,
        owner_registry,
        public_registry,
        plan,
        ASSESSMENT_TIME,
        MAXIMUM_LIFETIME_SECONDS,
    )
    validate_owner_scope_registry(owner_registry)
    verify_source_staging_authorization(
        authorization,
        governance,
        owner_registry,
        public_registry,
        plan,
        ASSESSMENT_TIME,
        MAXIMUM_LIFETIME_SECONDS,
    )
    validate_source_staging_gate_report(
        report,
        authorization,
        governance,
        owner_registry,
        public_registry,
        plan,
        ASSESSMENT_TIME,
        MAXIMUM_LIFETIME_SECONDS,
    )
    write_or_compare_example(examples / "owner-scope-exclusion-registry.example.json", owner_registry)
    write_or_compare_example(examples / "public-source-staging-authorization.example.json", authorization)
    write_or_compare_example(examples / "source-staging-gate-report.example.json", report)
    validate_contract(owner_registry, schemas / "owner-scope-exclusion-registry.schema.json", "owner scope")
    validate_contract(
        authorization,
        schemas / "public-source-staging-authorization.schema.json",
        "staging authorization",
    )
    validate_contract(report, schemas / "source-staging-gate-report.schema.json", "staging report")

    adversarial_count = 0
    registry_cases: list[tuple[str, Callable[[JsonObject], None]]] = [
        ("registry completion laundering", lambda value: value.__setitem__("registry_complete", True)),
        ("owner attestation laundering", lambda value: value.__setitem__("owner_attestation_present", True)),
        ("unknown ownership allowed", lambda value: value.__setitem__("unknown_ownership_action", "allow")),
        ("owner organization omitted", lambda value: value.__setitem__("excluded_organizations", [])),
        ("owner repository omitted", lambda value: value.__setitem__("excluded_repositories", [])),
        ("fabricated owner proof", lambda value: value.__setitem__("ownership_proof_digests", ["sha256:" + "0" * 64])),
        ("owner blocker omitted", lambda value: value.__setitem__("blockers", value["blockers"][:-1])),
        ("owner authority widened", lambda value: value["authority"].__setitem__("can_complete_registry", True)),
    ]
    for label, mutate in registry_cases:
        candidate = copy.deepcopy(owner_registry)
        mutate(candidate)
        expect_error(OwnerScopeRegistryError, lambda candidate=candidate: validate_owner_scope_registry(candidate), label)
        adversarial_count += 1

    authorization_cases: list[tuple[str, Callable[[JsonObject], None]]] = [
        ("governance substitution", lambda value: value.__setitem__("governance_state_digest", "sha256:" + "0" * 64)),
        ("owner registry substitution", lambda value: value.__setitem__("owner_registry_digest", "sha256:" + "0" * 64)),
        ("public registry substitution", lambda value: value.__setitem__("public_registry_digest", "sha256:" + "0" * 64)),
        ("replica plan substitution", lambda value: value.__setitem__("replica_plan_digest", "sha256:" + "0" * 64)),
        ("staging outcome laundering", lambda value: value.__setitem__("outcome", "authorize_staging")),
        ("staging status laundering", lambda value: value.__setitem__("status", "staging_authorized")),
        ("source request omission", lambda value: value.__setitem__("requested_source_ids", value["requested_source_ids"][:-1])),
        ("source authorization laundering", lambda value: value.__setitem__("authorized_source_ids", [value["requested_source_ids"][0]])),
        ("content authorization laundering", lambda value: value.__setitem__("authorized_content_digests", ["sha256:" + "1" * 64])),
        ("construction zone laundering", lambda value: value.__setitem__("construction_zone_id", "zone:unproven")),
        ("quarantine omission", lambda value: value.__setitem__("quarantine_requirements", value["quarantine_requirements"][:-1])),
        ("internet egress", lambda value: value["network"].__setitem__("internet_egress", True)),
        ("GitHub access", lambda value: value["network"].__setitem__("github_access", True)),
        ("registry access", lambda value: value["network"].__setitem__("registry_access", True)),
        ("staging blocker omission", lambda value: value.__setitem__("blockers", value["blockers"][:-1])),
        ("download authority", lambda value: value["authority"].__setitem__("can_download_source", True)),
        ("stage authority", lambda value: value["authority"].__setitem__("can_stage_source", True)),
        ("execute authority", lambda value: value["authority"].__setitem__("can_execute", True)),
        ("expired authorization", lambda value: value.__setitem__("expires_at", "2026-07-13T19:10:30Z")),
        ("missing signatures", lambda value: value.__setitem__("signatures", [])),
    ]
    for label, mutate in authorization_cases:
        candidate = copy.deepcopy(authorization)
        mutate(candidate)
        if label != "missing signatures":
            candidate = resign_authorization(candidate, signers)
        expect_error(
            SourceStagingAuthorizationError,
            lambda candidate=candidate: verify_source_staging_authorization(
                candidate,
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

    report_cases: list[tuple[str, Callable[[JsonObject], None]]] = [
        ("source authorization count laundering", lambda value: value.__setitem__("authorized_source_count", 5)),
        ("staged source laundering", lambda value: value.__setitem__("staged_source_count", 5)),
        ("quarantine completion laundering", lambda value: value.__setitem__("quarantine_completed_count", 8)),
        ("owner completeness laundering", lambda value: value.__setitem__("owner_exclusion_registry_complete", True)),
        ("staging authorization laundering", lambda value: value.__setitem__("staging_authorized", True)),
        ("build authorization laundering", lambda value: value.__setitem__("build_authorized", True)),
        ("download activity laundering", lambda value: value["activity"].__setitem__("repository_content_downloaded", True)),
        ("report authority laundering", lambda value: value["authority"].__setitem__("can_build_replica", True)),
    ]
    for label, mutate in report_cases:
        candidate = copy.deepcopy(report)
        mutate(candidate)
        expect_error(
            SourceStagingGateError,
            lambda candidate=candidate: validate_source_staging_gate_report(
                candidate,
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
        "status": report["status"],
        "origin": report["origin"],
        "verified_signer_count": len(report["verified_signer_ids"]),
        "verified_role_count": len(report["verified_roles"]),
        "requested_source_count": report["requested_source_count"],
        "authorized_source_count": report["authorized_source_count"],
        "staged_source_count": report["staged_source_count"],
        "quarantine_requirement_count": report["quarantine_requirement_count"],
        "quarantine_completed_count": report["quarantine_completed_count"],
        "owner_exclusion_registry_complete": report["owner_exclusion_registry_complete"],
        "owner_attestation_present": report["owner_attestation_present"],
        "staging_authorized": report["staging_authorized"],
        "build_authorized": report["build_authorized"],
        "range_connection_authorized": report["range_connection_authorized"],
        "execution_authorized": report["execution_authorized"],
        "adversarial_case_count": adversarial_count,
        "blockers": report["blockers"],
        "activity": copy.deepcopy(STAGING_ACTIVITY),
        "authority": copy.deepcopy(STAGING_AUTHORITY),
    }
    report_path = PROJECT_ROOT / "reports" / "SOURCE_STAGING_GATE_VALIDATION.json"
    report_path.write_text(json.dumps(validation_report, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps(validation_report, indent=2))


if __name__ == "__main__":
    main()
