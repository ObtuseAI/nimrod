"""Declaration-only construction-zone and missing quarantine-evidence preflight."""

from __future__ import annotations

import copy
from datetime import datetime

from nimrod_simulator.compiler import deterministic_uuid, format_timestamp
from nimrod_simulator.errors import (
    ConstructionZoneDeclarationError,
    ConstructionZonePreflightError,
    QuarantineEvidenceReceiptError,
)
from nimrod_simulator.jsonio import (
    require_boolean,
    require_integer,
    require_list,
    require_object,
    require_string,
    require_string_list,
    sha256_digest,
)
from nimrod_simulator.model import JsonObject
from nimrod_simulator.source_staging_gate import (
    EXPECTED_STAGING_BLOCKERS,
    QUARANTINE_REQUIREMENTS,
    STAGING_ACTIVITY,
    STAGING_AUTHORITY,
    verify_source_staging_authorization,
)


CONSTRUCTION_ZONE_CONTROLS: tuple[str, ...] = (
    "CLEAN_BASE_IMAGE",
    "DEDICATED_EPHEMERAL_IDENTITY",
    "DISPOSABLE_WORKSPACE",
    "NO_EXTERNAL_DNS",
    "NO_GITHUB_ACCESS",
    "NO_INTERNET_EGRESS",
    "NO_PUBLIC_INGRESS",
    "NO_REGISTRY_ACCESS",
    "OUT_OF_BAND_KILL",
    "SEPARATE_OUTPUT_STORE",
)
ZONE_AUTHORITY: JsonObject = copy.deepcopy(STAGING_AUTHORITY)
QUARANTINE_AUTHORITY: JsonObject = copy.deepcopy(STAGING_AUTHORITY)
PREFLIGHT_AUTHORITY: JsonObject = copy.deepcopy(STAGING_AUTHORITY)
ZONE_ACTIVITY: JsonObject = {
    "construction_zone_provisioned": False,
    "identity_created": False,
    "storage_created": False,
    "network_policy_applied": False,
    "kill_control_installed": False,
    "source_ingress_mounted": False,
    "output_store_created": False,
}
QUARANTINE_ACTIVITY: JsonObject = {
    "source_archive_present": False,
    "source_extracted": False,
    "scanner_executed": False,
    "sbom_generated": False,
    "secret_material_accessed": False,
    "network_access_performed": False,
}
PREFLIGHT_ACTIVITY: JsonObject = {
    **STAGING_ACTIVITY,
    **ZONE_ACTIVITY,
    "scanner_executed": False,
    "sbom_generated": False,
}
EXPECTED_PREFLIGHT_BLOCKERS: frozenset[str] = frozenset(
    {
        *EXPECTED_STAGING_BLOCKERS,
        "CONSTRUCTION_ZONE_CONTROLS_UNVERIFIED",
        "CONSTRUCTION_ZONE_NOT_PROVISIONED",
        "QUARANTINE_EVIDENCE_MISSING",
    }
)


def validate_construction_zone_declaration(
    declaration: JsonObject,
    staging_authorization: JsonObject,
) -> None:
    if declaration.get("zone_version") != "0.1.0":
        raise ConstructionZoneDeclarationError("Construction-zone declaration must use version 0.1.0.")
    if declaration.get("origin") != "simulated" or declaration.get("status") != "declared_not_provisioned":
        raise ConstructionZoneDeclarationError("Construction zone must remain a simulated declaration.")
    if declaration.get("staging_authorization_id") != staging_authorization.get("authorization_id"):
        raise ConstructionZoneDeclarationError("Construction-zone staging authorization ID mismatch.")
    if declaration.get("staging_authorization_digest") != sha256_digest(staging_authorization):
        raise ConstructionZoneDeclarationError("Construction-zone staging authorization digest mismatch.")
    if declaration.get("environment_class") != "isolated_construction_zone_candidate":
        raise ConstructionZoneDeclarationError("Construction-zone environment class is unsupported.")
    if require_integer(declaration.get("generation"), "zone.generation") != 1:
        raise ConstructionZoneDeclarationError("Construction-zone generation must begin at one.")
    controls = [
        require_object(value, f"zone.controls[{index}]")
        for index, value in enumerate(require_list(declaration.get("controls"), "zone.controls"))
    ]
    control_ids = [require_string(value.get("control_id"), "zone.control.control_id") for value in controls]
    if set(control_ids) != set(CONSTRUCTION_ZONE_CONTROLS) or len(control_ids) != len(CONSTRUCTION_ZONE_CONTROLS):
        raise ConstructionZoneDeclarationError("Construction-zone controls must be exact and unique.")
    for control in controls:
        if control.get("status") != "unproven" or require_list(control.get("evidence"), "zone.control.evidence"):
            raise ConstructionZoneDeclarationError("Construction-zone controls cannot claim unobserved evidence.")
    network = require_object(declaration.get("network"), "zone.network")
    if network != {
        "mode": "offline_default_deny_declaration",
        "internet_egress": False,
        "public_ingress": False,
        "github_access": False,
        "registry_access": False,
        "external_dns_resolution": False,
        "policy_applied": False,
    }:
        raise ConstructionZoneDeclarationError("Construction-zone network declaration is widened or claims enforcement.")
    storage = require_object(declaration.get("storage"), "zone.storage")
    if storage != {
        "workspace_kind": "disposable_ephemeral",
        "source_ingress_read_only": True,
        "separate_output_store_required": True,
        "workspace_created": False,
        "source_ingress_mounted": False,
        "output_store_created": False,
        "baseline_snapshot_digest": None,
    }:
        raise ConstructionZoneDeclarationError("Construction-zone storage declaration is unsafe or claims provisioning.")
    if require_object(declaration.get("activity"), "zone.activity") != ZONE_ACTIVITY:
        raise ConstructionZoneDeclarationError("Construction-zone declaration claims prohibited activity.")
    if require_object(declaration.get("authority"), "zone.authority") != ZONE_AUTHORITY:
        raise ConstructionZoneDeclarationError("Construction-zone declaration exposes prohibited authority.")


def validate_quarantine_evidence_receipt(
    receipt: JsonObject,
    declaration: JsonObject,
    staging_authorization: JsonObject,
) -> None:
    validate_construction_zone_declaration(declaration, staging_authorization)
    if receipt.get("receipt_version") != "0.1.0":
        raise QuarantineEvidenceReceiptError("Quarantine evidence receipt must use version 0.1.0.")
    if receipt.get("origin") != "simulated" or receipt.get("status") != "evidence_missing":
        raise QuarantineEvidenceReceiptError("Quarantine evidence receipt must preserve the missing-evidence state.")
    bindings = {
        "zone_id": declaration.get("zone_id"),
        "zone_digest": sha256_digest(declaration),
        "staging_authorization_id": staging_authorization.get("authorization_id"),
        "staging_authorization_digest": sha256_digest(staging_authorization),
    }
    for field, expected in bindings.items():
        if receipt.get(field) != expected:
            raise QuarantineEvidenceReceiptError(f"Quarantine receipt {field} binding mismatch.")
    requested_source_ids = require_string_list(
        staging_authorization.get("requested_source_ids"), "authorization.requested_source_ids"
    )
    receipt_source_ids = require_string_list(receipt.get("requested_source_ids"), "receipt.requested_source_ids")
    if set(receipt_source_ids) != set(requested_source_ids) or len(receipt_source_ids) != len(requested_source_ids):
        raise QuarantineEvidenceReceiptError("Quarantine receipt source identities are incomplete or duplicated.")
    if require_integer(receipt.get("source_archive_count"), "receipt.source_archive_count") != 0:
        raise QuarantineEvidenceReceiptError("Quarantine receipt cannot claim unstaged source archives.")
    if require_list(receipt.get("source_archive_digests"), "receipt.source_archive_digests"):
        raise QuarantineEvidenceReceiptError("Quarantine receipt cannot fabricate archive digests.")
    results = [
        require_object(value, f"receipt.results[{index}]")
        for index, value in enumerate(require_list(receipt.get("results"), "receipt.results"))
    ]
    requirement_ids = [require_string(value.get("requirement_id"), "receipt.result.requirement_id") for value in results]
    if set(requirement_ids) != set(QUARANTINE_REQUIREMENTS) or len(requirement_ids) != len(QUARANTINE_REQUIREMENTS):
        raise QuarantineEvidenceReceiptError("Quarantine receipt requirements must be exact and unique.")
    for result in results:
        if (
            result.get("status") != "missing"
            or require_boolean(result.get("performed"), "receipt.result.performed") is not False
            or result.get("evidence_digest") is not None
            or require_list(result.get("evidence"), "receipt.result.evidence")
        ):
            raise QuarantineEvidenceReceiptError("Quarantine result fabricates performed or retained evidence.")
    if require_object(receipt.get("activity"), "receipt.activity") != QUARANTINE_ACTIVITY:
        raise QuarantineEvidenceReceiptError("Quarantine receipt claims prohibited activity.")
    if require_object(receipt.get("authority"), "receipt.authority") != QUARANTINE_AUTHORITY:
        raise QuarantineEvidenceReceiptError("Quarantine receipt exposes prohibited authority.")


def build_construction_zone_preflight_result(
    declaration: JsonObject,
    receipt: JsonObject,
    staging_authorization: JsonObject,
    governance_state: JsonObject,
    owner_registry: JsonObject,
    public_registry: JsonObject,
    replica_plan: JsonObject,
    assessed_at: datetime,
    maximum_lifetime_seconds: int,
) -> JsonObject:
    if assessed_at.utcoffset() is None:
        raise ConstructionZonePreflightError("Construction-zone assessment time must be timezone-aware.")
    verify_source_staging_authorization(
        staging_authorization,
        governance_state,
        owner_registry,
        public_registry,
        replica_plan,
        assessed_at,
        maximum_lifetime_seconds,
    )
    validate_construction_zone_declaration(declaration, staging_authorization)
    validate_quarantine_evidence_receipt(receipt, declaration, staging_authorization)
    return {
        "result_version": "0.1.0",
        "result_id": deterministic_uuid(str(declaration["zone_id"]), str(receipt["receipt_id"]), "preflight"),
        "origin": "simulated",
        "status": "CONSTRUCTION_ZONE_DECLARED_QUARANTINE_EVIDENCE_MISSING_STAGING_BLOCKED",
        "assessed_at": format_timestamp(assessed_at),
        "zone_id": declaration["zone_id"],
        "zone_digest": sha256_digest(declaration),
        "receipt_id": receipt["receipt_id"],
        "receipt_digest": sha256_digest(receipt),
        "staging_authorization_id": staging_authorization["authorization_id"],
        "staging_authorization_digest": sha256_digest(staging_authorization),
        "zone_control_count": len(CONSTRUCTION_ZONE_CONTROLS),
        "verified_zone_control_count": 0,
        "quarantine_requirement_count": len(QUARANTINE_REQUIREMENTS),
        "verified_quarantine_requirement_count": 0,
        "source_archive_count": 0,
        "construction_zone_provisioned": False,
        "quarantine_evidence_complete": False,
        "staging_authorized": False,
        "build_authorized": False,
        "range_connection_authorized": False,
        "execution_authorized": False,
        "blockers": sorted(EXPECTED_PREFLIGHT_BLOCKERS),
        "activity": copy.deepcopy(PREFLIGHT_ACTIVITY),
        "authority": copy.deepcopy(PREFLIGHT_AUTHORITY),
    }


def validate_construction_zone_preflight_result(
    result: JsonObject,
    declaration: JsonObject,
    receipt: JsonObject,
    staging_authorization: JsonObject,
    governance_state: JsonObject,
    owner_registry: JsonObject,
    public_registry: JsonObject,
    replica_plan: JsonObject,
    assessed_at: datetime,
    maximum_lifetime_seconds: int,
) -> None:
    expected = build_construction_zone_preflight_result(
        declaration,
        receipt,
        staging_authorization,
        governance_state,
        owner_registry,
        public_registry,
        replica_plan,
        assessed_at,
        maximum_lifetime_seconds,
    )
    if result != expected:
        raise ConstructionZonePreflightError("Construction-zone preflight differs from the deterministic blocked result.")
