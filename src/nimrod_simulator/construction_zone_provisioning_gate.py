"""Signed construction-zone provisioning denial and independent-attestation gate."""

from __future__ import annotations

import copy
from collections.abc import Mapping
from datetime import datetime

from nimrod_simulator.authorization import parse_timestamp
from nimrod_simulator.compiler import deterministic_uuid, format_timestamp
from nimrod_simulator.construction_zone_preflight import (
    CONSTRUCTION_ZONE_CONTROLS,
    PREFLIGHT_ACTIVITY,
    validate_construction_zone_declaration,
    validate_construction_zone_preflight_result,
)
from nimrod_simulator.errors import (
    ConstructionZoneAttestationPlanError,
    ConstructionZoneProvisioningAuthorizationError,
    ConstructionZoneProvisioningGateError,
    ControlStateValidationError,
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
from nimrod_simulator.key_governance import SigningConnector, validate_governance_state
from nimrod_simulator.model import JsonObject
from nimrod_simulator.threshold_signing import sign_threshold_document, verify_threshold_signatures


PROVISIONING_AUTHORIZATION_DOMAIN: bytes = b"nimrod.construction-zone-provisioning-authorization.v0.1\x00"
PROVISIONING_OPERATIONS: tuple[str, ...] = (
    "APPLY_NETWORK_ISOLATION",
    "CREATE_DEDICATED_EPHEMERAL_IDENTITY",
    "CREATE_DISPOSABLE_WORKSPACE",
    "CREATE_SEPARATE_OUTPUT_STORE",
    "INSTALL_OUT_OF_BAND_KILL",
)
ATTESTATION_EVIDENCE_REQUIREMENTS: Mapping[str, tuple[str, ...]] = {
    "CLEAN_BASE_IMAGE": ("BASE_IMAGE_DIGEST", "IMAGE_PROVENANCE_SIGNATURE", "IMAGE_SCAN_REPORT"),
    "DEDICATED_EPHEMERAL_IDENTITY": ("IDENTITY_PRINCIPAL", "IDENTITY_EXPIRY", "CREDENTIAL_SCOPE"),
    "DISPOSABLE_WORKSPACE": ("WORKSPACE_IDENTITY", "LIFECYCLE_POLICY", "DESTRUCTION_PROOF_CONTRACT"),
    "NO_EXTERNAL_DNS": ("DNS_POLICY_EXPORT", "DNS_RESOLUTION_DENIAL_OBSERVATION"),
    "NO_GITHUB_ACCESS": ("EGRESS_POLICY_EXPORT", "GITHUB_ROUTE_DENIAL_OBSERVATION"),
    "NO_INTERNET_EGRESS": ("EGRESS_POLICY_EXPORT", "DEFAULT_ROUTE_DENIAL_OBSERVATION"),
    "NO_PUBLIC_INGRESS": ("INGRESS_POLICY_EXPORT", "PUBLIC_ROUTE_ABSENCE_OBSERVATION"),
    "NO_REGISTRY_ACCESS": ("EGRESS_POLICY_EXPORT", "REGISTRY_ROUTE_DENIAL_OBSERVATION"),
    "OUT_OF_BAND_KILL": ("KILL_CONTROL_IDENTITY", "INDEPENDENT_KILL_PATH_OBSERVATION"),
    "SEPARATE_OUTPUT_STORE": ("OUTPUT_STORE_IDENTITY", "WRITE_PRINCIPAL_SEPARATION", "SOURCE_MOUNT_READ_ONLY"),
}
ATTESTATION_PLAN_ACTIVITY: JsonObject = {
    "environment_contact_performed": False,
    "collector_identity_assigned": False,
    "verifier_identity_assigned": False,
    "observation_collected": False,
    "independent_verification_performed": False,
}
ATTESTATION_PLAN_AUTHORITY: JsonObject = {
    "can_collect": False,
    "can_verify": False,
    "can_mark_control_verified": False,
    "can_provision": False,
    "can_stage_source": False,
    "can_build_replica": False,
    "can_connect": False,
    "can_execute": False,
    "can_authorize_action": False,
}
PROVISIONING_AUTHORITY: JsonObject = {
    "can_create_identity": False,
    "can_create_storage": False,
    "can_apply_network_policy": False,
    "can_install_kill_control": False,
    "can_mount_source_ingress": False,
    "can_create_output_store": False,
    "can_provision": False,
    "can_stage_source": False,
    "can_build_replica": False,
    "can_connect": False,
    "can_execute": False,
    "can_target_public_host": False,
    "can_authorize_action": False,
}
PROVISIONING_ACTIVITY: JsonObject = {
    **PREFLIGHT_ACTIVITY,
    "operator_approval_recorded": False,
    "provider_selected": False,
    "provisioning_request_dispatched": False,
    "attestation_collectors_assigned": False,
    "attestation_verifiers_assigned": False,
    "attestation_observations_collected": False,
    "independent_verification_performed": False,
}
EXPECTED_ATTESTATION_PLAN_BLOCKERS: frozenset[str] = frozenset(
    {"INDEPENDENT_ATTESTORS_UNASSIGNED", "LIVE_ISOLATION_EVIDENCE_MISSING"}
)
EXPECTED_PROVISIONING_BLOCKERS: frozenset[str] = frozenset(
    {
        "ATTESTATION_PLAN_INCOMPLETE",
        "CONSTRUCTION_ZONE_CONTROLS_UNVERIFIED",
        "CONSTRUCTION_ZONE_NOT_PROVISIONED",
        "INDEPENDENT_ATTESTORS_UNASSIGNED",
        "OPERATOR_APPROVAL_MISSING",
        "PROVISIONING_AUTHORIZATION_DENIED",
        "PROVISIONING_PROVIDER_UNSELECTED",
        "QUARANTINE_EVIDENCE_MISSING",
        "SOURCE_STAGING_AUTHORIZATION_DENIED",
    }
)


def validate_construction_zone_attestation_plan(
    plan: JsonObject,
    zone: JsonObject,
    preflight_result: JsonObject,
    staging_authorization: JsonObject,
) -> None:
    validate_construction_zone_declaration(zone, staging_authorization)
    if plan.get("plan_version") != "0.1.0":
        raise ConstructionZoneAttestationPlanError("Construction-zone attestation plan must use version 0.1.0.")
    if plan.get("origin") != "simulated" or plan.get("status") != "independent_attestors_unassigned":
        raise ConstructionZoneAttestationPlanError("Attestation plan must preserve its simulated unassigned state.")
    bindings: Mapping[str, object] = {
        "zone_id": zone.get("zone_id"),
        "zone_digest": sha256_digest(zone),
        "preflight_result_id": preflight_result.get("result_id"),
        "preflight_result_digest": sha256_digest(preflight_result),
    }
    for field, expected in bindings.items():
        if plan.get(field) != expected:
            raise ConstructionZoneAttestationPlanError(f"Attestation plan {field} binding mismatch.")
    if plan.get("evidence_origin_requirement") != "live":
        raise ConstructionZoneAttestationPlanError("Isolation attestation requires live evidence.")
    if require_integer(plan.get("minimum_distinct_principals_per_control"), "plan.minimum_distinct_principals_per_control") != 2:
        raise ConstructionZoneAttestationPlanError("Every isolation control requires two distinct principals.")
    if require_integer(plan.get("minimum_distinct_processes_per_control"), "plan.minimum_distinct_processes_per_control") != 2:
        raise ConstructionZoneAttestationPlanError("Every isolation control requires two distinct processes.")
    controls = [
        require_object(value, f"plan.controls[{index}]")
        for index, value in enumerate(require_list(plan.get("controls"), "plan.controls"))
    ]
    control_ids = [require_string(value.get("control_id"), "plan.control.control_id") for value in controls]
    if set(control_ids) != set(CONSTRUCTION_ZONE_CONTROLS) or len(control_ids) != len(CONSTRUCTION_ZONE_CONTROLS):
        raise ConstructionZoneAttestationPlanError("Attestation-plan controls must be exact and unique.")
    for control in controls:
        control_id = require_string(control.get("control_id"), "plan.control.control_id")
        if tuple(require_string_list(control.get("required_evidence_kinds"), "plan.control.required_evidence_kinds")) != ATTESTATION_EVIDENCE_REQUIREMENTS[control_id]:
            raise ConstructionZoneAttestationPlanError(f"Attestation evidence contract for '{control_id}' is incomplete.")
        nullable_identity_fields = (
            "collector_id",
            "collector_principal",
            "collector_process_id",
            "verifier_id",
            "verifier_principal",
            "verifier_process_id",
        )
        if any(control.get(field) is not None for field in nullable_identity_fields):
            raise ConstructionZoneAttestationPlanError("Unassigned attestation plan cannot fabricate observer identities.")
        if control.get("status") != "unassigned" or require_list(control.get("evidence"), "plan.control.evidence"):
            raise ConstructionZoneAttestationPlanError("Unassigned attestation controls cannot claim evidence.")
    if set(require_string_list(plan.get("blockers"), "plan.blockers")) != EXPECTED_ATTESTATION_PLAN_BLOCKERS:
        raise ConstructionZoneAttestationPlanError("Attestation-plan blockers are incomplete or laundered.")
    if require_object(plan.get("activity"), "plan.activity") != ATTESTATION_PLAN_ACTIVITY:
        raise ConstructionZoneAttestationPlanError("Attestation plan claims prohibited activity.")
    if require_object(plan.get("authority"), "plan.authority") != ATTESTATION_PLAN_AUTHORITY:
        raise ConstructionZoneAttestationPlanError("Attestation plan exposes prohibited authority.")


def sign_construction_zone_provisioning_authorization(
    unsigned_authorization: JsonObject,
    connectors: list[SigningConnector],
) -> JsonObject:
    return sign_threshold_document(
        unsigned_authorization,
        connectors,
        PROVISIONING_AUTHORIZATION_DOMAIN,
        "construction-zone provisioning authorization",
        ConstructionZoneProvisioningAuthorizationError,
    )


def _parse_timestamp(value: object, field: str) -> datetime:
    try:
        return parse_timestamp(value, field)
    except ControlStateValidationError as error:
        raise ConstructionZoneProvisioningAuthorizationError(
            f"Construction-zone provisioning timestamp '{field}' is invalid: {error}."
        ) from error


def verify_construction_zone_provisioning_authorization(
    authorization: JsonObject,
    governance_state: JsonObject,
    attestation_plan: JsonObject,
    zone: JsonObject,
    preflight_result: JsonObject,
    quarantine_receipt: JsonObject,
    staging_authorization: JsonObject,
    owner_registry: JsonObject,
    public_registry: JsonObject,
    replica_plan: JsonObject,
    evaluated_at: datetime,
    maximum_lifetime_seconds: int,
) -> JsonObject:
    validate_governance_state(governance_state)
    preflight_assessed_at = _parse_timestamp(preflight_result.get("assessed_at"), "preflight_result.assessed_at")
    validate_construction_zone_preflight_result(
        preflight_result,
        zone,
        quarantine_receipt,
        staging_authorization,
        governance_state,
        owner_registry,
        public_registry,
        replica_plan,
        preflight_assessed_at,
        maximum_lifetime_seconds,
    )
    validate_construction_zone_attestation_plan(attestation_plan, zone, preflight_result, staging_authorization)
    if evaluated_at.utcoffset() is None or maximum_lifetime_seconds <= 0:
        raise ConstructionZoneProvisioningAuthorizationError("Provisioning evaluation time and lifetime must be valid.")
    if authorization.get("authorization_version") != "0.1.0":
        raise ConstructionZoneProvisioningAuthorizationError("Provisioning authorization must use version 0.1.0.")
    bindings: Mapping[str, object] = {
        "governance_state_digest": sha256_digest(governance_state),
        "zone_id": zone.get("zone_id"),
        "zone_digest": sha256_digest(zone),
        "preflight_result_id": preflight_result.get("result_id"),
        "preflight_result_digest": sha256_digest(preflight_result),
        "attestation_plan_id": attestation_plan.get("plan_id"),
        "attestation_plan_digest": sha256_digest(attestation_plan),
    }
    for field, expected in bindings.items():
        if authorization.get(field) != expected:
            raise ConstructionZoneProvisioningAuthorizationError(f"Provisioning authorization {field} binding mismatch.")
    issued_at = _parse_timestamp(authorization.get("issued_at"), "authorization.issued_at")
    not_before = _parse_timestamp(authorization.get("not_before"), "authorization.not_before")
    expires_at = _parse_timestamp(authorization.get("expires_at"), "authorization.expires_at")
    if issued_at > not_before or not_before >= expires_at:
        raise ConstructionZoneProvisioningAuthorizationError("Provisioning validity window is inconsistent.")
    if int((expires_at - issued_at).total_seconds()) > maximum_lifetime_seconds:
        raise ConstructionZoneProvisioningAuthorizationError("Provisioning authorization lifetime exceeds the maximum.")
    if evaluated_at < not_before or evaluated_at > expires_at:
        raise ConstructionZoneProvisioningAuthorizationError("Provisioning authorization is outside its active window.")
    if authorization.get("origin") != "simulated":
        raise ConstructionZoneProvisioningAuthorizationError("Canonical provisioning authorization must remain simulated.")
    if authorization.get("status") != "signed_denial_environment_and_attestors_unassigned":
        raise ConstructionZoneProvisioningAuthorizationError("Provisioning authorization status must preserve the denial.")
    if authorization.get("outcome") != "deny_provisioning":
        raise ConstructionZoneProvisioningAuthorizationError("Provisioning must remain explicitly denied.")
    requested_operations = require_string_list(
        authorization.get("requested_operations"), "authorization.requested_operations"
    )
    if set(requested_operations) != set(PROVISIONING_OPERATIONS) or len(requested_operations) != len(PROVISIONING_OPERATIONS):
        raise ConstructionZoneProvisioningAuthorizationError("Provisioning request operations must be exact and unique.")
    if require_list(authorization.get("authorized_operations"), "authorization.authorized_operations"):
        raise ConstructionZoneProvisioningAuthorizationError("Denied provisioning cannot authorize operations.")
    if authorization.get("operator_approval_reference") is not None:
        raise ConstructionZoneProvisioningAuthorizationError("Canonical fixture cannot fabricate operator approval.")
    if authorization.get("provider_id") is not None:
        raise ConstructionZoneProvisioningAuthorizationError("Canonical fixture cannot select a provisioning provider.")
    if require_list(authorization.get("credential_references"), "authorization.credential_references"):
        raise ConstructionZoneProvisioningAuthorizationError("Denied provisioning cannot carry credential references.")
    if set(require_string_list(authorization.get("blockers"), "authorization.blockers")) != EXPECTED_PROVISIONING_BLOCKERS:
        raise ConstructionZoneProvisioningAuthorizationError("Provisioning blockers are incomplete or laundered.")
    if require_object(authorization.get("authority"), "authorization.authority") != PROVISIONING_AUTHORITY:
        raise ConstructionZoneProvisioningAuthorizationError("Provisioning authorization exposes prohibited authority.")
    verified_signers, verified_roles = verify_threshold_signatures(
        authorization,
        governance_state,
        issued_at,
        PROVISIONING_AUTHORIZATION_DOMAIN,
        "construction-zone provisioning authorization",
        ConstructionZoneProvisioningAuthorizationError,
    )
    return {
        "authorization_id": require_string(authorization.get("authorization_id"), "authorization.authorization_id"),
        "authorization_digest": sha256_digest(authorization),
        "verified_signer_ids": verified_signers,
        "verified_roles": verified_roles,
    }


def build_construction_zone_provisioning_gate_result(
    authorization: JsonObject,
    governance_state: JsonObject,
    attestation_plan: JsonObject,
    zone: JsonObject,
    preflight_result: JsonObject,
    quarantine_receipt: JsonObject,
    staging_authorization: JsonObject,
    owner_registry: JsonObject,
    public_registry: JsonObject,
    replica_plan: JsonObject,
    assessed_at: datetime,
    maximum_lifetime_seconds: int,
) -> JsonObject:
    verification = verify_construction_zone_provisioning_authorization(
        authorization,
        governance_state,
        attestation_plan,
        zone,
        preflight_result,
        quarantine_receipt,
        staging_authorization,
        owner_registry,
        public_registry,
        replica_plan,
        assessed_at,
        maximum_lifetime_seconds,
    )
    return {
        "result_version": "0.1.0",
        "result_id": deterministic_uuid(str(zone["zone_id"]), str(authorization["authorization_id"]), "provisioning-gate"),
        "origin": "simulated",
        "status": "CONSTRUCTION_ZONE_PROVISIONING_SIGNED_DENIAL_INDEPENDENT_ATTESTATION_BLOCKED",
        "assessed_at": format_timestamp(assessed_at),
        "zone_id": zone["zone_id"],
        "zone_digest": sha256_digest(zone),
        "preflight_result_id": preflight_result["result_id"],
        "preflight_result_digest": sha256_digest(preflight_result),
        "attestation_plan_id": attestation_plan["plan_id"],
        "attestation_plan_digest": sha256_digest(attestation_plan),
        "authorization_id": verification["authorization_id"],
        "authorization_digest": verification["authorization_digest"],
        "verified_signer_ids": verification["verified_signer_ids"],
        "verified_roles": verification["verified_roles"],
        "required_control_count": len(CONSTRUCTION_ZONE_CONTROLS),
        "assigned_collector_count": 0,
        "assigned_verifier_count": 0,
        "verified_control_count": 0,
        "attestation_plan_complete": False,
        "operator_approval_present": False,
        "provider_selected": False,
        "provisioning_authorized": False,
        "provisioning_performed": False,
        "staging_authorized": False,
        "build_authorized": False,
        "range_connection_authorized": False,
        "execution_authorized": False,
        "blockers": sorted(EXPECTED_PROVISIONING_BLOCKERS),
        "activity": copy.deepcopy(PROVISIONING_ACTIVITY),
        "authority": copy.deepcopy(PROVISIONING_AUTHORITY),
    }


def validate_construction_zone_provisioning_gate_result(
    result: JsonObject,
    authorization: JsonObject,
    governance_state: JsonObject,
    attestation_plan: JsonObject,
    zone: JsonObject,
    preflight_result: JsonObject,
    quarantine_receipt: JsonObject,
    staging_authorization: JsonObject,
    owner_registry: JsonObject,
    public_registry: JsonObject,
    replica_plan: JsonObject,
    assessed_at: datetime,
    maximum_lifetime_seconds: int,
) -> None:
    expected = build_construction_zone_provisioning_gate_result(
        authorization,
        governance_state,
        attestation_plan,
        zone,
        preflight_result,
        quarantine_receipt,
        staging_authorization,
        owner_registry,
        public_registry,
        replica_plan,
        assessed_at,
        maximum_lifetime_seconds,
    )
    if result != expected:
        raise ConstructionZoneProvisioningGateError(
            "Construction-zone provisioning gate differs from the deterministic signed denial."
        )
