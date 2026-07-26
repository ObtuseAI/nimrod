"""Governed non-provisioning connector, scope, and pre-execution evidence gates."""

from __future__ import annotations

import copy
from datetime import datetime

from nimrod_simulator.authorization import parse_timestamp
from nimrod_simulator.authorization_crypto import verify_authorization
from nimrod_simulator.compiler import deterministic_uuid, format_timestamp
from nimrod_simulator.errors import (
    ControlStateValidationError,
    RangeConnectorCapabilityError,
    RangePreexecutionEvidenceError,
    RangeScopeCompilationError,
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
from nimrod_simulator.range_topology import validate_range_topology
from nimrod_simulator.threshold_signing import sign_threshold_document, verify_threshold_signatures


RANGE_CONNECTOR_CAPABILITY_DOMAIN = b"nimrod.range-connector-capability-manifest.v0.1\x00"
CONNECTOR_OPERATIONS = {"preflight", "compile", "verify"}
CONNECTOR_CAPABILITIES = {"range.test.simulate"}
CONNECTOR_BLOCKERS = {
    "CONNECTOR_RUNTIME_MISSING",
    "LICENSE_REVIEW_NOT_APPROVED",
    "REAL_RANGE_ATTESTATION_MISSING",
}
SCOPE_BLOCKERS = {
    "CONNECTOR_RUNTIME_MISSING",
    "REAL_RANGE_ENVIRONMENT_UNPROVEN",
    "RANGE_CONNECTION_AUTHORIZATION_MISSING",
    "EXECUTION_AUTHORIZATION_MISSING",
}
REQUIRED_ENVIRONMENT_ATTESTATIONS = {
    "CLEANUP_CONTRACT",
    "DEDICATED_CREDENTIALS",
    "DEFAULT_DENY_EGRESS",
    "DISPOSABLE_TARGET",
    "INDEPENDENT_VERIFIER",
    "OUT_OF_BAND_KILL",
    "RESTORABLE_SNAPSHOT",
    "TELEMETRY_SEPARATION",
    "TRUSTED_TIME",
}
REAL_RANGE_ORIGINS = {"range", "sacrificial_replica"}
CONNECTOR_AUTHORITY = {
    "can_install": False,
    "can_provision": False,
    "can_connect": False,
    "can_execute": False,
    "can_discover_targets": False,
}
SCOPE_AUTHORITY = {
    "can_install": False,
    "can_provision": False,
    "can_connect": False,
    "can_execute": False,
}
PACKET_AUTHORITY = {
    "can_install": False,
    "can_provision": False,
    "can_connect": False,
    "can_execute": False,
    "can_mark_evidence_complete": False,
}


def _timestamp(value: object, field: str, error_type: type[Exception]) -> datetime:
    try:
        return parse_timestamp(value, field)
    except ControlStateValidationError as error:
        raise error_type(f"Timestamp '{field}' is invalid: {error}.") from error


def sign_range_connector_capability_manifest(
    unsigned_manifest: JsonObject,
    connectors: list[SigningConnector],
) -> JsonObject:
    return sign_threshold_document(
        unsigned_manifest,
        connectors,
        RANGE_CONNECTOR_CAPABILITY_DOMAIN,
        "range connector capability manifest",
        RangeConnectorCapabilityError,
    )


def verify_range_connector_capability_manifest(
    manifest: JsonObject,
    source_manifest: JsonObject,
    governance_state: JsonObject,
    evaluated_at: datetime,
    maximum_lifetime_seconds: int,
) -> JsonObject:
    if evaluated_at.utcoffset() is None:
        raise RangeConnectorCapabilityError("Connector capability evaluation time must be timezone-aware.")
    if maximum_lifetime_seconds <= 0:
        raise RangeConnectorCapabilityError("Connector capability maximum lifetime must be positive.")
    validate_governance_state(governance_state)
    if manifest.get("manifest_version") != "0.1.0" or manifest.get("origin") != "simulated":
        raise RangeConnectorCapabilityError("Connector capability manifest must be version 0.1.0 and simulated.")
    if source_manifest.get("manifest_version") != "0.1.0":
        raise RangeConnectorCapabilityError("Source connector manifest must be version 0.1.0.")
    connector_id = require_string(manifest.get("connector_id"), "manifest.connector_id")
    if connector_id != source_manifest.get("connector_id"):
        raise RangeConnectorCapabilityError("Connector capability identity differs from its source manifest.")
    if manifest.get("connector_version") != source_manifest.get("connector_version"):
        raise RangeConnectorCapabilityError("Connector capability version differs from its source manifest.")
    if manifest.get("source_manifest_digest") != sha256_digest(source_manifest):
        raise RangeConnectorCapabilityError("Connector capability source-manifest digest mismatch.")
    if manifest.get("governance_state_digest") != sha256_digest(governance_state):
        raise RangeConnectorCapabilityError("Connector capability governance-state digest mismatch.")
    if set(require_string_list(manifest.get("capability_allowlist"), "manifest.capability_allowlist")) != CONNECTOR_CAPABILITIES:
        raise RangeConnectorCapabilityError("Connector capability allowlist must remain range.test.simulate only.")
    source_permissions = set(require_string_list(source_manifest.get("permissions"), "source_manifest.permissions"))
    if not CONNECTOR_CAPABILITIES.issubset(source_permissions):
        raise RangeConnectorCapabilityError("Source connector does not declare the bounded simulated capability.")
    operations = set(require_string_list(manifest.get("operation_allowlist"), "manifest.operation_allowlist"))
    if operations != CONNECTOR_OPERATIONS:
        raise RangeConnectorCapabilityError("Connector operations must remain preflight, compile, and verify only.")
    source_operations = set(
        require_string_list(source_manifest.get("lifecycle_operations"), "source_manifest.lifecycle_operations")
    )
    if not operations.issubset(source_operations):
        raise RangeConnectorCapabilityError("Connector capability operations exceed the source manifest.")
    if require_string_list(manifest.get("supported_environment_classes"), "manifest.supported_environment_classes") != ["isolated_range"]:
        raise RangeConnectorCapabilityError("Connector capability supports only the isolated_range environment.")
    if require_list(manifest.get("network_destinations"), "manifest.network_destinations"):
        raise RangeConnectorCapabilityError("Non-provisioning connector capability cannot declare network destinations.")
    if require_list(manifest.get("secret_references"), "manifest.secret_references"):
        raise RangeConnectorCapabilityError("Non-provisioning connector capability cannot request secrets.")
    for field in ("installation_required", "source_tool_contact_required", "target_discovery_performed"):
        if require_boolean(manifest.get(field), f"manifest.{field}"):
            raise RangeConnectorCapabilityError(f"Connector capability must keep '{field}' false.")
    if require_boolean(manifest.get("artifact_digest_required"), "manifest.artifact_digest_required") is not True:
        raise RangeConnectorCapabilityError("Connector capability must require content-addressed artifacts.")
    license_review = require_object(source_manifest.get("license_review"), "source_manifest.license_review")
    if license_review.get("status") == "approved":
        raise RangeConnectorCapabilityError(
            "The current non-provisioning manifest expects the source license review to remain unapproved."
        )
    if manifest.get("status") != "non_provisioning_contract_only_blocked":
        raise RangeConnectorCapabilityError("Connector capability status must remain contract-only and blocked.")
    blockers = set(require_string_list(manifest.get("blockers"), "manifest.blockers"))
    if blockers != CONNECTOR_BLOCKERS:
        raise RangeConnectorCapabilityError("Connector capability blockers do not match the current evidence boundary.")
    if require_object(manifest.get("authority"), "manifest.authority") != CONNECTOR_AUTHORITY:
        raise RangeConnectorCapabilityError("Connector capability cannot install, provision, connect, execute, or discover.")
    issued_at = _timestamp(manifest.get("issued_at"), "manifest.issued_at", RangeConnectorCapabilityError)
    not_before = _timestamp(manifest.get("not_before"), "manifest.not_before", RangeConnectorCapabilityError)
    expires_at = _timestamp(manifest.get("expires_at"), "manifest.expires_at", RangeConnectorCapabilityError)
    if issued_at > not_before or not_before >= expires_at:
        raise RangeConnectorCapabilityError("Connector capability requires issued_at <= not_before < expires_at.")
    lifetime_seconds = int((expires_at - issued_at).total_seconds())
    if lifetime_seconds > maximum_lifetime_seconds:
        raise RangeConnectorCapabilityError(
            f"Connector capability lifetime {lifetime_seconds}s exceeds {maximum_lifetime_seconds}s."
        )
    if evaluated_at < not_before or evaluated_at >= expires_at:
        raise RangeConnectorCapabilityError("Connector capability manifest is inactive or expired.")
    verified_signers, verified_roles = verify_threshold_signatures(
        manifest,
        governance_state,
        issued_at,
        RANGE_CONNECTOR_CAPABILITY_DOMAIN,
        "range connector capability manifest",
        RangeConnectorCapabilityError,
    )
    return {
        "verification_version": "0.1.0-internal",
        "status": "verified_non_provisioning_contract_only",
        "manifest_digest": sha256_digest(manifest),
        "connector_id": connector_id,
        "capability_allowlist": sorted(CONNECTOR_CAPABILITIES),
        "operation_allowlist": sorted(CONNECTOR_OPERATIONS),
        "verified_signer_ids": verified_signers,
        "verified_roles": verified_roles,
        "authority": copy.deepcopy(CONNECTOR_AUTHORITY),
    }


def _require_active_lease_window(lease: JsonObject, evaluated_at: datetime) -> None:
    issued_at = _timestamp(lease.get("issued_at"), "lease.issued_at", RangeScopeCompilationError)
    not_before = _timestamp(lease.get("not_before"), "lease.not_before", RangeScopeCompilationError)
    expires_at = _timestamp(lease.get("expires_at"), "lease.expires_at", RangeScopeCompilationError)
    if issued_at > not_before or not_before >= expires_at:
        raise RangeScopeCompilationError("Authorization lease requires issued_at <= not_before < expires_at.")
    if evaluated_at < not_before or evaluated_at >= expires_at:
        raise RangeScopeCompilationError("Authorization lease is inactive or expired for scope compilation.")


def _single_role_node(topology: JsonObject, role: str) -> JsonObject:
    nodes = [
        require_object(value, f"topology.nodes[{index}]")
        for index, value in enumerate(require_list(topology.get("nodes"), "topology.nodes"))
    ]
    matches = [node for node in nodes if node.get("role") == role]
    if len(matches) != 1:
        raise RangeScopeCompilationError(f"Topology requires exactly one '{role}' node.")
    return matches[0]


def compile_lease_to_topology_scope(
    lease: JsonObject,
    proof_bundle: JsonObject,
    trust_policy: JsonObject,
    topology: JsonObject,
    connector_manifest: JsonObject,
    source_manifest: JsonObject,
    governance_state: JsonObject,
    evaluated_at: datetime,
    maximum_connector_lifetime_seconds: int,
) -> JsonObject:
    if evaluated_at.utcoffset() is None:
        raise RangeScopeCompilationError("Scope compilation time must be timezone-aware.")
    _require_active_lease_window(lease, evaluated_at)
    authorization = verify_authorization(lease, proof_bundle, trust_policy, evaluated_at)
    connector = verify_range_connector_capability_manifest(
        connector_manifest,
        source_manifest,
        governance_state,
        evaluated_at,
        maximum_connector_lifetime_seconds,
    )
    topology_verdict = validate_range_topology(topology)
    if topology_verdict.get("environment_verified") is not False:
        raise RangeScopeCompilationError("Declaration-only topology cannot claim real environment verification.")
    targets = [
        require_object(value, f"lease.target_graph[{index}]")
        for index, value in enumerate(require_list(lease.get("target_graph"), "lease.target_graph"))
    ]
    if len(targets) != 1:
        raise RangeScopeCompilationError("Current disposable topology can bind exactly one lease target.")
    target = targets[0]
    target_id = require_string(target.get("stable_id"), "lease.target_graph[0].stable_id")
    if target.get("environment_class") != "range":
        raise RangeScopeCompilationError("Lease target must use the range environment class.")
    resource_type = require_string(target.get("resource_type"), "lease.target_graph[0].resource_type")
    if resource_type != "windows_device":
        raise RangeScopeCompilationError("Current topology compiler supports the bounded windows_device target only.")
    binding = require_object(target.get("binding"), "lease.target_graph[0].binding")
    capabilities = set(require_string_list(lease.get("allowed_capabilities"), "lease.allowed_capabilities"))
    connector_capabilities = set(
        require_string_list(connector_manifest.get("capability_allowlist"), "manifest.capability_allowlist")
    )
    capability_intersection = sorted(capabilities & connector_capabilities)
    if set(capability_intersection) != CONNECTOR_CAPABILITIES:
        raise RangeScopeCompilationError("Lease and connector capability intersection is not exactly range.test.simulate.")
    target_node = _single_role_node(topology, "sacrificial_target")
    kill_node = _single_role_node(topology, "kill_switch")
    kill_switch = require_object(lease.get("kill_switch"), "lease.kill_switch")
    if require_boolean(kill_switch.get("out_of_band"), "lease.kill_switch.out_of_band") is not True:
        raise RangeScopeCompilationError("Lease kill switch must remain out of band.")
    lease_id = require_string(lease.get("lease_id"), "lease.lease_id")
    scope_id = deterministic_uuid(
        lease_id,
        require_string(topology.get("topology_id"), "topology.topology_id"),
        require_string(connector_manifest.get("manifest_id"), "manifest.manifest_id"),
    )
    return {
        "scope_version": "0.1.0",
        "scope_id": scope_id,
        "origin": "simulated",
        "status": "compiled_contract_only_environment_unproven",
        "compiled_at": format_timestamp(evaluated_at),
        "lease_id": lease_id,
        "lease_digest": authorization["lease_digest"],
        "authorization_proof_bundle_digest": sha256_digest(proof_bundle),
        "trust_policy_digest": authorization["trust_policy_digest"],
        "cryptographic_authorization_verified": True,
        "verified_authorization_signer_ids": authorization["verified_signer_ids"],
        "verified_authorization_roles": authorization["verified_roles"],
        "topology_id": topology["topology_id"],
        "topology_digest": topology_verdict["topology_digest"],
        "topology_generation": topology["generation"],
        "topology_environment_verified": False,
        "connector_id": connector["connector_id"],
        "connector_manifest_digest": connector["manifest_digest"],
        "capability_intersection": capability_intersection,
        "target_bindings": [
            {
                "lease_target_id": target_id,
                "resource_type": resource_type,
                "environment_class": "range",
                "binding_digest": sha256_digest(binding),
                "topology_node_id": target_node["node_id"],
                "topology_zone_id": target_node["zone_id"],
                "effect_ceiling": lease["effect_ceiling"],
            }
        ],
        "kill_switch_binding": {
            "lease_kill_switch_id": kill_switch["id"],
            "controller": kill_switch["controller"],
            "maximum_revocation_seconds": kill_switch["maximum_revocation_seconds"],
            "out_of_band": True,
            "topology_node_id": kill_node["node_id"],
        },
        "budgets": copy.deepcopy(require_object(lease.get("budgets"), "lease.budgets")),
        "blockers": sorted(SCOPE_BLOCKERS),
        "provisioning_performed": False,
        "installation_performed": False,
        "network_contact_performed": False,
        "range_connection_authorized": False,
        "execution_authorized": False,
        "authority": copy.deepcopy(SCOPE_AUTHORITY),
    }


def _validate_attestations(
    attestations: list[object],
    assembled_at: datetime,
    maximum_age_seconds: int,
) -> tuple[list[JsonObject], list[str], int, int]:
    if maximum_age_seconds <= 0:
        raise RangePreexecutionEvidenceError("Pre-execution attestation maximum age must be positive.")
    objects = [
        require_object(value, f"environment_attestations[{index}]")
        for index, value in enumerate(attestations)
    ]
    identifiers = [
        require_string(attestation.get("control_id"), f"environment_attestations[{index}].control_id")
        for index, attestation in enumerate(objects)
    ]
    if len(identifiers) != len(set(identifiers)) or set(identifiers) != REQUIRED_ENVIRONMENT_ATTESTATIONS:
        raise RangePreexecutionEvidenceError(
            "Pre-execution packet must contain each required environment attestation exactly once."
        )
    verified_verifier_ids: set[str] = set()
    verified_principals: set[str] = set()
    verified_processes: set[int] = set()
    missing: list[str] = []
    verified_count = 0
    for index, attestation in enumerate(objects):
        control_id = identifiers[index]
        origin = require_string(attestation.get("origin"), f"environment_attestations[{index}].origin")
        status = require_string(attestation.get("status"), f"environment_attestations[{index}].status")
        evidence = require_list(attestation.get("evidence"), f"environment_attestations[{index}].evidence")
        observed_at = _timestamp(
            attestation.get("observed_at"),
            f"environment_attestations[{index}].observed_at",
            RangePreexecutionEvidenceError,
        )
        age_seconds = int((assembled_at - observed_at).total_seconds())
        if age_seconds < 0:
            raise RangePreexecutionEvidenceError(f"Environment attestation '{control_id}' is from the future.")
        if age_seconds > maximum_age_seconds:
            raise RangePreexecutionEvidenceError(f"Environment attestation '{control_id}' is stale.")
        if status not in {"verified", "unproven", "failed"}:
            raise RangePreexecutionEvidenceError(
                f"Environment attestation '{control_id}' has unsupported status '{status}'."
            )
        verifier = attestation.get("verifier")
        if status == "verified":
            if origin not in REAL_RANGE_ORIGINS:
                raise RangePreexecutionEvidenceError(
                    f"Environment attestation '{control_id}' cannot launder origin '{origin}' into verification."
                )
            if not evidence:
                raise RangePreexecutionEvidenceError(
                    f"Verified environment attestation '{control_id}' lacks content-addressed evidence."
                )
            verifier_object = require_object(verifier, f"environment_attestations[{index}].verifier")
            verified_verifier_ids.add(require_string(verifier_object.get("verifier_id"), "verifier.verifier_id"))
            verified_principals.add(require_string(verifier_object.get("logical_principal"), "verifier.logical_principal"))
            process_id = require_integer(verifier_object.get("process_id"), "verifier.process_id")
            if process_id <= 0:
                raise RangePreexecutionEvidenceError("Verified environment attestation process ID must be positive.")
            verified_processes.add(process_id)
            verified_count += 1
        else:
            missing.append(control_id)
            if verifier is not None:
                raise RangePreexecutionEvidenceError(
                    f"Non-verified environment attestation '{control_id}' cannot claim a verifier identity."
                )
    distinct_verifiers = min(
        len(verified_verifier_ids),
        len(verified_principals),
        len(verified_processes),
    )
    return objects, sorted(missing), verified_count, distinct_verifiers


def build_preexecution_evidence_packet(
    scope: JsonObject,
    connector_manifest: JsonObject,
    topology_verdict: JsonObject,
    preflight_result: JsonObject,
    environment_attestations: list[object],
    assembled_at: datetime,
    maximum_attestation_age_seconds: int,
) -> JsonObject:
    if assembled_at.utcoffset() is None:
        raise RangePreexecutionEvidenceError("Pre-execution packet assembly time must be timezone-aware.")
    if scope.get("status") != "compiled_contract_only_environment_unproven":
        raise RangePreexecutionEvidenceError("Pre-execution packet requires the declaration-only compiled scope.")
    if require_object(scope.get("authority"), "scope.authority") != SCOPE_AUTHORITY:
        raise RangePreexecutionEvidenceError("Pre-execution scope exposes prohibited authority.")
    if connector_manifest.get("status") != "non_provisioning_contract_only_blocked":
        raise RangePreexecutionEvidenceError("Pre-execution connector boundary is not explicitly blocked.")
    if require_object(connector_manifest.get("authority"), "connector.authority") != CONNECTOR_AUTHORITY:
        raise RangePreexecutionEvidenceError("Pre-execution connector exposes prohibited authority.")
    if topology_verdict.get("environment_verified") is not False:
        raise RangePreexecutionEvidenceError("Pre-execution topology verdict must remain environment-unverified.")
    if preflight_result.get("status") != "blocked" or preflight_result.get("connection_gate_satisfied") is not False:
        raise RangePreexecutionEvidenceError("Pre-execution range preflight must preserve its blocked current state.")
    attestations, missing, verified_count, distinct_verifiers = _validate_attestations(
        environment_attestations,
        assembled_at,
        maximum_attestation_age_seconds,
    )
    if verified_count:
        raise RangePreexecutionEvidenceError(
            "Version 0.1 simulated scope cannot accept real-origin verified attestations."
        )
    blockers = {
        "CONNECTOR_RUNTIME_MISSING",
        "RANGE_TOPOLOGY_ENVIRONMENT_UNVERIFIED",
        "RANGE_PREFLIGHT_BLOCKED",
        "SEPARATE_CONNECTION_AUTHORIZATION_MISSING",
        "EXECUTION_AUTHORIZATION_MISSING",
    }
    blockers.update(f"REAL_ENVIRONMENT_ATTESTATION_MISSING:{control_id}" for control_id in missing)
    scope_id = require_string(scope.get("scope_id"), "scope.scope_id")
    packet_id = deterministic_uuid(scope_id, sha256_digest(attestations), "preexecution-evidence")
    return {
        "packet_version": "0.1.0",
        "packet_id": packet_id,
        "origin": "simulated",
        "status": "blocked_missing_real_environment_evidence",
        "assembled_at": format_timestamp(assembled_at),
        "scope_id": scope_id,
        "scope_digest": sha256_digest(scope),
        "connector_manifest_digest": sha256_digest(connector_manifest),
        "topology_verdict_digest": sha256_digest(topology_verdict),
        "preflight_result_digest": sha256_digest(preflight_result),
        "required_attestation_controls": sorted(REQUIRED_ENVIRONMENT_ATTESTATIONS),
        "environment_attestations": copy.deepcopy(attestations),
        "missing_real_attestations": missing,
        "real_environment_attestation_count": verified_count,
        "distinct_verified_verifier_count": distinct_verifiers,
        "evidence_complete": False,
        "blockers": sorted(blockers),
        "provisioning_performed": False,
        "installation_performed": False,
        "source_tool_contacted": False,
        "network_contact_performed": False,
        "range_connection_authorized": False,
        "execution_authorized": False,
        "authority": copy.deepcopy(PACKET_AUTHORITY),
    }


def validate_preexecution_evidence_packet(
    packet: JsonObject,
    scope: JsonObject,
    connector_manifest: JsonObject,
    topology_verdict: JsonObject,
    preflight_result: JsonObject,
    assembled_at: datetime,
    maximum_attestation_age_seconds: int,
) -> None:
    attestations = require_list(packet.get("environment_attestations"), "packet.environment_attestations")
    expected = build_preexecution_evidence_packet(
        scope,
        connector_manifest,
        topology_verdict,
        preflight_result,
        attestations,
        assembled_at,
        maximum_attestation_age_seconds,
    )
    if packet != expected:
        raise RangePreexecutionEvidenceError(
            "Pre-execution evidence packet differs from the deterministic fail-closed projection."
        )
