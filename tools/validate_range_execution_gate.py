"""Validate the governed non-provisioning range execution gate."""

from __future__ import annotations

import base64
import copy
import json
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TypeVar, cast

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jsonschema import Draft202012Validator, FormatChecker

from nimrod_simulator.authorization_crypto import authorization_message
from nimrod_simulator.errors import (
    AuthorizationSignatureError,
    RangeConnectorCapabilityError,
    RangePreexecutionEvidenceError,
    RangeScopeCompilationError,
)
from nimrod_simulator.jsonio import read_json_object, sha256_digest
from nimrod_simulator.key_governance import EphemeralEd25519SigningConnector, governance_key
from nimrod_simulator.model import JsonObject
from nimrod_simulator.range_execution_gate import (
    CONNECTOR_AUTHORITY,
    CONNECTOR_BLOCKERS,
    CONNECTOR_CAPABILITIES,
    CONNECTOR_OPERATIONS,
    PACKET_AUTHORITY,
    REQUIRED_ENVIRONMENT_ATTESTATIONS,
    SCOPE_AUTHORITY,
    SCOPE_BLOCKERS,
    build_preexecution_evidence_packet,
    compile_lease_to_topology_scope,
    sign_range_connector_capability_manifest,
    validate_preexecution_evidence_packet,
    verify_range_connector_capability_manifest,
)
from nimrod_simulator.range_topology import validate_range_topology


TError = TypeVar("TError", bound=Exception)
VALIDATION_TIME = datetime(2026, 7, 12, 19, 5, 0, tzinfo=timezone.utc)
CONNECTOR_LIFETIME_SECONDS = 600
ATTESTATION_AGE_SECONDS = 120


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
    schema: object = json.loads(schema_path.read_text(encoding="utf-8"))
    if not isinstance(schema, dict):
        raise TypeError(f"{label} schema must be a JSON object.")
    errors = sorted(
        Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(value),
        key=lambda item: list(item.absolute_path),
    )
    if errors:
        rendered = "; ".join(error.message for error in errors)
        raise AssertionError(f"{label} failed schema validation: {rendered}")


def signing_connectors() -> list[EphemeralEd25519SigningConnector]:
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
    issued_at = "2026-07-12T19:00:00Z"
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


def signed_connector_manifest(
    source_manifest: JsonObject,
    governance: JsonObject,
    connectors: list[EphemeralEd25519SigningConnector],
    issued_at: datetime,
    not_before: datetime,
    expires_at: datetime,
) -> JsonObject:
    unsigned: JsonObject = {
        "manifest_version": "0.1.0",
        "manifest_id": "0b99147a-88ae-47db-b9ad-bf6ab46433ea",
        "origin": "simulated",
        "connector_id": source_manifest["connector_id"],
        "connector_version": source_manifest["connector_version"],
        "source_manifest_digest": sha256_digest(source_manifest),
        "governance_state_digest": sha256_digest(governance),
        "issued_at": issued_at.isoformat().replace("+00:00", "Z"),
        "not_before": not_before.isoformat().replace("+00:00", "Z"),
        "expires_at": expires_at.isoformat().replace("+00:00", "Z"),
        "capability_allowlist": sorted(CONNECTOR_CAPABILITIES),
        "operation_allowlist": sorted(CONNECTOR_OPERATIONS),
        "supported_environment_classes": ["isolated_range"],
        "network_destinations": [],
        "secret_references": [],
        "installation_required": False,
        "source_tool_contact_required": False,
        "target_discovery_performed": False,
        "artifact_digest_required": True,
        "status": "non_provisioning_contract_only_blocked",
        "blockers": sorted(CONNECTOR_BLOCKERS),
        "authority": copy.deepcopy(CONNECTOR_AUTHORITY),
    }
    return sign_range_connector_capability_manifest(unsigned, connectors[:2])


def signed_authorization_proof(
    lease: JsonObject,
    trust_policy: JsonObject,
    signed_at: datetime,
) -> JsonObject:
    proof: JsonObject = {
        "bundle_version": "0.1.0",
        "bundle_id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        "origin": "simulated",
        "lease_id": lease["lease_id"],
        "lease_digest": sha256_digest(lease),
        "trust_policy_digest": sha256_digest(trust_policy),
        "signed_at": signed_at.isoformat().replace("+00:00", "Z"),
    }
    message = authorization_message(lease, proof)
    signer_material = (
        ("signer:customer-authority", 11),
        ("signer:safety-officer", 12),
    )
    proof["signatures"] = [
        {
            "signer_id": signer_id,
            "algorithm": "Ed25519",
            "signature_base64": base64.b64encode(
                Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32).sign(message)
            ).decode("ascii"),
        }
        for signer_id, seed in signer_material
    ]
    return proof


def deterministic_authorization_trust_policy() -> JsonObject:
    signer_material = (
        ("signer:customer-authority", "customer_authority", 11),
        ("signer:safety-officer", "safety_officer", 12),
    )
    return {
        "policy_version": "0.1.0",
        "policy_id": "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
        "origin": "simulated",
        "trust_source": "validation_ephemeral_keys",
        "not_before": "2026-07-12T18:55:00Z",
        "expires_at": "2026-07-12T20:00:00Z",
        "threshold": 2,
        "required_roles": ["customer_authority", "safety_officer"],
        "trusted_signers": [
            {
                "signer_id": signer_id,
                "role": role,
                "algorithm": "Ed25519",
                "public_key_base64": base64.b64encode(
                    Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)
                    .public_key()
                    .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
                ).decode("ascii"),
            }
            for signer_id, role, seed in signer_material
        ],
    }


def blocked_attestations(observed_at: datetime) -> list[object]:
    return [
        {
            "control_id": control_id,
            "origin": "simulated",
            "status": "unproven",
            "observed_at": observed_at.isoformat().replace("+00:00", "Z"),
            "evidence": [],
            "verifier": None,
        }
        for control_id in sorted(REQUIRED_ENVIRONMENT_ATTESTATIONS)
    ]


def compile_scope(
    lease: JsonObject,
    proof_bundle: JsonObject,
    trust_policy: JsonObject,
    topology: JsonObject,
    connector_manifest: JsonObject,
    source_manifest: JsonObject,
    governance: JsonObject,
    evaluated_at: datetime,
) -> JsonObject:
    return compile_lease_to_topology_scope(
        lease,
        proof_bundle,
        trust_policy,
        topology,
        connector_manifest,
        source_manifest,
        governance,
        evaluated_at,
        CONNECTOR_LIFETIME_SECONDS,
    )


def build_packet(
    scope: JsonObject,
    connector_manifest: JsonObject,
    topology_verdict: JsonObject,
    preflight_result: JsonObject,
    attestations: list[object],
    assembled_at: datetime,
) -> JsonObject:
    return build_preexecution_evidence_packet(
        scope,
        connector_manifest,
        topology_verdict,
        preflight_result,
        attestations,
        assembled_at,
        ATTESTATION_AGE_SECONDS,
    )


def validate_range_execution_gate(project_root: Path) -> JsonObject:
    example_root = project_root / "specs" / "examples"
    lease = read_json_object(example_root / "authorization-lease.example.json")
    proof_bundle = read_json_object(example_root / "authorization-proof-bundle.example.json")
    trust_policy = read_json_object(example_root / "authorization-trust-policy.example.json")
    topology = read_json_object(example_root / "range-topology.example.json")
    preflight_result = read_json_object(example_root / "disposable-range-preflight-result.example.json")
    source_manifest = read_json_object(example_root / "connector-manifest.example.json")
    connectors = signing_connectors()
    governance = governance_state(connectors)
    issued_at = VALIDATION_TIME - timedelta(seconds=60)
    connector_manifest = signed_connector_manifest(
        source_manifest,
        governance,
        connectors,
        issued_at,
        issued_at,
        VALIDATION_TIME + timedelta(seconds=300),
    )
    connector_verification = verify_range_connector_capability_manifest(
        connector_manifest,
        source_manifest,
        governance,
        VALIDATION_TIME,
        CONNECTOR_LIFETIME_SECONDS,
    )
    validate_contract(
        connector_manifest,
        project_root / "specs" / "range-connector-capability-manifest.schema.json",
        "generated connector capability manifest",
    )
    scope = compile_scope(
        lease,
        proof_bundle,
        trust_policy,
        topology,
        connector_manifest,
        source_manifest,
        governance,
        VALIDATION_TIME,
    )
    validate_contract(
        scope,
        project_root / "specs" / "range-lease-topology-scope.schema.json",
        "generated lease-to-topology scope",
    )
    topology_verdict = validate_range_topology(topology)
    attestations = blocked_attestations(VALIDATION_TIME - timedelta(seconds=30))
    packet = build_packet(
        scope,
        connector_manifest,
        topology_verdict,
        preflight_result,
        attestations,
        VALIDATION_TIME,
    )
    validate_contract(
        packet,
        project_root / "specs" / "range-preexecution-evidence-packet.schema.json",
        "generated pre-execution evidence packet",
    )
    validate_preexecution_evidence_packet(
        packet,
        scope,
        connector_manifest,
        topology_verdict,
        preflight_result,
        VALIDATION_TIME,
        ATTESTATION_AGE_SECONDS,
    )
    require_condition(
        connector_manifest == read_json_object(example_root / "range-connector-capability-manifest.example.json"),
        "Canonical connector capability manifest example drifted from deterministic generation.",
    )
    require_condition(
        scope == read_json_object(example_root / "range-lease-topology-scope.example.json"),
        "Canonical lease-to-topology scope example drifted from deterministic generation.",
    )
    require_condition(
        packet == read_json_object(example_root / "range-preexecution-evidence-packet.example.json"),
        "Canonical pre-execution evidence packet example drifted from deterministic generation.",
    )
    require_condition(connector_verification["verified_signer_ids"] == ["key:range-owner", "key:range-safety"], "Connector manifest signer set drifted.")
    require_condition(scope["cryptographic_authorization_verified"] is True, "Scope did not preserve lease authorization proof.")
    require_condition(scope["topology_environment_verified"] is False, "Scope laundered the declared topology into real evidence.")
    require_condition(packet["evidence_complete"] is False, "Pre-execution packet claimed complete evidence.")
    require_condition(packet["missing_real_attestations"] == sorted(REQUIRED_ENVIRONMENT_ATTESTATIONS), "Pre-execution packet hid missing real attestations.")
    require_condition(all(packet[field] is False for field in ("provisioning_performed", "installation_performed", "source_tool_contacted", "network_contact_performed", "range_connection_authorized", "execution_authorized")), "Pre-execution packet exposed prohibited activity or authority.")

    adversarial_count = 0
    signature_tamper = copy.deepcopy(connector_manifest)
    signatures = cast(list[JsonObject], signature_tamper["signatures"])
    encoded = cast(str, signatures[0]["signature_base64"])
    signatures[0]["signature_base64"] = ("A" if encoded[0] != "A" else "B") + encoded[1:]
    expect_error(RangeConnectorCapabilityError, lambda: verify_range_connector_capability_manifest(signature_tamper, source_manifest, governance, VALIDATION_TIME, CONNECTOR_LIFETIME_SECONDS), "connector signature tamper")
    adversarial_count += 1
    one_signature = copy.deepcopy(connector_manifest)
    one_signature["signatures"] = cast(list[JsonObject], one_signature["signatures"])[:1]
    expect_error(RangeConnectorCapabilityError, lambda: verify_range_connector_capability_manifest(one_signature, source_manifest, governance, VALIDATION_TIME, CONNECTOR_LIFETIME_SECONDS), "connector threshold underflow")
    adversarial_count += 1

    manifest_mutations: list[tuple[JsonObject, str]] = []
    authority_widening = copy.deepcopy(connector_manifest)
    cast(JsonObject, authority_widening["authority"])["can_connect"] = True
    manifest_mutations.append((authority_widening, "connector authority widening"))
    operation_widening = copy.deepcopy(connector_manifest)
    operation_widening["operation_allowlist"] = ["compile", "execute", "verify"]
    manifest_mutations.append((operation_widening, "connector execute operation"))
    destination_widening = copy.deepcopy(connector_manifest)
    destination_widening["network_destinations"] = ["range:example"]
    manifest_mutations.append((destination_widening, "connector network destination"))
    secret_widening = copy.deepcopy(connector_manifest)
    secret_widening["secret_references"] = ["secret:example"]
    manifest_mutations.append((secret_widening, "connector secret request"))
    artifact_weakening = copy.deepcopy(connector_manifest)
    artifact_weakening["artifact_digest_required"] = False
    manifest_mutations.append((artifact_weakening, "connector artifact weakening"))
    source_substitution = copy.deepcopy(connector_manifest)
    source_substitution["source_manifest_digest"] = "sha256:" + "0" * 64
    manifest_mutations.append((source_substitution, "connector source substitution"))
    governance_substitution = copy.deepcopy(connector_manifest)
    governance_substitution["governance_state_digest"] = "sha256:" + "0" * 64
    manifest_mutations.append((governance_substitution, "connector governance substitution"))
    for mutated, label in manifest_mutations:
        expect_error(
            RangeConnectorCapabilityError,
            lambda mutated=mutated: verify_range_connector_capability_manifest(
                mutated,
                source_manifest,
                governance,
                VALIDATION_TIME,
                CONNECTOR_LIFETIME_SECONDS,
            ),
            label,
        )
        adversarial_count += 1
    expired_manifest = signed_connector_manifest(
        source_manifest,
        governance,
        connectors,
        VALIDATION_TIME - timedelta(seconds=300),
        VALIDATION_TIME - timedelta(seconds=300),
        VALIDATION_TIME - timedelta(seconds=1),
    )
    expect_error(RangeConnectorCapabilityError, lambda: verify_range_connector_capability_manifest(expired_manifest, source_manifest, governance, VALIDATION_TIME, CONNECTOR_LIFETIME_SECONDS), "expired connector manifest")
    adversarial_count += 1

    scope_mutations: list[tuple[JsonObject, str]] = []
    production_target = copy.deepcopy(lease)
    cast(list[JsonObject], production_target["target_graph"])[0]["environment_class"] = "production"
    scope_mutations.append((production_target, "production lease target"))
    duplicate_target = copy.deepcopy(lease)
    cast(list[JsonObject], duplicate_target["target_graph"]).append(copy.deepcopy(cast(list[JsonObject], duplicate_target["target_graph"])[0]))
    scope_mutations.append((duplicate_target, "multiple lease targets"))
    wrong_resource = copy.deepcopy(lease)
    cast(list[JsonObject], wrong_resource["target_graph"])[0]["resource_type"] = "linux_device"
    scope_mutations.append((wrong_resource, "unsupported target resource"))
    missing_capability = copy.deepcopy(lease)
    missing_capability["allowed_capabilities"] = ["range.test.other"]
    scope_mutations.append((missing_capability, "missing capability intersection"))
    in_band_kill = copy.deepcopy(lease)
    cast(JsonObject, in_band_kill["kill_switch"])["out_of_band"] = False
    scope_mutations.append((in_band_kill, "in-band kill switch"))
    for mutated, label in scope_mutations:
        mutation_trust_policy = deterministic_authorization_trust_policy()
        mutated_proof = signed_authorization_proof(
            mutated,
            mutation_trust_policy,
            VALIDATION_TIME - timedelta(minutes=5),
        )
        expect_error(
            RangeScopeCompilationError,
            lambda mutated=mutated, mutated_proof=mutated_proof: compile_scope(
                mutated,
                mutated_proof,
                mutation_trust_policy,
                topology,
                connector_manifest,
                source_manifest,
                governance,
                VALIDATION_TIME,
            ),
            label,
        )
        adversarial_count += 1
    expect_error(
        RangeScopeCompilationError,
        lambda: compile_scope(lease, proof_bundle, trust_policy, topology, connector_manifest, source_manifest, governance, VALIDATION_TIME + timedelta(hours=1)),
        "expired lease scope compilation",
    )
    adversarial_count += 1
    proof_tamper = copy.deepcopy(proof_bundle)
    proof_signatures = cast(list[JsonObject], proof_tamper["signatures"])
    proof_encoded = cast(str, proof_signatures[0]["signature_base64"])
    proof_signatures[0]["signature_base64"] = ("A" if proof_encoded[0] != "A" else "B") + proof_encoded[1:]
    expect_error(
        AuthorizationSignatureError,
        lambda: compile_scope(lease, proof_tamper, trust_policy, topology, connector_manifest, source_manifest, governance, VALIDATION_TIME),
        "authorization proof tamper",
    )
    adversarial_count += 1

    packet_source_cases: list[tuple[JsonObject, JsonObject, JsonObject, JsonObject, str]] = []
    widened_scope = copy.deepcopy(scope)
    cast(JsonObject, widened_scope["authority"])["can_connect"] = True
    packet_source_cases.append((widened_scope, connector_manifest, topology_verdict, preflight_result, "scope authority widening"))
    widened_connector = copy.deepcopy(connector_manifest)
    cast(JsonObject, widened_connector["authority"])["can_install"] = True
    packet_source_cases.append((scope, widened_connector, topology_verdict, preflight_result, "connector installation authority"))
    verified_topology = copy.deepcopy(topology_verdict)
    verified_topology["environment_verified"] = True
    packet_source_cases.append((scope, connector_manifest, verified_topology, preflight_result, "topology evidence laundering"))
    ready_preflight = copy.deepcopy(preflight_result)
    ready_preflight["status"] = "ready_for_separately_authorized_range_connection"
    ready_preflight["connection_gate_satisfied"] = True
    ready_preflight["blocked_controls"] = []
    packet_source_cases.append((scope, connector_manifest, topology_verdict, ready_preflight, "preflight readiness laundering"))
    for case_scope, case_connector, case_topology, case_preflight, label in packet_source_cases:
        expect_error(
            RangePreexecutionEvidenceError,
            lambda case_scope=case_scope, case_connector=case_connector, case_topology=case_topology, case_preflight=case_preflight: build_packet(
                case_scope,
                case_connector,
                case_topology,
                case_preflight,
                attestations,
                VALIDATION_TIME,
            ),
            label,
        )
        adversarial_count += 1

    attestation_cases: list[tuple[list[object], datetime, str]] = []
    duplicate_attestation = copy.deepcopy(attestations)
    cast(JsonObject, duplicate_attestation[1])["control_id"] = cast(JsonObject, duplicate_attestation[0])["control_id"]
    attestation_cases.append((duplicate_attestation, VALIDATION_TIME, "duplicate environment attestation"))
    missing_attestation = copy.deepcopy(attestations[:-1])
    attestation_cases.append((missing_attestation, VALIDATION_TIME, "missing environment attestation"))
    future_attestation = copy.deepcopy(attestations)
    cast(JsonObject, future_attestation[0])["observed_at"] = (VALIDATION_TIME + timedelta(seconds=1)).isoformat().replace("+00:00", "Z")
    attestation_cases.append((future_attestation, VALIDATION_TIME, "future environment attestation"))
    stale_attestation = copy.deepcopy(attestations)
    cast(JsonObject, stale_attestation[0])["observed_at"] = (VALIDATION_TIME - timedelta(seconds=ATTESTATION_AGE_SECONDS + 1)).isoformat().replace("+00:00", "Z")
    attestation_cases.append((stale_attestation, VALIDATION_TIME, "stale environment attestation"))
    simulated_verified = copy.deepcopy(attestations)
    cast(JsonObject, simulated_verified[0])["status"] = "verified"
    cast(JsonObject, simulated_verified[0])["evidence"] = [{"id": "evidence:fake", "digest": "sha256:" + "a" * 64}]
    cast(JsonObject, simulated_verified[0])["verifier"] = {"verifier_id": "verifier:fake", "logical_principal": "principal:fake", "process_id": 1}
    attestation_cases.append((simulated_verified, VALIDATION_TIME, "simulated evidence laundering"))
    unproven_verifier = copy.deepcopy(attestations)
    cast(JsonObject, unproven_verifier[0])["verifier"] = {"verifier_id": "verifier:fake", "logical_principal": "principal:fake", "process_id": 1}
    attestation_cases.append((unproven_verifier, VALIDATION_TIME, "unproven verifier claim"))
    for mutated, assembled_at, label in attestation_cases:
        expect_error(
            RangePreexecutionEvidenceError,
            lambda mutated=mutated, assembled_at=assembled_at: build_packet(
                scope,
                connector_manifest,
                topology_verdict,
                preflight_result,
                mutated,
                assembled_at,
            ),
            label,
        )
        adversarial_count += 1

    packet_mutations: list[tuple[JsonObject, str]] = []
    scope_substitution = copy.deepcopy(packet)
    scope_substitution["scope_digest"] = "sha256:" + "0" * 64
    packet_mutations.append((scope_substitution, "packet scope substitution"))
    packet_status_laundering = copy.deepcopy(packet)
    packet_status_laundering["status"] = "ready"
    packet_mutations.append((packet_status_laundering, "packet status laundering"))
    packet_authority = copy.deepcopy(packet)
    cast(JsonObject, packet_authority["authority"])["can_execute"] = True
    packet_mutations.append((packet_authority, "packet authority widening"))
    for mutated, label in packet_mutations:
        expect_error(
            RangePreexecutionEvidenceError,
            lambda mutated=mutated: validate_preexecution_evidence_packet(
                mutated,
                scope,
                connector_manifest,
                topology_verdict,
                preflight_result,
                VALIDATION_TIME,
                ATTESTATION_AGE_SECONDS,
            ),
            label,
        )
        adversarial_count += 1

    return {
        "status": "RANGE_EXECUTION_GATE_NON_PROVISIONING_SCOPE_COMPILED_REAL_EVIDENCE_BLOCKED",
        "origin": "simulated",
        "connector_manifest_status": connector_manifest["status"],
        "connector_signature_threshold": governance["threshold"],
        "connector_verified_signer_count": len(cast(list[object], connector_verification["verified_signer_ids"])),
        "connector_operation_count": len(CONNECTOR_OPERATIONS),
        "connector_capability_count": len(CONNECTOR_CAPABILITIES),
        "scope_status": scope["status"],
        "scope_target_binding_count": len(cast(list[object], scope["target_bindings"])),
        "cryptographic_authorization_verified": scope["cryptographic_authorization_verified"],
        "topology_environment_verified": scope["topology_environment_verified"],
        "preexecution_packet_status": packet["status"],
        "required_real_attestation_count": len(REQUIRED_ENVIRONMENT_ATTESTATIONS),
        "missing_real_attestation_count": len(cast(list[object], packet["missing_real_attestations"])),
        "real_environment_attestation_count": packet["real_environment_attestation_count"],
        "evidence_complete": packet["evidence_complete"],
        "adversarial_case_count": adversarial_count,
        "provisioning_performed": False,
        "installation_performed": False,
        "source_tool_contacted": False,
        "network_contact_performed": False,
        "offensive_tools_installed_or_launched": False,
        "range_connection_authorized": False,
        "execution_authorized": False,
        "live_execution_performed": False,
        "can_connect": False,
        "can_execute": False,
    }


def main() -> None:
    project_root = Path(__file__).resolve().parent.parent
    result = validate_range_execution_gate(project_root)
    report_path = project_root / "reports" / "RANGE_EXECUTION_GATE_VALIDATION.json"
    report_path.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
