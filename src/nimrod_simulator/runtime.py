"""End-to-end no-execution Crucible simulation runtime."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Protocol

from nimrod_simulator.authorization import (
    NOOP_CAPABILITY,
    NOOP_CONNECTOR_ID,
    evaluate_lease_state,
    parse_control_state,
    require_budget,
    require_campaign_binding,
    require_preflight,
)
from nimrod_simulator.authorization_crypto import verify_authorization
from nimrod_simulator.compiler import compile_campaign, deterministic_uuid, format_timestamp
from nimrod_simulator.errors import (
    CapabilityScopeError,
    ConnectorScopeError,
    ControlStateValidationError,
    WitnessIntegrityError,
)
from nimrod_simulator.jsonio import (
    canonical_json_bytes,
    read_json_object,
    require_list,
    require_string,
    require_string_list,
    sha256_digest,
    validate_contract,
)
from nimrod_simulator.model import ArtifactReference, CompiledStep, JsonObject, SimulationResult
from nimrod_simulator.state_journal import FileLeaseStateStore, no_state_failure
from nimrod_simulator.witness import FileWitnessStore, verify_witness_store


class Connector(Protocol):
    """Boundary implemented by external-system adapters."""

    def execute_noop(self, step: CompiledStep, observed_at: str) -> JsonObject:
        """Return simulated lifecycle evidence without target execution."""


class NoOpConnector:
    """Fixed Stage 1 connector with no command, network, or target-mutation path."""

    def __init__(self, connector_id: str, capability: str) -> None:
        if connector_id != NOOP_CONNECTOR_ID:
            raise ConnectorScopeError(
                f"No-op connector identity must be '{NOOP_CONNECTOR_ID}'; received '{connector_id}'."
            )
        if capability != NOOP_CAPABILITY:
            raise CapabilityScopeError(
                f"No-op connector capability must be '{NOOP_CAPABILITY}'; received '{capability}'."
            )
        self._connector_id = connector_id
        self._capability = capability

    def execute_noop(self, step: CompiledStep, observed_at: str) -> JsonObject:
        if step["connector_id"] != self._connector_id or step["capability"] != self._capability:
            raise ConnectorScopeError(
                f"Compiled step '{step['step_id']}' does not match the fixed no-op connector contract."
            )
        return {
            "result_version": "0.1.0-internal",
            "origin": "simulated",
            "connector_id": self._connector_id,
            "capability": self._capability,
            "step_id": step["step_id"],
            "target_id": step["target_id"],
            "observed_at": observed_at,
            "status": "completed_no_execution",
            "live_execution_performed": False,
            "target_state_changed": False,
            "cleanup_status": "verified_no_state_created",
            "lifecycle": ["preflight", "compile", "execute_noop", "cleanup_noop", "verify_no_state"],
            "action_envelope_digest": sha256_digest(step["action_envelope"]),
        }


def build_receipt(
    campaign_id: str,
    result: JsonObject,
    result_reference: ArtifactReference,
    connector_manifest_digest: str,
    observed_at: str,
) -> JsonObject:
    actor_reference: JsonObject = {
        "id": "service:nimrod-no-execution-simulator",
        "digest": sha256_digest({"principal_id": "service:nimrod-no-execution-simulator"}),
    }
    evidence_id = result_reference["digest"]
    return {
        "receipt_version": "0.1.0",
        "evidence_id": evidence_id,
        "incident_id": campaign_id,
        "origin": "simulated",
        "observation_time": observed_at,
        "collection_time": observed_at,
        "validity_interval": {"start": observed_at, "end": None},
        "source_identity": {
            "id": NOOP_CONNECTOR_ID,
            "digest": connector_manifest_digest,
        },
        "device_or_workload_attestation": None,
        "content_digest": result_reference["digest"],
        "classification": "E0",
        "supporting_material": [
            {"id": result_reference["id"], "digest": result_reference["digest"]}
        ],
        "contradictions": [],
        "processing_history": [
            {
                "actor": actor_reference,
                "operation": "record_simulated_noop_result",
                "timestamp": observed_at,
                "result_digest": sha256_digest(result),
            }
        ],
        "access_history": [],
        "retention_policy": {
            "purpose": "Stage 1 no-execution contract and evidence validation",
            "delete_after": None,
            "legal_hold": False,
        },
        "signatures": [],
    }


def validate_noop_connector_manifest(project_root: Path) -> str:
    manifest_path = project_root / "specs" / "examples" / "connector-manifest.example.json"
    manifest = read_json_object(manifest_path)
    validate_contract(
        manifest,
        project_root / "specs" / "connector-manifest.schema.json",
        "no-op connector manifest",
    )
    connector_id = require_string(manifest.get("connector_id"), "connector_manifest.connector_id")
    if connector_id != NOOP_CONNECTOR_ID:
        raise ConnectorScopeError(
            f"No-op connector manifest identity must be '{NOOP_CONNECTOR_ID}'; received '{connector_id}'."
        )
    permissions = set(require_string_list(manifest.get("permissions"), "connector_manifest.permissions"))
    if permissions != {NOOP_CAPABILITY}:
        raise CapabilityScopeError(
            f"No-op connector manifest must grant exactly '{NOOP_CAPABILITY}'; received {sorted(permissions)}."
        )
    required_lifecycle = {"preflight", "compile", "execute", "abort", "cleanup", "verify"}
    lifecycle = set(require_string_list(manifest.get("lifecycle_operations"), "connector_manifest.lifecycle_operations"))
    missing_lifecycle = sorted(required_lifecycle - lifecycle)
    if missing_lifecycle:
        raise ConnectorScopeError(
            f"No-op connector manifest lacks closed lifecycle operations: {', '.join(missing_lifecycle)}."
        )
    secrets = require_list(manifest.get("secret_references"), "connector_manifest.secret_references")
    if secrets:
        raise ConnectorScopeError("No-op connector manifest must not request secrets.")
    destinations = require_string_list(
        manifest.get("network_destinations"), "connector_manifest.network_destinations"
    )
    if any(not destination.startswith("range:simulated-") for destination in destinations):
        raise ConnectorScopeError(
            f"No-op connector manifest contains a non-simulated destination: {destinations}."
        )
    return sha256_digest(manifest)


def require_separate_storage_paths(output_root: Path, state_root: Path) -> None:
    output = output_root.resolve()
    state = state_root.resolve()
    if output == state or output in state.parents or state in output.parents:
        raise ControlStateValidationError(
            f"Witness output '{output}' and lease state '{state}' must be separate non-nested directories."
        )


def build_verdict(
    campaign_id: str,
    step: CompiledStep,
    action_reference: ArtifactReference,
    result_reference: ArtifactReference,
    receipt_reference: ArtifactReference,
    observed_at: str,
) -> JsonObject:
    verifier_reference: JsonObject = {
        "id": "verifier:no-execution-structural-only",
        "digest": sha256_digest({"verifier": "no-execution-structural-only"}),
    }
    return {
        "verdict_version": "0.2.0",
        "verdict_id": deterministic_uuid(campaign_id, step["step_id"], "verdict"),
        "origin": "simulated",
        "campaign_id": campaign_id,
        "step_id": step["step_id"],
        "target_id": step["target_id"],
        "observed_at": observed_at,
        "status": "ineffective",
        "causal_chain": {
            "intent": {"id": action_reference["id"], "digest": action_reference["digest"]},
            "attempt": {"id": result_reference["id"], "digest": result_reference["digest"]},
            "state_delta": None,
            "observation": {"id": receipt_reference["id"], "digest": receipt_reference["digest"]},
            "detection": None,
            "response": None,
            "recovery": {"id": receipt_reference["id"], "digest": receipt_reference["digest"]},
            "post_state": {"id": receipt_reference["id"], "digest": receipt_reference["digest"]},
        },
        "assurance_vector": {
            "prevention": None,
            "observation": None,
            "detection": None,
            "correlation": None,
            "response": None,
            "recovery": None,
            "precision": None,
            "evidence_completeness": 1.0,
            "privacy": 1.0,
            "performance": 1.0,
            "uncertainty": 1.0,
            "freshness_seconds": 0,
        },
        "supporting_evidence": [
            {"id": receipt_reference["id"], "digest": receipt_reference["digest"]}
        ],
        "contradicting_evidence": [],
        "uncertainties": [
            "The no-op connector intentionally produced no target state delta",
            "Authorization was verified only against the local simulated trust-policy fixture",
            "No defensive product, live sensor, or external offensive connector was exercised",
        ],
        "residual_risks": [
            "This verdict proves only the simulated contract and Witness pipeline",
            "No real prevention, observation, detection, response, cleanup, or recovery coverage is established",
        ],
        "verifier_signatures": [verifier_reference],
    }


def run_simulation(
    project_root: Path,
    lease: JsonObject,
    campaign: JsonObject,
    proof_bundle: JsonObject,
    trust_policy: JsonObject,
    control_state: JsonObject,
    output_root: Path,
    state_root: Path,
    now: datetime,
) -> SimulationResult:
    specs_root = project_root / "specs"
    validate_contract(lease, specs_root / "authorization-lease.schema.json", "authorization lease")
    validate_contract(campaign, specs_root / "validation-campaign.schema.json", "validation campaign")
    validate_contract(
        proof_bundle,
        specs_root / "authorization-proof-bundle.schema.json",
        "authorization proof bundle",
    )
    validate_contract(
        trust_policy,
        specs_root / "authorization-trust-policy.schema.json",
        "authorization trust policy",
    )
    connector_manifest_digest = validate_noop_connector_manifest(project_root)
    control = parse_control_state(control_state)
    evaluate_lease_state(lease, control, now)
    authorization_verification = verify_authorization(lease, proof_bundle, trust_policy, now)
    require_campaign_binding(lease, campaign)
    require_preflight(lease, control)
    require_budget(lease, campaign, control)
    compiled = compile_campaign(lease, campaign, now)
    require_separate_storage_paths(output_root, state_root)
    connector: Connector = NoOpConnector(NOOP_CONNECTOR_ID, NOOP_CAPABILITY)
    observed_at = format_timestamp(now)
    campaign_id = require_string(campaign.get("campaign_id"), "campaign_id")
    lease_id = require_string(lease.get("lease_id"), "lease_id")
    nonce = require_string(lease.get("nonce"), "nonce")
    store = FileWitnessStore(output_root)
    lease_state = FileLeaseStateStore(state_root, no_state_failure)
    lease_state.claim(lease_id, nonce, observed_at)
    authorization_state_report = lease_state.inspect()
    references: list[ArtifactReference] = []
    verdict_statuses: list[str] = []
    for step in compiled:
        validate_contract(
            step["action_envelope"], specs_root / "action-and-evidence-envelope.schema.json", "compiled action envelope"
        )
        action_reference = store.append("action-envelope", step["action_envelope"], observed_at)
        result = connector.execute_noop(step, observed_at)
        result_reference = store.append("connector-result", result, observed_at)
        receipt = build_receipt(
            campaign_id,
            result,
            result_reference,
            connector_manifest_digest,
            observed_at,
        )
        validate_contract(receipt, specs_root / "evidence-receipt.schema.json", "evidence receipt")
        receipt_reference = store.append("evidence-receipt", receipt, observed_at)
        verdict = build_verdict(
            campaign_id,
            step,
            action_reference,
            result_reference,
            receipt_reference,
            observed_at,
        )
        validate_contract(verdict, specs_root / "causal-coverage-verdict.schema.json", "causal coverage verdict")
        verdict_reference = store.append("causal-coverage-verdict", verdict, observed_at)
        references.extend([action_reference, result_reference, receipt_reference, verdict_reference])
        verdict_statuses.append(require_string(verdict.get("status"), "verdict.status"))
    verified_entries = verify_witness_store(output_root)
    if verified_entries != len(references):
        raise WitnessIntegrityError(
            f"Witness verification count mismatch: expected {len(references)}, received {verified_entries}."
        )
    summary: SimulationResult = {
        "run_version": "0.1.0",
        "origin": "simulated",
        "status": "completed_no_execution",
        "live_execution_performed": False,
        "cryptographic_authorization_verified": authorization_verification[
            "cryptographic_authorization_verified"
        ],
        "authorization_signers": authorization_verification["verified_signer_ids"],
        "lease_id": lease_id,
        "campaign_id": campaign_id,
        "action_count": len(compiled),
        "verdict_statuses": verdict_statuses,
        "artifacts": references,
        "witness_journal": str(store.journal_path),
    }
    summary_document: JsonObject = {
        **summary,
        "consumed_nonce": nonce,
        "authorization_verification": authorization_verification,
        "authorization_state": authorization_state_report,
        "witness_entries_verified": verified_entries,
        "security_claim": "No live security or offensive capability was exercised or established",
    }
    (output_root / "run-summary.json").write_bytes(canonical_json_bytes(summary_document) + b"\n")
    return summary
