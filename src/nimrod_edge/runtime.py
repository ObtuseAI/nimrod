"""Runnable observation-to-proof loop for the unprivileged Edge preview."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import cast

from nimrod_edge.model import EdgePreviewResult
from nimrod_edge.verifier import PROPOSAL_CAPABILITY, PROPOSAL_OPERATION
from nimrod_simulator.compiler import deterministic_uuid, format_timestamp
from nimrod_simulator.errors import EdgePolicyError, EdgeVerificationError
from nimrod_simulator.jsonio import (
    canonical_json_bytes,
    require_object,
    require_string,
    require_string_list,
    sha256_digest,
    validate_contract,
)
from nimrod_simulator.model import ArtifactReference, JsonObject
from nimrod_simulator.witness import FileWitnessStore, verify_witness_store


RESULT_STATUS = "EDGE_PREVIEW_REPLAY_PROPOSAL_STRUCTURALLY_VERIFIED_POST_STATE_UNOBSERVED"
SECURITY_CLAIM = (
    "Replayed evidence only; no endpoint observation, containment, recovery, or production protection was established"
)


def select_policy_rule(scenario: JsonObject) -> JsonObject:
    observation = require_object(scenario.get("observation"), "scenario.observation")
    facts = set(require_string_list(observation.get("facts"), "scenario.observation.facts"))
    policy = require_object(scenario.get("policy"), "scenario.policy")
    rule = require_object(policy.get("rule"), "scenario.policy.rule")
    required_facts = set(require_string_list(rule.get("match_all_facts"), "scenario.policy.rule.match_all_facts"))
    if not required_facts.issubset(facts):
        raise EdgePolicyError(
            f"Edge replay scenario does not satisfy rule '{rule.get('rule_id')}': missing {sorted(required_facts - facts)}."
        )
    if policy.get("autonomy_budget") != 1 or rule.get("outcome") != "challenge":
        raise EdgePolicyError("Edge preview policy must remain Budget 1 with a challenge outcome.")
    if rule.get("proposal_operation") != PROPOSAL_OPERATION:
        raise EdgePolicyError("Edge preview policy contains an unsupported proposal operation.")
    return rule


def build_action_proposal(scenario: JsonObject, rule: JsonObject, evaluated_at: datetime) -> JsonObject:
    scenario_id = require_string(scenario.get("scenario_id"), "scenario.scenario_id")
    rule_id = require_string(rule.get("rule_id"), "scenario.policy.rule.rule_id")
    device = require_object(scenario.get("device"), "scenario.device")
    observation = require_object(scenario.get("observation"), "scenario.observation")
    process = require_object(observation.get("process"), "scenario.observation.process")
    policy = require_object(scenario.get("policy"), "scenario.policy")
    expires_at = format_timestamp(evaluated_at + timedelta(minutes=5))
    return {
        "envelope_version": "0.1.0",
        "event_id": deterministic_uuid(scenario_id, rule_id, "edge-action-proposal"),
        "mission_id": scenario_id,
        "timestamp": format_timestamp(evaluated_at),
        "origin": "replayed",
        "actor": {
            "principal_id": "service:nimrod-edge-deterministic-policy",
            "actor_type": "service",
            "authentication": [],
            "device_attestation": None,
            "workload_attestation": None,
        },
        "intent": {
            "operation": PROPOSAL_OPERATION,
            "purpose": "Ask the user to review a reversible per-process egress restriction",
            "target": {
                "resource_type": "windows_process_replay",
                "resource_id": require_string(process.get("process_id"), "scenario.observation.process.process_id"),
                "binding": {
                    "device_id": require_string(device.get("device_id"), "scenario.device.device_id"),
                    "image_digest": require_string(process.get("image_digest"), "scenario.observation.process.image_digest"),
                },
            },
            "requested_capability": PROPOSAL_CAPABILITY,
        },
        "context": {
            "data_classification": "internal",
            "incident_id": scenario_id,
            "supporting_evidence": [
                {
                    "id": f"edge:scenario:{scenario_id}",
                    "digest": sha256_digest(scenario),
                }
            ],
            "contradicting_evidence": [],
            "uncertainties": [
                "The observation is replayed rather than collected from a live endpoint",
                "Publisher and destination reputation were not independently resolved",
            ],
        },
        "risk": {
            "impact": require_string(rule.get("risk_level"), "scenario.policy.rule.risk_level"),
            "confidence_interval": [0.72, 0.88],
            "blast_radius": "one replayed process identity on one declared Windows device",
            "reversibility": "fully_reversible",
            "urgency": "time_sensitive",
        },
        "execution_contract": {
            "preconditions": [
                "User confirmation is required",
                "A separately approved Edge executor must exist",
                "A rollback path must be verified before execution",
            ],
            "expected_state_delta": {"proposal_only": True, "target_state_changed": False},
            "prohibited_side_effects": [
                "No process suspension or termination",
                "No firewall or network-policy mutation",
                "No credential, file, registry, or service mutation",
            ],
            "resource_limits": {"autonomy_budget": 1, "maximum_targets": 1},
            "idempotency_key": deterministic_uuid(scenario_id, rule_id, "edge-idempotency"),
            "expires_at": expires_at,
        },
        "recovery": {
            "snapshot_required": False,
            "rollback_operation": None,
            "compensation_plan": ["No target change is permitted in the unprivileged preview"],
        },
        "verification": {
            "required_oracles": [],
            "independent_verifiers": [
                {
                    "id": "verifier:nimrod-edge-structural",
                    "digest": sha256_digest({"verifier": "nimrod-edge-structural", "version": "0.1.0"}),
                }
            ],
            "success_postconditions": ["The proposal exposes no execution surface"],
            "failure_postconditions": ["Any command-like field or execution authority fails closed"],
        },
        "authorization": {
            "policy_decision": "challenge",
            "policy_version": require_string(policy.get("policy_version"), "scenario.policy.policy_version"),
            "approvals": [],
        },
        "signatures": [],
    }


def build_evidence_receipt(
    scenario: JsonObject,
    scenario_reference: ArtifactReference,
    collected_at: str,
) -> JsonObject:
    scenario_id = require_string(scenario.get("scenario_id"), "scenario.scenario_id")
    source = require_object(scenario.get("source"), "scenario.source")
    source_id = require_string(source.get("source_id"), "scenario.source.source_id")
    actor = {
        "id": "service:nimrod-edge-replay",
        "digest": sha256_digest({"principal_id": "service:nimrod-edge-replay"}),
    }
    return {
        "receipt_version": "0.1.0",
        "evidence_id": scenario_reference["digest"],
        "incident_id": scenario_id,
        "origin": "replayed",
        "observation_time": require_string(scenario.get("observed_at"), "scenario.observed_at"),
        "collection_time": collected_at,
        "validity_interval": {"start": collected_at, "end": None},
        "source_identity": {"id": source_id, "digest": sha256_digest(source)},
        "device_or_workload_attestation": None,
        "content_digest": scenario_reference["digest"],
        "classification": "E1",
        "supporting_material": [
            {"id": scenario_reference["id"], "digest": scenario_reference["digest"]}
        ],
        "contradictions": [],
        "processing_history": [
            {
                "actor": actor,
                "operation": "admit_replayed_edge_observation",
                "timestamp": collected_at,
                "result_digest": scenario_reference["digest"],
            }
        ],
        "access_history": [],
        "retention_policy": {
            "purpose": "Unprivileged Edge policy and explanation validation",
            "delete_after": None,
            "legal_hold": False,
        },
        "signatures": [],
    }


def run_independent_verifier(
    project_root: Path,
    scenario: JsonObject,
    action: JsonObject,
    evaluated_at: datetime,
) -> JsonObject:
    verifier_input = canonical_json_bytes({"scenario": scenario, "action": action}).decode("utf-8")
    process = subprocess.run(
        [
            sys.executable,
            "-m",
            "nimrod_edge.verifier_cli",
            "--project-root",
            str(project_root),
            "--verified-at",
            format_timestamp(evaluated_at),
        ],
        cwd=project_root,
        input=verifier_input,
        capture_output=True,
        text=True,
        check=False,
    )
    if process.returncode != 0:
        raise EdgeVerificationError(
            "Independent Edge verifier failed: "
            f"returncode={process.returncode}; stdout={process.stdout!r}; stderr={process.stderr!r}."
        )
    try:
        value: object = json.loads(process.stdout)
    except json.JSONDecodeError as error:
        raise EdgeVerificationError(
            f"Independent Edge verifier returned invalid JSON: stdout={process.stdout!r}."
        ) from error
    if not isinstance(value, dict):
        raise EdgeVerificationError("Independent Edge verifier result must be a JSON object.")
    result = cast(JsonObject, value)
    verifier_process_id = result.get("verifier_process_id")
    if not isinstance(verifier_process_id, int) or isinstance(verifier_process_id, bool):
        raise EdgeVerificationError("Independent Edge verifier did not return an integer process ID.")
    if verifier_process_id == os.getpid():
        raise EdgeVerificationError("Edge verification did not execute in a distinct process.")
    return result


def build_result(
    scenario: JsonObject,
    rule: JsonObject,
    scenario_reference: ArtifactReference,
    action_reference: ArtifactReference,
    receipt_reference: ArtifactReference,
    verification: JsonObject,
    verification_reference: ArtifactReference,
    witness_journal: Path,
    evaluated_at: datetime,
) -> EdgePreviewResult:
    scenario_id = require_string(scenario.get("scenario_id"), "scenario.scenario_id")
    return {
        "result_version": "0.1.0",
        "run_id": deterministic_uuid(scenario_id, "edge-preview", "run"),
        "scenario_id": scenario_id,
        "scenario_digest": sha256_digest(scenario),
        "origin": "replayed",
        "status": RESULT_STATUS,
        "evaluated_at": format_timestamp(evaluated_at),
        "matched_rule_id": require_string(rule.get("rule_id"), "scenario.policy.rule.rule_id"),
        "risk": {
            "level": require_string(rule.get("risk_level"), "scenario.policy.rule.risk_level"),
            "confidence_interval": [0.72, 0.88],
        },
        "explanation": [
            "The replay shows an unsigned process in a user-writable location contacting a new destination",
            "Deterministic policy selected a user-confirmation proposal for reversible process egress isolation",
            "The preview contains no executor and changed no target state",
        ],
        "uncertainties": [
            "The event was replayed and not collected from this device",
            "No destination or publisher reputation oracle was queried",
            "No endpoint post-state or recovery state was observed",
        ],
        "references": {
            "scenario": scenario_reference,
            "action_proposal": action_reference,
            "evidence_receipt": receipt_reference,
            "verification": verification_reference,
        },
        "independent_verification": verification,
        "witness": {"entry_count": 4, "journal": str(witness_journal)},
        "authority": {
            "can_authorize": False,
            "can_execute": False,
            "target_state_changed": False,
            "recovery_verified": False,
        },
        "security_claim": SECURITY_CLAIM,
    }


def run_edge_preview(
    project_root: Path,
    scenario: JsonObject,
    output_root: Path,
    evaluated_at: datetime,
) -> EdgePreviewResult:
    specs_root = project_root / "specs"
    validate_contract(scenario, specs_root / "edge-preview-scenario.schema.json", "Edge preview scenario")
    rule = select_policy_rule(scenario)
    action = build_action_proposal(scenario, rule, evaluated_at)
    validate_contract(action, specs_root / "action-and-evidence-envelope.schema.json", "Edge action proposal")

    observed_at = format_timestamp(evaluated_at)
    witness = FileWitnessStore(output_root)
    scenario_reference = witness.append("edge-preview-scenario", scenario, observed_at)
    action_reference = witness.append("edge-action-proposal", action, observed_at)
    receipt = build_evidence_receipt(scenario, scenario_reference, observed_at)
    validate_contract(receipt, specs_root / "evidence-receipt.schema.json", "Edge evidence receipt")
    receipt_reference = witness.append("edge-evidence-receipt", receipt, observed_at)
    verification = run_independent_verifier(project_root, scenario, action, evaluated_at)
    verification_reference = witness.append("edge-independent-verification", verification, observed_at)

    result = build_result(
        scenario,
        rule,
        scenario_reference,
        action_reference,
        receipt_reference,
        verification,
        verification_reference,
        witness.journal_path,
        evaluated_at,
    )
    validate_contract(
        cast(JsonObject, result),
        specs_root / "edge-preview-result.schema.json",
        "Edge preview result",
    )
    verified_count = verify_witness_store(output_root)
    if verified_count != 4:
        raise EdgeVerificationError(
            f"Edge Witness verification count mismatch: expected 4, received {verified_count}."
        )
    (output_root / "edge-preview-result.json").write_bytes(
        canonical_json_bytes(cast(JsonObject, result)) + b"\n"
    )
    return result
