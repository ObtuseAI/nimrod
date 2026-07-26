"""Independent structural verification for Edge replay proposals."""

from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path

from nimrod_simulator.compiler import deterministic_uuid, format_timestamp, reject_execution_directives
from nimrod_simulator.errors import EdgeVerificationError
from nimrod_simulator.jsonio import require_list, require_object, require_string, sha256_digest, validate_contract
from nimrod_simulator.model import JsonObject


PROPOSAL_CAPABILITY = "edge.proposal.process_egress_isolation"
PROPOSAL_OPERATION = "recommend_process_egress_isolation"


def verify_edge_proposal(
    project_root: Path,
    scenario: JsonObject,
    action: JsonObject,
    verified_at: datetime,
) -> JsonObject:
    specs_root = project_root / "specs"
    validate_contract(scenario, specs_root / "edge-preview-scenario.schema.json", "Edge preview scenario")
    validate_contract(action, specs_root / "action-and-evidence-envelope.schema.json", "Edge action proposal")
    reject_execution_directives(action, "edge_action")

    scenario_id = require_string(scenario.get("scenario_id"), "scenario.scenario_id")
    policy = require_object(scenario.get("policy"), "scenario.policy")
    rule = require_object(policy.get("rule"), "scenario.policy.rule")
    rule_id = require_string(rule.get("rule_id"), "scenario.policy.rule.rule_id")
    intent = require_object(action.get("intent"), "action.intent")
    authorization = require_object(action.get("authorization"), "action.authorization")
    execution_contract = require_object(action.get("execution_contract"), "action.execution_contract")
    expected_delta = require_object(
        execution_contract.get("expected_state_delta"),
        "action.execution_contract.expected_state_delta",
    )

    if action.get("origin") != "replayed":
        raise EdgeVerificationError("Edge action origin must remain replayed.")
    if intent.get("operation") != PROPOSAL_OPERATION:
        raise EdgeVerificationError("Edge action operation is not the fixed proposal operation.")
    if intent.get("requested_capability") != PROPOSAL_CAPABILITY:
        raise EdgeVerificationError("Edge action requests capability outside the proposal-only boundary.")
    if authorization.get("policy_decision") != "challenge":
        raise EdgeVerificationError("Edge preview policy must challenge for user confirmation.")
    if require_list(authorization.get("approvals"), "action.authorization.approvals"):
        raise EdgeVerificationError("Edge preview action cannot contain approvals or execution authority.")
    if expected_delta != {"proposal_only": True, "target_state_changed": False}:
        raise EdgeVerificationError("Edge preview expected state delta must remain proposal-only and unchanged.")

    return {
        "verification_version": "0.1.0",
        "verification_id": deterministic_uuid(scenario_id, rule_id, "edge-independent-verification"),
        "origin": "replayed",
        "verified_at": format_timestamp(verified_at),
        "verifier_principal": "verifier:nimrod-edge-structural",
        "verifier_process_id": os.getpid(),
        "scenario_digest": sha256_digest(scenario),
        "action_digest": sha256_digest(action),
        "status": "independent_no_execution_structure_valid_post_state_unobserved",
        "checks": {
            "scenario_contract_valid": True,
            "action_contract_valid": True,
            "proposal_only": True,
            "execution_surface_present": False,
            "post_state_observed": False,
        },
        "verified_outcome": False,
        "execution_authorized": False,
        "execution_performed": False,
        "target_state_changed": False,
        "recovery_verified": False,
        "residual_risks": [
            "No live endpoint observation was performed",
            "No target post-state was observed",
            "No containment or recovery operation was exercised",
        ],
    }
