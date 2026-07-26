"""Pure campaign-to-envelope compilation."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from nimrod_simulator.authorization import evaluate_step_scope, ordered_steps
from nimrod_simulator.errors import ExecutionDirectiveError
from nimrod_simulator.jsonio import (
    require_integer,
    require_list,
    require_object,
    require_string,
    require_string_list,
)
from nimrod_simulator.model import CompiledStep, JsonObject, JsonValue


PROHIBITED_EXECUTION_KEYS = {
    "arguments",
    "argv",
    "bash",
    "cmd",
    "command",
    "executable",
    "payload",
    "powershell",
    "script",
    "shell",
}


def format_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def deterministic_uuid(campaign_id: str, step_id: str, purpose: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"nimrod:{campaign_id}:{step_id}:{purpose}"))


def reject_execution_directives(value: JsonValue, path: str) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = key.casefold().replace("-", "_")
            if normalized in PROHIBITED_EXECUTION_KEYS:
                raise ExecutionDirectiveError(
                    f"Command-like key '{key}' is prohibited in no-execution data at '{path}'."
                )
            reject_execution_directives(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            reject_execution_directives(child, f"{path}[{index}]")


def compile_campaign(lease: JsonObject, campaign: JsonObject, now: datetime) -> list[CompiledStep]:
    campaign_id = require_string(campaign.get("campaign_id"), "campaign_id")
    lease_id = require_string(lease.get("lease_id"), "lease_id")
    approvals = require_list(lease.get("approvals"), "approvals")
    cleanup_requirements = require_string_list(lease.get("cleanup_requirements"), "cleanup_requirements")
    prohibited_actions = require_string_list(lease.get("prohibited_actions"), "prohibited_actions")
    budgets = require_object(lease.get("budgets"), "budgets")
    expires_at = require_string(lease.get("expires_at"), "expires_at")
    compiled: list[CompiledStep] = []
    for step in ordered_steps(campaign):
        target, effect_class = evaluate_step_scope(lease, campaign, step)
        step_id = require_string(step.get("step_id"), "step.step_id")
        target_id = require_string(step.get("target_id"), f"{step_id}.target_id")
        capability = require_string(step.get("capability"), f"{step_id}.capability")
        connector_id = require_string(step.get("connector_id"), f"{step_id}.connector_id")
        cleanup_step_id = require_string(step.get("cleanup_step_id"), f"{step_id}.cleanup_step_id")
        preconditions = require_string_list(step.get("preconditions"), f"{step_id}.preconditions")
        expected_state_delta = require_object(step.get("expected_state_delta"), f"{step_id}.expected_state_delta")
        oracles = require_list(step.get("verification_oracles"), f"{step_id}.verification_oracles")
        binding = require_object(target.get("binding"), f"target_graph[{target_id}].binding")
        reject_execution_directives(expected_state_delta, f"{step_id}.expected_state_delta")
        reject_execution_directives(binding, f"target_graph[{target_id}].binding")
        resource_type = require_string(target.get("resource_type"), f"target_graph[{target_id}].resource_type")
        envelope: JsonObject = {
            "envelope_version": "0.1.0",
            "event_id": deterministic_uuid(campaign_id, step_id, "action"),
            "mission_id": campaign_id,
            "timestamp": format_timestamp(now),
            "origin": "simulated",
            "actor": {
                "principal_id": "service:nimrod-no-execution-simulator",
                "actor_type": "service",
                "authentication": [],
                "device_attestation": None,
                "workload_attestation": None,
            },
            "intent": {
                "operation": "simulate_typed_campaign_step_without_execution",
                "purpose": "Compile and witness a bounded Crucible step without changing any target",
                "target": {
                    "resource_type": resource_type,
                    "resource_id": target_id,
                    "binding": binding,
                },
                "requested_capability": capability,
            },
            "context": {
                "data_classification": "internal",
                "incident_id": None,
                "supporting_evidence": [],
                "contradicting_evidence": [],
                "uncertainties": [
                    "Lease signatures are structural fixture references and were not cryptographically verified",
                    "No live connector, command, target mutation, sensor, or defensive control was exercised",
                ],
            },
            "risk": {
                "impact": "none",
                "confidence_interval": [0.0, 0.0],
                "blast_radius": "no target state; no-execution simulator only",
                "reversibility": "fully_reversible",
                "urgency": "routine",
            },
            "execution_contract": {
                "preconditions": preconditions,
                "expected_state_delta": expected_state_delta,
                "prohibited_side_effects": prohibited_actions,
                "resource_limits": {
                    "maximum_actions": require_integer(budgets.get("maximum_actions"), "budgets.maximum_actions"),
                    "maximum_seconds": require_integer(budgets.get("maximum_seconds"), "budgets.maximum_seconds"),
                    "live_execution": False,
                },
                "idempotency_key": deterministic_uuid(campaign_id, step_id, "idempotency"),
                "expires_at": expires_at,
            },
            "recovery": {
                "snapshot_required": False,
                "rollback_operation": cleanup_step_id,
                "compensation_plan": cleanup_requirements,
            },
            "verification": {
                "required_oracles": oracles,
                "independent_verifiers": oracles,
                "success_postconditions": [
                    "The no-op connector reports no target state change",
                    "Witness artifacts retain simulated origin and pass content-hash verification",
                ],
                "failure_postconditions": [
                    "Any target state change, missing cleanup proof, ambiguity, or evidence-integrity failure is non-success"
                ],
            },
            "authorization": {
                "policy_decision": "allow",
                "policy_version": f"simulator-structural-only:{lease_id}",
                "approvals": approvals,
            },
            "signatures": [],
        }
        compiled.append(
            {
                "step_id": step_id,
                "sequence": require_integer(step.get("sequence"), f"{step_id}.sequence"),
                "connector_id": connector_id,
                "capability": capability,
                "target_id": target_id,
                "effect_class": effect_class,
                "cleanup_step_id": cleanup_step_id,
                "action_envelope": envelope,
            }
        )
    return compiled
