"""Governed proposal-only offensive and defensive swarm reference runtime."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from nimrod_simulator.authorization import evaluate_lease_state, parse_control_state
from nimrod_simulator.authorization_crypto import verify_authorization
from nimrod_simulator.compiler import deterministic_uuid, format_timestamp
from nimrod_simulator.errors import SwarmBudgetError, SwarmMissionError, SwarmSeparationError
from nimrod_simulator.jsonio import (
    require_integer,
    require_list,
    require_object,
    require_string,
    require_string_list,
    sha256_digest,
    validate_contract,
)
from nimrod_simulator.model import ArtifactReference, JsonObject, SwarmReviewResult
from nimrod_simulator.witness import FileWitnessStore, verify_witness_store


REQUIRED_SWARM_ROLES = {
    "offensive_planner",
    "defensive_hunter",
    "purple_compiler",
    "evidence_analyst",
    "recovery_planner",
    "independent_verifier",
    "safety_governor",
}

ROLE_WORK_TYPES: dict[str, set[str]] = {
    "offensive_planner": {"hypothesize"},
    "defensive_hunter": {"challenge_coverage"},
    "purple_compiler": {"compile_typed_test"},
    "evidence_analyst": {"assess_evidence"},
    "recovery_planner": {"plan_recovery"},
    "independent_verifier": {"assess_evidence"},
    "safety_governor": {"review_safety"},
}

ROLE_CONTRIBUTIONS: dict[str, tuple[str, str, float, str | None]] = {
    "offensive_planner": (
        "support",
        "The narrow simulated technique is sufficient to challenge the declared causal path without widening scope",
        0.6,
        "range.test.simulate",
    ),
    "defensive_hunter": (
        "oppose",
        "No real sensor or detector evidence exists, so defensive coverage remains unproven",
        0.1,
        None,
    ),
    "purple_compiler": (
        "support",
        "The hypothesis can compile into the fixed typed no-op capability without a command bridge",
        0.2,
        "range.test.simulate",
    ),
    "evidence_analyst": (
        "oppose",
        "Structural evidence completeness cannot establish real prevention, detection, response, or recovery",
        0.1,
        None,
    ),
    "recovery_planner": (
        "support",
        "Cleanup is explicit and the no-op proposal creates no target state requiring restoration",
        0.2,
        None,
    ),
    "independent_verifier": (
        "abstain",
        "An independent process must verify authorization and Witness integrity before advancement",
        0.5,
        None,
    ),
    "safety_governor": (
        "support",
        "The mission remains inside simulated proposal-only authority with no executor present",
        0.1,
        None,
    ),
}


def cell_index(mission: JsonObject) -> dict[str, JsonObject]:
    cell_values = require_list(mission.get("cells"), "cells")
    result: dict[str, JsonObject] = {}
    observed_roles: set[str] = set()
    for index, cell_value in enumerate(cell_values):
        cell = require_object(cell_value, f"cells[{index}]")
        agent_id = require_string(cell.get("agent_id"), f"cells[{index}].agent_id")
        role = require_string(cell.get("role"), f"cells[{index}].role")
        if agent_id in result:
            raise SwarmSeparationError(f"Swarm mission contains duplicate agent_id '{agent_id}'.")
        if role in observed_roles:
            raise SwarmSeparationError(
                f"Swarm role '{role}' is duplicated; role diversity cannot be manufactured by clones."
            )
        observed_roles.add(role)
        result[agent_id] = cell
    missing_roles = sorted(REQUIRED_SWARM_ROLES - observed_roles)
    if missing_roles:
        raise SwarmSeparationError(
            f"Swarm mission lacks required independent roles: {', '.join(missing_roles)}."
        )
    return result


def validate_work_graph(
    mission: JsonObject,
    lease: JsonObject,
    campaign: JsonObject,
    cells: dict[str, JsonObject],
) -> list[JsonObject]:
    target_values = require_list(lease.get("target_graph"), "target_graph")
    allowed_targets = {
        require_string(require_object(value, "target_graph item").get("stable_id"), "target_graph.stable_id")
        for value in target_values
    }
    allowed_techniques = set(require_string_list(lease.get("allowed_techniques"), "allowed_techniques"))
    campaign_steps = require_list(campaign.get("steps"), "campaign.steps")
    campaign_targets = {
        require_string(require_object(value, "campaign step").get("target_id"), "campaign.step.target_id")
        for value in campaign_steps
    }
    work_values = require_list(mission.get("work_items"), "work_items")
    work_items: list[JsonObject] = []
    work_by_id: dict[str, JsonObject] = {}
    assigned_counts: dict[str, int] = {}
    for index, work_value in enumerate(work_values):
        work = require_object(work_value, f"work_items[{index}]")
        work_id = require_string(work.get("work_id"), f"work_items[{index}].work_id")
        if work_id in work_by_id:
            raise SwarmMissionError(f"Swarm mission contains duplicate work_id '{work_id}'.")
        agent_id = require_string(work.get("assigned_agent_id"), f"{work_id}.assigned_agent_id")
        cell = cells.get(agent_id)
        if cell is None:
            raise SwarmMissionError(f"Work item '{work_id}' references unknown agent '{agent_id}'.")
        role = require_string(cell.get("role"), f"cell[{agent_id}].role")
        work_type = require_string(work.get("work_type"), f"{work_id}.work_type")
        if work_type not in ROLE_WORK_TYPES[role]:
            raise SwarmSeparationError(
                f"Role '{role}' cannot perform work type '{work_type}' for '{work_id}'."
            )
        target_id = require_string(work.get("target_id"), f"{work_id}.target_id")
        if target_id not in allowed_targets:
            raise SwarmMissionError(
                f"Work item '{work_id}' target '{target_id}' is outside the immutable lease target graph."
            )
        if target_id not in campaign_targets:
            raise SwarmMissionError(
                f"Work item '{work_id}' target '{target_id}' is not present in the bound validation campaign."
            )
        technique_id = require_string(work.get("technique_id"), f"{work_id}.technique_id")
        if technique_id not in allowed_techniques:
            raise SwarmMissionError(
                f"Work item '{work_id}' technique '{technique_id}' is not allowed by the lease."
            )
        assigned_counts[agent_id] = assigned_counts.get(agent_id, 0) + 1
        work_items.append(work)
        work_by_id[work_id] = work
    for agent_id, count in assigned_counts.items():
        budget = require_object(cells[agent_id].get("work_budget"), f"cell[{agent_id}].work_budget")
        maximum = require_integer(budget.get("maximum_items"), f"cell[{agent_id}].maximum_items")
        if count > maximum:
            raise SwarmBudgetError(
                f"Agent '{agent_id}' has {count} work items; maximum is {maximum}."
            )
    dependencies: dict[str, set[str]] = {}
    for work in work_items:
        work_id = require_string(work.get("work_id"), "work_id")
        dependency_ids = set(require_string_list(work.get("depends_on"), f"{work_id}.depends_on"))
        missing = sorted(dependency_ids - set(work_by_id))
        if missing:
            raise SwarmMissionError(
                f"Work item '{work_id}' has missing dependencies: {', '.join(missing)}."
            )
        dependencies[work_id] = dependency_ids
    ordered: list[JsonObject] = []
    resolved: set[str] = set()
    while len(ordered) < len(work_items):
        ready = sorted(
            work_id
            for work_id, dependency_ids in dependencies.items()
            if work_id not in resolved and dependency_ids <= resolved
        )
        if not ready:
            unresolved = sorted(set(dependencies) - resolved)
            raise SwarmMissionError(
                f"Swarm work dependency graph contains a cycle: {', '.join(unresolved)}."
            )
        for work_id in ready:
            ordered.append(work_by_id[work_id])
            resolved.add(work_id)
    return ordered


def build_contributions(
    cells: dict[str, JsonObject],
    proof_reference: JsonObject,
) -> list[JsonObject]:
    contributions: list[JsonObject] = []
    for agent_id in sorted(cells):
        cell = cells[agent_id]
        role = require_string(cell.get("role"), f"cell[{agent_id}].role")
        stance, claim, uncertainty, proposed_capability = ROLE_CONTRIBUTIONS[role]
        contributions.append(
            {
                "agent_id": agent_id,
                "role": role,
                "stance": stance,
                "claim": claim,
                "evidence": [proof_reference],
                "uncertainty": uncertainty,
                "proposed_capability": proposed_capability,
            }
        )
    return contributions


def run_swarm_review(
    project_root: Path,
    lease: JsonObject,
    campaign: JsonObject,
    mission: JsonObject,
    proof_bundle: JsonObject,
    trust_policy: JsonObject,
    control_state: JsonObject,
    output_root: Path,
    now: datetime,
) -> SwarmReviewResult:
    specs_root = project_root / "specs"
    contract_inputs: tuple[tuple[JsonObject, str, str], ...] = (
        (lease, "authorization-lease.schema.json", "authorization lease"),
        (campaign, "validation-campaign.schema.json", "validation campaign"),
        (mission, "swarm-mission.schema.json", "swarm mission"),
        (proof_bundle, "authorization-proof-bundle.schema.json", "authorization proof bundle"),
        (trust_policy, "authorization-trust-policy.schema.json", "authorization trust policy"),
    )
    for document, schema_name, label in contract_inputs:
        validate_contract(document, specs_root / schema_name, label)
    control = parse_control_state(control_state)
    evaluate_lease_state(lease, control, now)
    authorization = verify_authorization(lease, proof_bundle, trust_policy, now)
    lease_id = require_string(lease.get("lease_id"), "lease_id")
    mission_lease_id = require_string(mission.get("authorization_lease_id"), "authorization_lease_id")
    if mission_lease_id != lease_id:
        raise SwarmMissionError(
            f"Swarm mission references lease '{mission_lease_id}', but supplied lease is '{lease_id}'."
        )
    campaign_lease_id = require_string(campaign.get("authorization_lease_id"), "campaign.authorization_lease_id")
    if campaign_lease_id != lease_id:
        raise SwarmMissionError(
            f"Validation campaign references lease '{campaign_lease_id}', but supplied lease is '{lease_id}'."
        )
    cells = cell_index(mission)
    validate_work_graph(mission, lease, campaign, cells)
    proof_reference: JsonObject = {
        "id": f"authorization-proof:{require_string(proof_bundle.get('bundle_id'), 'bundle_id')}",
        "digest": sha256_digest(proof_bundle),
    }
    contributions = build_contributions(cells, proof_reference)
    support = sum(1 for contribution in contributions if contribution["stance"] == "support")
    oppose = sum(1 for contribution in contributions if contribution["stance"] == "oppose")
    vetoes = sum(1 for contribution in contributions if contribution["stance"] == "veto")
    distinct_roles = {require_string(contribution.get("role"), "contribution.role") for contribution in contributions}
    separation = require_object(mission.get("separation_rules"), "separation_rules")
    required_roles = require_integer(
        separation.get("minimum_distinct_roles"), "separation_rules.minimum_distinct_roles"
    )
    quorum_satisfied = len(distinct_roles) >= required_roles and vetoes == 0
    mission_id = require_string(mission.get("mission_id"), "mission_id")
    dissent = [
        require_string(contribution.get("claim"), "contribution.claim")
        for contribution in contributions
        if contribution["stance"] in {"oppose", "abstain", "veto"}
    ]
    verdict: JsonObject = {
        "verdict_version": "0.1.0",
        "verdict_id": deterministic_uuid(mission_id, "swarm", "verdict"),
        "mission_id": mission_id,
        "origin": "simulated",
        "status": "proposal_ready" if quorum_satisfied else "blocked",
        "contributions": contributions,
        "quorum": {
            "required_distinct_roles": required_roles,
            "observed_distinct_roles": len(distinct_roles),
            "support": support,
            "oppose": oppose,
            "vetoes": vetoes,
            "satisfied": quorum_satisfied,
        },
        "authority": {
            "execution_authorized": False,
            "maximum_outcome": "typed_proposal",
            "reason": "Swarm consensus cannot grant execution authority",
        },
        "dissent": dissent,
        "uncertainties": [
            "Contributions are deterministic reference-cell outputs, not model or operator judgments",
            "No live target, connector, sensor, defensive control, or recovery mechanism was exercised",
        ],
        "next_gate": "Independent process verification before isolated-range connector design",
    }
    validate_contract(verdict, specs_root / "swarm-verdict.schema.json", "swarm verdict")
    observed_at = format_timestamp(now)
    store = FileWitnessStore(output_root)
    mission_reference = store.append("swarm-mission", mission, observed_at)
    verdict_reference = store.append("swarm-verdict", verdict, observed_at)
    witness_count = verify_witness_store(output_root)
    artifacts: list[ArtifactReference] = [mission_reference, verdict_reference]
    return {
        "review_version": "0.1.0",
        "origin": "simulated",
        "status": require_string(verdict.get("status"), "verdict.status"),
        "mission_id": mission_id,
        "cryptographic_authorization_verified": authorization[
            "cryptographic_authorization_verified"
        ],
        "execution_authorized": False,
        "distinct_role_count": len(distinct_roles),
        "contribution_count": len(contributions),
        "dissent_count": len(dissent),
        "witness_entries_verified": witness_count,
        "artifacts": artifacts,
    }
