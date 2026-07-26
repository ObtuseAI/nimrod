"""Display-only Foundry assurance projection for the nimrod control board."""

from __future__ import annotations

from nimrod_simulator.errors import ControlBoardProjectionError
from nimrod_simulator.evolution_foundry import REQUIRED_EVALUATOR_ROLES
from nimrod_simulator.jsonio import require_boolean, require_list, require_object, require_string, sha256_digest
from nimrod_simulator.model import JsonObject


FOUNDRY_PROJECTION_AUTHORITY = {
    "can_promote": False,
    "can_execute": False,
    "can_modify_evaluators": False,
    "can_expand_resources": False,
}


def project_foundry_control_board(
    evaluation: JsonObject,
    assurance: JsonObject,
    captured_at: str,
) -> JsonObject:
    candidate_digest = require_string(evaluation.get("candidate_digest"), "evaluation.candidate_digest")
    if assurance.get("candidate_digest") != candidate_digest:
        raise ControlBoardProjectionError("Foundry assurance candidate does not bind the evaluation.")
    evaluator_values = require_list(assurance.get("evaluator_verifications"), "assurance.evaluator_verifications")
    evaluators = [
        require_object(value, f"assurance.evaluator_verifications[{index}]")
        for index, value in enumerate(evaluator_values)
    ]
    roles = {require_string(value.get("role"), "evaluator.role") for value in evaluators}
    evaluator_ids = {require_string(value.get("evaluator_id"), "evaluator.evaluator_id") for value in evaluators}
    principals = {
        require_string(value.get("logical_principal"), "evaluator.logical_principal") for value in evaluators
    }
    process_ids = {value.get("process_id") for value in evaluators}
    if (
        roles != REQUIRED_EVALUATOR_ROLES
        or len(evaluator_ids) != 4
        or len(principals) != 4
        or len(process_ids) != 4
    ):
        raise ControlBoardProjectionError(
            "Foundry projection requires four distinct evaluator roles, identities, principals, and processes."
        )
    resource_verification = require_object(
        assurance.get("resource_ledger_verification"), "assurance.resource_ledger_verification"
    )
    if resource_verification.get("ledger_digest") != assurance.get("resource_ledger_digest"):
        raise ControlBoardProjectionError("Foundry resource-ledger verification digest was substituted.")
    signed_evaluators_complete = all(value.get("signature_verified") is True for value in evaluators)
    isolation_contract_complete = all(value.get("isolation_boundary_verified") is True for value in evaluators)
    live_isolation_verified = all(value.get("production_isolation_verified") is True for value in evaluators)
    resource_within_constitution = require_boolean(
        resource_verification.get("within_constitution"),
        "assurance.resource_ledger_verification.within_constitution",
    )
    contract_boundary_verified = require_boolean(
        assurance.get("contract_boundary_verified"), "assurance.contract_boundary_verified"
    )
    derived_contract_boundary = (
        signed_evaluators_complete and isolation_contract_complete and resource_within_constitution
    )
    if contract_boundary_verified != derived_contract_boundary:
        raise ControlBoardProjectionError("Foundry assurance contract-boundary result is internally inconsistent.")
    evaluation_eligible = evaluation.get("status") == "eligible_for_shadow" and evaluation.get("blockers") == []
    shadow_eligible = evaluation_eligible and contract_boundary_verified
    blockers: list[str] = []
    if not evaluation_eligible:
        blockers.append("EVALUATION_NOT_SHADOW_ELIGIBLE")
    if not signed_evaluators_complete:
        blockers.append("SIGNED_EVALUATOR_QUORUM_INCOMPLETE")
    if not isolation_contract_complete:
        blockers.append("EVALUATOR_OS_ISOLATION_INCOMPLETE")
    if not resource_within_constitution:
        blockers.append("LINEAGE_RESOURCE_LEDGER_BLOCKED")
    if not live_isolation_verified:
        blockers.append("LIVE_OS_ISOLATION_UNPROVEN")
    operator_state = "blocked"
    if shadow_eligible:
        operator_state = "shadow_eligible_live_isolation" if live_isolation_verified else "shadow_eligible_contract_only"
    production_ready = False
    evaluator_mesh = [
        {
            "evaluator_id": value["evaluator_id"],
            "logical_principal": value["logical_principal"],
            "process_id": value["process_id"],
            "role": value["role"],
            "status": value["status"],
            "signature_verified": value["signature_verified"],
            "isolation_boundary_verified": value["isolation_boundary_verified"],
            "production_isolation_verified": value["production_isolation_verified"],
            "envelope_digest": value["envelope_digest"],
            "isolation_attestation_digest": value["isolation_attestation_digest"],
        }
        for value in sorted(evaluators, key=lambda item: str(item["role"]))
    ]
    return {
        "projection_version": "0.1.0",
        "origin": assurance["origin"],
        "captured_at": captured_at,
        "candidate_digest": candidate_digest,
        "evaluation_digest": sha256_digest(evaluation),
        "assurance_digest": sha256_digest(assurance),
        "operator_state": operator_state,
        "severity": "contract_valid" if shadow_eligible else "blocked",
        "summary": (
            "Signed evaluator observations, isolation contracts, and lineage resource accounting permit shadow evaluation only."
            if shadow_eligible
            else "Foundry assurance is incomplete; shadow evaluation and production promotion remain blocked."
        ),
        "evaluator_mesh": evaluator_mesh,
        "resource_lineage": {
            "ledger_id": resource_verification["ledger_id"],
            "lineage_id": resource_verification["lineage_id"],
            "ledger_digest": resource_verification["ledger_digest"],
            "head_entry_digest": resource_verification["head_entry_digest"],
            "entry_count": resource_verification["entry_count"],
            "status": resource_verification["status"],
            "totals": resource_verification["totals"],
            "blockers": resource_verification["blockers"],
        },
        "boundary": {
            "signed_evaluators_complete": signed_evaluators_complete,
            "os_isolation_contract_complete": isolation_contract_complete,
            "live_os_enforcement_verified": live_isolation_verified,
            "resource_ledger_within_constitution": resource_within_constitution,
            "shadow_eligible": shadow_eligible,
            "production_ready": production_ready,
            "missing_controls": sorted(blockers),
        },
        "authority": FOUNDRY_PROJECTION_AUTHORITY,
    }
