"""Assurance-bound autonomous threshold promotion for Tier A/B shadow lanes."""

from __future__ import annotations

from datetime import datetime
from typing import cast

from nimrod_simulator.errors import AutonomousPromotionError
from nimrod_simulator.evaluator_observation import EVALUATOR_ASSURANCE_AUTHORITY, evaluation_input_digest
from nimrod_simulator.evolution_constitution import REQUIRED_TIER_POLICIES, verify_evolution_constitution
from nimrod_simulator.evolution_foundry import REQUIRED_EVALUATOR_ROLES
from nimrod_simulator.evolution_transition import EvolutionTransitionStore, verify_evolution_transition
from nimrod_simulator.jsonio import require_integer, require_list, require_object, require_string, sha256_digest
from nimrod_simulator.model import JsonObject


AUTONOMOUS_PROMOTION_AUTHORITY = {
    "can_sign": False,
    "can_select_signers": False,
    "can_select_evaluators": False,
    "can_modify_constitution": False,
    "can_modify_active_baseline": False,
    "can_execute_candidate": False,
    "can_promote_to_production": False,
    "can_expand_authority": False,
}
AUTONOMOUS_TIERS = frozenset({"A", "B"})


def _object_list(value: object, field: str) -> list[JsonObject]:
    values = require_list(value, field)
    if not all(isinstance(item, dict) for item in values):
        raise AutonomousPromotionError(f"Autonomous promotion field '{field}' must contain only objects.")
    return cast(list[JsonObject], values)


def _verify_assurance_binding(
    candidate: JsonObject,
    evaluation: JsonObject,
    capability_report: JsonObject,
    assurance: JsonObject,
) -> JsonObject:
    candidate_digest = sha256_digest(candidate)
    constitution_digest = require_string(candidate.get("constitution_digest"), "candidate.constitution_digest")
    capability_digest = sha256_digest(capability_report)
    if evaluation.get("candidate_digest") != candidate_digest:
        raise AutonomousPromotionError("Autonomous promotion evaluation candidate binding is invalid.")
    if evaluation.get("constitution_digest") != constitution_digest:
        raise AutonomousPromotionError("Autonomous promotion evaluation Constitution binding is invalid.")
    if evaluation.get("capability_report_digest") != capability_digest:
        raise AutonomousPromotionError("Autonomous promotion evaluation capability binding is invalid.")
    expected_input_digest = evaluation_input_digest(
        capability_report,
        _object_list(evaluation.get("hard_gate_results"), "evaluation.hard_gate_results"),
        _object_list(evaluation.get("champion_floor_results"), "evaluation.champion_floor_results"),
        _object_list(evaluation.get("metrics"), "evaluation.metrics"),
    )
    if assurance.get("assurance_version") != "0.1.0":
        raise AutonomousPromotionError("Autonomous promotion requires evaluator assurance version 0.1.0.")
    if assurance.get("origin") != candidate.get("origin"):
        raise AutonomousPromotionError("Autonomous promotion assurance origin differs from its candidate.")
    if assurance.get("candidate_digest") != candidate_digest:
        raise AutonomousPromotionError("Autonomous promotion assurance candidate binding is invalid.")
    if assurance.get("constitution_digest") != constitution_digest:
        raise AutonomousPromotionError("Autonomous promotion assurance Constitution binding is invalid.")
    if assurance.get("evaluation_input_digest") != expected_input_digest:
        raise AutonomousPromotionError("Autonomous promotion assurance input binding is invalid.")
    if assurance.get("contract_boundary_verified") is not True:
        raise AutonomousPromotionError("Autonomous promotion requires a verified evaluator contract boundary.")
    if assurance.get("production_promotion_authorized") is not False:
        raise AutonomousPromotionError("Autonomous promotion assurance attempted production authority.")
    if require_object(assurance.get("authority"), "assurance.authority") != EVALUATOR_ASSURANCE_AUTHORITY:
        raise AutonomousPromotionError("Autonomous promotion assurance authority was widened.")
    resource_verification = require_object(
        assurance.get("resource_ledger_verification"),
        "assurance.resource_ledger_verification",
    )
    if resource_verification.get("within_constitution") is not True or resource_verification.get("status") != "within_constitution":
        raise AutonomousPromotionError("Autonomous promotion resource lineage is outside its Constitution.")
    verifications = _object_list(assurance.get("evaluator_verifications"), "assurance.evaluator_verifications")
    roles: set[str] = set()
    evaluator_ids: set[str] = set()
    principals: set[str] = set()
    process_ids: set[int] = set()
    for verification in verifications:
        roles.add(require_string(verification.get("role"), "evaluator.role"))
        evaluator_ids.add(require_string(verification.get("evaluator_id"), "evaluator.evaluator_id"))
        principals.add(require_string(verification.get("logical_principal"), "evaluator.logical_principal"))
        process_ids.add(require_integer(verification.get("process_id"), "evaluator.process_id"))
        if verification.get("signature_verified") is not True or verification.get("isolation_boundary_verified") is not True:
            raise AutonomousPromotionError("Autonomous promotion contains an unsigned or boundary-unverified evaluator.")
        if verification.get("candidate_digest") not in {None, candidate_digest}:
            raise AutonomousPromotionError("Autonomous promotion evaluator candidate binding is invalid.")
    if (
        roles != REQUIRED_EVALUATOR_ROLES
        or len(evaluator_ids) != len(REQUIRED_EVALUATOR_ROLES)
        or len(principals) != len(REQUIRED_EVALUATOR_ROLES)
        or len(process_ids) != len(REQUIRED_EVALUATOR_ROLES)
    ):
        raise AutonomousPromotionError(
            "Autonomous promotion requires four distinct evaluator roles, identities, principals, and processes."
        )
    return {
        "candidate_digest": candidate_digest,
        "constitution_digest": constitution_digest,
        "capability_report_digest": capability_digest,
        "evaluation_digest": sha256_digest(evaluation),
        "assurance_digest": sha256_digest(assurance),
        "evaluation_input_digest": expected_input_digest,
        "evaluator_count": len(verifications),
    }


def _verify_common_job(
    job: JsonObject,
    now: datetime,
    maximum_constitution_lifetime_seconds: int,
    maximum_transition_lifetime_seconds: int,
) -> tuple[JsonObject, JsonObject, JsonObject, JsonObject, JsonObject, JsonObject, JsonObject, JsonObject]:
    if set(job) != {
        "job_version",
        "job_id",
        "origin",
        "mode",
        "candidate",
        "evaluation",
        "capability_report",
        "assurance",
        "constitution",
        "governance_state",
        "transition_envelope",
        "authority",
    }:
        raise AutonomousPromotionError("Autonomous promotion job fields are incomplete or widened.")
    if job.get("job_version") != "0.1.0" or job.get("mode") != "autonomous_threshold":
        raise AutonomousPromotionError("Autonomous promotion job identity or mode is invalid.")
    require_string(job.get("job_id"), "job.job_id")
    if require_object(job.get("authority"), "job.authority") != AUTONOMOUS_PROMOTION_AUTHORITY:
        raise AutonomousPromotionError("Autonomous promotion job authority was widened.")
    candidate = require_object(job.get("candidate"), "job.candidate")
    evaluation = require_object(job.get("evaluation"), "job.evaluation")
    capability_report = require_object(job.get("capability_report"), "job.capability_report")
    assurance = require_object(job.get("assurance"), "job.assurance")
    constitution = require_object(job.get("constitution"), "job.constitution")
    governance_state = require_object(job.get("governance_state"), "job.governance_state")
    envelope = require_object(job.get("transition_envelope"), "job.transition_envelope")
    if job.get("origin") != candidate.get("origin") or job.get("origin") != "simulated":
        raise AutonomousPromotionError("Autonomous promotion replay requires an explicit simulated origin.")
    authority_tier = require_string(candidate.get("authority_tier"), "candidate.authority_tier")
    if authority_tier not in AUTONOMOUS_TIERS:
        raise AutonomousPromotionError("Autonomous promotion is restricted to Tier A/B candidates.")
    constitution_verification = verify_evolution_constitution(
        constitution,
        governance_state,
        now,
        maximum_constitution_lifetime_seconds,
    )
    tier_policy = REQUIRED_TIER_POLICIES[authority_tier]
    if tier_policy != ("shadow", False):
        raise AutonomousPromotionError("Autonomous promotion tier requires human approval or exceeds shadow.")
    assurance_verification = _verify_assurance_binding(candidate, evaluation, capability_report, assurance)
    transition_verification = verify_evolution_transition(
        envelope,
        candidate,
        evaluation,
        capability_report,
        constitution,
        governance_state,
        now,
        maximum_constitution_lifetime_seconds,
        maximum_transition_lifetime_seconds,
    )
    if len(cast(list[object], transition_verification["verified_signer_ids"])) < 2:
        raise AutonomousPromotionError("Autonomous promotion threshold requires at least two signers.")
    if len(cast(list[object], transition_verification["verified_roles"])) < 2:
        raise AutonomousPromotionError("Autonomous promotion threshold requires at least two signer roles.")
    return (
        candidate,
        evaluation,
        capability_report,
        assurance,
        constitution,
        governance_state,
        envelope,
        {**constitution_verification, **assurance_verification, **transition_verification},
    )


def verify_autonomous_shadow_promotion_job(
    job: JsonObject,
    now: datetime,
    maximum_constitution_lifetime_seconds: int,
    maximum_transition_lifetime_seconds: int,
) -> JsonObject:
    values = _verify_common_job(
        job,
        now,
        maximum_constitution_lifetime_seconds,
        maximum_transition_lifetime_seconds,
    )
    candidate, evaluation, capability_report, assurance, _, _, _, verified = values
    if verified.get("action") != "register_shadow" or verified.get("destination") != "shadow":
        raise AutonomousPromotionError("Autonomous shadow promotion requires the register_shadow transition.")
    if evaluation.get("status") != "eligible_for_shadow" or require_list(evaluation.get("blockers"), "evaluation.blockers"):
        raise AutonomousPromotionError("Autonomous shadow promotion requires a blocker-free eligible evaluation.")
    if capability_report.get("status") != "clear" or capability_report.get("paused") is not False:
        raise AutonomousPromotionError("Autonomous shadow promotion requires clear capability thresholds.")
    if assurance.get("shadow_evaluation_eligible") is not True:
        raise AutonomousPromotionError("Autonomous shadow promotion requires positive signed evaluator assurance.")
    if candidate.get("candidate_executed") is not False or candidate.get("active_baseline_modified") is not False:
        raise AutonomousPromotionError("Autonomous shadow promotion candidate already claims execution or mutation.")
    return {
        "status": "autonomous_threshold_shadow_eligible",
        "job_id": job["job_id"],
        "candidate_id": candidate["candidate_id"],
        "candidate_digest": verified["candidate_digest"],
        "authority_tier": candidate["authority_tier"],
        "action": "register_shadow",
        "destination": "shadow",
        "verified_signer_ids": verified["verified_signer_ids"],
        "verified_roles": verified["verified_roles"],
        "evaluator_count": verified["evaluator_count"],
        "human_approval_required": False,
        "production_promotion_authorized": False,
        "candidate_executed": False,
        "active_baseline_modified": False,
        "authority": AUTONOMOUS_PROMOTION_AUTHORITY,
    }


def _regression_signal_count(evaluation: JsonObject) -> int:
    evaluator_failures = sum(
        1
        for value in _object_list(evaluation.get("evaluator_observations"), "evaluation.evaluator_observations")
        if value.get("status") != "pass"
    )
    gate_failures = sum(
        1
        for value in _object_list(evaluation.get("hard_gate_results"), "evaluation.hard_gate_results")
        if value.get("status") != "pass"
    )
    floor_failures = sum(
        1
        for value in _object_list(evaluation.get("champion_floor_results"), "evaluation.champion_floor_results")
        if value.get("status") != "pass"
    )
    metric_failures = sum(
        1
        for value in _object_list(evaluation.get("metrics"), "evaluation.metrics")
        if value.get("outcome") in {"regressed", "unknown"}
    )
    return evaluator_failures + gate_failures + floor_failures + metric_failures


def verify_autonomous_regression_demotion_job(
    job: JsonObject,
    now: datetime,
    maximum_constitution_lifetime_seconds: int,
    maximum_transition_lifetime_seconds: int,
) -> JsonObject:
    values = _verify_common_job(
        job,
        now,
        maximum_constitution_lifetime_seconds,
        maximum_transition_lifetime_seconds,
    )
    candidate, evaluation, _, assurance, _, _, _, verified = values
    if verified.get("action") != "demote" or verified.get("destination") != "quarantine":
        raise AutonomousPromotionError("Autonomous regression demotion requires the demote transition.")
    regression_signal_count = _regression_signal_count(evaluation)
    if evaluation.get("status") != "blocked" or regression_signal_count <= 0:
        raise AutonomousPromotionError("Autonomous demotion requires a blocked evaluation with a regression signal.")
    if assurance.get("shadow_evaluation_eligible") is not False:
        raise AutonomousPromotionError("Autonomous demotion assurance cannot remain shadow eligible.")
    return {
        "status": "autonomous_threshold_demotion_required",
        "job_id": job["job_id"],
        "candidate_id": candidate["candidate_id"],
        "candidate_digest": verified["candidate_digest"],
        "authority_tier": candidate["authority_tier"],
        "action": "demote",
        "destination": "quarantine",
        "regression_signal_count": regression_signal_count,
        "verified_signer_ids": verified["verified_signer_ids"],
        "verified_roles": verified["verified_roles"],
        "evaluator_count": verified["evaluator_count"],
        "human_approval_required": False,
        "production_promotion_authorized": False,
        "candidate_executed": False,
        "active_baseline_modified": False,
        "authority": AUTONOMOUS_PROMOTION_AUTHORITY,
    }


def apply_autonomous_shadow_promotion(
    store: EvolutionTransitionStore,
    job: JsonObject,
    now: datetime,
    maximum_constitution_lifetime_seconds: int,
    maximum_transition_lifetime_seconds: int,
) -> JsonObject:
    decision = verify_autonomous_shadow_promotion_job(
        job,
        now,
        maximum_constitution_lifetime_seconds,
        maximum_transition_lifetime_seconds,
    )
    receipt = store.apply(
        require_object(job.get("transition_envelope"), "job.transition_envelope"),
        require_object(job.get("candidate"), "job.candidate"),
        require_object(job.get("evaluation"), "job.evaluation"),
        require_object(job.get("capability_report"), "job.capability_report"),
        require_object(job.get("constitution"), "job.constitution"),
        require_object(job.get("governance_state"), "job.governance_state"),
        now,
        maximum_constitution_lifetime_seconds,
        maximum_transition_lifetime_seconds,
    )
    if receipt.get("status") != "shadow_candidate_registered":
        raise AutonomousPromotionError("Autonomous promotion store returned a non-shadow receipt.")
    return {"decision": decision, "transition_receipt": receipt}


def apply_autonomous_regression_demotion(
    store: EvolutionTransitionStore,
    job: JsonObject,
    now: datetime,
    maximum_constitution_lifetime_seconds: int,
    maximum_transition_lifetime_seconds: int,
) -> JsonObject:
    decision = verify_autonomous_regression_demotion_job(
        job,
        now,
        maximum_constitution_lifetime_seconds,
        maximum_transition_lifetime_seconds,
    )
    receipt = store.apply(
        require_object(job.get("transition_envelope"), "job.transition_envelope"),
        require_object(job.get("candidate"), "job.candidate"),
        require_object(job.get("evaluation"), "job.evaluation"),
        require_object(job.get("capability_report"), "job.capability_report"),
        require_object(job.get("constitution"), "job.constitution"),
        require_object(job.get("governance_state"), "job.governance_state"),
        now,
        maximum_constitution_lifetime_seconds,
        maximum_transition_lifetime_seconds,
    )
    if receipt.get("status") != "candidate_demoted":
        raise AutonomousPromotionError("Autonomous demotion store returned a non-demotion receipt.")
    return {"decision": decision, "transition_receipt": receipt}
