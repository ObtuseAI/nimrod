"""Validate autonomous threshold promotion and regression demotion for Tier A/B."""

from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import cast
from nimrod_simulator.autonomous_promotion import (
    AUTONOMOUS_PROMOTION_AUTHORITY,
    verify_autonomous_regression_demotion_job,
    verify_autonomous_shadow_promotion_job,
)
from nimrod_simulator.errors import AutonomousPromotionError, SimulatorError
from nimrod_simulator.evaluator_observation import evaluate_signed_cognitive_candidate
from nimrod_simulator.jsonio import sha256_digest
from nimrod_simulator.key_governance import EphemeralEd25519SigningConnector
from nimrod_simulator.model import JsonObject
from validate_evolution_assurance import (
    MAXIMUM_LIFETIME_SECONDS,
    VALIDATION_TIME,
    candidate_document,
    capability_report,
    constitution,
    evaluation_claims,
    evaluator_connectors,
    evaluator_envelopes,
    evaluator_policy,
    governance_connectors,
    governance_state,
    isolation_attestations,
    resource_ledger,
)
from validate_evolution_foundry import TRANSITION_LIFETIME_SECONDS, transition_envelope


WORKER_COUNT = 8


def require_condition(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def expect_error(expected: type[SimulatorError], operation: Callable[[], object], label: str) -> None:
    try:
        operation()
    except expected:
        return
    raise AssertionError(f"Expected {expected.__name__} for {label}.")


def build_assured_evaluation(
    candidate: JsonObject,
    signed_constitution: JsonObject,
    governance: JsonObject,
    governance_signers: list[EphemeralEd25519SigningConnector],
    evaluators: list[EphemeralEd25519SigningConnector],
    report: JsonObject,
    hard_gates: list[JsonObject],
    floors: list[JsonObject],
    metrics: list[JsonObject],
) -> tuple[JsonObject, JsonObject]:
    policy = evaluator_policy(signed_constitution, governance, governance_signers, evaluators)
    attestations = isolation_attestations(policy, governance, governance_signers, "fixture")
    ledger = resource_ledger(candidate, signed_constitution, governance, governance_signers, 8)
    envelopes = evaluator_envelopes(
        candidate,
        signed_constitution,
        report,
        policy,
        attestations,
        ledger,
        hard_gates,
        floors,
        metrics,
        evaluators,
    )
    return evaluate_signed_cognitive_candidate(
        candidate,
        signed_constitution,
        governance,
        report,
        policy,
        envelopes,
        attestations,
        ledger,
        hard_gates,
        floors,
        metrics,
        VALIDATION_TIME,
        MAXIMUM_LIFETIME_SECONDS,
        MAXIMUM_LIFETIME_SECONDS,
        MAXIMUM_LIFETIME_SECONDS,
    )


def promotion_job(
    candidate: JsonObject,
    evaluation: JsonObject,
    report: JsonObject,
    assurance: JsonObject,
    signed_constitution: JsonObject,
    governance: JsonObject,
    envelope: JsonObject,
    job_id: str,
) -> JsonObject:
    return {
        "job_version": "0.1.0",
        "job_id": job_id,
        "origin": "simulated",
        "mode": "autonomous_threshold",
        "candidate": candidate,
        "evaluation": evaluation,
        "capability_report": report,
        "assurance": assurance,
        "constitution": signed_constitution,
        "governance_state": governance,
        "transition_envelope": envelope,
        "authority": AUTONOMOUS_PROMOTION_AUTHORITY,
    }


def worker_command(project_root: Path, state_root: Path, job_path: Path, failure_point: str) -> list[str]:
    return [
        sys.executable,
        str(project_root / "tools" / "autonomous_promotion_worker.py"),
        "--state-root",
        str(state_root),
        "--job",
        str(job_path),
        "--now",
        VALIDATION_TIME.isoformat().replace("+00:00", "Z"),
        "--maximum-constitution-lifetime-seconds",
        str(MAXIMUM_LIFETIME_SECONDS),
        "--maximum-transition-lifetime-seconds",
        str(TRANSITION_LIFETIME_SECONDS),
        "--failure-point",
        failure_point,
    ]


def run_worker(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=False, capture_output=True, text=True, timeout=60)


def write_job(path: Path, job: JsonObject) -> None:
    path.write_text(json.dumps(job, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def validate_autonomous_promotion(project_root: Path) -> JsonObject:
    governance_signers = governance_connectors()
    evaluators = evaluator_connectors()
    governance = governance_state(governance_signers, "simulated")
    signed_constitution = constitution(governance, governance_signers)
    candidate = candidate_document(project_root, signed_constitution)
    report = capability_report(candidate, signed_constitution)
    hard_gates, floors, metrics = evaluation_claims()
    evaluation, assurance = build_assured_evaluation(
        candidate,
        signed_constitution,
        governance,
        governance_signers,
        evaluators,
        report,
        hard_gates,
        floors,
        metrics,
    )
    promotion_envelope = transition_envelope(
        candidate,
        evaluation,
        report,
        signed_constitution,
        governance_signers,
        "register_shadow",
        "shadow",
        1,
        None,
        "8dbda766-ae8c-4074-9222-12836f19efca",
    )
    promotion = promotion_job(
        candidate,
        evaluation,
        report,
        assurance,
        signed_constitution,
        governance,
        promotion_envelope,
        "job:autonomous:promotion",
    )
    promotion_decision = verify_autonomous_shadow_promotion_job(
        promotion,
        VALIDATION_TIME,
        MAXIMUM_LIFETIME_SECONDS,
        TRANSITION_LIFETIME_SECONDS,
    )
    require_condition(promotion_decision["human_approval_required"] is False, "Tier A/B promotion required a human.")
    require_condition(len(cast(list[object], promotion_decision["verified_signer_ids"])) == 2, "Promotion threshold was not 2.")
    require_condition(len(cast(list[object], promotion_decision["verified_roles"])) == 2, "Promotion role threshold was not 2.")

    negative_case_count = 0
    mutations: list[tuple[JsonObject, str]] = []
    authority_widened = copy.deepcopy(promotion)
    cast(JsonObject, authority_widened["authority"])["can_promote_to_production"] = True
    mutations.append((authority_widened, "job production authority"))
    assurance_substitution = copy.deepcopy(promotion)
    cast(JsonObject, assurance_substitution["assurance"])["candidate_digest"] = "sha256:" + "0" * 64
    mutations.append((assurance_substitution, "assurance candidate substitution"))
    input_substitution = copy.deepcopy(promotion)
    cast(JsonObject, input_substitution["assurance"])["evaluation_input_digest"] = "sha256:" + "0" * 64
    mutations.append((input_substitution, "assurance input substitution"))
    boundary_removed = copy.deepcopy(promotion)
    cast(JsonObject, boundary_removed["assurance"])["contract_boundary_verified"] = False
    mutations.append((boundary_removed, "evaluator boundary removal"))
    resource_widened = copy.deepcopy(promotion)
    resource_verification = cast(JsonObject, cast(JsonObject, resource_widened["assurance"])["resource_ledger_verification"])
    resource_verification["within_constitution"] = False
    resource_verification["status"] = "blocked"
    mutations.append((resource_widened, "resource lineage widening"))
    process_collapse = copy.deepcopy(promotion)
    verifications = cast(list[JsonObject], cast(JsonObject, process_collapse["assurance"])["evaluator_verifications"])
    verifications[1]["process_id"] = verifications[0]["process_id"]
    mutations.append((process_collapse, "evaluator process collapse"))
    threshold_underflow = copy.deepcopy(promotion)
    threshold_envelope = cast(JsonObject, threshold_underflow["transition_envelope"])
    threshold_envelope["signatures"] = cast(list[object], threshold_envelope["signatures"])[:1]
    mutations.append((threshold_underflow, "promotion threshold underflow"))
    tier_widening = copy.deepcopy(promotion)
    cast(JsonObject, tier_widening["candidate"])["authority_tier"] = "C"
    mutations.append((tier_widening, "Tier C autonomous promotion"))
    production_claim = copy.deepcopy(promotion)
    cast(JsonObject, production_claim["assurance"])["production_promotion_authorized"] = True
    mutations.append((production_claim, "assurance production claim"))
    for mutated, label in mutations:
        expect_error(
            SimulatorError,
            lambda mutated=mutated: verify_autonomous_shadow_promotion_job(
                mutated,
                VALIDATION_TIME,
                MAXIMUM_LIFETIME_SECONDS,
                TRANSITION_LIFETIME_SECONDS,
            ),
            label,
        )
        negative_case_count += 1

    with tempfile.TemporaryDirectory(prefix="nimrod-autonomous-promotion-") as temporary:
        root = Path(temporary)
        promotion_path = root / "promotion-job.json"
        write_job(promotion_path, promotion)
        primary_root = root / "primary-state"
        primary = run_worker(worker_command(project_root, primary_root, promotion_path, "none"))
        require_condition(primary.returncode == 0, f"Autonomous promotion worker failed: {primary.stderr}")
        primary_result = cast(JsonObject, json.loads(primary.stdout))
        require_condition(primary_result.get("status") == "accepted", "Autonomous promotion was not accepted.")
        promotion_receipt = cast(JsonObject, primary_result["transition_receipt"])
        require_condition(promotion_receipt.get("status") == "shadow_candidate_registered", "Shadow promotion receipt is invalid.")
        require_condition(cast(int, primary_result["process_id"]) != 0, "Autonomous promotion process identity is invalid.")

        regression_floors = copy.deepcopy(floors)
        regression_floors[0]["status"] = "regressed"
        regression_evaluation, regression_assurance = build_assured_evaluation(
            candidate,
            signed_constitution,
            governance,
            governance_signers,
            evaluators,
            report,
            hard_gates,
            regression_floors,
            metrics,
        )
        require_condition(regression_evaluation.get("status") == "blocked", "Regression did not block evaluation.")
        demotion_envelope = transition_envelope(
            candidate,
            regression_evaluation,
            report,
            signed_constitution,
            governance_signers,
            "demote",
            "quarantine",
            2,
            sha256_digest(promotion_receipt),
            "87298b62-3491-4b0c-8ee8-a3123a18e28f",
        )
        demotion = promotion_job(
            candidate,
            regression_evaluation,
            report,
            regression_assurance,
            signed_constitution,
            governance,
            demotion_envelope,
            "job:autonomous:demotion",
        )
        demotion_decision = verify_autonomous_regression_demotion_job(
            demotion,
            VALIDATION_TIME,
            MAXIMUM_LIFETIME_SECONDS,
            TRANSITION_LIFETIME_SECONDS,
        )
        require_condition(cast(int, demotion_decision["regression_signal_count"]) == 1, "Regression signal count is invalid.")
        demotion_path = root / "demotion-job.json"
        write_job(demotion_path, demotion)
        demoted = run_worker(worker_command(project_root, primary_root, demotion_path, "none"))
        require_condition(demoted.returncode == 0, f"Autonomous demotion worker failed: {demoted.stderr}")
        demoted_result = cast(JsonObject, json.loads(demoted.stdout))
        require_condition(
            cast(JsonObject, demoted_result["transition_receipt"]).get("status") == "candidate_demoted",
            "Regression did not automatically demote the shadow candidate.",
        )

        nonregression_envelope = transition_envelope(
            candidate,
            evaluation,
            report,
            signed_constitution,
            governance_signers,
            "demote",
            "quarantine",
            2,
            sha256_digest(promotion_receipt),
            "3d2091bf-9747-42e0-9ab1-20c83d1d7e59",
        )
        nonregression = promotion_job(
            candidate,
            evaluation,
            report,
            assurance,
            signed_constitution,
            governance,
            nonregression_envelope,
            "job:autonomous:false-demotion",
        )
        expect_error(
            AutonomousPromotionError,
            lambda: verify_autonomous_regression_demotion_job(
                nonregression,
                VALIDATION_TIME,
                MAXIMUM_LIFETIME_SECONDS,
                TRANSITION_LIFETIME_SECONDS,
            ),
            "demotion without regression",
        )
        negative_case_count += 1

        contention_root = root / "contention-state"
        processes = [
            subprocess.Popen(
                worker_command(project_root, contention_root, promotion_path, "none"),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            for _ in range(WORKER_COUNT)
        ]
        contention_results: list[JsonObject] = []
        for process in processes:
            stdout, stderr = process.communicate(timeout=60)
            require_condition(process.returncode == 0, f"Autonomous promotion contention failed: {stderr}")
            contention_results.append(cast(JsonObject, json.loads(stdout)))
        contention_accept_count = sum(1 for result in contention_results if result.get("status") == "accepted")
        contention_replay_count = sum(1 for result in contention_results if result.get("status") == "replay_denied")
        require_condition(
            contention_accept_count == 1 and contention_replay_count == WORKER_COUNT - 1,
            "Autonomous promotion contention did not produce exactly one durable promotion.",
        )

        crash_before_root = root / "crash-before-state"
        before = run_worker(worker_command(project_root, crash_before_root, promotion_path, "temporary_durable"))
        require_condition(before.returncode == 111, "Autonomous pre-publication crash did not fire.")
        retry_before = run_worker(worker_command(project_root, crash_before_root, promotion_path, "none"))
        require_condition(retry_before.returncode == 0 and json.loads(retry_before.stdout)["status"] == "accepted", "Autonomous pre-publication crash was not retryable.")
        crash_after_root = root / "crash-after-state"
        after = run_worker(worker_command(project_root, crash_after_root, promotion_path, "state_published"))
        require_condition(after.returncode == 112, "Autonomous post-publication crash did not fire.")
        retry_after = run_worker(worker_command(project_root, crash_after_root, promotion_path, "none"))
        require_condition(retry_after.returncode == 0 and json.loads(retry_after.stdout)["status"] == "replay_denied", "Autonomous published promotion was not durable after crash.")

    worker_source = (project_root / "tools" / "autonomous_promotion_worker.py").read_text(encoding="utf-8").casefold()
    require_condition(
        all(token not in worker_source for token in ("import openai", "import requests", "import socket")),
        "Autonomous promotion worker exposes a model or network client.",
    )
    return {
        "status": "AUTONOMOUS_THRESHOLD_PROMOTION_REPLAY_VALID_SHADOW_AND_DEMOTION_ONLY",
        "origin": "simulated",
        "autonomous_promotion_standard": True,
        "eligible_tiers": ["A", "B"],
        "human_approval_required_for_eligible_tiers": False,
        "threshold_signer_count": 2,
        "threshold_role_count": 2,
        "independent_evaluator_count": 4,
        "shadow_promotion_count": 1,
        "automatic_regression_demotion_count": 1,
        "contention_worker_count": WORKER_COUNT,
        "contention_accept_count": contention_accept_count,
        "contention_replay_denial_count": contention_replay_count,
        "crash_boundary_count": 2,
        "negative_fail_closed_case_count": negative_case_count,
        "active_baseline_modified": False,
        "candidate_executed": False,
        "production_promotion_authorized": False,
        "constitution_modified": False,
        "trust_root_modified": False,
        "network_access_performed": False,
        "model_api_called": False,
        "authority": AUTONOMOUS_PROMOTION_AUTHORITY,
    }


def main() -> None:
    project_root = Path(__file__).resolve().parent.parent
    result = validate_autonomous_promotion(project_root)
    report_path = project_root / "reports" / "AUTONOMOUS_PROMOTION_VALIDATION.json"
    report_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
