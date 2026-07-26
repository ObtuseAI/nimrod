from __future__ import annotations

import argparse
import json
import os
from datetime import datetime
from pathlib import Path
from typing import cast

from nimrod_simulator.evaluator_observation import evaluate_signed_cognitive_candidate
from nimrod_simulator.evolution_foundry import EvolutionArtifactStore, assess_capability_thresholds
from nimrod_simulator.jsonio import read_json_object
from nimrod_simulator.model import JsonObject


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def require_object_list(value: object, label: str) -> list[JsonObject]:
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise TypeError(f"{label} must be a list of objects.")
    return cast(list[JsonObject], value)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--constitution", type=Path, required=True)
    parser.add_argument("--governance", type=Path, required=True)
    parser.add_argument("--assessment-input", type=Path, required=True)
    parser.add_argument("--evaluation-input", type=Path, required=True)
    parser.add_argument("--evaluator-policy", type=Path, required=True)
    parser.add_argument("--isolation-attestations", type=Path, required=True)
    parser.add_argument("--resource-ledger", type=Path, required=True)
    parser.add_argument("--artifact-root", type=Path, required=True)
    parser.add_argument("--evaluated-at", required=True)
    parser.add_argument("--maximum-policy-lifetime-seconds", type=int, required=True)
    parser.add_argument("--maximum-attestation-lifetime-seconds", type=int, required=True)
    parser.add_argument("--maximum-ledger-lifetime-seconds", type=int, required=True)
    args = parser.parse_args()
    candidate = read_json_object(args.candidate)
    constitution = read_json_object(args.constitution)
    governance = read_json_object(args.governance)
    assessment_input = read_json_object(args.assessment_input)
    evaluation_input = read_json_object(args.evaluation_input)
    evaluator_policy = read_json_object(args.evaluator_policy)
    isolation_input = read_json_object(args.isolation_attestations)
    resource_ledger = read_json_object(args.resource_ledger)
    evaluated_at = parse_time(args.evaluated_at)
    capability_report = assess_capability_thresholds(
        candidate,
        constitution,
        require_object_list(assessment_input.get("assessments"), "assessments"),
        evaluated_at,
    )
    evaluation, assurance = evaluate_signed_cognitive_candidate(
        candidate,
        constitution,
        governance,
        capability_report,
        evaluator_policy,
        require_object_list(evaluation_input.get("evaluator_envelopes"), "evaluator_envelopes"),
        require_object_list(isolation_input.get("attestations"), "attestations"),
        resource_ledger,
        require_object_list(evaluation_input.get("hard_gate_results"), "hard_gate_results"),
        require_object_list(evaluation_input.get("champion_floor_results"), "champion_floor_results"),
        require_object_list(evaluation_input.get("metrics"), "metrics"),
        evaluated_at,
        args.maximum_policy_lifetime_seconds,
        args.maximum_attestation_lifetime_seconds,
        args.maximum_ledger_lifetime_seconds,
    )
    store = EvolutionArtifactStore(args.artifact_root)
    capability_digest = store.publish(capability_report, "capability_threshold_report")
    evaluation_digest = store.publish(evaluation, "evolution_evaluation_vector")
    assurance_digest = store.publish(assurance, "evolution_assurance_receipt")
    print(json.dumps({"process_id": os.getpid(), "capability_digest": capability_digest, "capability_report": capability_report, "evaluation_digest": evaluation_digest, "evaluation": evaluation, "assurance_digest": assurance_digest, "assurance": assurance}, sort_keys=True))


if __name__ == "__main__":
    main()
