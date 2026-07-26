"""Validate the replay-only W3 constitutional intelligence research engine."""

from __future__ import annotations

import copy
import json
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import cast

from nimrod_research.cli import run_research_replay
from nimrod_research.intelligence_lab import (
    build_intelligence_research_settlement,
    validate_intelligence_research_mission,
    validate_intelligence_research_settlement,
)
from nimrod_simulator.errors import IntelligenceResearchError
from nimrod_simulator.jsonio import read_json_object, sha256_digest, validate_contract
from nimrod_simulator.model import JsonObject


Mutation = Callable[[JsonObject], None]


def object_value(value: JsonObject, field: str) -> JsonObject:
    return cast(JsonObject, value[field])


def object_list(value: JsonObject, field: str) -> list[JsonObject]:
    return cast(list[JsonObject], value[field])


def body(value: JsonObject) -> JsonObject:
    return object_value(value, "settlement")


def expect_research_error(label: str, operation: Callable[[], object]) -> None:
    try:
        operation()
    except IntelligenceResearchError:
        return
    raise RuntimeError(f"Expected IntelligenceResearchError for {label}.")


def mission_case(project_root: Path, mission: JsonObject, mutation: Mutation) -> Callable[[], object]:
    def operation() -> object:
        candidate = copy.deepcopy(mission)
        mutation(candidate)
        validate_intelligence_research_mission(candidate)
        return build_intelligence_research_settlement(candidate, project_root)

    return operation


def settlement_case(document: JsonObject, mission: JsonObject, mutation: Mutation) -> Callable[[], object]:
    def operation() -> object:
        candidate = copy.deepcopy(document)
        mutation(candidate)
        candidate["settlement_digest"] = sha256_digest(body(candidate))
        validate_intelligence_research_settlement(candidate, mission)
        return candidate

    return operation


def validate_cli(project_root: Path, mission_path: Path, expected: JsonObject) -> bool:
    with tempfile.TemporaryDirectory(prefix="nimrod-intelligence-research-") as temporary:
        output_path = Path(temporary) / "settlement.json"
        summary = run_research_replay(project_root, mission_path, output_path)
        restored = read_json_object(output_path)
        if restored != expected:
            raise RuntimeError("Intelligence research CLI output differs from canonical deterministic settlement.")
        if (
            summary.get("candidate_theory_status") != "candidate_only"
            or summary.get("generalization_allowed") is not False
            or summary.get("promotion_authorized") is not False
            or summary.get("execution_performed") is not False
        ):
            raise RuntimeError(f"Intelligence research CLI widened its outcome: summary={summary!r}.")
    return True


def validate_intelligence_research(project_root: Path) -> JsonObject:
    mission_path = project_root / "specs" / "examples" / "intelligence-research-mission.example.json"
    settlement_path = project_root / "specs" / "examples" / "intelligence-research-settlement.example.json"
    mission = read_json_object(mission_path)
    expected = read_json_object(settlement_path)
    validate_contract(
        mission,
        project_root / "specs" / "intelligence-research-mission.schema.json",
        "intelligence research mission",
    )
    validate_intelligence_research_mission(mission)
    generated = build_intelligence_research_settlement(mission, project_root)
    validate_contract(
        generated,
        project_root / "specs" / "intelligence-research-settlement.schema.json",
        "intelligence research settlement",
    )
    validate_intelligence_research_settlement(generated, mission)
    if generated != expected or generated != build_intelligence_research_settlement(copy.deepcopy(mission), project_root):
        raise RuntimeError("Intelligence research replay is nondeterministic or differs from its canonical settlement.")
    cli_verified = validate_cli(project_root, mission_path, expected)

    mission_cases: tuple[tuple[str, Mutation], ...] = (
        ("mission live-origin laundering", lambda value: value.__setitem__("origin", "live")),
        ("mission outcome widening", lambda value: value.__setitem__("maximum_outcome", "promoted_theory")),
        ("mission interval reversal", lambda value: value.__setitem__("expires_at", value["issued_at"])),
        ("source digest substitution", lambda value: object_list(value, "source_evidence")[0].__setitem__("digest", "sha256:" + "1" * 64)),
        ("source kind substitution", lambda value: object_list(value, "source_evidence")[0].__setitem__("kind", "immune_lifecycle_receipt")),
        ("source origin laundering", lambda value: object_list(value, "source_evidence")[0].__setitem__("origin", "live")),
        ("creativity operator removal", lambda value: cast(list[object], value["creativity_operators"]).pop()),
        ("null hypothesis removal", lambda value: object_list(object_value(value, "preregistration"), "hypotheses").pop(0)),
        ("hypothesis kind duplication", lambda value: object_list(object_value(value, "preregistration"), "hypotheses")[0].__setitem__("kind", "candidate")),
        ("hypothesis identity duplication", lambda value: object_list(object_value(value, "preregistration"), "hypotheses")[1].__setitem__("hypothesis_id", object_list(object_value(value, "preregistration"), "hypotheses")[0]["hypothesis_id"])),
        ("primary hypothesis substitution", lambda value: object_value(value, "preregistration").__setitem__("primary_hypothesis_id", object_list(object_value(value, "preregistration"), "hypotheses")[0]["hypothesis_id"])),
        ("prediction unknown hypothesis", lambda value: object_list(object_value(value, "preregistration"), "predictions")[0].__setitem__("hypothesis_id", "73000000-0000-4000-8000-000000009999")),
        ("prediction identity duplication", lambda value: object_list(object_value(value, "preregistration"), "predictions")[1].__setitem__("prediction_id", object_list(object_value(value, "preregistration"), "predictions")[0]["prediction_id"])),
        ("prediction threshold gaming", lambda value: object_list(object_value(value, "preregistration"), "predictions")[0].__setitem__("threshold", 0.9)),
        ("hard failure removal", lambda value: cast(list[object], object_value(value, "preregistration")["hard_failure_conditions"]).pop()),
        ("post-hoc registration", lambda value: object_value(value, "preregistration").__setitem__("registered_before_experiment", False)),
        ("method role duplication", lambda value: object_list(value, "methods")[1].__setitem__("role", "baseline")),
        ("method identity duplication", lambda value: object_list(value, "methods")[1].__setitem__("method_id", object_list(value, "methods")[0]["method_id"])),
        ("baseline name substitution", lambda value: object_list(value, "methods")[0].__setitem__("name", "uncertainty_first_adversarial_decomposition")),
        ("baseline order mutation", lambda value: cast(list[object], object_list(value, "methods")[0]["operators"]).reverse()),
        ("candidate operator removal", lambda value: cast(list[object], object_list(value, "methods")[1]["operators"]).pop(0)),
        ("candidate decision mismatch", lambda value: object_list(value, "methods")[1].__setitem__("decision_operator", "decide")),
        ("method authorization", lambda value: object_list(value, "methods")[1].__setitem__("can_authorize", True)),
        ("method execution", lambda value: object_list(value, "methods")[1].__setitem__("can_execute", True)),
        ("benchmark removal", lambda value: object_list(value, "benchmark_cases").pop()),
        ("benchmark identity duplication", lambda value: object_list(value, "benchmark_cases")[1].__setitem__("case_id", object_list(value, "benchmark_cases")[0]["case_id"])),
        ("benchmark live-origin laundering", lambda value: object_list(value, "benchmark_cases")[0].__setitem__("origin", "live")),
        ("benchmark unknown suppression", lambda value: object_list(value, "benchmark_cases")[0].__setitem__("material_unknown_count", 0)),
        ("benchmark contradiction suppression", lambda value: object_list(value, "benchmark_cases")[0].__setitem__("contradiction_count", 0)),
        ("metric removal", lambda value: cast(list[object], object_value(value, "experiment")["metrics"]).pop()),
        ("held-out evidence fabrication", lambda value: object_value(value, "experiment").__setitem__("held_out_evaluation_performed", True)),
        ("generalization authorization", lambda value: object_value(value, "experiment").__setitem__("generalization_claim_allowed", True)),
        ("model-call authorization", lambda value: object_value(value, "experiment").__setitem__("model_calls_allowed", True)),
        ("network authorization", lambda value: object_value(value, "experiment").__setitem__("network_access_allowed", True)),
        ("complexity ceiling gaming", lambda value: object_value(value, "experiment").__setitem__("maximum_candidate_complexity_delta", 3)),
        ("verifier capture", lambda value: object_value(value, "verifier").__setitem__("same_research_principal", True)),
        ("verifier promotion", lambda value: object_value(value, "verifier").__setitem__("can_promote", True)),
        ("production independence fabrication", lambda value: object_value(value, "verifier").__setitem__("production_independence_claimed", True)),
        ("mission execution authority", lambda value: object_value(value, "authority").__setitem__("can_execute", True)),
        ("mission promotion authority", lambda value: object_value(value, "authority").__setitem__("can_promote", True)),
        ("mission constitution mutation", lambda value: object_value(value, "authority").__setitem__("can_modify_constitution", True)),
    )
    negative_count = 0
    for label, mutation in mission_cases:
        expect_research_error(label, mission_case(project_root, mission, mutation))
        negative_count += 1

    settlement_cases: tuple[tuple[str, Mutation], ...] = (
        ("mission binding substitution", lambda value: body(value).__setitem__("mission_digest", "sha256:" + "2" * 64)),
        ("source evidence substitution", lambda value: cast(list[object], body(value)["source_evidence_digests"]).__setitem__(0, "sha256:" + "3" * 64)),
        ("result digest substitution", lambda value: object_list(body(value), "method_results")[0].__setitem__("result_digest", "sha256:" + "4" * 64)),
        ("result matrix duplication", lambda value: object_list(body(value), "method_results")[1].__setitem__("case_id", object_list(body(value), "method_results")[0]["case_id"])),
        ("result metric inflation", lambda value: object_value(object_list(body(value), "method_results")[0], "metrics").__setitem__("required_operation_coverage", 1.0)),
        ("abstention laundering", lambda value: object_list(body(value), "method_results")[2].__setitem__("abstention_preserved", False)),
        ("aggregate coverage inflation", lambda value: object_value(body(value), "aggregate_comparison").__setitem__("mean_required_operation_coverage_delta", 1.0)),
        ("aggregate hard failure suppression", lambda value: object_value(body(value), "aggregate_comparison").__setitem__("hard_failure_count", 1)),
        ("prediction outcome laundering", lambda value: object_list(body(value), "predictions")[0].__setitem__("passed", False)),
        ("challenge removal", lambda value: object_list(body(value), "challenge_log").pop()),
        ("challenge kind duplication", lambda value: object_list(body(value), "challenge_log")[1].__setitem__("kind", object_list(body(value), "challenge_log")[0]["kind"])),
        ("challenge materiality suppression", lambda value: object_list(body(value), "challenge_log")[0].__setitem__("material", False)),
        ("hypothesis status inflation", lambda value: object_list(body(value), "hypotheses")[1].__setitem__("status", "promoted")),
        ("hypothesis counter-evidence omission", lambda value: object_list(body(value), "hypotheses")[1].__setitem__("counter_evidence_ids", [])),
        ("metacognitive knowledge inflation", lambda value: object_value(body(value), "metacognition").__setitem__("knowledge_state", "known")),
        ("generalization abstention removal", lambda value: object_value(body(value), "metacognition").__setitem__("should_abstain_from_generalization", False)),
        ("missing evidence removal", lambda value: cast(list[object], object_value(body(value), "metacognition")["missing_evidence"]).pop()),
        ("verification removal", lambda value: object_value(body(value), "independent_verification").__setitem__("performed", False)),
        ("verification self-capture", lambda value: object_value(body(value), "independent_verification").__setitem__("same_research_principal", True)),
        ("separate-process removal", lambda value: object_value(body(value), "independent_verification").__setitem__("separate_process", False)),
        ("production verification fabrication", lambda value: object_value(body(value), "independent_verification").__setitem__("production_independence_verified", True)),
        ("verified claim removal", lambda value: cast(list[object], object_value(body(value), "independent_verification")["verified_claims"]).pop()),
        ("verifier limitation removal", lambda value: cast(list[object], object_value(body(value), "independent_verification")["limitations"]).pop()),
        ("theory promotion", lambda value: object_value(body(value), "candidate_theory").__setitem__("status", "promoted")),
        ("theory generalization", lambda value: object_value(body(value), "candidate_theory").__setitem__("generalization_allowed", True)),
        ("theory promotion authorization", lambda value: object_value(body(value), "candidate_theory").__setitem__("promotion_authorized", True)),
        ("theory authority retention", lambda value: object_value(body(value), "candidate_theory").__setitem__("authority_retained", True)),
        ("settlement execution authority", lambda value: object_value(body(value), "authority").__setitem__("can_execute", True)),
        ("settlement promotion authority", lambda value: object_value(body(value), "authority").__setitem__("can_promote", True)),
        ("security claim widening", lambda value: body(value).__setitem__("security_claim", "general intelligence improvement verified")),
    )
    for label, mutation in settlement_cases:
        expect_research_error(label, settlement_case(generated, mission, mutation))
        negative_count += 1

    settlement = body(generated)
    aggregate = object_value(settlement, "aggregate_comparison")
    theory = object_value(settlement, "candidate_theory")
    verification = object_value(settlement, "independent_verification")
    metacognition = object_value(settlement, "metacognition")
    result: JsonObject = {
        "status": "INTELLIGENCE_RESEARCH_W3_REPLAY_VALID_CANDIDATE_THEORY_ONLY",
        "origin": "replayed",
        "mission_digest": settlement["mission_digest"],
        "settlement_digest": generated["settlement_digest"],
        "hypothesis_count": len(object_list(settlement, "hypotheses")),
        "benchmark_case_count": len(object_list(mission, "benchmark_cases")),
        "method_result_count": len(object_list(settlement, "method_results")),
        "challenge_count": len(object_list(settlement, "challenge_log")),
        "coverage_delta": aggregate["mean_required_operation_coverage_delta"],
        "candidate_theory_status": theory["status"],
        "knowledge_state": metacognition["knowledge_state"],
        "negative_fail_closed_case_count": negative_count,
        "deterministic_replay_verified": True,
        "cli_replay_verified": cli_verified,
        "logical_read_only_verification_performed": verification["performed"],
        "separate_process_verification_performed": verification["separate_process"],
        "production_independence_verified": verification["production_independence_verified"],
        "held_out_evaluation_performed": False,
        "external_replication_performed": False,
        "generalization_allowed": False,
        "promotion_authorized": False,
        "execution_authorized": False,
        "execution_performed": False,
        "target_contact_performed": False,
        "model_api_called": False,
        "network_access_performed": False,
    }
    return result


def main() -> None:
    project_root = Path(__file__).resolve().parents[1]
    result = validate_intelligence_research(project_root)
    report_path = project_root / "reports" / "INTELLIGENCE_RESEARCH_VALIDATION.json"
    report_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
