"""Deterministic, candidate-only research engine for methods of intelligence."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime
from pathlib import Path
from typing import cast

from nimrod_research.process_verification import run_separate_process_verification
from nimrod_research.verifier import build_structural_verification
from nimrod_simulator.errors import IntelligenceResearchError
from nimrod_simulator.jsonio import sha256_digest
from nimrod_simulator.model import JsonObject


EXPECTED_AUTHORITY: Mapping[str, bool] = {
    "can_authorize": False,
    "can_execute": False,
    "can_change_policy": False,
    "can_contact_targets": False,
    "can_use_credentials": False,
    "can_self_verify": False,
    "can_promote": False,
    "can_modify_constitution": False,
}

EXPECTED_HARD_FAILURES: frozenset[str] = frozenset(
    {
        "authority_growth",
        "evidence_substitution",
        "hypothesis_omission",
        "counter_evidence_omission",
        "metric_redefinition",
        "generalization_laundering",
        "self_verification",
        "candidate_promotion",
    }
)

EXPECTED_CREATIVITY_OPERATORS: frozenset[str] = frozenset(
    {
        "analogy",
        "inversion",
        "morphological_search",
        "cross_domain_transfer",
        "counterfactual_reasoning",
        "first_principles_reconstruction",
    }
)

EXPECTED_SOURCE_EVIDENCE: frozenset[tuple[str, str]] = frozenset(
    {
        ("world_model_generation", "sha256:4f679eb5e8ff1e00761369a928247aed55e10a581b9b257b617a78e8000b5766"),
        ("immune_lifecycle_receipt", "sha256:6e860d5e51a210ce0056266b3b95fc460c078785ef0db8c0ff8fb143c9838cc8"),
        ("immune_lifecycle_receipt", "sha256:0ea0059f0c6e10d53870c2885f3004dcb0c334f0729cdb05a3a74449aeb8394a"),
    }
)


def require_object(value: object, label: str) -> JsonObject:
    if not isinstance(value, dict):
        raise IntelligenceResearchError(f"Intelligence research {label} must be an object.")
    return cast(JsonObject, value)


def require_object_list(value: object, label: str) -> tuple[JsonObject, ...]:
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise IntelligenceResearchError(f"Intelligence research {label} must be a list of objects.")
    return tuple(cast(JsonObject, item) for item in value)


def require_string_list(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise IntelligenceResearchError(f"Intelligence research {label} must be a list of strings.")
    strings = tuple(cast(Sequence[str], value))
    if len(strings) != len(set(strings)):
        raise IntelligenceResearchError(f"Intelligence research {label} must not contain duplicates.")
    return strings


def parse_time(value: object, label: str) -> datetime:
    if not isinstance(value, str):
        raise IntelligenceResearchError(f"Intelligence research {label} must be a timestamp string.")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise IntelligenceResearchError(f"Intelligence research {label} is invalid: value={value!r}.") from error


def validate_authority(value: object, label: str) -> None:
    authority = require_object(value, label)
    if authority != EXPECTED_AUTHORITY:
        raise IntelligenceResearchError(
            f"Intelligence research authority must remain exactly denied: expected={dict(EXPECTED_AUTHORITY)!r}, received={authority!r}."
        )


def validate_hypotheses(mission: JsonObject) -> None:
    preregistration = require_object(mission.get("preregistration"), "mission.preregistration")
    hypotheses = require_object_list(preregistration.get("hypotheses"), "mission.preregistration.hypotheses")
    kinds = tuple(str(hypothesis.get("kind")) for hypothesis in hypotheses)
    if len({hypothesis.get("hypothesis_id") for hypothesis in hypotheses}) != len(hypotheses):
        raise IntelligenceResearchError("Intelligence research hypothesis identifiers must be unique.")
    if set(kinds) != {"null", "candidate", "rival", "unknown"} or len(hypotheses) != 4:
        raise IntelligenceResearchError(
            f"Intelligence research requires null, candidate, rival, and unknown hypotheses: received={kinds!r}."
        )
    primary = preregistration.get("primary_hypothesis_id")
    candidate_ids = {hypothesis.get("hypothesis_id") for hypothesis in hypotheses if hypothesis.get("kind") == "candidate"}
    if {primary} != candidate_ids:
        raise IntelligenceResearchError("Intelligence research primary hypothesis must identify the sole candidate hypothesis.")
    hypothesis_ids = {hypothesis.get("hypothesis_id") for hypothesis in hypotheses}
    predictions = require_object_list(preregistration.get("predictions"), "mission.preregistration.predictions")
    if len({prediction.get("prediction_id") for prediction in predictions}) != len(predictions):
        raise IntelligenceResearchError("Intelligence research prediction identifiers must be unique.")
    if any(prediction.get("hypothesis_id") not in hypothesis_ids for prediction in predictions):
        raise IntelligenceResearchError("Intelligence research prediction references an unknown hypothesis.")
    failures = frozenset(require_string_list(preregistration.get("hard_failure_conditions"), "hard failures"))
    if failures != EXPECTED_HARD_FAILURES or preregistration.get("registered_before_experiment") is not True:
        raise IntelligenceResearchError("Intelligence research preregistration is incomplete or post-hoc.")


def validate_methods_and_cases(mission: JsonObject) -> None:
    methods = require_object_list(mission.get("methods"), "mission.methods")
    if len(methods) != 2 or {method.get("role") for method in methods} != {"baseline", "candidate"}:
        raise IntelligenceResearchError("Intelligence research requires exactly one baseline and one candidate method.")
    if len({method.get("method_id") for method in methods}) != 2:
        raise IntelligenceResearchError("Intelligence research method identifiers must be unique.")
    expected_names = {"baseline": "retrieval_first_planning", "candidate": "uncertainty_first_adversarial_decomposition"}
    for method in methods:
        role = str(method.get("role"))
        operators = require_string_list(method.get("operators"), f"method {role} operators")
        if method.get("name") != expected_names[role]:
            raise IntelligenceResearchError(f"Intelligence research {role} method identity is substituted.")
        if operators[-1] != method.get("decision_operator"):
            raise IntelligenceResearchError(f"Intelligence research {role} decision operator must terminate the sequence.")
        if method.get("can_authorize") is not False or method.get("can_execute") is not False:
            raise IntelligenceResearchError(f"Intelligence research {role} method cannot authorize or execute.")
    baseline = next(method for method in methods if method.get("role") == "baseline")
    candidate = next(method for method in methods if method.get("role") == "candidate")
    if require_string_list(baseline.get("operators"), "baseline operators") != ("retrieve", "synthesize", "decide"):
        raise IntelligenceResearchError("Intelligence research baseline must preserve the preregistered operator order.")
    expected_candidate = (
        "represent_uncertainty",
        "decompose",
        "adversarial_challenge",
        "counterfactual_reasoning",
        "retrieve",
        "synthesize",
        "abstain_or_decide",
    )
    if require_string_list(candidate.get("operators"), "candidate operators") != expected_candidate:
        raise IntelligenceResearchError("Intelligence research candidate must preserve the preregistered operator order.")
    cases = require_object_list(mission.get("benchmark_cases"), "mission.benchmark_cases")
    if len(cases) != 2 or {case.get("scenario") for case in cases} != {"credential_theft", "suspicious_script"}:
        raise IntelligenceResearchError("Intelligence research requires both preregistered replay scenarios.")
    if len({case.get("case_id") for case in cases}) != len(cases):
        raise IntelligenceResearchError("Intelligence research benchmark case identifiers must be unique.")
    for case in cases:
        if case.get("origin") != "replayed":
            raise IntelligenceResearchError("Intelligence research benchmark cases cannot launder replay as live evidence.")
        if int(cast(int, case.get("material_unknown_count"))) < 1 or int(cast(int, case.get("contradiction_count"))) < 1:
            raise IntelligenceResearchError("Intelligence research cases must preserve material unknowns and contradictions.")


def validate_intelligence_research_mission(mission: JsonObject) -> None:
    """Validate the constitutional and scientific boundaries of a research mission."""

    if mission.get("origin") != "replayed" or mission.get("maximum_outcome") != "candidate_theory":
        raise IntelligenceResearchError("Intelligence research is replay-only and candidate-theory-only.")
    if parse_time(mission.get("issued_at"), "issued_at") >= parse_time(mission.get("expires_at"), "expires_at"):
        raise IntelligenceResearchError("Intelligence research mission validity interval must be increasing.")
    sources = require_object_list(mission.get("source_evidence"), "mission.source_evidence")
    if len({source.get("digest") for source in sources}) != len(sources) or any(source.get("origin") != "replayed" for source in sources):
        raise IntelligenceResearchError("Intelligence research source evidence is duplicate or origin-ambiguous.")
    source_evidence = frozenset((str(source.get("kind")), str(source.get("digest"))) for source in sources)
    if source_evidence != EXPECTED_SOURCE_EVIDENCE:
        raise IntelligenceResearchError(
            "Intelligence research source evidence must bind the canonical W1 generation and both W2 lifecycle receipts: "
            f"expected={sorted(EXPECTED_SOURCE_EVIDENCE)!r}, received={sorted(source_evidence)!r}."
        )
    creativity = frozenset(require_string_list(mission.get("creativity_operators"), "creativity_operators"))
    if creativity != EXPECTED_CREATIVITY_OPERATORS:
        raise IntelligenceResearchError("Intelligence research must preserve the complete preregistered creative operator set.")
    validate_hypotheses(mission)
    validate_methods_and_cases(mission)
    experiment = require_object(mission.get("experiment"), "mission.experiment")
    expected_metrics = {
        "required_operation_coverage",
        "uncertainty_preservation",
        "challenge_coverage",
        "evidence_efficiency",
        "complexity_cost",
    }
    if set(require_string_list(experiment.get("metrics"), "experiment.metrics")) != expected_metrics:
        raise IntelligenceResearchError("Intelligence research metrics cannot be redefined after preregistration.")
    if experiment.get("design") != "paired_deterministic_method_structure_replay":
        raise IntelligenceResearchError("Intelligence research experiment design is not the bounded replay design.")
    for field in ("held_out_evaluation_performed", "generalization_claim_allowed", "model_calls_allowed", "network_access_allowed"):
        if experiment.get(field) is not False:
            raise IntelligenceResearchError(f"Intelligence research unsupported capability claimed: field={field!r}.")
    verifier = require_object(mission.get("verifier"), "mission.verifier")
    expected_verifier: JsonObject = {
        "verifier_id": "verifier:cire-structural-v1",
        "scope": "structural_replay_only",
        "read_only": True,
        "same_research_principal": False,
        "can_promote": False,
        "production_independence_claimed": False,
    }
    if verifier != expected_verifier:
        raise IntelligenceResearchError(
            f"Intelligence research verifier boundary is widened or substituted: expected={expected_verifier!r}."
        )
    validate_authority(mission.get("authority"), "mission.authority")


def compute_metrics(method: JsonObject, case: JsonObject) -> JsonObject:
    operators = require_string_list(method.get("operators"), "method operators")
    required = require_string_list(case.get("required_operations"), "case required operations")
    matched = len(set(operators).intersection(required))
    challenge_requirements = {item for item in required if item in {"adversarial_challenge", "counterfactual_reasoning"}}
    challenge_matched = len(set(operators).intersection(challenge_requirements))
    decision_index = len(operators) - 1
    uncertainty_preserved = int("represent_uncertainty" in operators and operators.index("represent_uncertainty") < decision_index)
    return {
        "required_operation_coverage": round(matched / len(required), 6),
        "uncertainty_preservation": uncertainty_preserved,
        "challenge_coverage": round(challenge_matched / len(challenge_requirements), 6),
        "evidence_efficiency": round(matched / int(cast(int, case.get("evidence_budget"))), 6),
        "complexity_cost": len(operators),
    }


def build_method_results(mission: JsonObject) -> list[JsonObject]:
    methods = require_object_list(mission.get("methods"), "mission.methods")
    cases = require_object_list(mission.get("benchmark_cases"), "mission.benchmark_cases")
    results: list[JsonObject] = []
    sequence = 100
    for method in methods:
        for case in cases:
            unsigned: JsonObject = {
                "result_id": f"73000000-0000-4000-8000-{sequence:012d}",
                "method_id": method.get("method_id"),
                "case_id": case.get("case_id"),
                "metrics": compute_metrics(method, case),
                "abstention_preserved": method.get("decision_operator") == "abstain_or_decide",
            }
            results.append({**unsigned, "result_digest": sha256_digest(unsigned)})
            sequence += 1
    return results


def mean(values: Sequence[float]) -> float:
    return round(sum(values) / len(values), 6)


def build_aggregate(mission: JsonObject, results: list[JsonObject]) -> JsonObject:
    methods = require_object_list(mission.get("methods"), "mission.methods")
    baseline_id = str(next(method for method in methods if method.get("role") == "baseline").get("method_id"))
    candidate_id = str(next(method for method in methods if method.get("role") == "candidate").get("method_id"))
    baseline = [result for result in results if result.get("method_id") == baseline_id]
    candidate = [result for result in results if result.get("method_id") == candidate_id]
    baseline_coverage = mean([float(require_object(result["metrics"], "metrics")["required_operation_coverage"]) for result in baseline])
    candidate_coverage = mean([float(require_object(result["metrics"], "metrics")["required_operation_coverage"]) for result in candidate])
    baseline_uncertainty = mean([float(require_object(result["metrics"], "metrics")["uncertainty_preservation"]) for result in baseline])
    candidate_uncertainty = mean([float(require_object(result["metrics"], "metrics")["uncertainty_preservation"]) for result in candidate])
    baseline_complexity = max(int(cast(int, require_object(result["metrics"], "metrics")["complexity_cost"])) for result in baseline)
    candidate_complexity = max(int(cast(int, require_object(result["metrics"], "metrics")["complexity_cost"])) for result in candidate)
    return {
        "baseline_method_id": baseline_id,
        "candidate_method_id": candidate_id,
        "mean_required_operation_coverage_baseline": baseline_coverage,
        "mean_required_operation_coverage_candidate": candidate_coverage,
        "mean_required_operation_coverage_delta": round(candidate_coverage - baseline_coverage, 6),
        "mean_uncertainty_preservation_delta": round(candidate_uncertainty - baseline_uncertainty, 6),
        "maximum_complexity_delta": candidate_complexity - baseline_complexity,
        "preregistered_predictions_passed": True,
        "hard_failure_count": 0,
    }


def build_predictions(mission: JsonObject, aggregate: JsonObject) -> list[JsonObject]:
    registered = require_object_list(
        require_object(mission.get("preregistration"), "preregistration").get("predictions"),
        "preregistration.predictions",
    )
    observed: dict[str, float] = {
        "mean_required_operation_coverage_delta": float(cast(float, aggregate["mean_required_operation_coverage_delta"])),
        "mean_uncertainty_preservation_delta": float(cast(float, aggregate["mean_uncertainty_preservation_delta"])),
        "maximum_complexity_delta": float(cast(float, aggregate["maximum_complexity_delta"])),
    }
    results: list[JsonObject] = []
    for prediction in registered:
        value = observed[str(prediction["metric"])]
        threshold = float(cast(float, prediction["threshold"]))
        passed = value >= threshold if prediction["comparator"] == "greater_than_or_equal" else value <= threshold
        results.append({"prediction_id": prediction["prediction_id"], "observed_value": value, "passed": passed})
    if not all(result["passed"] is True for result in results):
        raise IntelligenceResearchError("Intelligence research preregistered predictions did not all pass.")
    return results


def build_challenges(mission: JsonObject) -> list[JsonObject]:
    hypotheses = require_object_list(
        require_object(mission.get("preregistration"), "preregistration").get("hypotheses"),
        "preregistration.hypotheses",
    )
    by_kind = {str(hypothesis["kind"]): str(hypothesis["hypothesis_id"]) for hypothesis in hypotheses}
    rows = (
        ("null_challenge", "candidate", "The replay rejects no-effect structurally but cannot eliminate the null beyond two fixtures.", "preserved"),
        ("complexity_confound", "rival", "The candidate uses four additional operators, so complexity remains a material confound.", "bounded"),
        ("fixture_scarcity", "unknown", "Only two preregistered replay fixtures were evaluated.", "unresolved"),
        ("structural_proxy_limit", "candidate", "Operation coverage is a structural proxy and not a measured real-world problem-solving outcome.", "unresolved"),
        ("verifier_boundary_limit", "candidate", "The verifier runs in a separate process, but dedicated OS-account and production independence remain unproven.", "bounded"),
        ("generalization_limit", "unknown", "No hidden, private, external, forward, or production evaluation was performed.", "unresolved"),
    )
    return [
        {
            "challenge_id": f"73000000-0000-4000-8000-{200 + index:012d}",
            "kind": kind,
            "target_hypothesis_id": by_kind[target],
            "finding": finding,
            "disposition": disposition,
            "material": True,
        }
        for index, (kind, target, finding, disposition) in enumerate(rows)
    ]


def build_hypothesis_results(mission: JsonObject, results: list[JsonObject], challenges: list[JsonObject]) -> list[JsonObject]:
    hypotheses = require_object_list(
        require_object(mission.get("preregistration"), "preregistration").get("hypotheses"),
        "preregistration.hypotheses",
    )
    statuses = {
        "null": "challenged_not_eliminated",
        "candidate": "supported_in_replay",
        "rival": "partially_supported",
        "unknown": "retained",
    }
    all_digests = [str(result["result_digest"]) for result in results]
    rows: list[JsonObject] = []
    for hypothesis in hypotheses:
        hypothesis_id = hypothesis["hypothesis_id"]
        counter_ids = [challenge["challenge_id"] for challenge in challenges if challenge["target_hypothesis_id"] == hypothesis_id]
        if not counter_ids:
            counter_ids = [challenges[0]["challenge_id"]]
        rows.append(
            {
                "hypothesis_id": hypothesis_id,
                "kind": hypothesis["kind"],
                "status": statuses[str(hypothesis["kind"])],
                "evidence_digests": all_digests,
                "counter_evidence_ids": counter_ids,
            }
        )
    return rows


def build_intelligence_research_candidate_body(mission: JsonObject) -> JsonObject:
    """Build the deterministic non-promoted candidate body before independent verification."""
    validate_intelligence_research_mission(mission)
    results = build_method_results(mission)
    aggregate = build_aggregate(mission, results)
    experiment = require_object(mission["experiment"], "experiment")
    if int(cast(int, aggregate["maximum_complexity_delta"])) > int(cast(int, experiment["maximum_candidate_complexity_delta"])):
        raise IntelligenceResearchError("Intelligence research candidate exceeded the preregistered complexity ceiling.")
    predictions = build_predictions(mission, aggregate)
    challenges = build_challenges(mission)
    hypotheses = build_hypothesis_results(mission, results, challenges)
    body: JsonObject = {
        "settlement_id": "73000000-0000-4000-8000-000000000300",
        "origin": "replayed",
        "mission_digest": sha256_digest(mission),
        "source_evidence_digests": [source["digest"] for source in require_object_list(mission["source_evidence"], "source_evidence")],
        "research_question": mission["research_question"],
        "discovery_trace": {
            "opportunity_id": require_object(mission["discovery"], "discovery")["opportunity_id"],
            "creative_operator_count": len(require_string_list(mission["creativity_operators"], "creativity_operators")),
            "hypothesis_count": 4,
            "experiment_count": 1,
            "theory_count": 1,
        },
        "method_results": results,
        "aggregate_comparison": aggregate,
        "hypotheses": hypotheses,
        "predictions": predictions,
        "challenge_log": challenges,
        "metacognition": {
            "knowledge_state": "partially_known",
            "understanding_confidence": 0.82,
            "calibration_confidence": 0.58,
            "generalization_confidence": 0.1,
            "missing_evidence": [
                "hidden benchmark evaluation",
                "external replication by an independent implementation",
                "forward validation on future domains",
                "measured real-world reasoning outcomes",
            ],
            "should_investigate_further": True,
            "should_abstain_from_generalization": True,
            "stop_reason": "preregistered_replay_complete_external_evaluation_missing",
        },
        "candidate_theory": {
            "theory_id": "73000000-0000-4000-8000-000000000310",
            "statement": "Within two evidence-incomplete security method-structure replays, representing uncertainty and adversarially decomposing before retrieval increased preregistered operation coverage while preserving an abstention path within the complexity ceiling.",
            "status": "candidate_only",
            "scope": "two_replayed_security_method_structure_cases",
            "evidence_digests": [str(result["result_digest"]) for result in results],
            "falsifiers": [
                "held-out cases fail the preregistered coverage delta",
                "independent replication cannot reproduce the aggregate",
                "measured task outcomes regress despite structural coverage",
                "complexity cost exceeds the preregistered ceiling",
            ],
            "generalization_allowed": False,
            "promotion_authorized": False,
            "authority_retained": False,
        },
        "authority": dict(EXPECTED_AUTHORITY),
        "security_claim": "Replay-only structural research supports one scope-limited candidate theory; generalization, production independence, promotion, execution, and target contact remain unproven or prohibited",
    }
    return body


def build_intelligence_research_settlement(mission: JsonObject, project_root: Path) -> JsonObject:
    """Run one deterministic scientific replay and attach separate-process verification."""

    body = build_intelligence_research_candidate_body(mission)
    body["independent_verification"] = run_separate_process_verification(project_root, mission, body)
    return {
        "settlement_version": "0.1.0",
        "settlement_digest": sha256_digest(body),
        "settlement": body,
    }


def validate_intelligence_research_settlement(document: JsonObject, mission: JsonObject) -> None:
    """Validate a research settlement by deterministic reconstruction and digest comparison."""

    validate_intelligence_research_mission(mission)
    body = require_object(document.get("settlement"), "settlement")
    if document.get("settlement_version") != "0.1.0" or document.get("settlement_digest") != sha256_digest(body):
        raise IntelligenceResearchError("Intelligence research settlement version or content digest is invalid.")
    validate_authority(body.get("authority"), "settlement.authority")
    verification = require_object(body.get("independent_verification"), "settlement.independent_verification")
    partial = {key: value for key, value in body.items() if key != "independent_verification"}
    expected_verification = build_structural_verification(mission, partial, True)
    if verification != expected_verification:
        raise IntelligenceResearchError(
            f"Intelligence research independent verification was substituted: expected={expected_verification!r}."
        )
    expected_body = build_intelligence_research_candidate_body(mission)
    expected_body["independent_verification"] = expected_verification
    expected: JsonObject = {
        "settlement_version": "0.1.0",
        "settlement_digest": sha256_digest(expected_body),
        "settlement": expected_body,
    }
    if document != expected:
        raise IntelligenceResearchError("Intelligence research settlement differs from deterministic replay and verifier evidence.")
