"""Read-only structural verifier for constitutional intelligence research replays."""

from __future__ import annotations

from collections.abc import Sequence
from typing import cast

from nimrod_simulator.errors import IntelligenceResearchError
from nimrod_simulator.jsonio import sha256_digest
from nimrod_simulator.model import JsonObject


EXPECTED_VERIFIED_CLAIMS: tuple[str, ...] = (
    "mission_digest_bound",
    "source_evidence_bound",
    "paired_case_matrix_complete",
    "result_digests_valid",
    "aggregate_recomputed",
    "predictions_recomputed",
    "counter_evidence_preserved",
    "candidate_theory_non_authorizing",
)


def require_object(value: object, label: str) -> JsonObject:
    if not isinstance(value, dict):
        raise IntelligenceResearchError(f"Research verifier {label} must be an object.")
    return cast(JsonObject, value)


def require_object_list(value: object, label: str) -> tuple[JsonObject, ...]:
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise IntelligenceResearchError(f"Research verifier {label} must be a list of objects.")
    return tuple(cast(JsonObject, item) for item in value)


def require_number(value: object, label: str) -> float:
    if not isinstance(value, int | float) or isinstance(value, bool):
        raise IntelligenceResearchError(f"Research verifier {label} must be numeric.")
    return float(value)


def rounded_mean(values: Sequence[float]) -> float:
    if not values:
        raise IntelligenceResearchError("Research verifier cannot average an empty metric sequence.")
    return round(sum(values) / len(values), 6)


def verify_result_digests(results: tuple[JsonObject, ...]) -> None:
    identities: set[tuple[object, object]] = set()
    for result in results:
        identity = (result.get("method_id"), result.get("case_id"))
        if identity in identities:
            raise IntelligenceResearchError(f"Research verifier found duplicate method/case result: {identity!r}.")
        identities.add(identity)
        digest = result.get("result_digest")
        unsigned = {key: value for key, value in result.items() if key != "result_digest"}
        if digest != sha256_digest(unsigned):
            raise IntelligenceResearchError(
                f"Research verifier result digest mismatch: result_id={result.get('result_id')!r}."
            )


def verify_matrix(mission: JsonObject, results: tuple[JsonObject, ...]) -> tuple[str, str]:
    methods = require_object_list(mission.get("methods"), "mission.methods")
    cases = require_object_list(mission.get("benchmark_cases"), "mission.benchmark_cases")
    expected_pairs = {(method.get("method_id"), case.get("case_id")) for method in methods for case in cases}
    received_pairs = {(result.get("method_id"), result.get("case_id")) for result in results}
    if received_pairs != expected_pairs:
        raise IntelligenceResearchError(
            "Research verifier requires one result for every preregistered method/case pair: "
            f"expected={sorted(expected_pairs)!r}, received={sorted(received_pairs)!r}."
        )
    by_role = {str(method.get("role")): str(method.get("method_id")) for method in methods}
    if set(by_role) != {"baseline", "candidate"}:
        raise IntelligenceResearchError("Research verifier requires exactly one baseline and one candidate method.")
    return by_role["baseline"], by_role["candidate"]


def verify_aggregate(
    aggregate: JsonObject,
    results: tuple[JsonObject, ...],
    baseline_id: str,
    candidate_id: str,
) -> None:
    baseline = tuple(result for result in results if result.get("method_id") == baseline_id)
    candidate = tuple(result for result in results if result.get("method_id") == candidate_id)
    baseline_coverages = tuple(
        require_number(require_object(result.get("metrics"), "result.metrics").get("required_operation_coverage"), "baseline coverage")
        for result in baseline
    )
    candidate_coverages = tuple(
        require_number(require_object(result.get("metrics"), "result.metrics").get("required_operation_coverage"), "candidate coverage")
        for result in candidate
    )
    baseline_uncertainty = tuple(
        require_number(require_object(result.get("metrics"), "result.metrics").get("uncertainty_preservation"), "baseline uncertainty")
        for result in baseline
    )
    candidate_uncertainty = tuple(
        require_number(require_object(result.get("metrics"), "result.metrics").get("uncertainty_preservation"), "candidate uncertainty")
        for result in candidate
    )
    baseline_complexity = tuple(
        int(require_number(require_object(result.get("metrics"), "result.metrics").get("complexity_cost"), "baseline complexity"))
        for result in baseline
    )
    candidate_complexity = tuple(
        int(require_number(require_object(result.get("metrics"), "result.metrics").get("complexity_cost"), "candidate complexity"))
        for result in candidate
    )
    expected: JsonObject = {
        "baseline_method_id": baseline_id,
        "candidate_method_id": candidate_id,
        "mean_required_operation_coverage_baseline": rounded_mean(baseline_coverages),
        "mean_required_operation_coverage_candidate": rounded_mean(candidate_coverages),
        "mean_required_operation_coverage_delta": round(
            rounded_mean(candidate_coverages) - rounded_mean(baseline_coverages), 6
        ),
        "mean_uncertainty_preservation_delta": round(
            rounded_mean(candidate_uncertainty) - rounded_mean(baseline_uncertainty), 6
        ),
        "maximum_complexity_delta": max(candidate_complexity) - max(baseline_complexity),
        "preregistered_predictions_passed": True,
        "hard_failure_count": 0,
    }
    if aggregate != expected:
        raise IntelligenceResearchError(
            f"Research verifier aggregate differs from independent recomputation: expected={expected!r}, received={aggregate!r}."
        )


def verify_predictions(mission: JsonObject, body: JsonObject) -> None:
    aggregate = require_object(body.get("aggregate_comparison"), "settlement.aggregate_comparison")
    predictions = require_object_list(body.get("predictions"), "settlement.predictions")
    registered = require_object_list(
        require_object(mission.get("preregistration"), "mission.preregistration").get("predictions"),
        "mission.preregistration.predictions",
    )
    observed_by_metric: dict[str, float] = {
        "mean_required_operation_coverage_delta": require_number(
            aggregate.get("mean_required_operation_coverage_delta"), "aggregate coverage delta"
        ),
        "mean_uncertainty_preservation_delta": require_number(
            aggregate.get("mean_uncertainty_preservation_delta"), "aggregate uncertainty delta"
        ),
        "maximum_complexity_delta": require_number(
            aggregate.get("maximum_complexity_delta"), "aggregate complexity delta"
        ),
    }
    expected: list[JsonObject] = []
    for prediction in registered:
        metric = str(prediction.get("metric"))
        observed = observed_by_metric[metric]
        threshold = require_number(prediction.get("threshold"), f"prediction {metric} threshold")
        comparator = prediction.get("comparator")
        passed = observed >= threshold if comparator == "greater_than_or_equal" else observed <= threshold
        expected.append({"prediction_id": prediction.get("prediction_id"), "observed_value": observed, "passed": passed})
    if list(predictions) != expected or not all(item["passed"] is True for item in expected):
        raise IntelligenceResearchError(
            f"Research verifier prediction outcomes differ from preregistration: expected={expected!r}."
        )


def verify_challenges(body: JsonObject) -> None:
    challenges = require_object_list(body.get("challenge_log"), "settlement.challenge_log")
    kinds = {challenge.get("kind") for challenge in challenges}
    required = {
        "null_challenge",
        "complexity_confound",
        "fixture_scarcity",
        "structural_proxy_limit",
        "verifier_boundary_limit",
        "generalization_limit",
    }
    if kinds != required:
        raise IntelligenceResearchError(
            f"Research verifier requires every skeptical challenge exactly once: expected={sorted(required)!r}, received={sorted(kinds)!r}."
        )
    if any(challenge.get("material") is not True for challenge in challenges):
        raise IntelligenceResearchError("Research verifier rejects non-material or suppressed challenge entries.")


def verify_theory(body: JsonObject) -> None:
    theory = require_object(body.get("candidate_theory"), "settlement.candidate_theory")
    if theory.get("status") != "candidate_only":
        raise IntelligenceResearchError("Research verifier cannot accept a promoted theory.")
    for field in ("generalization_allowed", "promotion_authorized", "authority_retained"):
        if theory.get(field) is not False:
            raise IntelligenceResearchError(
                f"Research verifier theory boundary widened: field={field!r}, value={theory.get(field)!r}."
            )


def build_structural_verification(mission: JsonObject, body: JsonObject, separate_process: bool) -> JsonObject:
    """Independently recompute replay structure without authorizing or mutating inputs."""

    if body.get("mission_digest") != sha256_digest(mission):
        raise IntelligenceResearchError("Research verifier mission digest binding is invalid.")
    expected_sources = [source.get("digest") for source in require_object_list(mission.get("source_evidence"), "mission.source_evidence")]
    if body.get("source_evidence_digests") != expected_sources:
        raise IntelligenceResearchError("Research verifier source evidence binding is invalid.")
    results = require_object_list(body.get("method_results"), "settlement.method_results")
    verify_result_digests(results)
    baseline_id, candidate_id = verify_matrix(mission, results)
    verify_aggregate(
        require_object(body.get("aggregate_comparison"), "settlement.aggregate_comparison"),
        results,
        baseline_id,
        candidate_id,
    )
    verify_predictions(mission, body)
    verify_challenges(body)
    verify_theory(body)
    verifier = require_object(mission.get("verifier"), "mission.verifier")
    return {
        "required": True,
        "performed": True,
        "verifier_id": verifier.get("verifier_id"),
        "scope": "structural_replay_only",
        "status": "replay_structure_verified",
        "read_only": True,
        "same_research_principal": False,
        "separate_process": separate_process,
        "production_independence_verified": False,
        "verified_claims": list(EXPECTED_VERIFIED_CLAIMS),
        "limitations": [
            "separate process used; dedicated OS-account and production independence remain unproven",
            "no hidden, private, external, or production evaluation was performed",
        ],
    }
