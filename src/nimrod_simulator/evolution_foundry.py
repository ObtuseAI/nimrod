"""Candidate-only compilation, capability escalation, and lexicographic evaluation."""

from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

from nimrod_simulator.authorization import parse_timestamp
from nimrod_simulator.errors import (
    ControlStateValidationError,
    EvolutionArtifactError,
    EvolutionCandidateError,
    EvolutionEvaluationError,
    JsonDocumentError,
)
from nimrod_simulator.evolution_constitution import (
    REQUIRED_CAPABILITY_RESPONSES,
    REQUIRED_HARD_FAILURES,
    verify_evolution_constitution,
)
from nimrod_simulator.jsonio import canonical_json_bytes, read_json_object, require_integer, require_list, require_object, require_string, sha256_digest
from nimrod_simulator.model import JsonObject


EPISTEMIC_POSTURE_CONTRACT = "epistemic-posture.schema.json"
EVOLUTION_BASELINE_CONTRACT = "evolution-baseline.schema.json"


EPISTEMIC_STANDARD_BY_MODE = {
    "deterministic": "exact_proof",
    "probabilistic": "calibrated_evidence",
    "plural_context": "context_bounded_interpretation",
}
CLAIM_TYPES = {"observed", "inferred", "predicted", "counterfactual", "normative", "human_assertion"}
REQUIRED_CHAMPION_FLOORS = {"SAFETY", "CALIBRATION", "PRIVACY", "RECOVERY", "CONTROLLABILITY"}
REQUIRED_EVALUATOR_ROLES = {"public_regression", "sealed_holdout", "adversarial", "rights_and_recovery"}
CANDIDATE_AUTHORITY = {
    "can_execute": False,
    "can_modify_active_baseline": False,
    "can_modify_constitution": False,
    "can_modify_evaluators": False,
    "can_select_signers": False,
    "can_access_sealed_answers": False,
    "can_acquire_credentials": False,
    "can_expand_network": False,
    "can_replicate_or_persist": False,
    "can_expand_compute": False,
}


def _utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def validate_epistemic_posture(posture: JsonObject) -> None:
    if posture.get("posture_version") != "0.1.0" or posture.get("origin") != "simulated":
        raise EvolutionCandidateError("Epistemic posture must be version 0.1.0 and simulated.")
    mode = require_string(posture.get("mode"), "posture.mode")
    if EPISTEMIC_STANDARD_BY_MODE.get(mode) != posture.get("evidence_standard"):
        raise EvolutionCandidateError("Epistemic posture mode and evidence standard are inconsistent.")
    claim_type = require_string(posture.get("claim_type"), "posture.claim_type")
    if claim_type not in CLAIM_TYPES:
        raise EvolutionCandidateError(f"Unsupported epistemic claim type '{claim_type}'.")
    counterfactual = posture.get("counterfactual")
    if not isinstance(counterfactual, bool) or counterfactual != (claim_type == "counterfactual"):
        raise EvolutionCandidateError("Only counterfactual claims may set counterfactual true.")
    boundaries = require_list(posture.get("context_boundaries"), "posture.context_boundaries")
    if mode == "plural_context" and not boundaries:
        raise EvolutionCandidateError("Plural-context posture requires explicit context boundaries.")
    authority = require_object(posture.get("authority"), "posture.authority")
    if authority != {"can_relabel_evidence": False, "can_waive_hard_failures": False}:
        raise EvolutionCandidateError("Epistemic posture cannot relabel evidence or waive hard failures.")


def _validate_resource_lease(
    resource_lease: JsonObject,
    constitution: JsonObject,
    now: datetime,
) -> None:
    ceilings = require_object(constitution.get("resource_ceilings"), "constitution.resource_ceilings")
    mappings = {
        "maximum_cycle_seconds": "maximum_cycle_seconds",
        "maximum_compute_units": "maximum_compute_units",
        "maximum_memory_megabytes": "maximum_memory_megabytes",
        "maximum_storage_megabytes": "maximum_storage_megabytes",
        "maximum_candidate_children": "maximum_candidate_children",
    }
    for lease_field, ceiling_field in mappings.items():
        value = require_integer(resource_lease.get(lease_field), f"resource_lease.{lease_field}")
        ceiling = require_integer(ceilings.get(ceiling_field), f"resource_ceilings.{ceiling_field}")
        if value <= 0 or value > ceiling:
            raise EvolutionCandidateError(
                f"Candidate resource '{lease_field}' value {value} exceeds constitutional ceiling {ceiling}."
            )
    try:
        expires_at = parse_timestamp(resource_lease.get("expires_at"), "resource_lease.expires_at")
    except ControlStateValidationError as error:
        raise EvolutionCandidateError(f"Candidate resource lease expiry is invalid: {error}.") from error
    if now.utcoffset() is None or expires_at <= now:
        raise EvolutionCandidateError("Candidate resource lease must be timezone-aware and active.")
    authority = require_object(resource_lease.get("authority"), "resource_lease.authority")
    if authority != {"can_self_extend": False, "can_purchase_compute": False}:
        raise EvolutionCandidateError("Candidate resource lease cannot self-extend or purchase compute.")


def compile_cognitive_candidate(
    source_candidate: JsonObject,
    active_baseline: JsonObject,
    constitution: JsonObject,
    governance_state: JsonObject,
    epistemic_posture: JsonObject,
    resource_lease: JsonObject,
    uncertainty: JsonObject,
    now: datetime,
    maximum_constitution_lifetime_seconds: int,
) -> JsonObject:
    constitution_verification = verify_evolution_constitution(
        constitution,
        governance_state,
        now,
        maximum_constitution_lifetime_seconds,
    )
    if source_candidate.get("candidate_version") != "0.1.0" or source_candidate.get("status") != "quarantined":
        raise EvolutionCandidateError("Source improvement candidate must be v0.1.0 and quarantined.")
    if active_baseline.get("baseline_version") != "0.1.0" or active_baseline.get("origin") != "simulated":
        raise EvolutionCandidateError("Active baseline must be version 0.1.0 and simulated.")
    if active_baseline.get("active") is not True:
        raise EvolutionCandidateError("Candidate compilation requires an explicitly active baseline.")
    baseline_authority = require_object(active_baseline.get("authority"), "baseline.authority")
    if baseline_authority != {"candidate_write_permitted": False, "can_execute": False}:
        raise EvolutionCandidateError("Active baseline cannot permit candidate writes or execution.")
    validate_epistemic_posture(epistemic_posture)
    _validate_resource_lease(resource_lease, constitution, now)
    uncertainty_level = require_string(uncertainty.get("level"), "uncertainty.level")
    if uncertainty_level not in {"bounded", "high", "unknown"}:
        raise EvolutionCandidateError(f"Unsupported candidate uncertainty level '{uncertainty_level}'.")
    limitations = require_list(uncertainty.get("known_limitations"), "uncertainty.known_limitations")
    if uncertainty_level != "bounded" and not limitations:
        raise EvolutionCandidateError("High or unknown uncertainty requires explicit limitations.")
    source_evidence = require_list(source_candidate.get("source_evidence"), "source_candidate.source_evidence")
    if not source_evidence:
        raise EvolutionCandidateError("Cognitive candidate requires source evidence.")
    proposed_delta = require_object(source_candidate.get("proposed_delta"), "source_candidate.proposed_delta")
    rollback_steps = require_list(source_candidate.get("rollback"), "source_candidate.rollback")
    if not rollback_steps:
        raise EvolutionCandidateError("Cognitive candidate requires rollback evidence.")
    return {
        "bundle_version": "0.1.0",
        "candidate_id": source_candidate["candidate_id"],
        "origin": "simulated",
        "compiled_at": _utc(now),
        "source_candidate_digest": sha256_digest(source_candidate),
        "active_baseline_digest": sha256_digest(active_baseline),
        "constitution_digest": constitution_verification["constitution_digest"],
        "candidate_class": source_candidate["candidate_class"],
        "authority_tier": source_candidate["authority_tier"],
        "lens": source_candidate["lens"],
        "mutation_family": source_candidate["mutation_family"],
        "epistemic_posture": epistemic_posture,
        "source_evidence": source_evidence,
        "contradicting_evidence": source_candidate.get("contradicting_evidence", []),
        "proposed_delta_digest": sha256_digest(proposed_delta),
        "proposed_delta_retained": False,
        "prediction": source_candidate["prediction"],
        "uncertainty": uncertainty,
        "resource_lease": resource_lease,
        "rollback_digest": sha256_digest(rollback_steps),
        "status": "quarantined",
        "active_baseline_modified": False,
        "candidate_executed": False,
        "authority": CANDIDATE_AUTHORITY,
    }


def assess_capability_thresholds(
    candidate: JsonObject,
    constitution: JsonObject,
    assessments: list[JsonObject],
    assessed_at: datetime,
) -> JsonObject:
    if candidate.get("constitution_digest") != sha256_digest(constitution):
        raise EvolutionEvaluationError("Capability assessment candidate constitution mismatch.")
    by_trigger: dict[str, JsonObject] = {}
    for assessment in assessments:
        trigger_id = require_string(assessment.get("trigger_id"), "assessment.trigger_id")
        if trigger_id in by_trigger:
            raise EvolutionEvaluationError(f"Capability assessment repeats trigger '{trigger_id}'.")
        status = require_string(assessment.get("status"), "assessment.status")
        if status not in {"absent", "present", "unknown"}:
            raise EvolutionEvaluationError(f"Capability trigger '{trigger_id}' has unsupported status '{status}'.")
        evidence = require_list(assessment.get("evidence"), "assessment.evidence")
        if status != "unknown" and not evidence:
            raise EvolutionEvaluationError(f"Capability trigger '{trigger_id}' status '{status}' lacks evidence.")
        by_trigger[trigger_id] = assessment
    if set(by_trigger) != set(REQUIRED_CAPABILITY_RESPONSES):
        raise EvolutionEvaluationError("Capability assessment must contain every constitutional trigger exactly once.")
    levels: list[str] = []
    blockers: list[str] = []
    for trigger_id, assessment in by_trigger.items():
        status = assessment["status"]
        if status == "unknown":
            levels.append("pause")
            blockers.append(f"UNKNOWN_{trigger_id}")
        elif status == "present":
            response = REQUIRED_CAPABILITY_RESPONSES[trigger_id]
            levels.append(response)
            blockers.append(trigger_id)
    precedence = {"baseline": 0, "elevated": 1, "isolated_enclave": 2, "pause": 3}
    required_level = max(["baseline", *levels], key=lambda value: precedence[value])
    return {
        "report_version": "0.1.0",
        "report_id": str(uuid.uuid5(uuid.UUID("8860abff-5a7d-46e3-9969-2f7aa991cf3d"), f"{sha256_digest(candidate)}:{_utc(assessed_at)}")),
        "origin": "simulated",
        "candidate_digest": sha256_digest(candidate),
        "constitution_digest": sha256_digest(constitution),
        "assessed_at": _utc(assessed_at),
        "assessments": [by_trigger[key] for key in sorted(by_trigger)],
        "required_safeguard_level": required_level,
        "paused": required_level == "pause",
        "status": "clear" if required_level == "baseline" else "escalation_required",
        "blockers": sorted(blockers),
        "authority": {"can_expand_safeguards": False, "can_expand_authority": False, "can_execute": False},
    }


def evaluate_cognitive_candidate(
    candidate: JsonObject,
    constitution: JsonObject,
    capability_report: JsonObject,
    evaluator_observations: list[JsonObject],
    hard_gate_results: list[JsonObject],
    champion_floor_results: list[JsonObject],
    metrics: list[JsonObject],
    evaluated_at: datetime,
) -> JsonObject:
    candidate_digest = sha256_digest(candidate)
    if candidate.get("authority") != CANDIDATE_AUTHORITY:
        raise EvolutionEvaluationError("Cognitive candidate authority was widened.")
    if candidate.get("constitution_digest") != sha256_digest(constitution):
        raise EvolutionEvaluationError("Evaluation constitution digest mismatch.")
    if capability_report.get("candidate_digest") != candidate_digest:
        raise EvolutionEvaluationError("Capability report candidate digest mismatch.")
    if capability_report.get("constitution_digest") != sha256_digest(constitution):
        raise EvolutionEvaluationError("Capability report constitution digest mismatch.")
    roles: set[str] = set()
    evaluator_ids: set[str] = set()
    principals: set[str] = set()
    process_ids: set[int] = set()
    blockers: list[str] = []
    for observation in evaluator_observations:
        role = require_string(observation.get("role"), "evaluator.role")
        roles.add(role)
        evaluator_ids.add(require_string(observation.get("evaluator_id"), "evaluator.evaluator_id"))
        principals.add(require_string(observation.get("logical_principal"), "evaluator.logical_principal"))
        process_ids.add(require_integer(observation.get("process_id"), "evaluator.process_id"))
        if observation.get("subject_digest") != candidate_digest:
            raise EvolutionEvaluationError("Evaluator observation candidate digest mismatch.")
        status = require_string(observation.get("status"), "evaluator.status")
        if status not in {"pass", "fail", "inconclusive"}:
            raise EvolutionEvaluationError(f"Unsupported evaluator status '{status}'.")
        if status != "pass":
            blockers.append(f"EVALUATOR_{role}_{status}".upper())
    if roles != REQUIRED_EVALUATOR_ROLES or len(evaluator_ids) != 4 or len(principals) != 4 or len(process_ids) != 4:
        raise EvolutionEvaluationError("Evaluation requires four distinct evaluator roles, identities, principals, and processes.")
    gate_status: dict[str, str] = {}
    for result in hard_gate_results:
        gate_id = require_string(result.get("gate_id"), "hard_gate.gate_id")
        if gate_id in gate_status:
            raise EvolutionEvaluationError(f"Evaluation repeats hard gate '{gate_id}'.")
        status = require_string(result.get("status"), "hard_gate.status")
        if status not in {"pass", "fail", "inconclusive"}:
            raise EvolutionEvaluationError(f"Hard gate '{gate_id}' has unsupported status '{status}'.")
        if status == "pass" and not require_list(result.get("evidence"), "hard_gate.evidence"):
            raise EvolutionEvaluationError(f"Passing hard gate '{gate_id}' lacks evidence.")
        gate_status[gate_id] = status
        if status != "pass":
            blockers.append(gate_id)
    if set(gate_status) != REQUIRED_HARD_FAILURES:
        raise EvolutionEvaluationError("Evaluation must contain every constitutional hard gate exactly once.")
    floor_status: dict[str, str] = {}
    for result in champion_floor_results:
        floor_id = require_string(result.get("floor_id"), "champion_floor.floor_id")
        if floor_id in floor_status:
            raise EvolutionEvaluationError(f"Evaluation repeats champion floor '{floor_id}'.")
        status = require_string(result.get("status"), "champion_floor.status")
        if status not in {"pass", "regressed", "inconclusive"}:
            raise EvolutionEvaluationError(f"Champion floor '{floor_id}' has unsupported status '{status}'.")
        floor_status[floor_id] = status
        if status != "pass":
            blockers.append(f"CHAMPION_{floor_id}_{status}".upper())
    if set(floor_status) != REQUIRED_CHAMPION_FLOORS:
        raise EvolutionEvaluationError("Evaluation must contain every champion floor exactly once.")
    if not metrics:
        raise EvolutionEvaluationError("Evaluation requires at least one vector metric.")
    for metric in metrics:
        if any("score" in key.casefold() for key in metric):
            raise EvolutionEvaluationError("Evaluation vector cannot contain an aggregate or scalar score field.")
        outcome = require_string(metric.get("outcome"), "metric.outcome")
        if outcome not in {"improved", "equal", "regressed", "unknown"}:
            raise EvolutionEvaluationError(f"Evaluation metric has unsupported outcome '{outcome}'.")
        if outcome in {"regressed", "unknown"}:
            blockers.append(f"METRIC_{require_string(metric.get('dimension'), 'metric.dimension')}_{outcome}".upper())
    if capability_report.get("status") != "clear":
        blockers.extend(require_string(value, "capability.blocker") for value in require_list(capability_report.get("blockers"), "capability.blockers"))
    if candidate.get("authority_tier") not in {"A", "B"}:
        blockers.append("TIER_NOT_SHADOW_ELIGIBLE")
    if require_object(candidate.get("uncertainty"), "candidate.uncertainty").get("level") != "bounded":
        blockers.append("UNCERTAINTY_NOT_BOUNDED")
    blockers = sorted(set(blockers))
    eligible = not blockers
    return {
        "evaluation_version": "0.1.0",
        "evaluation_id": str(uuid.uuid5(uuid.UUID("451489a9-720b-4cf5-90fd-e95a2d634351"), f"{candidate_digest}:{_utc(evaluated_at)}")),
        "origin": "simulated",
        "candidate_digest": candidate_digest,
        "active_baseline_digest": candidate["active_baseline_digest"],
        "constitution_digest": candidate["constitution_digest"],
        "capability_report_digest": sha256_digest(capability_report),
        "evaluated_at": _utc(evaluated_at),
        "evaluator_observations": evaluator_observations,
        "hard_gate_results": hard_gate_results,
        "champion_floor_results": champion_floor_results,
        "metrics": metrics,
        "aggregate_score_present": False,
        "status": "eligible_for_shadow" if eligible else "blocked",
        "blockers": blockers,
        "candidate_executed": False,
        "active_baseline_modified": False,
        "authority": {"can_promote": False, "can_execute": False, "can_modify_evaluators": False},
    }


class EvolutionArtifactStore:
    """Content-addressed immutable artifact connector for Foundry boundaries."""

    def __init__(self, root: Path) -> None:
        self._root = root / "evolution-foundry" / "v1" / "artifacts"
        self._temporary_root = root / "evolution-foundry" / "v1" / "temporary"
        self._root.mkdir(parents=True, exist_ok=True)
        self._temporary_root.mkdir(parents=True, exist_ok=True)

    def publish(self, document: JsonObject, artifact_kind: str) -> str:
        if not artifact_kind:
            raise EvolutionArtifactError("Evolution artifact kind cannot be empty.")
        digest = sha256_digest(document)
        path = self._path(digest)
        if path.is_file():
            if self.read(digest) != document:
                raise EvolutionArtifactError(f"Evolution artifact digest collision at '{path}'.")
            return digest
        temporary = self._temporary_root / f".{digest.removeprefix('sha256:')}.{uuid.uuid4().hex}.tmp"
        wrapped: JsonObject = {"artifact_kind": artifact_kind, "artifact_digest": digest, "document": document}
        try:
            with temporary.open("xb") as handle:
                handle.write(canonical_json_bytes(wrapped) + b"\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.link(temporary, path)
        except FileExistsError:
            if path.is_file() and self.read(digest) == document:
                return digest
            raise EvolutionArtifactError(f"Evolution artifact publication conflicts at '{path}'.")
        except OSError as error:
            raise EvolutionArtifactError(f"Evolution artifact publication failed for '{path}': {error}.") from error
        finally:
            if temporary.exists():
                temporary.unlink()
        return digest

    def read(self, digest: str) -> JsonObject:
        path = self._path(digest)
        try:
            wrapped = read_json_object(path)
            document = require_object(wrapped.get("document"), "artifact.document")
        except JsonDocumentError as error:
            raise EvolutionArtifactError(f"Evolution artifact is missing or malformed: '{path}'.") from error
        if wrapped.get("artifact_digest") != digest or sha256_digest(document) != digest:
            raise EvolutionArtifactError(f"Evolution artifact digest mismatch: '{path}'.")
        return document

    def _path(self, digest: str) -> Path:
        if not digest.startswith("sha256:") or len(digest) != 71:
            raise EvolutionArtifactError(f"Evolution artifact digest is invalid: '{digest}'.")
        return self._root / f"{digest.removeprefix('sha256:')}.json"
