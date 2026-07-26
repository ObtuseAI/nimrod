from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from functools import partial
from pathlib import Path
from typing import cast

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from nimrod_simulator.errors import (
    EvolutionArtifactError,
    EvolutionCandidateError,
    EvolutionConstitutionError,
    EvolutionEvaluationError,
    EvolutionTransitionError,
    SimulatorError,
)
from nimrod_simulator.evolution_constitution import (
    REQUIRED_AXIOMS,
    REQUIRED_CAPABILITY_RESPONSES,
    REQUIRED_HARD_FAILURES,
    sign_evolution_constitution,
    verify_evolution_constitution,
)
from nimrod_simulator.evolution_foundry import (
    CANDIDATE_AUTHORITY,
    REQUIRED_CHAMPION_FLOORS,
    EvolutionArtifactStore,
    assess_capability_thresholds,
    compile_cognitive_candidate,
    evaluate_cognitive_candidate,
    validate_epistemic_posture,
)
from nimrod_simulator.evolution_transition import EvolutionTransitionStore, no_transition_failure, sign_evolution_transition, verify_evolution_transition
from nimrod_simulator.jsonio import read_json_object, sha256_digest, validate_contract
from nimrod_simulator.key_governance import EphemeralEd25519SigningConnector, governance_key
from nimrod_simulator.model import JsonObject
from validate_evolution_assurance import (
    evaluator_connectors,
    evaluator_envelopes,
    evaluator_policy,
    isolation_attestations,
    resource_ledger as build_resource_ledger,
)


VALIDATION_TIME = datetime(2026, 7, 13, 4, 31, 0, tzinfo=timezone.utc)
CONSTITUTION_LIFETIME_SECONDS = 1200
TRANSITION_LIFETIME_SECONDS = 300
WORKER_COUNT = 16


def require_condition(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def expect_error(expected: type[SimulatorError], operation: Callable[[], object], label: str) -> None:
    try:
        operation()
    except expected:
        return
    raise AssertionError(f"Expected {expected.__name__} for {label}.")


def reference(identifier: str) -> JsonObject:
    return {"id": identifier, "digest": sha256_digest({"fixture": identifier})}


def signing_connectors() -> list[EphemeralEd25519SigningConnector]:
    return [
        EphemeralEd25519SigningConnector("key:evolution-owner", "customer_authority", Ed25519PrivateKey.generate()),
        EphemeralEd25519SigningConnector("key:evolution-safety", "safety_officer", Ed25519PrivateKey.generate()),
        EphemeralEd25519SigningConnector("key:evolution-recovery", "recovery_officer", Ed25519PrivateKey.generate()),
    ]


def governance_state(connectors: list[EphemeralEd25519SigningConnector]) -> JsonObject:
    issued_at = "2026-07-12T23:30:00Z"
    return {
        "state_version": "0.1.0", "governance_id": "47d4a999-cd36-4805-be3c-1313c736a217", "origin": "simulated", "epoch": 1,
        "issued_at": issued_at, "previous_state_digest": None, "threshold": 2, "ceremony_key_count": 3, "minimum_distinct_roles": 2,
        "keys": [
            governance_key(connector, "active", issued_at, None, "test_ephemeral", f"connector:custody:{connector.key_id}", f"memory:{connector.key_id}", False, None)
            for connector in connectors
        ],
    }


def signed_constitution(
    governance: JsonObject,
    connectors: list[EphemeralEd25519SigningConnector],
    issued_at: datetime,
    not_before: datetime,
    expires_at: datetime,
) -> JsonObject:
    unsigned: JsonObject = {
        "constitution_version": "0.1.0", "constitution_id": "dfc3fb9d-6088-434b-814e-813108fba665", "origin": "simulated",
        "governance_state_digest": sha256_digest(governance),
        "issued_at": issued_at.isoformat().replace("+00:00", "Z"), "not_before": not_before.isoformat().replace("+00:00", "Z"), "expires_at": expires_at.isoformat().replace("+00:00", "Z"),
        "axioms": sorted(REQUIRED_AXIOMS), "hard_failures": sorted(REQUIRED_HARD_FAILURES),
        "capability_triggers": [{"trigger_id": trigger_id, "response": response} for trigger_id, response in sorted(REQUIRED_CAPABILITY_RESPONSES.items())],
        "tier_policies": [
            {"tier": "A", "maximum_destination": "shadow", "threshold_humans_required": False},
            {"tier": "B", "maximum_destination": "shadow", "threshold_humans_required": False},
            {"tier": "C", "maximum_destination": "production_candidate", "threshold_humans_required": True},
            {"tier": "D", "maximum_destination": "quarantine", "threshold_humans_required": True},
        ],
        "resource_ceilings": {"maximum_cycle_seconds": 300, "maximum_compute_units": 100, "maximum_memory_megabytes": 512, "maximum_storage_megabytes": 1024, "maximum_candidate_children": 4},
        "authority": {"can_modify_itself": False, "can_select_evaluators": False, "can_select_signers": False, "can_expand_authority": False, "can_execute": False},
    }
    return sign_evolution_constitution(unsigned, connectors[:2])


def baseline() -> JsonObject:
    return {
        "baseline_version": "0.1.0", "baseline_id": "ccf20158-0b59-4e99-a29b-4463796d2d04", "origin": "simulated", "generation": 1, "active": True,
        "artifact_digest": sha256_digest({"active_baseline": "immutable-fixture-v1"}),
        "authority": {"candidate_write_permitted": False, "can_execute": False},
    }


def posture() -> JsonObject:
    return {
        "posture_version": "0.1.0", "posture_id": "81b82841-b718-4d68-8ff7-fb0cf5c4f07b", "origin": "simulated", "mode": "probabilistic",
        "claim_type": "predicted", "evidence_standard": "calibrated_evidence", "counterfactual": False,
        "context_boundaries": ["simulated security fixture corpus"],
        "authority": {"can_relabel_evidence": False, "can_waive_hard_failures": False},
    }


def resource_lease() -> JsonObject:
    return {
        "cycle_id": "a28085e4-88c7-445e-a17e-8410ce5937e9", "maximum_cycle_seconds": 60, "maximum_compute_units": 10,
        "maximum_memory_megabytes": 128, "maximum_storage_megabytes": 64, "maximum_candidate_children": 1,
        "expires_at": (VALIDATION_TIME + timedelta(seconds=240)).isoformat().replace("+00:00", "Z"),
        "authority": {"can_self_extend": False, "can_purchase_compute": False},
    }


def uncertainty() -> JsonObject:
    return {"level": "bounded", "known_limitations": ["fixture-only evidence"]}


def assessments() -> list[JsonObject]:
    return [{"trigger_id": trigger_id, "status": "absent", "evidence": [reference(f"assessment:{trigger_id.casefold()}")]} for trigger_id in sorted(REQUIRED_CAPABILITY_RESPONSES)]


def evaluation_input(candidate: JsonObject) -> JsonObject:
    digest = sha256_digest(candidate)
    roles = ["public_regression", "sealed_holdout", "adversarial", "rights_and_recovery"]
    observations = [
        {"evaluator_id": f"evaluator:{role}", "logical_principal": f"principal:{role}", "process_id": 7101 + index, "role": role, "subject_digest": digest, "status": "pass", "evidence": [reference(f"evaluator:{role}")]}
        for index, role in enumerate(roles)
    ]
    gates = [{"gate_id": gate_id, "status": "pass", "evidence": [reference(f"gate:{gate_id.casefold()}")]} for gate_id in sorted(REQUIRED_HARD_FAILURES)]
    floors = [{"floor_id": floor_id, "status": "pass", "evidence": [reference(f"floor:{floor_id.casefold()}")]} for floor_id in sorted(REQUIRED_CHAMPION_FLOORS)]
    metrics = [{"dimension": "simulated_detection_precision", "outcome": "equal", "evidence": [reference("metric:precision")]}]
    return {"evaluator_observations": observations, "hard_gate_results": gates, "champion_floor_results": floors, "metrics": metrics}


def transition_envelope(
    candidate: JsonObject,
    evaluation: JsonObject,
    capability_report: JsonObject,
    constitution: JsonObject,
    connectors: list[EphemeralEd25519SigningConnector],
    action: str,
    destination: str,
    sequence: int,
    previous_receipt_digest: str | None,
    envelope_id: str,
) -> JsonObject:
    issued_at = VALIDATION_TIME - timedelta(seconds=10)
    unsigned: JsonObject = {
        "envelope_version": "0.1.0", "envelope_id": envelope_id, "origin": "simulated",
        "candidate_digest": sha256_digest(candidate), "evaluation_digest": sha256_digest(evaluation), "capability_report_digest": sha256_digest(capability_report),
        "constitution_digest": sha256_digest(constitution), "active_baseline_digest": candidate["active_baseline_digest"],
        "action": action, "destination": destination, "sequence": sequence, "previous_receipt_digest": previous_receipt_digest,
        "issued_at": issued_at.isoformat().replace("+00:00", "Z"), "not_before": issued_at.isoformat().replace("+00:00", "Z"), "expires_at": (VALIDATION_TIME + timedelta(seconds=120)).isoformat().replace("+00:00", "Z"),
        "authority": {"can_modify_active_baseline": False, "can_execute_candidate": False, "can_promote_to_production": False, "can_expand_authority": False},
    }
    return sign_evolution_transition(unsigned, connectors[:2])


def write_json(path: Path, value: JsonObject) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def run_worker(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=False, capture_output=True, text=True, timeout=30)


def promoter_command(project_root: Path, state_root: Path, paths: dict[str, Path], failure_point: str) -> list[str]:
    return [sys.executable, str(project_root / "tools" / "evolution_promoter_worker.py"), "--state-root", str(state_root), "--envelope", str(paths["envelope"]), "--candidate", str(paths["candidate"]), "--evaluation", str(paths["evaluation"]), "--capability-report", str(paths["capability"]), "--constitution", str(paths["constitution"]), "--governance", str(paths["governance"]), "--now", VALIDATION_TIME.isoformat().replace("+00:00", "Z"), "--maximum-constitution-lifetime-seconds", str(CONSTITUTION_LIFETIME_SECONDS), "--maximum-transition-lifetime-seconds", str(TRANSITION_LIFETIME_SECONDS), "--failure-point", failure_point]


def validate_evolution_foundry(project_root: Path) -> JsonObject:
    connectors = signing_connectors()
    governance = governance_state(connectors)
    constitution = signed_constitution(governance, connectors, VALIDATION_TIME - timedelta(seconds=30), VALIDATION_TIME - timedelta(seconds=30), VALIDATION_TIME + timedelta(seconds=600))
    verify_evolution_constitution(constitution, governance, VALIDATION_TIME, CONSTITUTION_LIFETIME_SECONDS)
    validate_contract(constitution, project_root / "specs" / "evolution-constitution.schema.json", "generated Evolution Constitution")
    active_baseline = baseline()
    source_candidate = read_json_object(project_root / "specs" / "examples" / "improvement-candidate.example.json")
    baseline_before = sha256_digest(active_baseline)
    adversarial_count = 0

    with tempfile.TemporaryDirectory(prefix="nimrod-evolution-foundry-") as temporary:
        root = Path(temporary)
        input_root = root / "inputs"
        input_root.mkdir()
        values = {"source": source_candidate, "baseline": active_baseline, "constitution": constitution, "governance": governance, "posture": posture(), "resource": resource_lease(), "uncertainty": uncertainty()}
        paths: dict[str, Path] = {}
        for name, value in values.items():
            path = input_root / f"{name}.json"
            write_json(path, value)
            paths[name] = path
        artifact_root = root / "artifacts"
        foundry_command = [sys.executable, str(project_root / "tools" / "evolution_foundry_worker.py"), "--source-candidate", str(paths["source"]), "--baseline", str(paths["baseline"]), "--constitution", str(paths["constitution"]), "--governance", str(paths["governance"]), "--posture", str(paths["posture"]), "--resource-lease", str(paths["resource"]), "--uncertainty", str(paths["uncertainty"]), "--artifact-root", str(artifact_root), "--now", VALIDATION_TIME.isoformat().replace("+00:00", "Z"), "--maximum-constitution-lifetime-seconds", str(CONSTITUTION_LIFETIME_SECONDS)]
        foundry_process = run_worker(foundry_command)
        require_condition(foundry_process.returncode == 0, f"Foundry worker failed: {foundry_process.stderr}")
        foundry_result = cast(JsonObject, json.loads(foundry_process.stdout))
        candidate = cast(JsonObject, foundry_result["document"])
        candidate_digest = cast(str, foundry_result["artifact_digest"])
        validate_contract(candidate, project_root / "specs" / "cognitive-candidate-bundle.schema.json", "generated cognitive candidate")
        require_condition(EvolutionArtifactStore(artifact_root).read(candidate_digest) == candidate, "Candidate CAS readback mismatch.")
        paths["candidate"] = input_root / "candidate.json"
        write_json(paths["candidate"], candidate)
        assessment_input: JsonObject = {"assessments": assessments()}
        paths["assessment"] = input_root / "assessment.json"
        write_json(paths["assessment"], assessment_input)
        eval_input = evaluation_input(candidate)
        evaluator_signers = evaluator_connectors()
        signed_evaluator_policy = evaluator_policy(
            constitution,
            governance,
            connectors,
            evaluator_signers,
        )
        signed_isolation_attestations = isolation_attestations(
            signed_evaluator_policy,
            governance,
            connectors,
            "fixture",
        )
        signed_resource_ledger = build_resource_ledger(
            candidate,
            constitution,
            governance,
            connectors,
            4,
        )
        canonical_capability_report = assess_capability_thresholds(
            candidate,
            constitution,
            assessments(),
            VALIDATION_TIME,
        )
        eval_input["evaluator_envelopes"] = evaluator_envelopes(
            candidate,
            constitution,
            canonical_capability_report,
            signed_evaluator_policy,
            signed_isolation_attestations,
            signed_resource_ledger,
            cast(list[JsonObject], eval_input["hard_gate_results"]),
            cast(list[JsonObject], eval_input["champion_floor_results"]),
            cast(list[JsonObject], eval_input["metrics"]),
            evaluator_signers,
        )
        paths["evaluation_input"] = input_root / "evaluation-input.json"
        write_json(paths["evaluation_input"], eval_input)
        paths["evaluator_policy"] = input_root / "evaluator-policy.json"
        paths["isolation_attestations"] = input_root / "isolation-attestations.json"
        paths["resource_ledger"] = input_root / "resource-ledger.json"
        write_json(paths["evaluator_policy"], signed_evaluator_policy)
        write_json(paths["isolation_attestations"], {"attestations": signed_isolation_attestations})
        write_json(paths["resource_ledger"], signed_resource_ledger)
        evaluator_command = [sys.executable, str(project_root / "tools" / "evolution_evaluator_worker.py"), "--candidate", str(paths["candidate"]), "--constitution", str(paths["constitution"]), "--governance", str(paths["governance"]), "--assessment-input", str(paths["assessment"]), "--evaluation-input", str(paths["evaluation_input"]), "--evaluator-policy", str(paths["evaluator_policy"]), "--isolation-attestations", str(paths["isolation_attestations"]), "--resource-ledger", str(paths["resource_ledger"]), "--artifact-root", str(artifact_root), "--evaluated-at", VALIDATION_TIME.isoformat().replace("+00:00", "Z"), "--maximum-policy-lifetime-seconds", str(CONSTITUTION_LIFETIME_SECONDS), "--maximum-attestation-lifetime-seconds", str(CONSTITUTION_LIFETIME_SECONDS), "--maximum-ledger-lifetime-seconds", str(CONSTITUTION_LIFETIME_SECONDS)]
        evaluator_process = run_worker(evaluator_command)
        require_condition(evaluator_process.returncode == 0, f"Evaluator worker failed: {evaluator_process.stderr}")
        evaluator_result = cast(JsonObject, json.loads(evaluator_process.stdout))
        capability_report = cast(JsonObject, evaluator_result["capability_report"])
        evaluation = cast(JsonObject, evaluator_result["evaluation"])
        assurance = cast(JsonObject, evaluator_result["assurance"])
        validate_contract(capability_report, project_root / "specs" / "capability-threshold-report.schema.json", "generated capability report")
        validate_contract(evaluation, project_root / "specs" / "evolution-evaluation-vector.schema.json", "generated evolution evaluation")
        validate_contract(assurance, project_root / "specs" / "evolution-assurance-receipt.schema.json", "generated evolution assurance")
        require_condition(evaluation["status"] == "eligible_for_shadow", "Canonical candidate was not shadow-eligible.")
        require_condition(assurance["contract_boundary_verified"] is True, "Signed evaluator assurance was not verified.")
        require_condition(assurance["live_os_enforcement_verified"] is False, "Fixture evaluator isolation claimed live enforcement.")
        paths["capability"] = input_root / "capability.json"
        paths["evaluation"] = input_root / "evaluation.json"
        write_json(paths["capability"], capability_report)
        write_json(paths["evaluation"], evaluation)
        envelope = transition_envelope(candidate, evaluation, capability_report, constitution, connectors, "register_shadow", "shadow", 1, None, "6a8e6979-f004-4db9-a95b-e5e1837cad76")
        validate_contract(envelope, project_root / "specs" / "evolution-transition-envelope.schema.json", "generated shadow transition")
        paths["envelope"] = input_root / "envelope.json"
        write_json(paths["envelope"], envelope)

        primary_root = root / "primary"
        primary = run_worker(promoter_command(project_root, primary_root, paths, "none"))
        require_condition(primary.returncode == 0, f"Promoter worker failed: {primary.stderr}")
        primary_result = cast(JsonObject, json.loads(primary.stdout))
        receipt = cast(JsonObject, primary_result["receipt"])
        validate_contract(receipt, project_root / "specs" / "evolution-transition-receipt.schema.json", "generated shadow receipt")
        require_condition(receipt["status"] == "shadow_candidate_registered" and receipt["active_baseline_modified"] is False, "Shadow receipt modified baseline.")
        process_ids = {cast(int, foundry_result["process_id"]), cast(int, evaluator_result["process_id"]), cast(int, primary_result["process_id"])}
        require_condition(len(process_ids) == 3, "Foundry, evaluator, and promoter did not use distinct processes.")

        demotion = transition_envelope(candidate, evaluation, capability_report, constitution, connectors, "demote", "quarantine", 2, sha256_digest(receipt), "3cbe349d-f5bc-4749-9e1f-276a5e9ad99e")
        paths["envelope"] = input_root / "demotion-envelope.json"
        write_json(paths["envelope"], demotion)
        demoted = run_worker(promoter_command(project_root, primary_root, paths, "none"))
        require_condition(demoted.returncode == 0 and json.loads(demoted.stdout)["receipt"]["status"] == "candidate_demoted", "Signed demotion did not complete.")
        adversarial_count += 1
        paths["envelope"] = input_root / "envelope.json"

        crash_before_root = root / "crash-before"
        before = run_worker(promoter_command(project_root, crash_before_root, paths, "temporary_durable"))
        require_condition(before.returncode == 101, "Pre-publication transition crash did not fire.")
        retry_before = run_worker(promoter_command(project_root, crash_before_root, paths, "none"))
        require_condition(retry_before.returncode == 0 and json.loads(retry_before.stdout)["status"] == "accepted", "Pre-publication transition was not retryable.")
        adversarial_count += 1
        crash_after_root = root / "crash-after"
        after = run_worker(promoter_command(project_root, crash_after_root, paths, "state_published"))
        require_condition(after.returncode == 102, "Post-publication transition crash did not fire.")
        retry_after = run_worker(promoter_command(project_root, crash_after_root, paths, "none"))
        require_condition(retry_after.returncode == 0 and json.loads(retry_after.stdout)["status"] == "replay_denied", "Published transition was not durable after crash.")
        adversarial_count += 1

        contention_root = root / "contention"
        processes = [subprocess.Popen(promoter_command(project_root, contention_root, paths, "none"), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) for _ in range(WORKER_COUNT)]
        contention_results: list[JsonObject] = []
        for process in processes:
            stdout, stderr = process.communicate(timeout=30)
            require_condition(process.returncode == 0, f"Promoter contention worker failed: {stderr}")
            contention_results.append(cast(JsonObject, json.loads(stdout)))
        accepted = sum(1 for value in contention_results if value.get("status") == "accepted")
        replayed = sum(1 for value in contention_results if value.get("status") == "replay_denied")
        require_condition(accepted == 1 and replayed == WORKER_COUNT - 1, "Promoter contention did not yield exactly one shadow registration.")
        adversarial_count += 1

        constitution_mutations: list[tuple[JsonObject, str]] = []
        missing_axiom = copy.deepcopy(constitution); missing_axiom["axioms"] = cast(list[object], missing_axiom["axioms"])[:-1]; constitution_mutations.append((missing_axiom, "missing constitution axiom"))
        missing_failure = copy.deepcopy(constitution); missing_failure["hard_failures"] = cast(list[object], missing_failure["hard_failures"])[:-1]; constitution_mutations.append((missing_failure, "missing hard failure"))
        trigger_downgrade = copy.deepcopy(constitution); cast(list[JsonObject], trigger_downgrade["capability_triggers"])[0]["response"] = "elevated"; constitution_mutations.append((trigger_downgrade, "capability response downgrade"))
        tier_widening = copy.deepcopy(constitution); cast(list[JsonObject], tier_widening["tier_policies"])[3]["maximum_destination"] = "shadow"; constitution_mutations.append((tier_widening, "Tier D widening"))
        constitution_authority = copy.deepcopy(constitution); cast(JsonObject, constitution_authority["authority"])["can_modify_itself"] = True; constitution_mutations.append((constitution_authority, "constitution self-modification"))
        resource_zero = copy.deepcopy(constitution); cast(JsonObject, resource_zero["resource_ceilings"])["maximum_compute_units"] = 0; constitution_mutations.append((resource_zero, "zero resource ceiling"))
        governance_substitution = copy.deepcopy(constitution); governance_substitution["governance_state_digest"] = "sha256:" + "0" * 64; constitution_mutations.append((governance_substitution, "constitution governance substitution"))
        for mutated, label in constitution_mutations:
            expect_error(EvolutionConstitutionError, partial(verify_evolution_constitution, mutated, governance, VALIDATION_TIME, CONSTITUTION_LIFETIME_SECONDS), label)
            adversarial_count += 1
        signature_tamper = copy.deepcopy(constitution)
        signature_values = cast(list[JsonObject], signature_tamper["signatures"])
        encoded = cast(str, signature_values[0]["signature_base64"])
        signature_values[0]["signature_base64"] = ("A" if encoded[0] != "A" else "B") + encoded[1:]
        expect_error(EvolutionConstitutionError, partial(verify_evolution_constitution, signature_tamper, governance, VALIDATION_TIME, CONSTITUTION_LIFETIME_SECONDS), "constitution signature tamper")
        adversarial_count += 1
        one_signer = copy.deepcopy(constitution); one_signer["signatures"] = cast(list[object], one_signer["signatures"])[:1]
        expect_error(EvolutionConstitutionError, partial(verify_evolution_constitution, one_signer, governance, VALIDATION_TIME, CONSTITUTION_LIFETIME_SECONDS), "constitution threshold underflow")
        adversarial_count += 1

        posture_mutations: list[tuple[JsonObject, str]] = []
        standard_mismatch = posture(); standard_mismatch["evidence_standard"] = "exact_proof"; posture_mutations.append((standard_mismatch, "epistemic standard mismatch"))
        fact_laundering = posture(); fact_laundering["counterfactual"] = True; posture_mutations.append((fact_laundering, "counterfactual laundering"))
        plural_without_context = posture(); plural_without_context["mode"] = "plural_context"; plural_without_context["evidence_standard"] = "context_bounded_interpretation"; plural_without_context["context_boundaries"] = []; posture_mutations.append((plural_without_context, "unbounded plural context"))
        posture_authority = posture(); cast(JsonObject, posture_authority["authority"])["can_waive_hard_failures"] = True; posture_mutations.append((posture_authority, "posture hard-failure waiver"))
        for mutated, label in posture_mutations:
            expect_error(EvolutionCandidateError, partial(validate_epistemic_posture, mutated), label)
            adversarial_count += 1

        oversized_lease = resource_lease(); oversized_lease["maximum_compute_units"] = 101
        expect_error(EvolutionCandidateError, partial(compile_cognitive_candidate, source_candidate, active_baseline, constitution, governance, posture(), oversized_lease, uncertainty(), VALIDATION_TIME, CONSTITUTION_LIFETIME_SECONDS), "resource ceiling expansion")
        adversarial_count += 1
        unknown_uncertainty: JsonObject = {"level": "unknown", "known_limitations": []}
        expect_error(EvolutionCandidateError, partial(compile_cognitive_candidate, source_candidate, active_baseline, constitution, governance, posture(), resource_lease(), unknown_uncertainty, VALIDATION_TIME, CONSTITUTION_LIFETIME_SECONDS), "unbounded unknown uncertainty")
        adversarial_count += 1
        baseline_writable = copy.deepcopy(active_baseline); cast(JsonObject, baseline_writable["authority"])["candidate_write_permitted"] = True
        expect_error(EvolutionCandidateError, partial(compile_cognitive_candidate, source_candidate, baseline_writable, constitution, governance, posture(), resource_lease(), uncertainty(), VALIDATION_TIME, CONSTITUTION_LIFETIME_SECONDS), "writable active baseline")
        adversarial_count += 1

        unknown_assessments = assessments(); unknown_assessments[0]["status"] = "unknown"; unknown_assessments[0]["evidence"] = []
        unknown_report = assess_capability_thresholds(candidate, constitution, unknown_assessments, VALIDATION_TIME)
        require_condition(unknown_report["paused"] is True and unknown_report["required_safeguard_level"] == "pause", "Unknown capability did not pause.")
        adversarial_count += 1
        replication_assessments = assessments()
        for assessment in replication_assessments:
            if assessment["trigger_id"] == "REPLICATION_ADAPTATION": assessment["status"] = "present"
        replication_report = assess_capability_thresholds(candidate, constitution, replication_assessments, VALIDATION_TIME)
        require_condition(replication_report["paused"] is True, "Replication capability did not pause.")
        adversarial_count += 1
        missing_assessment = assessments()[:-1]
        expect_error(EvolutionEvaluationError, partial(assess_capability_thresholds, candidate, constitution, missing_assessment, VALIDATION_TIME), "missing capability trigger")
        adversarial_count += 1

        failed_gates = copy.deepcopy(cast(list[JsonObject], eval_input["hard_gate_results"])); failed_gates[0]["status"] = "fail"
        blocked_evaluation = evaluate_cognitive_candidate(candidate, constitution, capability_report, cast(list[JsonObject], eval_input["evaluator_observations"]), failed_gates, cast(list[JsonObject], eval_input["champion_floor_results"]), cast(list[JsonObject], eval_input["metrics"]), VALIDATION_TIME)
        require_condition(blocked_evaluation["status"] == "blocked", "Hard failure did not block evaluation.")
        adversarial_count += 1
        scalar_metrics = copy.deepcopy(cast(list[JsonObject], eval_input["metrics"])); scalar_metrics[0]["aggregate_score"] = 1
        expect_error(EvolutionEvaluationError, partial(evaluate_cognitive_candidate, candidate, constitution, capability_report, cast(list[JsonObject], eval_input["evaluator_observations"]), cast(list[JsonObject], eval_input["hard_gate_results"]), cast(list[JsonObject], eval_input["champion_floor_results"]), scalar_metrics, VALIDATION_TIME), "aggregate score injection")
        adversarial_count += 1
        duplicate_evaluators = copy.deepcopy(cast(list[JsonObject], eval_input["evaluator_observations"])); duplicate_evaluators[1]["process_id"] = duplicate_evaluators[0]["process_id"]
        expect_error(EvolutionEvaluationError, partial(evaluate_cognitive_candidate, candidate, constitution, capability_report, duplicate_evaluators, cast(list[JsonObject], eval_input["hard_gate_results"]), cast(list[JsonObject], eval_input["champion_floor_results"]), cast(list[JsonObject], eval_input["metrics"]), VALIDATION_TIME), "evaluator process collapse")
        adversarial_count += 1
        floor_regression = copy.deepcopy(cast(list[JsonObject], eval_input["champion_floor_results"])); floor_regression[0]["status"] = "regressed"
        floor_blocked = evaluate_cognitive_candidate(candidate, constitution, capability_report, cast(list[JsonObject], eval_input["evaluator_observations"]), cast(list[JsonObject], eval_input["hard_gate_results"]), floor_regression, cast(list[JsonObject], eval_input["metrics"]), VALIDATION_TIME)
        require_condition(floor_blocked["status"] == "blocked", "Champion regression did not block evaluation.")
        adversarial_count += 1

        transition_mutations: list[tuple[JsonObject, str]] = []
        candidate_substitution = copy.deepcopy(envelope); candidate_substitution["candidate_digest"] = "sha256:" + "0" * 64; transition_mutations.append((candidate_substitution, "transition candidate substitution"))
        evaluation_substitution = copy.deepcopy(envelope); evaluation_substitution["evaluation_digest"] = "sha256:" + "0" * 64; transition_mutations.append((evaluation_substitution, "transition evaluation substitution"))
        capability_substitution = copy.deepcopy(envelope); capability_substitution["capability_report_digest"] = "sha256:" + "0" * 64; transition_mutations.append((capability_substitution, "transition capability substitution"))
        baseline_substitution = copy.deepcopy(envelope); baseline_substitution["active_baseline_digest"] = "sha256:" + "0" * 64; transition_mutations.append((baseline_substitution, "transition baseline substitution"))
        transition_authority = copy.deepcopy(envelope); cast(JsonObject, transition_authority["authority"])["can_modify_active_baseline"] = True; transition_mutations.append((transition_authority, "transition baseline authority"))
        production_destination = copy.deepcopy(envelope); production_destination["destination"] = "production"; transition_mutations.append((production_destination, "production destination widening"))
        for mutated, label in transition_mutations:
            expect_error(EvolutionTransitionError, partial(verify_evolution_transition, mutated, candidate, evaluation, capability_report, constitution, governance, VALIDATION_TIME, CONSTITUTION_LIFETIME_SECONDS, TRANSITION_LIFETIME_SECONDS), label)
            adversarial_count += 1
        expect_error(EvolutionTransitionError, partial(verify_evolution_transition, envelope, candidate, blocked_evaluation, capability_report, constitution, governance, VALIDATION_TIME, CONSTITUTION_LIFETIME_SECONDS, TRANSITION_LIFETIME_SECONDS), "blocked evaluation promotion")
        adversarial_count += 1
        expect_error(EvolutionTransitionError, partial(verify_evolution_transition, envelope, candidate, evaluation, replication_report, constitution, governance, VALIDATION_TIME, CONSTITUTION_LIFETIME_SECONDS, TRANSITION_LIFETIME_SECONDS), "capability pause bypass")
        adversarial_count += 1

        cas_path = artifact_root / "evolution-foundry" / "v1" / "artifacts" / f"{candidate_digest.removeprefix('sha256:')}.json"
        original_cas = cas_path.read_text(encoding="utf-8")
        cas_path.write_text("{}\n", encoding="utf-8", newline="\n")
        expect_error(EvolutionArtifactError, partial(EvolutionArtifactStore(artifact_root).read, candidate_digest), "CAS corruption")
        cas_path.write_text(original_cas, encoding="utf-8", newline="\n")
        adversarial_count += 1

        for worker_name in ("evolution_foundry_worker.py", "evolution_evaluator_worker.py", "evolution_promoter_worker.py"):
            source = (project_root / "tools" / worker_name).read_text(encoding="utf-8").casefold()
            require_condition(all(token not in source for token in ("import openai", "import requests", "import socket")), f"Worker '{worker_name}' exposes a model or network client.")
        require_condition(sha256_digest(active_baseline) == baseline_before, "Active baseline changed during Foundry validation.")

    return {
        "status": "CONSTITUTIONAL_EVOLUTION_FOUNDRY_VALID_SHADOW_ONLY",
        "origin": "simulated",
        "constitution_axiom_count": len(REQUIRED_AXIOMS),
        "hard_gate_count": len(REQUIRED_HARD_FAILURES),
        "capability_trigger_count": len(REQUIRED_CAPABILITY_RESPONSES),
        "champion_floor_count": len(REQUIRED_CHAMPION_FLOORS),
        "separate_control_process_count": 3,
        "artifact_content_addressed": True,
        "candidate_status": candidate["status"],
        "evaluation_status": evaluation["status"],
        "maximum_transition": receipt["status"],
        "signed_demotion_validated": True,
        "crash_boundary_count": 2,
        "contention_worker_count": WORKER_COUNT,
        "contention_accept_count": 1,
        "contention_replay_denial_count": WORKER_COUNT - 1,
        "adversarial_case_count": adversarial_count,
        "aggregate_score_present": False,
        "active_baseline_modified": False,
        "candidate_executed": False,
        "model_api_called": False,
        "network_access_performed": False,
        "credentials_acquired": False,
        "compute_expanded": False,
        "replication_or_persistence_performed": False,
        "production_promotion_authorized": False,
        "can_execute": False,
    }


def main() -> None:
    project_root = Path(__file__).resolve().parent.parent
    result = validate_evolution_foundry(project_root)
    report_path = project_root / "reports" / "EVOLUTION_FOUNDRY_VALIDATION.json"
    report_path.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n"
    )
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
