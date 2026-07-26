from __future__ import annotations

import copy
import json
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import cast

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from nimrod_simulator.control_board_foundry import project_foundry_control_board
from nimrod_simulator.errors import (
    ControlBoardProjectionError,
    EvaluatorObservationError,
    EvaluatorTrustPolicyError,
    IsolationBoundaryError,
    ResourceLedgerError,
    SimulatorError,
)
from nimrod_simulator.evaluator_observation import (
    EVALUATOR_OBSERVATION_AUTHORITY,
    EVALUATOR_POLICY_AUTHORITY,
    evaluate_signed_cognitive_candidate,
    evaluation_input_digest,
    sign_evaluator_observation,
    sign_evaluator_trust_policy,
    verify_evaluator_trust_policy,
)
from nimrod_simulator.evolution_constitution import (
    REQUIRED_AXIOMS,
    REQUIRED_CAPABILITY_RESPONSES,
    REQUIRED_HARD_FAILURES,
    sign_evolution_constitution,
)
from nimrod_simulator.evolution_foundry import REQUIRED_CHAMPION_FLOORS, assess_capability_thresholds
from nimrod_simulator.isolation_boundary import (
    ISOLATION_AUTHORITY,
    REQUIRED_ISOLATION_CONTROLS,
    sign_isolation_attestation,
    verify_isolation_attestation,
)
from nimrod_simulator.jsonio import read_json_object, sha256_digest, validate_contract
from nimrod_simulator.key_governance import EphemeralEd25519SigningConnector, governance_key
from nimrod_simulator.model import JsonObject
from nimrod_simulator.resource_ledger import (
    build_lineage_resource_ledger,
    sign_lineage_resource_ledger,
    verify_lineage_resource_ledger,
)


VALIDATION_TIME = datetime(2026, 7, 13, 4, 31, 0, tzinfo=timezone.utc)
MAXIMUM_LIFETIME_SECONDS = 1200
EVALUATOR_ROLES = ("public_regression", "sealed_holdout", "adversarial", "rights_and_recovery")


def require_condition(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def expect_error(expected: type[SimulatorError], callback: Callable[[], object], label: str) -> None:
    try:
        callback()
    except expected:
        return
    raise AssertionError(f"Expected {expected.__name__} for {label}.")


def reference(identifier: str) -> JsonObject:
    return {"id": identifier, "digest": sha256_digest({"fixture": identifier})}


def governance_connectors() -> list[EphemeralEd25519SigningConnector]:
    return [
        EphemeralEd25519SigningConnector("key:evolution-owner", "customer_authority", Ed25519PrivateKey.generate()),
        EphemeralEd25519SigningConnector("key:evolution-safety", "safety_officer", Ed25519PrivateKey.generate()),
        EphemeralEd25519SigningConnector("key:evolution-recovery", "recovery_officer", Ed25519PrivateKey.generate()),
    ]


def evaluator_connectors() -> list[EphemeralEd25519SigningConnector]:
    return [
        EphemeralEd25519SigningConnector(f"evaluator:{role}", role, Ed25519PrivateKey.generate())
        for role in EVALUATOR_ROLES
    ]


def governance_state(connectors: list[EphemeralEd25519SigningConnector], origin: str) -> JsonObject:
    issued_at = "2026-07-13T04:00:00Z"
    return {
        "state_version": "0.1.0",
        "governance_id": "2f5c6087-0c57-4a52-9c29-cb46fb83bd07",
        "origin": origin,
        "epoch": 1,
        "issued_at": issued_at,
        "previous_state_digest": None,
        "threshold": 2,
        "ceremony_key_count": 3,
        "minimum_distinct_roles": 2,
        "keys": [
            governance_key(
                connector,
                "active",
                issued_at,
                None,
                "test_ephemeral",
                f"connector:custody:{connector.key_id}",
                f"memory:{connector.key_id}",
                False,
                None,
            )
            for connector in connectors
        ],
    }


def constitution(
    governance: JsonObject,
    connectors: list[EphemeralEd25519SigningConnector],
) -> JsonObject:
    unsigned: JsonObject = {
        "constitution_version": "0.1.0",
        "constitution_id": "dfc3fb9d-6088-434b-814e-813108fba665",
        "origin": governance["origin"],
        "governance_state_digest": sha256_digest(governance),
        "issued_at": "2026-07-13T04:29:00Z",
        "not_before": "2026-07-13T04:29:00Z",
        "expires_at": "2026-07-13T04:40:00Z",
        "axioms": sorted(REQUIRED_AXIOMS),
        "hard_failures": sorted(REQUIRED_HARD_FAILURES),
        "capability_triggers": [
            {"trigger_id": trigger_id, "response": response}
            for trigger_id, response in sorted(REQUIRED_CAPABILITY_RESPONSES.items())
        ],
        "tier_policies": [
            {"tier": "A", "maximum_destination": "shadow", "threshold_humans_required": False},
            {"tier": "B", "maximum_destination": "shadow", "threshold_humans_required": False},
            {"tier": "C", "maximum_destination": "production_candidate", "threshold_humans_required": True},
            {"tier": "D", "maximum_destination": "quarantine", "threshold_humans_required": True},
        ],
        "resource_ceilings": {
            "maximum_cycle_seconds": 300,
            "maximum_compute_units": 100,
            "maximum_memory_megabytes": 512,
            "maximum_storage_megabytes": 1024,
            "maximum_candidate_children": 4,
        },
        "authority": {
            "can_modify_itself": False,
            "can_select_evaluators": False,
            "can_select_signers": False,
            "can_expand_authority": False,
            "can_execute": False,
        },
    }
    return sign_evolution_constitution(unsigned, connectors[:2])


def candidate_document(project_root: Path, signed_constitution: JsonObject) -> JsonObject:
    candidate = read_json_object(project_root / "specs" / "examples" / "cognitive-candidate-bundle.example.json")
    candidate["constitution_digest"] = sha256_digest(signed_constitution)
    return candidate


def capability_report(candidate: JsonObject, signed_constitution: JsonObject) -> JsonObject:
    assessments = [
        {"trigger_id": trigger_id, "status": "absent", "evidence": [reference(f"trigger:{trigger_id}")]}
        for trigger_id in sorted(REQUIRED_CAPABILITY_RESPONSES)
    ]
    return assess_capability_thresholds(candidate, signed_constitution, assessments, VALIDATION_TIME)


def evaluation_claims() -> tuple[list[JsonObject], list[JsonObject], list[JsonObject]]:
    hard_gates = [
        {"gate_id": gate_id, "status": "pass", "evidence": [reference(f"gate:{gate_id}")]}
        for gate_id in sorted(REQUIRED_HARD_FAILURES)
    ]
    floors = [
        {"floor_id": floor_id, "status": "pass", "evidence": [reference(f"floor:{floor_id}")]}
        for floor_id in sorted(REQUIRED_CHAMPION_FLOORS)
    ]
    metrics = [
        {"dimension": "simulated_detection_precision", "outcome": "equal", "evidence": [reference("metric:precision")]}
    ]
    return hard_gates, floors, metrics


def evaluator_policy(
    signed_constitution: JsonObject,
    governance: JsonObject,
    governance_signers: list[EphemeralEd25519SigningConnector],
    evaluators: list[EphemeralEd25519SigningConnector],
) -> JsonObject:
    unsigned: JsonObject = {
        "policy_version": "0.1.0",
        "policy_id": "69cd20d8-f907-4862-a50d-0850bc00eef2",
        "origin": governance["origin"],
        "constitution_digest": sha256_digest(signed_constitution),
        "governance_state_digest": sha256_digest(governance),
        "issued_at": "2026-07-13T04:29:30Z",
        "not_before": "2026-07-13T04:29:30Z",
        "expires_at": "2026-07-13T04:40:00Z",
        "evaluators": [
            {
                "evaluator_id": connector.key_id,
                "logical_principal": f"principal:{connector.role}",
                "role": connector.role,
                "public_key_base64": connector.public_key_base64,
                "expected_os_account_identifier": f"nimrod-evaluator-{index + 1}",
                "expected_os_account_sid": f"S-1-5-21-{8101 + index}",
            }
            for index, connector in enumerate(evaluators)
        ],
        "authority": EVALUATOR_POLICY_AUTHORITY,
    }
    return sign_evaluator_trust_policy(unsigned, governance_signers[:2])


def isolation_attestations(
    policy: JsonObject,
    governance: JsonObject,
    governance_signers: list[EphemeralEd25519SigningConnector],
    collector_kind: str,
) -> list[JsonObject]:
    result: list[JsonObject] = []
    policy_evaluators = cast(list[JsonObject], policy["evaluators"])
    for index, evaluator in enumerate(policy_evaluators):
        controls = [
            {
                "control_id": control_id,
                "status": "verified",
                "evidence": [reference(f"isolation:{evaluator['evaluator_id']}:{control_id}")],
            }
            for control_id in sorted(REQUIRED_ISOLATION_CONTROLS)
        ]
        unsigned: JsonObject = {
            "attestation_version": "0.1.0",
            "attestation_id": f"{index + 1:08d}-1111-4111-8111-{index + 1:012d}",
            "origin": governance["origin"],
            "component_kind": "evaluator",
            "component_id": evaluator["evaluator_id"],
            "logical_principal": evaluator["logical_principal"],
            "governance_state_digest": sha256_digest(governance),
            "captured_at": "2026-07-13T04:30:00Z",
            "issued_at": "2026-07-13T04:30:01Z",
            "not_before": "2026-07-13T04:30:00Z",
            "expires_at": "2026-07-13T04:36:00Z",
            "process": {
                "process_id": 8101 + index,
                "os_account_identifier": evaluator["expected_os_account_identifier"],
                "os_account_sid": evaluator["expected_os_account_sid"],
                "executable_digest": sha256_digest({"evaluator_binary": evaluator["evaluator_id"]}),
            },
            "collector": {
                "collector_id": f"collector:{collector_kind}",
                "kind": collector_kind,
                "raw_evidence_digest": sha256_digest({"raw_isolation": evaluator["evaluator_id"]}),
            },
            "controls": controls,
            "status": "verified",
            "blockers": [],
            "authority": ISOLATION_AUTHORITY,
        }
        result.append(sign_isolation_attestation(unsigned, governance_signers[:2]))
    return result


def resource_ledger(
    candidate: JsonObject,
    signed_constitution: JsonObject,
    governance: JsonObject,
    governance_signers: list[EphemeralEd25519SigningConnector],
    compute_units: int,
) -> JsonObject:
    entry: JsonObject = {
        "candidate_id": candidate["candidate_id"],
        "candidate_digest": sha256_digest(candidate),
        "parent_candidate_digest": None,
        "resource_lease_digest": sha256_digest(candidate["resource_lease"]),
        "lease": {
            "maximum_cycle_seconds": 60,
            "maximum_compute_units": 10,
            "maximum_memory_megabytes": 128,
            "maximum_storage_megabytes": 64,
            "maximum_candidate_children": 1,
        },
        "usage": {
            "cycle_seconds": 12,
            "compute_units": compute_units,
            "peak_memory_megabytes": 96,
            "peak_storage_megabytes": 24,
        },
        "evidence": [reference("meter:root")],
    }
    unsigned = build_lineage_resource_ledger(
        "72f836fd-da75-438e-aae9-f4614aababe0",
        "e56338ee-47fe-4252-866c-4f289b138fe3",
        cast(str, governance["origin"]),
        signed_constitution,
        governance,
        "2026-07-13T04:30:30Z",
        "2026-07-13T04:30:00Z",
        "2026-07-13T04:40:00Z",
        [entry],
    )
    return sign_lineage_resource_ledger(unsigned, governance_signers[:2])


def evaluator_envelopes(
    candidate: JsonObject,
    signed_constitution: JsonObject,
    report: JsonObject,
    policy: JsonObject,
    attestations: list[JsonObject],
    ledger: JsonObject,
    hard_gates: list[JsonObject],
    floors: list[JsonObject],
    metrics: list[JsonObject],
    evaluators: list[EphemeralEd25519SigningConnector],
) -> list[JsonObject]:
    input_digest = evaluation_input_digest(report, hard_gates, floors, metrics)
    return [
        sign_evaluator_observation(
            {
                "envelope_version": "0.1.0",
                "envelope_id": f"{index + 1:08d}-2222-4222-8222-{index + 1:012d}",
                "origin": candidate["origin"],
                "evaluator_policy_digest": sha256_digest(policy),
                "evaluator_id": connector.key_id,
                "logical_principal": f"principal:{connector.role}",
                "process_id": 8101 + index,
                "os_account_identifier": f"nimrod-evaluator-{index + 1}",
                "os_account_sid": f"S-1-5-21-{8101 + index}",
                "role": connector.role,
                "subject_digest": sha256_digest(candidate),
                "constitution_digest": sha256_digest(signed_constitution),
                "capability_report_digest": sha256_digest(report),
                "evaluation_input_digest": input_digest,
                "resource_ledger_digest": sha256_digest(ledger),
                "isolation_attestation_digest": sha256_digest(attestations[index]),
                "observed_at": "2026-07-13T04:30:45Z",
                "expires_at": "2026-07-13T04:36:00Z",
                "status": "pass",
                "evidence": [reference(f"evaluation:{connector.role}")],
                "authority": EVALUATOR_OBSERVATION_AUTHORITY,
            },
            connector,
        )
        for index, connector in enumerate(evaluators)
    ]


def validate_evolution_assurance(project_root: Path) -> JsonObject:
    governance_signers = governance_connectors()
    evaluators = evaluator_connectors()
    governance = governance_state(governance_signers, "simulated")
    signed_constitution = constitution(governance, governance_signers)
    candidate = candidate_document(project_root, signed_constitution)
    report = capability_report(candidate, signed_constitution)
    hard_gates, floors, metrics = evaluation_claims()
    policy = evaluator_policy(signed_constitution, governance, governance_signers, evaluators)
    attestations = isolation_attestations(policy, governance, governance_signers, "fixture")
    ledger = resource_ledger(candidate, signed_constitution, governance, governance_signers, 4)
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
    evaluation, assurance = evaluate_signed_cognitive_candidate(
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
    projection = project_foundry_control_board(evaluation, assurance, "2026-07-13T04:31:02Z")
    generated_contracts = (
        (policy, "evaluator-trust-policy.schema.json", "generated evaluator trust policy"),
        (ledger, "lineage-resource-ledger.schema.json", "generated lineage resource ledger"),
        (assurance, "evolution-assurance-receipt.schema.json", "generated evolution assurance receipt"),
        (projection, "control-board-foundry-projection.schema.json", "generated Foundry projection"),
    )
    for document, schema_name, label in generated_contracts:
        validate_contract(document, project_root / "specs" / schema_name, label)
    for index, attestation in enumerate(attestations):
        validate_contract(
            attestation,
            project_root / "specs" / "os-isolation-attestation.schema.json",
            f"generated OS isolation attestation {index}",
        )
    for index, envelope in enumerate(envelopes):
        validate_contract(
            envelope,
            project_root / "specs" / "evaluator-observation-envelope.schema.json",
            f"generated evaluator observation {index}",
        )
    require_condition(evaluation["status"] == "eligible_for_shadow", "Signed evaluation was not shadow-eligible.")
    require_condition(assurance["contract_boundary_verified"] is True, "Evaluator assurance boundary was not verified.")
    require_condition(assurance["live_os_enforcement_verified"] is False, "Fixture isolation claimed live OS enforcement.")
    require_condition(projection["operator_state"] == "shadow_eligible_contract_only", "Foundry projection hid the non-live boundary.")
    require_condition(projection["authority"]["can_promote"] is False, "Foundry projection exposed promotion authority.")

    adversarial_count = 0
    tampered_envelopes = copy.deepcopy(envelopes)
    tampered_envelopes[0]["status"] = "fail"
    expect_error(
        EvaluatorObservationError,
        lambda: evaluate_signed_cognitive_candidate(candidate, signed_constitution, governance, report, policy, tampered_envelopes, attestations, ledger, hard_gates, floors, metrics, VALIDATION_TIME, MAXIMUM_LIFETIME_SECONDS, MAXIMUM_LIFETIME_SECONDS, MAXIMUM_LIFETIME_SECONDS),
        "evaluator signature tamper",
    )
    adversarial_count += 1
    collapsed_policy = copy.deepcopy(policy)
    cast(list[JsonObject], collapsed_policy["evaluators"])[1]["role"] = "public_regression"
    expect_error(
        EvaluatorTrustPolicyError,
        lambda: verify_evaluator_trust_policy(collapsed_policy, signed_constitution, governance, VALIDATION_TIME, MAXIMUM_LIFETIME_SECONDS),
        "evaluator role collapse",
    )
    adversarial_count += 1
    substituted_attestations = copy.deepcopy(attestations)
    substituted_attestations[0]["component_id"] = "evaluator:substituted"
    expect_error(
        IsolationBoundaryError,
        lambda: verify_isolation_attestation(substituted_attestations[0], governance, VALIDATION_TIME, MAXIMUM_LIFETIME_SECONDS),
        "isolation identity signature substitution",
    )
    adversarial_count += 1
    missing_control = copy.deepcopy(attestations[0])
    cast(list[JsonObject], missing_control["controls"]).pop()
    expect_error(
        IsolationBoundaryError,
        lambda: verify_isolation_attestation(missing_control, governance, VALIDATION_TIME, MAXIMUM_LIFETIME_SECONDS),
        "missing OS isolation control",
    )
    adversarial_count += 1
    tampered_ledger = copy.deepcopy(ledger)
    cast(JsonObject, tampered_ledger["totals"])["total_compute_units"] = 5
    expect_error(
        ResourceLedgerError,
        lambda: verify_lineage_resource_ledger(tampered_ledger, signed_constitution, governance, VALIDATION_TIME, MAXIMUM_LIFETIME_SECONDS),
        "resource total substitution",
    )
    adversarial_count += 1
    overrun_ledger = resource_ledger(candidate, signed_constitution, governance, governance_signers, 11)
    overrun_verification = verify_lineage_resource_ledger(
        overrun_ledger,
        signed_constitution,
        governance,
        VALIDATION_TIME,
        MAXIMUM_LIFETIME_SECONDS,
    )
    require_condition(overrun_verification["within_constitution"] is False, "Resource overrun was not blocked.")
    adversarial_count += 1
    substituted_candidate_envelopes = copy.deepcopy(envelopes)
    substituted_candidate_envelopes[0]["subject_digest"] = "sha256:" + "0" * 64
    expect_error(
        EvaluatorObservationError,
        lambda: evaluate_signed_cognitive_candidate(candidate, signed_constitution, governance, report, policy, substituted_candidate_envelopes, attestations, ledger, hard_gates, floors, metrics, VALIDATION_TIME, MAXIMUM_LIFETIME_SECONDS, MAXIMUM_LIFETIME_SECONDS, MAXIMUM_LIFETIME_SECONDS),
        "candidate substitution",
    )
    adversarial_count += 1
    future_parent_entry = {
        "candidate_id": "candidate:child",
        "candidate_digest": sha256_digest({"candidate": "child"}),
        "parent_candidate_digest": sha256_digest({"candidate": "absent"}),
        "resource_lease_digest": sha256_digest({"lease": "child"}),
        "lease": {"maximum_cycle_seconds": 10, "maximum_compute_units": 2, "maximum_memory_megabytes": 32, "maximum_storage_megabytes": 16, "maximum_candidate_children": 1},
        "usage": {"cycle_seconds": 1, "compute_units": 1, "peak_memory_megabytes": 8, "peak_storage_megabytes": 4},
        "evidence": [reference("meter:child")],
    }
    expect_error(
        ResourceLedgerError,
        lambda: build_lineage_resource_ledger("72f836fd-da75-438e-aae9-f4614aababe0", "e56338ee-47fe-4252-866c-4f289b138fe3", "simulated", signed_constitution, governance, "2026-07-13T04:30:30Z", "2026-07-13T04:30:00Z", "2026-07-13T04:40:00Z", [cast(JsonObject, {"candidate_id": candidate["candidate_id"], "candidate_digest": sha256_digest(candidate), "parent_candidate_digest": None, "resource_lease_digest": sha256_digest(candidate["resource_lease"]), "lease": {"maximum_cycle_seconds": 60, "maximum_compute_units": 10, "maximum_memory_megabytes": 128, "maximum_storage_megabytes": 64, "maximum_candidate_children": 1}, "usage": {"cycle_seconds": 12, "compute_units": 4, "peak_memory_megabytes": 96, "peak_storage_megabytes": 24}, "evidence": [reference("meter:root")]}), cast(JsonObject, future_parent_entry)]),
        "future lineage parent",
    )
    adversarial_count += 1
    assurance_tamper = copy.deepcopy(assurance)
    assurance_tamper["candidate_digest"] = "sha256:" + "0" * 64
    expect_error(
        ControlBoardProjectionError,
        lambda: project_foundry_control_board(evaluation, assurance_tamper, "2026-07-13T04:31:02Z"),
        "Foundry assurance substitution",
    )
    adversarial_count += 1
    live_governance = governance_state(governance_signers, "live")
    live_constitution = constitution(live_governance, governance_signers)
    live_policy = evaluator_policy(live_constitution, live_governance, governance_signers, evaluators)
    live_fixture_attestation = isolation_attestations(live_policy, live_governance, governance_signers, "fixture")[0]
    expect_error(
        IsolationBoundaryError,
        lambda: verify_isolation_attestation(live_fixture_attestation, live_governance, VALIDATION_TIME, MAXIMUM_LIFETIME_SECONDS),
        "live fixture isolation laundering",
    )
    adversarial_count += 1

    return {
        "status": "EVOLUTION_ASSURANCE_SIGNED_EVALUATORS_AND_RESOURCE_LINEAGE_VALID_PRODUCTION_BLOCKED",
        "origin": "simulated",
        "evaluator_role_count": 4,
        "signed_evaluator_observation_count": len(envelopes),
        "threshold_certified_isolation_attestation_count": len(attestations),
        "isolation_control_count_per_process": len(REQUIRED_ISOLATION_CONTROLS),
        "resource_ledger_entry_count": assurance["resource_ledger_verification"]["entry_count"],
        "resource_ledger_within_constitution": True,
        "foundry_operator_state": projection["operator_state"],
        "contract_boundary_verified": True,
        "live_os_enforcement_verified": False,
        "production_promotion_authorized": False,
        "adversarial_case_count": adversarial_count,
        "candidate_executed": False,
        "model_api_called": False,
        "network_access_performed": False,
    }


def main() -> None:
    project_root = Path(__file__).resolve().parent.parent
    result = validate_evolution_assurance(project_root)
    report_path = project_root / "reports" / "EVOLUTION_ASSURANCE_VALIDATION.json"
    report_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
