"""Validate signed World Model source governance, retention, and bounded backpressure."""

from __future__ import annotations

import copy
import json
import tempfile
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import cast

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from nimrod_cacis.world_intake import (
    build_empty_cursor_state,
    build_world_intake_candidate,
)
from nimrod_cacis.world_intake_governance import (
    DECISION_DOMAIN,
    HEALTH_DOMAIN,
    POLICY_DOMAIN,
    VERIFIER_BOUNDARY,
    build_governed_intake_decision,
    build_governed_world_intake,
    build_source_health_attestation,
    build_source_policy,
    commit_governed_world_intake_store,
    validate_governed_intake_decision,
    validate_source_health_attestation,
    validate_source_policy,
    validate_verifier_boundary,
)
from nimrod_cacis.world_intake_governance_process import run_governed_world_intake_verification
from nimrod_cacis.world_model import build_world_model_generation, commit_world_model_store, prepare_world_model_store
from nimrod_simulator.errors import WorldIntakeError, WorldIntakeGovernanceError
from nimrod_simulator.jsonio import sha256_digest
from nimrod_simulator.key_governance import (
    EphemeralEd25519SigningConnector,
    SigningConnector,
    governance_key,
)
from nimrod_simulator.model import JsonObject
from nimrod_simulator.threshold_signing import sign_threshold_document
from validate_world_intake import build_session, event


def expect_error(operation: Callable[[], object], label: str) -> None:
    try:
        operation()
    except (WorldIntakeGovernanceError, WorldIntakeError):
        return
    raise RuntimeError(f"Expected governed World Model intake failure for {label}.")


def governance_state(connectors: list[SigningConnector], issued_at: str) -> JsonObject:
    return {
        "state_version": "0.1.0",
        "governance_id": "d41777da-ea99-4b31-9eec-6b8612fb1f19",
        "origin": "simulated",
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
                f"connector:{connector.key_id}",
                f"memory:{connector.key_id}",
                False,
                None,
            )
            for connector in connectors
        ],
    }


def resign(document: JsonObject, connectors: list[SigningConnector], domain: bytes, label: str) -> JsonObject:
    unsigned = {key: value for key, value in document.items() if key != "signatures"}
    return sign_threshold_document(unsigned, connectors, domain, label, WorldIntakeGovernanceError)


def validate_world_intake_governance(project_root: Path) -> JsonObject:
    issued_at = datetime(2026, 7, 16, 10, 0, 0, tzinfo=timezone.utc)
    health_issued_at = datetime(2026, 7, 16, 10, 0, 1, tzinfo=timezone.utc)
    decision_issued_at = datetime(2026, 7, 16, 10, 0, 2, tzinfo=timezone.utc)
    connectors: list[SigningConnector] = [
        EphemeralEd25519SigningConnector("key:source-owner", "source_owner", Ed25519PrivateKey.generate()),
        EphemeralEd25519SigningConnector("key:privacy", "privacy_officer", Ed25519PrivateKey.generate()),
        EphemeralEd25519SigningConnector("key:safety", "safety_officer", Ed25519PrivateKey.generate()),
    ]
    state = governance_state(connectors, issued_at.isoformat().replace("+00:00", "Z"))
    edge_document = build_session(
        issued_at,
        {
            "powershell_operational": [
                event("powershell_operational", 101, "2026-07-16T10:00:00Z"),
                event("powershell_operational", 102, "2026-07-16T10:00:01Z"),
                event("powershell_operational", 103, "2026-07-16T10:00:04Z"),
            ],
            "sysmon_operational": [],
            "dns_client_operational": [
                event("dns_client_operational", 201, "2026-07-16T10:00:02Z"),
                event("dns_client_operational", 202, "2026-07-16T10:00:03Z"),
            ],
        },
    )
    policy = build_source_policy(state, connectors[:2], issued_at)
    policy_signers, policy_roles = validate_source_policy(policy, state, decision_issued_at)
    health = build_source_health_attestation(edge_document, policy, state, connectors[:2], health_issued_at)
    health_signers, health_roles = validate_source_health_attestation(
        health,
        edge_document,
        policy,
        state,
        decision_issued_at,
    )
    boundary = cast(JsonObject, dict(VERIFIER_BOUNDARY))
    decision, admitted_edge = build_governed_intake_decision(
        edge_document,
        policy,
        health,
        state,
        connectors[:2],
        boundary,
        2,
        2,
        1,
        decision_issued_at,
    )
    decision_signers, decision_roles = validate_governed_intake_decision(
        edge_document,
        admitted_edge,
        policy,
        health,
        state,
        boundary,
        decision,
        decision_issued_at,
    )
    baseline_scenario_path = project_root / "tests" / "fixtures" / "cacis" / "world-model-replay-credential-theft.json"
    baseline_scenario = json.loads(baseline_scenario_path.read_text(encoding="utf-8"))
    if not isinstance(baseline_scenario, dict):
        raise RuntimeError("World intake governance baseline scenario is malformed.")
    baseline_generation = build_world_model_generation(cast(JsonObject, baseline_scenario))
    baseline_digest = cast(str, baseline_generation["generation_digest"])
    cursor = build_empty_cursor_state(baseline_digest)
    base_candidate = build_world_intake_candidate(admitted_edge, cursor, baseline_generation)
    governed_intake = build_governed_world_intake(decision, admitted_edge, base_candidate)
    verification = run_governed_world_intake_verification(
        project_root,
        edge_document,
        admitted_edge,
        policy,
        health,
        decision,
        state,
        boundary,
        cursor,
        baseline_generation,
        governed_intake,
        decision_issued_at,
    )
    if verification.get("status") != "governed_replay_intake_verified_live_admission_blocked":
        raise RuntimeError("Separate governed intake verifier did not accept the canonical replay.")
    with tempfile.TemporaryDirectory(prefix="nimrod-governed-world-store-") as temporary:
        store_root = Path(temporary)
        prepare_world_model_store(store_root, cast(JsonObject, baseline_scenario), baseline_generation)
        commit_world_model_store(store_root, baseline_digest)
        recovered = commit_governed_world_intake_store(
            store_root,
            edge_document,
            admitted_edge,
            policy,
            health,
            state,
            boundary,
            decision,
            governed_intake,
            decision_issued_at,
        )
        if recovered.get("status") != "world_and_cursor_active":
            raise RuntimeError("Governed intake candidate did not advance the immutable World Model store.")

    adversarial_count = 0
    mismatched_projection_decision, mismatched_projection_edge = build_governed_intake_decision(
        edge_document,
        policy,
        health,
        state,
        connectors[:2],
        boundary,
        2,
        3,
        2,
        decision_issued_at,
    )
    mismatched_projection_candidate = build_world_intake_candidate(
        mismatched_projection_edge,
        cursor,
        baseline_generation,
    )
    mismatched_projection_wrapper = build_governed_world_intake(
        mismatched_projection_decision,
        mismatched_projection_edge,
        mismatched_projection_candidate,
    )
    with tempfile.TemporaryDirectory(prefix="nimrod-governed-projection-") as temporary:
        mismatched_store = Path(temporary)
        prepare_world_model_store(mismatched_store, cast(JsonObject, baseline_scenario), baseline_generation)
        commit_world_model_store(mismatched_store, baseline_digest)
        expect_error(
            lambda: commit_governed_world_intake_store(
                mismatched_store,
                edge_document,
                mismatched_projection_edge,
                policy,
                health,
                state,
                boundary,
                mismatched_projection_decision,
                mismatched_projection_wrapper,
                decision_issued_at,
            ),
            "immutable store retention projection mismatch",
        )
    adversarial_count += 1
    missing_policy_signature = copy.deepcopy(policy)
    cast(list[object], missing_policy_signature["signatures"]).pop()
    expect_error(lambda: validate_source_policy(missing_policy_signature, state, decision_issued_at), "policy threshold loss")
    adversarial_count += 1
    widened_retention = copy.deepcopy(policy)
    cast(JsonObject, widened_retention["retention"])["raw_event_payload_retention_seconds"] = 3600
    widened_retention = resign(widened_retention, connectors[:2], POLICY_DOMAIN, "World intake source policy")
    expect_error(lambda: validate_source_policy(widened_retention, state, decision_issued_at), "raw payload retention widening")
    adversarial_count += 1
    widened_budget = copy.deepcopy(policy)
    cast(JsonObject, widened_budget["ingestion_budget"])["maximum_queue_depth"] = 400
    widened_budget = resign(widened_budget, connectors[:2], POLICY_DOMAIN, "World intake source policy")
    expect_error(lambda: validate_source_policy(widened_budget, state, decision_issued_at), "queue budget widening")
    adversarial_count += 1
    changed_source = copy.deepcopy(policy)
    cast(list[JsonObject], changed_source["sources"])[0]["channel"] = "Security"
    changed_source = resign(changed_source, connectors[:2], POLICY_DOMAIN, "World intake source policy")
    expect_error(lambda: validate_source_policy(changed_source, state, decision_issued_at), "source configuration substitution")
    adversarial_count += 1
    expired_policy = copy.deepcopy(policy)
    expired_policy["expires_at"] = "2026-07-16T10:00:01Z"
    expired_policy = resign(expired_policy, connectors[:2], POLICY_DOMAIN, "World intake source policy")
    expect_error(lambda: validate_source_policy(expired_policy, state, decision_issued_at), "expired policy")
    adversarial_count += 1
    missing_health_signature = copy.deepcopy(health)
    cast(list[object], missing_health_signature["signatures"]).pop()
    expect_error(
        lambda: validate_source_health_attestation(
            missing_health_signature, edge_document, policy, state, decision_issued_at
        ),
        "health threshold loss",
    )
    adversarial_count += 1
    false_freshness = copy.deepcopy(health)
    cast(list[JsonObject], false_freshness["sources"])[1]["fresh"] = True
    false_freshness = resign(false_freshness, connectors[:2], HEALTH_DOMAIN, "World intake source health")
    expect_error(
        lambda: validate_source_health_attestation(false_freshness, edge_document, policy, state, decision_issued_at),
        "freshness laundering",
    )
    adversarial_count += 1
    false_health = copy.deepcopy(health)
    cast(list[JsonObject], false_health["sources"])[1]["status"] = "observed"
    false_health = resign(false_health, connectors[:2], HEALTH_DOMAIN, "World intake source health")
    expect_error(
        lambda: validate_source_health_attestation(false_health, edge_document, policy, state, decision_issued_at),
        "sensor health laundering",
    )
    adversarial_count += 1
    false_session = copy.deepcopy(health)
    false_session["source_session_digest"] = "sha256:" + "0" * 64
    false_session = resign(false_session, connectors[:2], HEALTH_DOMAIN, "World intake source health")
    expect_error(
        lambda: validate_source_health_attestation(false_session, edge_document, policy, state, decision_issued_at),
        "health session substitution",
    )
    adversarial_count += 1
    missing_decision_signature = copy.deepcopy(decision)
    cast(list[object], missing_decision_signature["signatures"]).pop()
    expect_error(
        lambda: validate_governed_intake_decision(
            edge_document,
            admitted_edge,
            policy,
            health,
            state,
            boundary,
            missing_decision_signature,
            decision_issued_at,
        ),
        "decision threshold loss",
    )
    adversarial_count += 1
    dropped_event = copy.deepcopy(decision)
    cast(JsonObject, dropped_event["queue"])["dropped_event_count"] = 1
    dropped_event = resign(dropped_event, connectors[:2], DECISION_DOMAIN, "World intake governance decision")
    expect_error(
        lambda: validate_governed_intake_decision(
            edge_document, admitted_edge, policy, health, state, boundary, dropped_event, decision_issued_at
        ),
        "event drop laundering",
    )
    adversarial_count += 1
    widened_live = copy.deepcopy(decision)
    widened_live["live_admission_authorized"] = True
    widened_live = resign(widened_live, connectors[:2], DECISION_DOMAIN, "World intake governance decision")
    expect_error(
        lambda: validate_governed_intake_decision(
            edge_document, admitted_edge, policy, health, state, boundary, widened_live, decision_issued_at
        ),
        "live admission widening",
    )
    adversarial_count += 1
    skipped_event = copy.deepcopy(decision)
    cast(JsonObject, skipped_event["queue"])["accepted_event_indexes"] = [0, 2]
    skipped_event = resign(skipped_event, connectors[:2], DECISION_DOMAIN, "World intake governance decision")
    expect_error(
        lambda: validate_governed_intake_decision(
            edge_document, admitted_edge, policy, health, state, boundary, skipped_event, decision_issued_at
        ),
        "non-prefix backpressure selection",
    )
    adversarial_count += 1
    altered_admitted = copy.deepcopy(admitted_edge)
    cast(list[JsonObject], altered_admitted["events"]).pop()
    altered_admitted["event_set_digest"] = sha256_digest(cast(list[JsonObject], altered_admitted["events"]))
    cast(list[JsonObject], altered_admitted["sources"])[0]["event_count"] = 1
    expect_error(
        lambda: validate_governed_intake_decision(
            edge_document, altered_admitted, policy, health, state, boundary, decision, decision_issued_at
        ),
        "admitted projection substitution",
    )
    adversarial_count += 1
    fabricated_boundary = copy.deepcopy(boundary)
    fabricated_boundary["production_independence_verified"] = True
    expect_error(lambda: validate_verifier_boundary(fabricated_boundary), "verifier independence fabrication")
    adversarial_count += 1
    live_edge = copy.deepcopy(edge_document)
    live_edge["origin"] = "live"
    expect_error(
        lambda: build_governed_intake_decision(
            live_edge,
            policy,
            health,
            state,
            connectors[:2],
            boundary,
            2,
            2,
            1,
            decision_issued_at,
        ),
        "live-origin intake",
    )
    adversarial_count += 1
    full_queue_decision, empty_admitted = build_governed_intake_decision(
        edge_document,
        policy,
        health,
        state,
        connectors[:2],
        boundary,
        4,
        2,
        1,
        decision_issued_at,
    )
    expect_error(
        lambda: build_governed_world_intake(
            full_queue_decision,
            empty_admitted,
            build_world_intake_candidate(empty_admitted, cursor, baseline_generation),
        ),
        "full-queue replay admission",
    )
    adversarial_count += 1
    wrapper_substitution = copy.deepcopy(governed_intake)
    cast(JsonObject, wrapper_substitution["governed_intake"])["governance_decision_digest"] = "sha256:" + "0" * 64
    expect_error(
        lambda: run_governed_world_intake_verification(
            project_root,
            edge_document,
            admitted_edge,
            policy,
            health,
            decision,
            state,
            boundary,
            cursor,
            baseline_generation,
            wrapper_substitution,
            decision_issued_at,
        ),
        "governed wrapper substitution",
    )
    adversarial_count += 1

    queue = cast(JsonObject, decision["queue"])
    health_summary = cast(JsonObject, decision["health_summary"])
    return {
        "status": "CACIS_WORLD_INTAKE_GOVERNANCE_REPLAY_VALID_LIVE_ADMISSION_BLOCKED",
        "source_policy_verified_signer_count": len(policy_signers),
        "source_policy_verified_role_count": len(policy_roles),
        "source_health_verified_signer_count": len(health_signers),
        "source_health_verified_role_count": len(health_roles),
        "intake_decision_verified_signer_count": len(decision_signers),
        "intake_decision_verified_role_count": len(decision_roles),
        "source_count": len(cast(list[object], health["sources"])),
        "fresh_source_count": health_summary["fresh_source_count"],
        "source_gap_count": health_summary["source_gap_count"],
        "queue_depth_before": queue["depth_before"],
        "queue_depth_after": queue["depth_after"],
        "accepted_event_count": queue["accepted_event_count"],
        "deferred_event_count": queue["deferred_event_count"],
        "dropped_event_count": queue["dropped_event_count"],
        "retention_within_limits": cast(JsonObject, decision["retention"])["within_limits"],
        "raw_event_payload_retention_seconds": cast(JsonObject, policy["retention"])[
            "raw_event_payload_retention_seconds"
        ],
        "separate_process_verification_performed": True,
        "production_verifier_independence_verified": False,
        "negative_fail_closed_case_count": adversarial_count,
        "live_sensor_admission_authorized": False,
        "policy_input_ready": False,
        "execution_authorized": False,
        "execution_performed": False,
        "target_contact_performed": False,
    }


def main() -> None:
    project_root = Path(__file__).resolve().parents[1]
    result = validate_world_intake_governance(project_root)
    report_path = project_root / "reports" / "CACIS_WORLD_INTAKE_GOVERNANCE_VALIDATION.json"
    report_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
