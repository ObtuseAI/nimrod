"""Separate-process verifier for governed World Model source intake."""

from __future__ import annotations

import argparse
import json
import os
from datetime import datetime
from pathlib import Path

from nimrod_cacis.world_intake_governance import (
    build_governed_world_intake,
    validate_governed_intake_decision,
)
from nimrod_cacis.world_intake_verifier import build_world_intake_verification
from nimrod_simulator.errors import WorldIntakeGovernanceError
from nimrod_simulator.jsonio import canonical_json_bytes, read_json_object, sha256_digest
from nimrod_simulator.model import JsonObject


def _parse_timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise WorldIntakeGovernanceError("Governed intake verification time requires an offset.")
    return parsed


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify one governed World Model replay intake")
    parser.add_argument("--edge-document", required=True, type=Path)
    parser.add_argument("--admitted-edge", required=True, type=Path)
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--health", required=True, type=Path)
    parser.add_argument("--decision", required=True, type=Path)
    parser.add_argument("--governance-state", required=True, type=Path)
    parser.add_argument("--verifier-boundary", required=True, type=Path)
    parser.add_argument("--previous-cursor", required=True, type=Path)
    parser.add_argument("--previous-generation", required=True, type=Path)
    parser.add_argument("--governed-intake", required=True, type=Path)
    parser.add_argument("--verified-at", required=True)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    values = {
        "edge_document": read_json_object(arguments.edge_document),
        "admitted_edge": read_json_object(arguments.admitted_edge),
        "policy": read_json_object(arguments.policy),
        "health": read_json_object(arguments.health),
        "decision": read_json_object(arguments.decision),
        "governance_state": read_json_object(arguments.governance_state),
        "verifier_boundary": read_json_object(arguments.verifier_boundary),
        "previous_cursor": read_json_object(arguments.previous_cursor),
        "previous_generation": read_json_object(arguments.previous_generation),
        "governed_intake": read_json_object(arguments.governed_intake),
    }
    verified_at = _parse_timestamp(arguments.verified_at)
    signers, roles = validate_governed_intake_decision(
        values["edge_document"],
        values["admitted_edge"],
        values["policy"],
        values["health"],
        values["governance_state"],
        values["verifier_boundary"],
        values["decision"],
        verified_at,
    )
    governed_body = values["governed_intake"].get("governed_intake")
    if not isinstance(governed_body, dict):
        raise WorldIntakeGovernanceError("Governed intake wrapper is malformed.")
    base_candidate = governed_body.get("base_candidate")
    if not isinstance(base_candidate, dict):
        raise WorldIntakeGovernanceError("Governed intake base candidate is malformed.")
    causal = build_world_intake_verification(
        values["admitted_edge"],
        values["previous_cursor"],
        values["previous_generation"],
        base_candidate,
    )
    expected_wrapper = build_governed_world_intake(values["decision"], values["admitted_edge"], base_candidate)
    if expected_wrapper != values["governed_intake"]:
        raise WorldIntakeGovernanceError("Governed intake wrapper differs from independent reconstruction.")
    verification: JsonObject = {
        "verification_version": "0.1.0",
        "status": "governed_replay_intake_verified_live_admission_blocked",
        "read_only": True,
        "separate_process": True,
        "production_independence_verified": False,
        "verified_signer_ids": signers,
        "verified_roles": roles,
        "causal_verification_digest": sha256_digest(causal),
        "verified_claims": [
            "threshold_source_policy_valid",
            "threshold_source_health_valid",
            "threshold_intake_decision_valid",
            "purpose_and_retention_bound",
            "queue_and_ingestion_budget_recomputed",
            "backpressure_and_deferred_events_recomputed",
            "freshness_and_clock_skew_recomputed",
            "admitted_event_projection_bound",
            "cursor_and_generation_causality_recomputed",
            "live_admission_block_preserved",
        ],
        "authority": {
            "can_authorize": False,
            "can_execute": False,
            "can_change_policy": False,
            "can_claim_truth": False,
        },
    }
    envelope: JsonObject = {
        "worker_process_id": os.getpid(),
        "input_digests": {name: sha256_digest(value) for name, value in values.items()},
        "verification": verification,
    }
    arguments.output.write_bytes(canonical_json_bytes(envelope) + b"\n")
    print(json.dumps({"status": "CACIS_GOVERNED_WORLD_INTAKE_VERIFIED", "worker_process_id": os.getpid()}, sort_keys=True))


if __name__ == "__main__":
    main()
