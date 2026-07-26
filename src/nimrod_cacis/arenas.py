"""Replay-only CACIS W6 security arenas and signed display-only Observatory."""

from __future__ import annotations

import uuid
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta
from typing import cast

from nimrod_simulator.errors import ArenaObservatoryError
from nimrod_simulator.jsonio import require_object, sha256_digest
from nimrod_simulator.key_governance import SigningConnector, validate_governance_state
from nimrod_simulator.model import JsonObject
from nimrod_simulator.threshold_signing import sign_threshold_document, verify_threshold_signatures


OBSERVATORY_DOMAIN = b"nimrod.cacis-observatory.v0.1\x00"
ARENA_NAMESPACE = uuid.UUID("128d62ad-75ca-5e53-adcc-721e4af8189d")
ARENAS: tuple[str, ...] = (
    "credential_theft",
    "suspicious_script",
    "ransomware",
    "cloud",
    "containers",
    "supply_chain",
    "identity",
    "insider",
    "novel_malware",
    "living_off_the_land",
    "privilege_escalation",
    "misconfiguration",
    "recovery",
    "purple_validation",
    "metacognition",
)
DIMENSIONS: tuple[str, ...] = (
    "detection_quality",
    "false_positive_rate",
    "false_negative_rate",
    "calibration",
    "recovery_quality",
    "verification_quality",
    "containment_quality",
    "investigation_efficiency",
    "resource_efficiency",
    "agent_contribution",
    "genome_improvement",
    "evolution_quality",
    "metacognitive_quality",
    "governance_preservation",
)
AUTHORITY: Mapping[str, bool] = {
    "can_authorize": False,
    "can_execute": False,
    "can_suppress_dissent": False,
    "can_change_policy": False,
    "can_promote": False,
}


def _arena_metrics(seed: int) -> JsonObject:
    quality = round(0.68 + (seed % 5) * 0.04, 2)
    return {
        "detection_quality": quality,
        "false_positive_rate": round(0.08 + (seed % 3) * 0.02, 2),
        "false_negative_rate": round(1.0 - quality, 2),
        "calibration": round(0.7 + (seed % 4) * 0.04, 2),
        "recovery_quality": round(0.66 + (seed % 4) * 0.05, 2),
        "verification_quality": round(0.72 + (seed % 3) * 0.05, 2),
        "containment_quality": round(0.67 + (seed % 5) * 0.04, 2),
        "investigation_efficiency": round(0.64 + (seed % 4) * 0.05, 2),
        "resource_efficiency": round(0.7 + (seed % 3) * 0.04, 2),
        "agent_contribution": round(0.69 + (seed % 4) * 0.04, 2),
        "genome_improvement": round(0.6 + (seed % 5) * 0.05, 2),
        "evolution_quality": round(0.62 + (seed % 4) * 0.05, 2),
        "metacognitive_quality": round(0.71 + (seed % 3) * 0.05, 2),
        "governance_preservation": 1.0,
    }


def _arena_report(genome_digest: str, scenario_fixture: JsonObject) -> JsonObject:
    scenarios = scenario_fixture.get("scenarios")
    if (
        scenario_fixture.get("fixture_version") != "0.1.0"
        or scenario_fixture.get("origin") != "synthetic_deterministic_replay_fixture"
        or not isinstance(scenarios, list)
        or [scenario.get("arena") for scenario in scenarios if isinstance(scenario, dict)] != list(ARENAS)
    ):
        raise ArenaObservatoryError("CACIS W6 replay scenario fixture is incomplete, reordered, or mislabeled.")
    rows: list[JsonObject] = []
    for arena, scenario in zip(ARENAS, cast(list[JsonObject], scenarios), strict=True):
        seed = scenario.get("seed")
        expected_evidence = scenario.get("expected_evidence")
        if isinstance(seed, bool) or not isinstance(seed, int) or not isinstance(expected_evidence, list) or not expected_evidence:
            raise ArenaObservatoryError(f"CACIS W6 arena '{arena}' has an invalid replay scenario.")
        rows.append(
            {
                "arena": arena,
                "origin": "replayed",
                "status": "synthetic_replay_evaluated_live_blocked",
                "scenario_id": scenario.get("scenario_id"),
                "scenario_digest": sha256_digest(scenario),
                "evidence_basis": "synthetic_deterministic_replay_fixture",
                "expected_evidence": list(expected_evidence),
                "metrics": _arena_metrics(seed),
                "hard_failures": [],
                "public_host_targeted": False,
                "execution_performed": False,
                "live_evidence_present": False,
            }
        )
    body: JsonObject = {
        "arena_version": "0.1.0",
        "campaign_id": str(uuid.uuid5(ARENA_NAMESPACE, genome_digest)),
        "origin": "replayed",
        "genome_digest": genome_digest,
        "scenario_fixture_digest": sha256_digest(scenario_fixture),
        "dimensions": list(DIMENSIONS),
        "arenas": rows,
        "summary": {
            "evaluated_arena_count": len(ARENAS),
            "synthetic_replay_fixture_count": len(ARENAS),
            "blocked_live_gate_count": len(ARENAS),
            "hard_failure_count": 0,
            "aggregate_may_override_hard_failure": False,
            "external_replication_performed": False,
            "live_range_connected": False,
        },
        "authority": dict(AUTHORITY),
    }
    return {"arena_digest": sha256_digest(body), "arena_report": body}


def build_arenas_observatory(
    genome_document: JsonObject,
    scenario_fixture: JsonObject,
    connectors: Sequence[SigningConnector],
    governance_state: JsonObject,
    issued_at: datetime,
) -> JsonObject:
    """Evaluate replay arenas and sign a freshness-bound display-only projection."""
    validate_governance_state(governance_state)
    genome_body = require_object(genome_document.get("genome"), "genome")
    if genome_document.get("genome_digest") != sha256_digest(genome_body):
        raise ArenaObservatoryError("CACIS W6 received an invalid W5 genome digest.")
    genome_digest = cast(str, genome_document["genome_digest"])
    arena = _arena_report(genome_digest, scenario_fixture)
    projection: JsonObject = {
        "projection_version": "0.1.0",
        "projection_id": str(uuid.uuid5(ARENA_NAMESPACE, f"projection:{genome_digest}")),
        "origin": "replayed",
        "issued_at": issued_at.isoformat().replace("+00:00", "Z"),
        "genome_digest": genome_digest,
        "arena_digest": arena["arena_digest"],
        "evaluated_arena_count": len(ARENAS),
        "blocked_live_gate_count": len(ARENAS),
        "hard_failure_count": 0,
        "knowledge_state": "partially_known",
        "dissent_preserved": True,
        "missing_evidence": [
            "live isolated-range arena evidence",
            "external replication",
            "production-independent verifier custody",
        ],
        "display_only": True,
        "authority": dict(AUTHORITY),
    }
    projection_digest = sha256_digest(projection)
    unsigned_snapshot: JsonObject = {
        "snapshot_version": "0.1.0",
        "snapshot_id": str(uuid.uuid5(ARENA_NAMESPACE, f"snapshot:{projection_digest}")),
        "snapshot_kind": "observatory_projection",
        "origin": "simulated",
        "issuer_service_id": "cacis-observatory-supervisor",
        "audience": "nimrod-control-board",
        "sequence": 1,
        "issued_at": issued_at.isoformat().replace("+00:00", "Z"),
        "not_before": issued_at.isoformat().replace("+00:00", "Z"),
        "expires_at": (issued_at + timedelta(seconds=30)).isoformat().replace("+00:00", "Z"),
        "previous_snapshot_digest": None,
        "projection_digest": projection_digest,
        "governance_state_digest": sha256_digest(governance_state),
        "authority": {"can_authorize": False, "can_execute": False},
    }
    snapshot = sign_threshold_document(
        unsigned_snapshot,
        list(connectors),
        OBSERVATORY_DOMAIN,
        "CACIS Observatory snapshot",
        ArenaObservatoryError,
    )
    document: JsonObject = {
        "w6_version": "0.1.0",
        "arena": arena,
        "projection": projection,
        "snapshot": snapshot,
        "security_claim": (
            "Replay-only W6 evaluates fifteen explicitly synthetic deterministic scenarios and exposes a threshold-signed display projection; "
            "live arenas, external replication, authorization, execution, and production outcomes remain blocked"
        ),
    }
    validate_arenas_observatory(document, genome_document, scenario_fixture, governance_state, issued_at)
    return document


def validate_arenas_observatory(
    document: JsonObject,
    genome_document: JsonObject,
    scenario_fixture: JsonObject,
    governance_state: JsonObject,
    issued_at: datetime,
) -> tuple[list[str], list[str]]:
    if set(document) != {"w6_version", "arena", "projection", "snapshot", "security_claim"} or document.get("w6_version") != "0.1.0":
        raise ArenaObservatoryError("CACIS W6 wrapper is malformed.")
    arena = require_object(document.get("arena"), "arena")
    arena_body = require_object(arena.get("arena_report"), "arena.arena_report")
    projection = require_object(document.get("projection"), "projection")
    snapshot = require_object(document.get("snapshot"), "snapshot")
    if arena.get("arena_digest") != sha256_digest(arena_body):
        raise ArenaObservatoryError("CACIS W6 arena digest is invalid.")
    genome_body = require_object(genome_document.get("genome"), "genome")
    genome_digest = genome_document.get("genome_digest")
    if genome_digest != sha256_digest(genome_body) or arena_body.get("genome_digest") != genome_digest:
        raise ArenaObservatoryError("CACIS W6 arena is not bound to its W5 genome.")
    if arena_body.get("scenario_fixture_digest") != sha256_digest(scenario_fixture):
        raise ArenaObservatoryError("CACIS W6 arena is not bound to its replay scenario fixture.")
    rows = arena_body.get("arenas")
    if not isinstance(rows, list) or [row.get("arena") for row in rows if isinstance(row, dict)] != list(ARENAS):
        raise ArenaObservatoryError("CACIS W6 arena set is incomplete or reordered.")
    for row in cast(list[JsonObject], rows):
        if row.get("origin") != "replayed" or row.get("public_host_targeted") is not False or row.get("execution_performed") is not False:
            raise ArenaObservatoryError("CACIS W6 arena laundered origin, public targeting, or execution.")
        if (
            row.get("status") != "synthetic_replay_evaluated_live_blocked"
            or row.get("evidence_basis") != "synthetic_deterministic_replay_fixture"
            or row.get("live_evidence_present") is not False
            or set(cast(JsonObject, row.get("metrics"))) != set(DIMENSIONS)
        ):
            raise ArenaObservatoryError("CACIS W6 evaluated arena lacks its multidimensional replay metrics.")
        if row.get("hard_failures") != []:
            raise ArenaObservatoryError("CACIS W6 hard failure cannot be hidden inside an aggregate.")
    if projection.get("display_only") is not True or projection.get("authority") != AUTHORITY:
        raise ArenaObservatoryError("CACIS Observatory projection is not display-only or widened authority.")
    if projection.get("arena_digest") != arena.get("arena_digest") or snapshot.get("projection_digest") != sha256_digest(projection):
        raise ArenaObservatoryError("CACIS Observatory projection or snapshot binding is invalid.")
    if snapshot.get("snapshot_kind") != "observatory_projection" or snapshot.get("audience") != "nimrod-control-board":
        raise ArenaObservatoryError("CACIS Observatory snapshot kind or audience was substituted.")
    if snapshot.get("authority") != {"can_authorize": False, "can_execute": False}:
        raise ArenaObservatoryError("CACIS Observatory snapshot widened operational authority.")
    if snapshot.get("governance_state_digest") != sha256_digest(governance_state):
        raise ArenaObservatoryError("CACIS Observatory snapshot governance binding is invalid.")
    expected_issued_at = issued_at.isoformat().replace("+00:00", "Z")
    expected_expires_at = (issued_at + timedelta(seconds=30)).isoformat().replace("+00:00", "Z")
    if (
        snapshot.get("issued_at") != expected_issued_at
        or snapshot.get("not_before") != expected_issued_at
        or snapshot.get("expires_at") != expected_expires_at
    ):
        raise ArenaObservatoryError("CACIS Observatory snapshot freshness window is invalid.")
    return verify_threshold_signatures(
        snapshot,
        governance_state,
        issued_at,
        OBSERVATORY_DOMAIN,
        "CACIS Observatory snapshot",
        ArenaObservatoryError,
    )
