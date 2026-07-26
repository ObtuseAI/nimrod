"""Validate CACIS W6 replay arenas and threshold-signed display-only Observatory."""

from __future__ import annotations

import copy
import json
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import cast

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from nimrod_cacis.arenas import ARENAS, DIMENSIONS, build_arenas_observatory, validate_arenas_observatory
from nimrod_cacis.genome import build_genome_evaluation
from nimrod_simulator.errors import ArenaObservatoryError
from nimrod_simulator.jsonio import sha256_digest
from nimrod_simulator.key_governance import EphemeralEd25519SigningConnector, SigningConnector, governance_key
from nimrod_simulator.model import JsonObject
from validate_genome_evaluation import source_digests


def expect_error(operation: Callable[[], object], label: str) -> None:
    try:
        operation()
    except ArenaObservatoryError:
        return
    raise RuntimeError(f"Expected ArenaObservatoryError for {label}.")


def governance(connectors: list[SigningConnector], issued_at: str) -> JsonObject:
    return {
        "state_version": "0.1.0",
        "governance_id": "76100000-0000-4000-8000-000000000001",
        "origin": "simulated",
        "epoch": 1,
        "issued_at": issued_at,
        "previous_state_digest": None,
        "threshold": 2,
        "ceremony_key_count": 3,
        "minimum_distinct_roles": 2,
        "keys": [
            governance_key(connector, "active", issued_at, None, "test_ephemeral", f"connector:{connector.key_id}", f"memory:{connector.key_id}", False, None)
            for connector in connectors
        ],
    }


def validate_arenas(project_root: Path) -> JsonObject:
    genome = build_genome_evaluation(source_digests(project_root))
    scenario_fixture = cast(
        JsonObject,
        json.loads((project_root / "tests" / "fixtures" / "cacis" / "arena-replay-scenarios.json").read_text(encoding="utf-8")),
    )
    connectors: list[SigningConnector] = [
        EphemeralEd25519SigningConnector("key:observatory-a", "observatory_supervisor", Ed25519PrivateKey.generate()),
        EphemeralEd25519SigningConnector("key:safety-b", "safety_officer", Ed25519PrivateKey.generate()),
        EphemeralEd25519SigningConnector("key:recovery-c", "recovery_officer", Ed25519PrivateKey.generate()),
    ]
    issued_at = datetime(2026, 7, 16, 9, 0, 0, tzinfo=timezone.utc)
    state = governance(connectors, issued_at.isoformat().replace("+00:00", "Z"))
    generated = build_arenas_observatory(genome, scenario_fixture, connectors[:2], state, issued_at)
    verified_signers, verified_roles = validate_arenas_observatory(generated, genome, scenario_fixture, state, issued_at)
    adversarial_count = 0
    mutations: tuple[tuple[str, Callable[[JsonObject], None]], ...] = (
        ("public targeting", lambda value: cast(list[JsonObject], cast(JsonObject, cast(JsonObject, value["arena"])["arena_report"])["arenas"])[0].__setitem__("public_host_targeted", True)),
        ("metric substitution", lambda value: cast(list[JsonObject], cast(JsonObject, cast(JsonObject, value["arena"])["arena_report"])["arenas"])[2].__setitem__("metrics", {})),
        ("live evidence fabrication", lambda value: cast(list[JsonObject], cast(JsonObject, cast(JsonObject, value["arena"])["arena_report"])["arenas"])[2].__setitem__("live_evidence_present", True)),
        ("hard failure suppression", lambda value: cast(list[JsonObject], cast(JsonObject, cast(JsonObject, value["arena"])["arena_report"])["arenas"])[0].__setitem__("hard_failures", ["authority_growth"])),
        ("display authority widening", lambda value: cast(JsonObject, cast(JsonObject, value["projection"])["authority"]).__setitem__("can_authorize", True)),
        ("display-only removal", lambda value: cast(JsonObject, value["projection"]).__setitem__("display_only", False)),
        ("snapshot execution authority", lambda value: cast(JsonObject, cast(JsonObject, value["snapshot"])["authority"]).__setitem__("can_execute", True)),
        ("projection binding substitution", lambda value: cast(JsonObject, value["snapshot"]).__setitem__("projection_digest", "sha256:" + "0" * 64)),
        ("signature removal", lambda value: cast(list[object], cast(JsonObject, value["snapshot"])["signatures"]).pop()),
    )
    for label, mutation in mutations:
        candidate = copy.deepcopy(generated)
        mutation(candidate)
        arena_wrapper = cast(JsonObject, candidate["arena"])
        arena_wrapper["arena_digest"] = sha256_digest(cast(JsonObject, arena_wrapper["arena_report"]))
        expect_error(lambda candidate=candidate: validate_arenas_observatory(candidate, genome, scenario_fixture, state, issued_at), label)
        adversarial_count += 1
    arena_wrapper = cast(JsonObject, generated["arena"])
    arena_body = cast(JsonObject, arena_wrapper["arena_report"])
    return {
        "status": "CACIS_ARENAS_OBSERVATORY_W6_REPLAY_VALID_DISPLAY_ONLY",
        "arena_digest": arena_wrapper["arena_digest"],
        "arena_count": len(ARENAS),
        "evaluated_arena_count": len(ARENAS),
        "synthetic_replay_fixture_count": len(ARENAS),
        "blocked_live_gate_count": len(ARENAS),
        "benchmark_dimension_count": len(DIMENSIONS),
        "hard_failure_count": cast(JsonObject, arena_body["summary"])["hard_failure_count"],
        "verified_signer_count": len(verified_signers),
        "verified_role_count": len(verified_roles),
        "negative_fail_closed_case_count": adversarial_count,
        "display_only": True,
        "external_replication_performed": False,
        "live_range_connected": False,
        "execution_authorized": False,
        "execution_performed": False,
    }


def main() -> None:
    project_root = Path(__file__).resolve().parents[1]
    result = validate_arenas(project_root)
    report_path = project_root / "reports" / "CACIS_ARENAS_OBSERVATORY_VALIDATION.json"
    report_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
