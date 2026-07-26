"""Validate W4 metabolism, homeostasis, and Chronos replay controls."""

from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import cast

from nimrod_cacis.homeostasis import (
    CLOCK_TYPES,
    RESOURCE_TYPES,
    SIGNAL_TYPES,
    build_homeostasis_chronos_receipt,
    validate_homeostasis_chronos_mission,
    validate_homeostasis_chronos_receipt,
)
from nimrod_simulator.errors import HomeostasisChronosError
from nimrod_simulator.jsonio import read_json_object, validate_contract
from nimrod_simulator.model import JsonObject


Mutation = Callable[[JsonObject], None]


def expect_error(label: str, operation: Callable[[], object]) -> None:
    try:
        operation()
    except HomeostasisChronosError:
        return
    raise RuntimeError(f"Expected HomeostasisChronosError for {label}.")


def mission_case(source: JsonObject, mutation: Mutation) -> Callable[[], object]:
    def run() -> object:
        value = copy.deepcopy(source)
        mutation(value)
        validate_homeostasis_chronos_mission(value)
        return value

    return run


def receipt_body(value: JsonObject) -> JsonObject:
    return cast(JsonObject, value["receipt"])


def receipt_case(mission: JsonObject, source: JsonObject, mutation: Mutation) -> Callable[[], object]:
    def run() -> object:
        value = copy.deepcopy(source)
        mutation(value)
        validate_homeostasis_chronos_receipt(mission, value)
        return value

    return run


def set_signal(value: JsonObject, index: int, field: str, replacement: object) -> None:
    cast(list[JsonObject], value["signals"])[index][field] = cast(object, replacement)


def set_clock(value: JsonObject, index: int, field: str, replacement: object) -> None:
    cast(list[JsonObject], value["chronos_policy"])[index][field] = cast(object, replacement)


def set_work(value: JsonObject, index: int, field: str, replacement: object) -> None:
    cast(list[JsonObject], value["work_items"])[index][field] = cast(object, replacement)


def validate_cli(project_root: Path, mission_path: Path, expected: JsonObject) -> bool:
    with tempfile.TemporaryDirectory(prefix="nimrod-w4-") as temporary:
        output_path = Path(temporary) / "receipt.json"
        completed = subprocess.run(
            [sys.executable, "-m", "nimrod_cacis.homeostasis_cli", "--mission", str(mission_path), "--output", str(output_path)],
            cwd=project_root,
            check=False,
            capture_output=True,
            text=True,
        )
        if completed.returncode != 0:
            raise RuntimeError(f"W4 CLI replay failed: stdout={completed.stdout!r}, stderr={completed.stderr!r}.")
        return read_json_object(output_path) == expected


def validate_homeostasis_wave(project_root: Path) -> JsonObject:
    mission_path = project_root / "specs" / "examples" / "homeostasis-chronos-mission.example.json"
    receipt_path = project_root / "specs" / "examples" / "homeostasis-chronos-receipt.example.json"
    mission = read_json_object(mission_path)
    expected_receipt = read_json_object(receipt_path)
    validate_contract(mission, project_root / "specs" / "homeostasis-chronos-mission.schema.json", "W4 mission")
    validate_contract(expected_receipt, project_root / "specs" / "homeostasis-chronos-receipt.schema.json", "W4 receipt")
    validate_homeostasis_chronos_mission(mission)
    generated = build_homeostasis_chronos_receipt(mission)
    validate_homeostasis_chronos_receipt(mission, generated)
    if generated != expected_receipt:
        raise RuntimeError("Canonical W4 receipt differs from deterministic replay output.")
    if build_homeostasis_chronos_receipt(copy.deepcopy(mission)) != generated:
        raise RuntimeError("W4 API replay is not deterministic.")
    if not validate_cli(project_root, mission_path, generated):
        raise RuntimeError("W4 CLI replay differs from API replay.")

    mission_mutations: tuple[tuple[str, Mutation], ...] = (
        ("live origin", lambda value: value.__setitem__("origin", "live")),
        ("execution outcome", lambda value: value.__setitem__("maximum_outcome", "execution")),
        ("source substitution", lambda value: value.__setitem__("source_settlement_digest", "sha256:" + "0" * 64)),
        ("inverted issuance", lambda value: value.__setitem__("issued_at", "2026-07-16T12:30:00Z")),
        ("expired mission", lambda value: value.__setitem__("expires_at", "2026-07-16T12:00:00Z")),
        ("missing resource", lambda value: cast(JsonObject, value["resource_budget"]).pop("cpu")),
        ("extra resource", lambda value: cast(JsonObject, value["resource_budget"]).__setitem__("gpu", 1)),
        ("negative resource", lambda value: cast(JsonObject, value["resource_budget"]).__setitem__("cpu", -1)),
        ("fractional resource", lambda value: cast(JsonObject, value["resource_budget"]).__setitem__("cpu", 1.5)),
        ("weight drift", lambda value: cast(JsonObject, value["priority_weights"]).__setitem__("information_gain", 0.5)),
        ("weight omission", lambda value: cast(JsonObject, value["priority_weights"]).pop("risk_reduction")),
        ("signal omission", lambda value: cast(list[JsonObject], value["signals"]).pop()),
        ("signal reorder", lambda value: cast(list[JsonObject], value["signals"]).reverse()),
        ("signal substitution", lambda value: set_signal(value, 0, "signal", "unknown")),
        ("signal underflow", lambda value: set_signal(value, 0, "observed", -0.1)),
        ("signal overflow", lambda value: set_signal(value, 0, "threshold", 1.1)),
        ("confidence omission", lambda value: cast(JsonObject, value["confidence_vector"]).pop("verification")),
        ("confidence overflow", lambda value: cast(JsonObject, value["confidence_vector"]).__setitem__("understanding", 1.1)),
        ("clock omission", lambda value: cast(list[JsonObject], value["chronos_policy"]).pop()),
        ("clock reorder", lambda value: cast(list[JsonObject], value["chronos_policy"]).reverse()),
        ("clock substitution", lambda value: set_clock(value, 0, "clock", "wall_clock")),
        ("zero freshness", lambda value: set_clock(value, 0, "freshness_ms", 0)),
        ("inverted clock", lambda value: set_clock(value, 0, "expiry_ms", 100)),
        ("too few work items", lambda value: value.__setitem__("work_items", cast(list[JsonObject], value["work_items"])[:4])),
        ("duplicate work identity", lambda value: set_work(value, 1, "work_id", cast(list[JsonObject], value["work_items"])[0]["work_id"])),
        ("unknown work clock", lambda value: set_work(value, 0, "clock", "wall_clock")),
        ("future evidence", lambda value: set_work(value, 0, "observed_at", "2026-07-16T12:00:01Z")),
        ("work resource omission", lambda value: cast(JsonObject, cast(list[JsonObject], value["work_items"])[0]["costs"]).pop("cpu")),
        ("negative work cost", lambda value: cast(JsonObject, cast(list[JsonObject], value["work_items"])[0]["costs"]).__setitem__("cpu", -1)),
        ("unknown response signal", lambda value: set_work(value, 0, "responds_to", ["unknown"])),
        ("duplicate response signal", lambda value: set_work(value, 0, "responds_to", ["sensor_health", "sensor_health"])),
        ("empty response signals", lambda value: set_work(value, 0, "responds_to", [])),
        ("authorize", lambda value: cast(JsonObject, value["authority"]).__setitem__("can_authorize", True)),
        ("execute", lambda value: cast(JsonObject, value["authority"]).__setitem__("can_execute", True)),
        ("change policy", lambda value: cast(JsonObject, value["authority"]).__setitem__("can_change_policy", True)),
        ("contact targets", lambda value: cast(JsonObject, value["authority"]).__setitem__("can_contact_targets", True)),
        ("use credentials", lambda value: cast(JsonObject, value["authority"]).__setitem__("can_use_credentials", True)),
        ("self verify", lambda value: cast(JsonObject, value["authority"]).__setitem__("can_self_verify", True)),
        ("promote", lambda value: cast(JsonObject, value["authority"]).__setitem__("can_promote", True)),
        ("modify constitution", lambda value: cast(JsonObject, value["authority"]).__setitem__("can_modify_constitution", True)),
    )
    negative_count = 0
    for label, mutation in mission_mutations:
        expect_error(label, mission_case(mission, mutation))
        negative_count += 1

    receipt_mutations: tuple[tuple[str, Mutation], ...] = (
        ("receipt digest tamper", lambda value: value.__setitem__("receipt_digest", "sha256:" + "0" * 64)),
        ("receipt version", lambda value: value.__setitem__("receipt_version", "9.0.0")),
        ("mission binding", lambda value: receipt_body(value).__setitem__("mission_digest", "sha256:" + "1" * 64)),
        ("status laundering", lambda value: receipt_body(value).__setitem__("status", "executed")),
        ("origin laundering", lambda value: receipt_body(value).__setitem__("origin", "live")),
        ("signal omission", lambda value: cast(list[JsonObject], receipt_body(value)["signal_assessments"]).pop()),
        ("signal state tamper", lambda value: cast(list[JsonObject], receipt_body(value)["signal_assessments"])[0].__setitem__("state", "healthy")),
        ("clock omission", lambda value: cast(list[JsonObject], receipt_body(value)["chronos_assessments"]).pop()),
        ("expiry laundering", lambda value: cast(list[JsonObject], receipt_body(value)["chronos_assessments"])[4].__setitem__("state", "fresh")),
        ("decision omission", lambda value: cast(list[JsonObject], receipt_body(value)["allocation_decisions"]).pop()),
        ("defer laundering", lambda value: cast(list[JsonObject], receipt_body(value)["allocation_decisions"])[3].__setitem__("action", "scheduled")),
        ("abstention laundering", lambda value: cast(list[JsonObject], receipt_body(value)["allocation_decisions"])[4].__setitem__("action", "scheduled")),
        ("priority tamper", lambda value: cast(list[JsonObject], receipt_body(value)["allocation_decisions"])[0].__setitem__("priority_score", 0.0)),
        ("resource oversubscription", lambda value: cast(JsonObject, cast(JsonObject, receipt_body(value)["resource_ledger"])["verification"]).__setitem__("allocated", 6)),
        ("confidence laundering", lambda value: cast(JsonObject, receipt_body(value)["homeostasis"]).__setitem__("confidence_inflation", 0.0)),
        ("backlog laundering", lambda value: cast(JsonObject, receipt_body(value)["homeostasis"]).__setitem__("verification_backlog", 0.0)),
        ("health laundering", lambda value: cast(JsonObject, receipt_body(value)["homeostasis"]).__setitem__("state", "healthy_bounded")),
        ("execution authority", lambda value: cast(JsonObject, receipt_body(value)["authority"]).__setitem__("can_execute", True)),
        ("promotion authority", lambda value: cast(JsonObject, receipt_body(value)["authority"]).__setitem__("can_promote", True)),
        ("security claim substitution", lambda value: receipt_body(value).__setitem__("security_claim", "production safe")),
    )
    for label, mutation in receipt_mutations:
        expect_error(label, receipt_case(mission, generated, mutation))
        negative_count += 1

    body = receipt_body(generated)
    health = cast(JsonObject, body["homeostasis"])
    decisions = cast(list[JsonObject], body["allocation_decisions"])
    clocks = cast(list[JsonObject], body["chronos_assessments"])
    return {
        "status": "CACIS_W4_HOMEOSTASIS_CHRONOS_REPLAY_VALID_SCHEDULE_PROPOSAL_ONLY",
        "origin": "replayed",
        "mission_digest": body["mission_digest"],
        "receipt_digest": generated["receipt_digest"],
        "resource_type_count": len(RESOURCE_TYPES),
        "signal_count": len(SIGNAL_TYPES),
        "clock_count": len(CLOCK_TYPES),
        "work_item_count": len(decisions),
        "breach_count": health["breach_count"],
        "scheduled_count": health["scheduled_count"],
        "deferred_count": health["deferred_count"],
        "abstained_count": health["abstained_count"],
        "stale_count": sum(item["state"] == "stale" for item in clocks),
        "expired_count": sum(item["state"] == "expired" for item in clocks),
        "resource_backpressure_verified": any(item["reason"] == "resource_backpressure" for item in decisions),
        "confidence_inflation_verified": health["confidence_inflation"] == 0.72,
        "verification_backlog_preserved": health["verification_backlog"] == 0.8,
        "chronos_abstention_verified": all(item["action"] == "abstained" for item in decisions if item["clock_state"] == "expired"),
        "deterministic_api_replay_verified": True,
        "deterministic_cli_replay_verified": True,
        "negative_fail_closed_case_count": negative_count,
        "independent_verification_performed": False,
        "live_sensing_performed": False,
        "execution_authorized": False,
        "execution_performed": False,
        "target_contact_performed": False,
        "production_control_claimed": False,
    }


def main() -> None:
    project_root = Path(__file__).resolve().parents[1]
    result = validate_homeostasis_wave(project_root)
    report_path = project_root / "reports" / "CACIS_HOMEOSTASIS_CHRONOS_VALIDATION.json"
    report_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
