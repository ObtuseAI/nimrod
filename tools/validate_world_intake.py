"""Validate replay-safe continuous-observation intake into immutable World Model generations."""

from __future__ import annotations

import copy
import json
import tempfile
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import cast

from nimrod_cacis.world_intake import (
    build_empty_cursor_state,
    build_world_intake_candidate,
    commit_world_intake_store,
    finalize_prepared_cursor_recovery,
    prepare_world_intake_store,
    recover_cursor_store,
    recover_world_intake_store,
    validate_world_intake_candidate,
)
from nimrod_cacis.world_intake_cli import run_world_intake
from nimrod_cacis.world_intake_process import run_world_intake_verification
from nimrod_cacis.world_intake_verifier import build_world_intake_verification
from nimrod_cacis.world_model import (
    build_world_model_generation,
    commit_world_model_store,
    digest_filename,
    prepare_world_model_store,
    read_json_document,
)
from nimrod_edge.continuous_observation import SOURCE_CHANNELS, EventSummary, SourceRead, collect_continuous_observation
from nimrod_simulator.errors import WorldIntakeError, WorldModelError
from nimrod_simulator.jsonio import canonical_json_bytes, read_json_object, sha256_digest
from nimrod_simulator.model import JsonObject


def require_condition(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def expect_error(operation: Callable[[], object], label: str) -> None:
    try:
        operation()
    except (WorldIntakeError, WorldModelError):
        return
    raise RuntimeError(f"Expected fail-closed World Model intake error for {label}.")


def event(source_id: str, record_id: int, observed_at: str) -> EventSummary:
    event_id = 4104 if source_id == "powershell_operational" else 22
    return {
        "source_id": source_id,
        "channel": SOURCE_CHANNELS[source_id],
        "provider_digest": "sha256:" + "1" * 64,
        "event_id": event_id,
        "record_id": record_id,
        "observed_at": observed_at,
        "evidence_digest": "sha256:" + f"{record_id + len(source_id):064x}",
    }


def session_reader(source_events: dict[str, list[EventSummary]]) -> Callable[[str, int], SourceRead]:
    def read(source_id: str, maximum_events: int) -> SourceRead:
        require_condition(maximum_events == 8, "World intake replay reader received the wrong event bound.")
        if source_id == "sysmon_operational":
            return {"status": "unavailable", "events": [], "error_digest": "sha256:" + "9" * 64}
        return {"status": "observed", "events": source_events[source_id], "error_digest": None}

    return read


def build_session(started_at: datetime, source_events: dict[str, list[EventSummary]]) -> JsonObject:
    return collect_continuous_observation(
        tuple(SOURCE_CHANNELS),
        1,
        0.0,
        8,
        started_at,
        session_reader(source_events),
        lambda delay_seconds: None,
        "replayed",
    )


def refresh_transition(candidate: JsonObject) -> None:
    transition_document = cast(JsonObject, candidate["cursor_transition"])
    transition = cast(JsonObject, transition_document["transition"])
    transition_digest = sha256_digest(transition)
    transition_document["transition_digest"] = transition_digest
    cast(JsonObject, candidate["current_cursor"])["active_transition_digest"] = transition_digest


def rebuild_generation(candidate: JsonObject) -> None:
    generation = build_world_model_generation(cast(JsonObject, candidate["scenario"]))
    candidate["generation"] = generation
    transition = cast(JsonObject, cast(JsonObject, candidate["cursor_transition"])["transition"])
    transition["candidate_generation_digest"] = generation["generation_digest"]
    cast(JsonObject, candidate["current_cursor"])["world_generation_digest"] = generation["generation_digest"]
    refresh_transition(candidate)


def validate_world_intake(project_root: Path) -> JsonObject:
    baseline_scenario = read_json_object(project_root / "tests" / "fixtures" / "cacis" / "world-model-replay-credential-theft.json")
    baseline_generation = build_world_model_generation(baseline_scenario)
    baseline_digest = cast(str, baseline_generation["generation_digest"])
    empty_cursor = build_empty_cursor_state(baseline_digest)
    first_session = build_session(
        datetime(2026, 7, 16, 9, 0, 0, tzinfo=timezone.utc),
        {
            "powershell_operational": [event("powershell_operational", 10, "2026-07-16T09:00:01Z")],
            "sysmon_operational": [],
            "dns_client_operational": [event("dns_client_operational", 30, "2026-07-16T09:00:02Z")],
        },
    )
    second_session = build_session(
        datetime(2026, 7, 16, 9, 1, 0, tzinfo=timezone.utc),
        {
            "powershell_operational": [
                event("powershell_operational", 10, "2026-07-16T09:00:01Z"),
                event("powershell_operational", 11, "2026-07-16T09:01:01Z"),
                event("powershell_operational", 13, "2026-07-16T09:01:03Z"),
            ],
            "sysmon_operational": [],
            "dns_client_operational": [
                event("dns_client_operational", 30, "2026-07-16T09:00:02Z"),
                event("dns_client_operational", 31, "2026-07-16T09:01:02Z"),
            ],
        },
    )

    with tempfile.TemporaryDirectory(prefix="nimrod-world-intake-") as temporary:
        root = Path(temporary)
        store_root = root / "store"
        prepare_world_model_store(store_root, baseline_scenario, baseline_generation)
        commit_world_model_store(store_root, baseline_digest)
        edge_path = root / "edge.json"
        cursor_path = root / "cursor.json"
        generation_path = root / "previous-generation.json"
        receipt_path = root / "receipt.json"
        edge_path.write_bytes(canonical_json_bytes(first_session) + b"\n")
        cursor_path.write_bytes(canonical_json_bytes(empty_cursor) + b"\n")
        generation_path.write_bytes(canonical_json_bytes(baseline_generation) + b"\n")
        first_receipt = run_world_intake(
            project_root,
            edge_path,
            cursor_path,
            generation_path,
            store_root,
            receipt_path,
        )
        require_condition(read_json_object(receipt_path) == first_receipt, "World intake CLI receipt is not canonical.")
        first_generation_digest = cast(str, first_receipt["generation_digest"])
        first_generation = read_json_document(
            store_root / "generations" / digest_filename(first_generation_digest),
            "first intake generation",
        )
        active_cursor_head = read_json_document(store_root / "CURSOR.json", "active cursor head")
        first_cursor = cast(JsonObject, active_cursor_head["cursor"])
        second_candidate = build_world_intake_candidate(second_session, first_cursor, first_generation)
        second_verification = run_world_intake_verification(
            project_root,
            second_session,
            first_cursor,
            first_generation,
            second_candidate,
        )
        require_condition(second_verification["status"] == "causal_replay_verified", "Separate verifier rejected valid intake.")
        prepare_world_intake_store(store_root, second_candidate)
        second_generation_digest = cast(str, cast(JsonObject, second_candidate["generation"])["generation_digest"])
        commit_world_model_store(store_root, second_generation_digest)
        interrupted = recover_world_intake_store(store_root)
        require_condition(
            interrupted["status"] == "world_advanced_cursor_prepared" and interrupted["policy_input_ready"] is False,
            "World-ahead cursor publication crash was not recovered fail-closed.",
        )
        recovered = finalize_prepared_cursor_recovery(store_root)
        require_condition(recovered["status"] == "world_and_cursor_active", "Prepared cursor recovery did not finalize.")
        cursor_recovery = recover_cursor_store(store_root)
        transition_count = int(cast(int, cursor_recovery["transition_file_count"]))
        generation_count = len(list((store_root / "generations").glob("*.json")))

        adversarial_count = 0
        widened = copy.deepcopy(second_candidate)
        widened["authority"]["can_execute"] = True
        expect_error(lambda: validate_world_intake_candidate(widened), "candidate authority widening")
        adversarial_count += 1
        substituted_transition = copy.deepcopy(second_candidate)
        substituted_transition["cursor_transition"]["transition_digest"] = "sha256:" + "0" * 64
        expect_error(lambda: validate_world_intake_candidate(substituted_transition), "transition digest substitution")
        adversarial_count += 1
        wrong_cursor_generation = copy.deepcopy(second_candidate)
        wrong_cursor_generation["current_cursor"]["world_generation_digest"] = baseline_digest
        expect_error(lambda: validate_world_intake_candidate(wrong_cursor_generation), "cursor generation substitution")
        adversarial_count += 1
        wrong_source = copy.deepcopy(second_candidate)
        wrong_source["source_session_digest"] = "sha256:" + "0" * 64
        expect_error(
            lambda: build_world_intake_verification(second_session, first_cursor, first_generation, wrong_source),
            "source session substitution",
        )
        adversarial_count += 1
        wrong_previous_cursor = copy.deepcopy(first_cursor)
        wrong_previous_cursor["sources"][0]["last_record_id"] = 9
        expect_error(
            lambda: build_world_intake_verification(second_session, wrong_previous_cursor, first_generation, second_candidate),
            "previous cursor substitution",
        )
        adversarial_count += 1
        bad_records = copy.deepcopy(second_candidate)
        bad_records["cursor_transition"]["transition"]["sources"][0]["accepted_record_ids"] = [11]
        refresh_transition(bad_records)
        expect_error(
            lambda: build_world_intake_verification(second_session, first_cursor, first_generation, bad_records),
            "accepted record omission",
        )
        adversarial_count += 1
        bad_event_digest = copy.deepcopy(second_candidate)
        bad_event_digest["cursor_transition"]["transition"]["sources"][0]["accepted_event_digests"][0] = "sha256:" + "0" * 64
        refresh_transition(bad_event_digest)
        expect_error(
            lambda: build_world_intake_verification(second_session, first_cursor, first_generation, bad_event_digest),
            "event evidence substitution",
        )
        adversarial_count += 1
        hidden_gap = copy.deepcopy(second_candidate)
        hidden_gap["cursor_transition"]["transition"]["sources"][0]["missing_record_count"] = 0
        hidden_gap["cursor_transition"]["transition"]["sources"][0]["continuity"] = "contiguous"
        refresh_transition(hidden_gap)
        expect_error(
            lambda: build_world_intake_verification(second_session, first_cursor, first_generation, hidden_gap),
            "gap evidence suppression",
        )
        adversarial_count += 1
        false_health = copy.deepcopy(second_candidate)
        false_health["cursor_transition"]["transition"]["sources"][1]["source_status"] = "observed"
        refresh_transition(false_health)
        expect_error(
            lambda: build_world_intake_verification(second_session, first_cursor, first_generation, false_health),
            "sensor health laundering",
        )
        adversarial_count += 1
        typed_value = copy.deepcopy(second_candidate)
        typed_value["scenario"]["observations"][0]["assertion"]["value"] = "healthy"
        rebuild_generation(typed_value)
        expect_error(
            lambda: build_world_intake_verification(second_session, first_cursor, first_generation, typed_value),
            "typed observation substitution",
        )
        adversarial_count += 1
        live_origin = copy.deepcopy(second_session)
        live_origin["origin"] = "live"
        expect_error(
            lambda: build_world_intake_verification(live_origin, first_cursor, first_generation, second_candidate),
            "live-origin admission",
        )
        adversarial_count += 1
        bad_sequence = copy.deepcopy(second_candidate)
        bad_sequence["cursor_transition"]["transition"]["transition_sequence"] = 9
        refresh_transition(bad_sequence)
        expect_error(
            lambda: build_world_intake_verification(second_session, first_cursor, first_generation, bad_sequence),
            "cursor sequence jump",
        )
        adversarial_count += 1
        cursor_path_to_tamper = store_root / "CURSOR.json"
        original_cursor_bytes = cursor_path_to_tamper.read_bytes()
        cursor_path_to_tamper.write_text("{}\n", encoding="utf-8", newline="\n")
        expect_error(lambda: recover_cursor_store(store_root), "active cursor tamper")
        cursor_path_to_tamper.write_bytes(original_cursor_bytes)
        adversarial_count += 1
        escaped_cursor_head = read_json_document(cursor_path_to_tamper, "active cursor head")
        escaped_cursor_head["transition_path"] = "../cursor-transition.json"
        cursor_path_to_tamper.write_bytes(canonical_json_bytes(escaped_cursor_head) + b"\n")
        expect_error(lambda: recover_cursor_store(store_root), "active cursor path escape")
        cursor_path_to_tamper.write_bytes(original_cursor_bytes)
        adversarial_count += 1
        world_head_path = store_root / "HEAD.json"
        original_world_head_bytes = world_head_path.read_bytes()
        escaped_world_head = read_json_document(world_head_path, "active world head")
        escaped_world_head["generation_path"] = "../generation.json"
        world_head_path.write_bytes(canonical_json_bytes(escaped_world_head) + b"\n")
        expect_error(lambda: recover_world_intake_store(store_root), "active generation path escape")
        world_head_path.write_bytes(original_world_head_bytes)
        adversarial_count += 1

    with tempfile.TemporaryDirectory(prefix="nimrod-world-intake-stale-") as temporary:
        stale_store = Path(temporary)
        prepare_world_model_store(stale_store, baseline_scenario, baseline_generation)
        commit_world_model_store(stale_store, baseline_digest)
        first_candidate = build_world_intake_candidate(first_session, empty_cursor, baseline_generation)
        prepare_world_intake_store(stale_store, first_candidate)
        commit_world_intake_store(stale_store, first_candidate)
        stale_candidate = build_world_intake_candidate(second_session, empty_cursor, baseline_generation)
        prepare_world_intake_store(stale_store, stale_candidate)
        expect_error(
            lambda: commit_world_model_store(
                stale_store,
                cast(str, cast(JsonObject, stale_candidate["generation"])["generation_digest"]),
            ),
            "stale predecessor commit",
        )
        adversarial_count += 1

    transition_rows = cast(
        list[JsonObject],
        cast(JsonObject, cast(JsonObject, second_candidate["cursor_transition"])["transition"])["sources"],
    )
    return {
        "status": "CACIS_WORLD_INTAKE_SUCCESSION_REPLAY_VALID_POLICY_AND_ACTION_BLOCKED",
        "origin": "replayed",
        "world_generation_count": generation_count,
        "cursor_transition_count": transition_count,
        "source_count": len(SOURCE_CHANNELS),
        "typed_observation_count_per_generation": len(cast(JsonObject, second_candidate["scenario"])["observations"]),
        "replayed_event_deduplication_count": sum(int(cast(int, row["replayed_event_count"])) for row in transition_rows),
        "gap_source_count": len([row for row in transition_rows if row["continuity"] == "gap_detected"]),
        "missing_record_count": sum(int(cast(int, row["missing_record_count"])) for row in transition_rows),
        "separate_process_causal_verification_performed": True,
        "production_verifier_independence_verified": False,
        "world_ahead_cursor_crash_recovery_verified": True,
        "immutable_successor_generation_verified": True,
        "negative_fail_closed_case_count": adversarial_count,
        "live_sensor_admission_performed": False,
        "raw_event_payload_retained": False,
        "policy_input_ready": False,
        "execution_authorized": False,
        "execution_performed": False,
        "target_contact_performed": False,
    }


def main() -> None:
    project_root = Path(__file__).resolve().parents[1]
    result = validate_world_intake(project_root)
    report_path = project_root / "reports" / "CACIS_WORLD_INTAKE_VALIDATION.json"
    report_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
