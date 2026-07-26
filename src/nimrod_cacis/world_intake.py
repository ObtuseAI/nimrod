"""Replay-safe continuous-observation intake for immutable CACIS World Model generations."""

from __future__ import annotations

import os
import uuid
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import cast

from nimrod_cacis.world_model import (
    DOMAINS,
    build_world_model_generation,
    commit_world_model_store,
    digest_filename,
    prepare_world_model_store,
    read_json_document,
    recover_world_model_store,
    require_object,
    require_object_list,
    require_string,
    validate_world_model_generation,
    write_immutable_json,
)
from nimrod_edge.continuous_observation import SOURCE_CHANNELS, validate_continuous_observation
from nimrod_simulator.errors import WorldIntakeError
from nimrod_simulator.jsonio import sha256_digest
from nimrod_simulator.model import JsonObject


INTAKE_NAMESPACE = uuid.UUID("db302d51-8854-5631-99d4-8fb5367c3467")
SOURCE_DOMAINS: Mapping[str, str] = {
    "powershell_operational": "endpoint",
    "sysmon_operational": "endpoint",
    "dns_client_operational": "network",
}
SOURCE_KINDS: Mapping[str, str] = {
    "powershell_operational": "endpoint_sensor",
    "sysmon_operational": "endpoint_sensor",
    "dns_client_operational": "network_sensor",
}
AUTHORITY: Mapping[str, bool] = {
    "can_authorize": False,
    "can_execute": False,
    "can_change_policy": False,
    "can_contact_targets": False,
    "policy_input_ready": False,
}


def _parse_timestamp(value: object, label: str) -> datetime:
    text = require_string(value, label)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as error:
        raise WorldIntakeError(f"CACIS World Model intake timestamp is invalid: label={label!r}, value={text!r}.") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise WorldIntakeError(f"CACIS World Model intake timestamp lacks an offset: label={label!r}.")
    return parsed.astimezone(timezone.utc)


def _format_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def build_empty_cursor_state(previous_generation_digest: str) -> JsonObject:
    digest_filename(previous_generation_digest)
    return {
        "cursor_version": "0.1.0",
        "transition_sequence": 0,
        "active_transition_digest": None,
        "world_generation_digest": previous_generation_digest,
        "sources": [
            {
                "source_id": source_id,
                "last_record_id": None,
                "last_observed_at": None,
                "last_source_status": "unseen",
            }
            for source_id in SOURCE_CHANNELS
        ],
        "authority": dict(AUTHORITY),
    }


def validate_cursor_state(cursor: JsonObject) -> None:
    expected_fields = {
        "cursor_version",
        "transition_sequence",
        "active_transition_digest",
        "world_generation_digest",
        "sources",
        "authority",
    }
    if set(cursor) != expected_fields or cursor.get("cursor_version") != "0.1.0":
        raise WorldIntakeError("CACIS World Model cursor fields or version are invalid.")
    if cursor.get("authority") != AUTHORITY:
        raise WorldIntakeError("CACIS World Model cursor widened authority.")
    sequence = cursor.get("transition_sequence")
    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 0:
        raise WorldIntakeError("CACIS World Model cursor sequence must be a non-negative integer.")
    active_transition_digest = cursor.get("active_transition_digest")
    if active_transition_digest is not None:
        digest_filename(require_string(active_transition_digest, "cursor.active_transition_digest"))
    digest_filename(require_string(cursor.get("world_generation_digest"), "cursor.world_generation_digest"))
    sources = require_object_list(cursor.get("sources"), "cursor.sources")
    if tuple(source.get("source_id") for source in sources) != tuple(SOURCE_CHANNELS):
        raise WorldIntakeError("CACIS World Model cursor source order or coverage is invalid.")
    for source in sources:
        if set(source) != {"source_id", "last_record_id", "last_observed_at", "last_source_status"}:
            raise WorldIntakeError("CACIS World Model cursor source fields are invalid.")
        record_id = source.get("last_record_id")
        if record_id is not None and (not isinstance(record_id, int) or isinstance(record_id, bool) or record_id < 0):
            raise WorldIntakeError("CACIS World Model cursor record identifier is invalid.")
        observed_at = source.get("last_observed_at")
        if observed_at is not None:
            _parse_timestamp(observed_at, "cursor.sources.last_observed_at")


def _indexed_cursor_sources(cursor: JsonObject) -> dict[str, JsonObject]:
    validate_cursor_state(cursor)
    return {
        require_string(source.get("source_id"), "cursor source_id"): source
        for source in require_object_list(cursor.get("sources"), "cursor.sources")
    }


def _source_transition_rows(edge_document: JsonObject, cursor: JsonObject) -> tuple[JsonObject, ...]:
    validate_continuous_observation(edge_document)
    if edge_document.get("origin") != "replayed":
        raise WorldIntakeError("CACIS World Model intake admits replayed continuous evidence only in this wave.")
    cursor_sources = _indexed_cursor_sources(cursor)
    events = require_object_list(edge_document.get("events"), "continuous observation.events")
    source_states = {
        require_string(source.get("source_id"), "continuous observation source_id"): source
        for source in require_object_list(edge_document.get("sources"), "continuous observation.sources")
    }
    rows: list[JsonObject] = []
    for source_id in SOURCE_CHANNELS:
        prior = cursor_sources[source_id]
        prior_record_id = cast(int | None, prior.get("last_record_id"))
        source_events = sorted(
            (event for event in events if event.get("source_id") == source_id),
            key=lambda event: int(cast(int, event.get("record_id"))),
        )
        accepted = [
            event
            for event in source_events
            if prior_record_id is None or int(cast(int, event.get("record_id"))) > prior_record_id
        ]
        replayed_count = len(source_events) - len(accepted)
        accepted_record_ids = [int(cast(int, event.get("record_id"))) for event in accepted]
        current_record_id = max(accepted_record_ids, default=prior_record_id)
        source_status = require_string(source_states[source_id].get("status"), "continuous observation source status")
        if source_status != "observed":
            continuity = source_status
            missing_record_count = 0
        elif prior_record_id is None:
            continuity = "baseline_established" if accepted else "empty_baseline"
            missing_record_count = 0
        elif not accepted:
            continuity = "no_new_events"
            missing_record_count = 0
        else:
            ordered_points = [prior_record_id, *accepted_record_ids]
            missing_record_count = sum(
                max(current_record_id - previous_record_id - 1, 0)
                for previous_record_id, current_record_id in zip(ordered_points, ordered_points[1:])
            )
            continuity = "gap_detected" if missing_record_count else "contiguous"
        last_observed_at = (
            max((require_string(event.get("observed_at"), "event.observed_at") for event in accepted), default=None)
            or prior.get("last_observed_at")
        )
        rows.append(
            {
                "source_id": source_id,
                "source_status": source_status,
                "previous_record_id": prior_record_id,
                "current_record_id": current_record_id,
                "accepted_record_ids": accepted_record_ids,
                "accepted_event_digests": [event.get("evidence_digest") for event in accepted],
                "accepted_event_count": len(accepted),
                "replayed_event_count": replayed_count,
                "continuity": continuity,
                "missing_record_count": missing_record_count,
                "last_observed_at": last_observed_at,
            }
        )
    return tuple(rows)


def _requirements(rows: Sequence[JsonObject]) -> list[JsonObject]:
    requirements: list[JsonObject] = []
    for domain in DOMAINS:
        domain_rows = [row for row in rows if SOURCE_DOMAINS[str(row["source_id"])] == domain]
        if not domain_rows:
            requirements.append(
                {
                    "domain": domain,
                    "subject_id": f"telemetry:{domain}",
                    "subject_type": "telemetry_plane",
                    "fact_key": "telemetry.coverage",
                }
            )
            continue
        for row in domain_rows:
            source_id = str(row["source_id"])
            for metric in ("health", "continuity", "new_event_count"):
                requirements.append(
                    {
                        "domain": domain,
                        "subject_id": f"sensor:{source_id}",
                        "subject_type": "windows_event_channel",
                        "fact_key": f"telemetry.{source_id}.{metric}",
                    }
                )
    return requirements


def _observations(edge_document: JsonObject, cursor: JsonObject, rows: Sequence[JsonObject]) -> list[JsonObject]:
    session_digest = sha256_digest(edge_document)
    event_set_digest = require_string(edge_document.get("event_set_digest"), "continuous observation.event_set_digest")
    evidence_refs = sorted({session_digest, event_set_digest})
    previous_cursor_digest = sha256_digest(cursor)
    collected_at = _parse_timestamp(edge_document.get("completed_at"), "continuous observation.completed_at")
    valid_until = _format_timestamp(collected_at + timedelta(minutes=5))
    observations: list[JsonObject] = []
    sequence = 0
    for row in rows:
        source_id = require_string(row.get("source_id"), "source transition.source_id")
        domain = SOURCE_DOMAINS[source_id]
        values = (
            ("health", require_string(row.get("source_status"), "source transition.source_status")),
            ("continuity", require_string(row.get("continuity"), "source transition.continuity")),
            ("new_event_count", str(row.get("accepted_event_count"))),
        )
        for metric, value in values:
            sequence += 1
            observation_name = f"{session_digest}:{source_id}:{metric}"
            observations.append(
                {
                    "observation_version": "0.1.0",
                    "observation_id": str(uuid.uuid5(INTAKE_NAMESPACE, observation_name)),
                    "origin": "replayed",
                    "replay_sequence": sequence,
                    "domain": domain,
                    "subject": {
                        "subject_id": f"sensor:{source_id}",
                        "subject_type": "windows_event_channel",
                    },
                    "fact_key": f"telemetry.{source_id}.{metric}",
                    "assertion": {"posture": "observed", "value": value},
                    "source": {
                        "source_id": f"edge:{source_id}",
                        "source_kind": SOURCE_KINDS[source_id],
                        "artifact_digest": session_digest,
                    },
                    "observed_at": edge_document["completed_at"],
                    "collected_at": edge_document["completed_at"],
                    "valid_until": valid_until,
                    "confidence": 1.0,
                    "evidence_refs": evidence_refs,
                    "parent_event_digest": previous_cursor_digest,
                    "authority": {
                        "can_authorize": False,
                        "can_execute": False,
                        "can_change_policy": False,
                        "can_claim_truth": False,
                    },
                }
            )
    return observations


def build_world_intake_candidate(
    edge_document: JsonObject,
    previous_cursor: JsonObject,
    previous_generation: JsonObject,
) -> JsonObject:
    validate_continuous_observation(edge_document)
    validate_cursor_state(previous_cursor)
    validate_world_model_generation(previous_generation)
    previous_generation_digest = require_string(previous_generation.get("generation_digest"), "previous generation digest")
    if previous_cursor.get("world_generation_digest") != previous_generation_digest:
        raise WorldIntakeError("CACIS World Model cursor is not bound to the active predecessor generation.")
    rows = _source_transition_rows(edge_document, previous_cursor)
    session_digest = sha256_digest(edge_document)
    scenario: JsonObject = {
        "scenario_version": "0.1.0",
        "scenario_id": str(uuid.uuid5(INTAKE_NAMESPACE, f"scenario:{previous_generation_digest}:{session_digest}")),
        "origin": "replayed",
        "title": "Continuous defensive observation World Model intake replay",
        "generated_at": edge_document["completed_at"],
        "previous_generation_digest": previous_generation_digest,
        "requirements": _requirements(rows),
        "observations": _observations(edge_document, previous_cursor, rows),
    }
    generation = build_world_model_generation(scenario)
    generation_digest = require_string(generation.get("generation_digest"), "candidate generation digest")
    previous_cursor_digest = sha256_digest(previous_cursor)
    transition_body: JsonObject = {
        "transition_version": "0.1.0",
        "transition_id": str(uuid.uuid5(INTAKE_NAMESPACE, f"cursor:{previous_cursor_digest}:{session_digest}")),
        "origin": "replayed",
        "transition_sequence": int(cast(int, previous_cursor["transition_sequence"])) + 1,
        "previous_cursor_digest": previous_cursor_digest,
        "prior_active_transition_digest": previous_cursor["active_transition_digest"],
        "previous_generation_digest": previous_generation_digest,
        "candidate_generation_digest": generation_digest,
        "source_session_digest": session_digest,
        "source_event_set_digest": edge_document["event_set_digest"],
        "sources": list(rows),
        "authority": dict(AUTHORITY),
    }
    transition_digest = sha256_digest(transition_body)
    current_cursor: JsonObject = {
        "cursor_version": "0.1.0",
        "transition_sequence": transition_body["transition_sequence"],
        "active_transition_digest": transition_digest,
        "world_generation_digest": generation_digest,
        "sources": [
            {
                "source_id": row["source_id"],
                "last_record_id": row["current_record_id"],
                "last_observed_at": row["last_observed_at"],
                "last_source_status": row["source_status"],
            }
            for row in rows
        ],
        "authority": dict(AUTHORITY),
    }
    validate_cursor_state(current_cursor)
    return {
        "intake_version": "0.1.0",
        "origin": "replayed",
        "source_session_digest": session_digest,
        "previous_cursor_digest": previous_cursor_digest,
        "cursor_transition": {
            "transition_digest": transition_digest,
            "transition": transition_body,
        },
        "current_cursor": current_cursor,
        "scenario": scenario,
        "generation": generation,
        "authority": dict(AUTHORITY),
    }


def validate_world_intake_candidate(candidate: JsonObject) -> None:
    expected_fields = {
        "intake_version",
        "origin",
        "source_session_digest",
        "previous_cursor_digest",
        "cursor_transition",
        "current_cursor",
        "scenario",
        "generation",
        "authority",
    }
    if set(candidate) != expected_fields or candidate.get("intake_version") != "0.1.0" or candidate.get("origin") != "replayed":
        raise WorldIntakeError("CACIS World Model intake candidate fields, version, or origin are invalid.")
    if candidate.get("authority") != AUTHORITY:
        raise WorldIntakeError("CACIS World Model intake candidate widened authority.")
    transition_document = require_object(candidate.get("cursor_transition"), "cursor_transition")
    transition = require_object(transition_document.get("transition"), "cursor_transition.transition")
    if transition_document.get("transition_digest") != sha256_digest(transition):
        raise WorldIntakeError("CACIS World Model cursor transition digest is invalid.")
    if transition.get("authority") != AUTHORITY:
        raise WorldIntakeError("CACIS World Model cursor transition widened authority.")
    if transition.get("previous_cursor_digest") != candidate.get("previous_cursor_digest"):
        raise WorldIntakeError("CACIS World Model intake previous-cursor binding is invalid.")
    if transition.get("source_session_digest") != candidate.get("source_session_digest"):
        raise WorldIntakeError("CACIS World Model intake source-session binding is invalid.")
    scenario = require_object(candidate.get("scenario"), "scenario")
    generation_document = require_object(candidate.get("generation"), "generation")
    validate_world_model_generation(generation_document)
    generation = require_object(generation_document.get("generation"), "generation.generation")
    if generation.get("scenario_digest") != sha256_digest(scenario):
        raise WorldIntakeError("CACIS World Model intake scenario digest is not bound to the generation.")
    if transition.get("candidate_generation_digest") != generation_document.get("generation_digest"):
        raise WorldIntakeError("CACIS World Model cursor transition is not bound to its candidate generation.")
    if transition.get("previous_generation_digest") != generation.get("previous_generation_digest"):
        raise WorldIntakeError("CACIS World Model intake predecessor linkage is inconsistent.")
    current_cursor = require_object(candidate.get("current_cursor"), "current_cursor")
    validate_cursor_state(current_cursor)
    transition_digest = transition_document.get("transition_digest")
    if current_cursor.get("active_transition_digest") != transition_digest:
        raise WorldIntakeError("CACIS World Model current cursor does not bind its transition.")
    if current_cursor.get("world_generation_digest") != generation_document.get("generation_digest"):
        raise WorldIntakeError("CACIS World Model current cursor does not bind its generation.")


def prepare_cursor_transition(store_root: Path, candidate: JsonObject) -> JsonObject:
    validate_world_intake_candidate(candidate)
    transition_document = require_object(candidate["cursor_transition"], "cursor_transition")
    transition_digest = require_string(transition_document["transition_digest"], "transition_digest")
    transition_path = store_root / "cursor-transitions" / digest_filename(transition_digest)
    write_immutable_json(transition_path, transition_document)
    transition = require_object(transition_document["transition"], "cursor_transition.transition")
    prepared_head: JsonObject = {
        "cursor_head_version": "0.1.0",
        "transition_digest": transition_digest,
        "transition_path": transition_path.relative_to(store_root).as_posix(),
        "previous_cursor_digest": transition["previous_cursor_digest"],
        "prior_active_transition_digest": transition["prior_active_transition_digest"],
        "world_generation_digest": transition["candidate_generation_digest"],
        "cursor": candidate["current_cursor"],
    }
    prepared_path = store_root / ("CURSOR." + transition_digest.removeprefix("sha256:") + ".prepared")
    write_immutable_json(prepared_path, prepared_head)
    return prepared_head


def commit_cursor_transition(store_root: Path, transition_digest: str) -> JsonObject:
    prepared_path = store_root / ("CURSOR." + transition_digest.removeprefix("sha256:") + ".prepared")
    active_path = store_root / "CURSOR.json"
    if not prepared_path.exists():
        if active_path.exists():
            active = read_json_document(active_path, "active cursor head")
            if active.get("transition_digest") == transition_digest:
                return active
        raise WorldIntakeError(f"CACIS prepared cursor head is missing: path={prepared_path}.")
    prepared = read_json_document(prepared_path, "prepared cursor head")
    if prepared.get("transition_digest") != transition_digest:
        raise WorldIntakeError("CACIS prepared cursor digest does not match its filename.")
    transition_path = store_root / require_string(prepared.get("transition_path"), "prepared cursor transition_path")
    expected_transition_path = store_root / "cursor-transitions" / digest_filename(transition_digest)
    if transition_path.resolve() != expected_transition_path.resolve():
        raise WorldIntakeError("CACIS prepared cursor transition path is not digest-derived.")
    transition_document = read_json_document(transition_path, "prepared cursor transition")
    transition = require_object(transition_document.get("transition"), "prepared cursor transition")
    if transition_document.get("transition_digest") != sha256_digest(transition):
        raise WorldIntakeError("CACIS prepared cursor transition artifact is invalid.")
    cursor = require_object(prepared.get("cursor"), "prepared cursor")
    validate_cursor_state(cursor)
    expected_head_bindings = {
        "previous_cursor_digest": transition.get("previous_cursor_digest"),
        "prior_active_transition_digest": transition.get("prior_active_transition_digest"),
        "world_generation_digest": transition.get("candidate_generation_digest"),
    }
    for field, expected in expected_head_bindings.items():
        if prepared.get(field) != expected:
            raise WorldIntakeError(f"CACIS prepared cursor head binding is invalid: field={field!r}.")
    if cursor.get("active_transition_digest") != transition_digest or cursor.get("world_generation_digest") != prepared.get(
        "world_generation_digest"
    ):
        raise WorldIntakeError("CACIS prepared cursor state is not bound to its transition and generation.")
    prior_active = prepared.get("prior_active_transition_digest")
    if active_path.exists():
        active = read_json_document(active_path, "active cursor head")
        active_digest = active.get("transition_digest")
        if active_digest == transition_digest:
            prepared_path.unlink()
            return active
        if prior_active != active_digest:
            raise WorldIntakeError("CACIS cursor transition does not extend the active cursor head.")
    elif prior_active is not None:
        raise WorldIntakeError("CACIS cursor transition requires a missing active predecessor.")
    os.replace(prepared_path, active_path)
    return read_json_document(active_path, "active cursor head")


def recover_cursor_store(store_root: Path) -> JsonObject:
    transition_paths = sorted((store_root / "cursor-transitions").glob("*.json")) if (store_root / "cursor-transitions").exists() else []
    for transition_path in transition_paths:
        document = read_json_document(transition_path, "immutable cursor transition")
        transition = require_object(document.get("transition"), "cursor transition")
        digest = require_string(document.get("transition_digest"), "cursor transition digest")
        if digest != sha256_digest(transition) or transition_path.name != digest_filename(digest):
            raise WorldIntakeError(f"CACIS immutable cursor transition is corrupt: path={transition_path}.")
    active_path = store_root / "CURSOR.json"
    prepared_paths = sorted(store_root.glob("CURSOR.*.prepared")) if store_root.exists() else []
    if not active_path.exists():
        return {
            "status": "cursor_prepared_uncommitted" if prepared_paths else "cursor_empty",
            "active_transition_digest": None,
            "world_generation_digest": None,
            "transition_file_count": len(transition_paths),
            "prepared_cursor_count": len(prepared_paths),
        }
    active = read_json_document(active_path, "active cursor head")
    cursor = require_object(active.get("cursor"), "active cursor")
    validate_cursor_state(cursor)
    transition_digest = require_string(active.get("transition_digest"), "active cursor transition_digest")
    transition_path = store_root / require_string(active.get("transition_path"), "active cursor transition_path")
    expected_transition_path = store_root / "cursor-transitions" / digest_filename(transition_digest)
    if transition_path.resolve() != expected_transition_path.resolve() or not transition_path.exists():
        raise WorldIntakeError("CACIS active cursor transition artifact is missing.")
    transition_document = read_json_document(transition_path, "active cursor transition")
    transition = require_object(transition_document.get("transition"), "active cursor transition")
    if transition_document.get("transition_digest") != sha256_digest(transition):
        raise WorldIntakeError("CACIS active cursor transition artifact is corrupt.")
    if cursor.get("active_transition_digest") != transition_digest:
        raise WorldIntakeError("CACIS active cursor head is not bound to its cursor state.")
    if active.get("world_generation_digest") != cursor.get("world_generation_digest"):
        raise WorldIntakeError("CACIS active cursor head is not bound to its World Model generation.")
    return {
        "status": "cursor_active",
        "active_transition_digest": transition_digest,
        "world_generation_digest": cursor["world_generation_digest"],
        "transition_file_count": len(transition_paths),
        "prepared_cursor_count": len(prepared_paths),
    }


def prepare_world_intake_store(store_root: Path, candidate: JsonObject) -> None:
    validate_world_intake_candidate(candidate)
    prepare_world_model_store(
        store_root,
        require_object(candidate["scenario"], "scenario"),
        require_object(candidate["generation"], "generation"),
    )
    prepare_cursor_transition(store_root, candidate)


def commit_world_intake_store(store_root: Path, candidate: JsonObject) -> JsonObject:
    validate_world_intake_candidate(candidate)
    generation_digest = require_string(
        require_object(candidate["generation"], "generation").get("generation_digest"),
        "generation_digest",
    )
    transition_digest = require_string(
        require_object(candidate["cursor_transition"], "cursor_transition").get("transition_digest"),
        "transition_digest",
    )
    commit_world_model_store(store_root, generation_digest)
    commit_cursor_transition(store_root, transition_digest)
    return recover_world_intake_store(store_root)


def recover_world_intake_store(store_root: Path) -> JsonObject:
    world = recover_world_model_store(store_root)
    cursor = recover_cursor_store(store_root)
    world_digest = world.get("active_generation_digest")
    cursor_digest = cursor.get("world_generation_digest")
    if world_digest != cursor_digest and world_digest is not None:
        prepared_paths = sorted(store_root.glob("CURSOR.*.prepared"))
        matching = [
            path
            for path in prepared_paths
            if read_json_document(path, "prepared cursor head").get("world_generation_digest") == world_digest
        ]
        if len(matching) == 1:
            return {
                "status": "world_advanced_cursor_prepared",
                "world_generation_digest": world_digest,
                "cursor_generation_digest": cursor_digest,
                "policy_input_ready": False,
                "execution_authorized": False,
            }
    if world_digest != cursor_digest:
        raise WorldIntakeError(
            "CACIS World Model and cursor heads diverged without one recoverable prepared transition: "
            f"world={world_digest!r}, cursor={cursor_digest!r}."
        )
    return {
        "status": "world_and_cursor_active",
        "world_generation_digest": world_digest,
        "cursor_generation_digest": cursor_digest,
        "policy_input_ready": False,
        "execution_authorized": False,
    }


def finalize_prepared_cursor_recovery(store_root: Path) -> JsonObject:
    recovery = recover_world_intake_store(store_root)
    if recovery.get("status") != "world_advanced_cursor_prepared":
        raise WorldIntakeError(f"CACIS cursor recovery is not required: state={recovery!r}.")
    prepared_paths = sorted(store_root.glob("CURSOR.*.prepared"))
    matching = [
        read_json_document(path, "prepared cursor head")
        for path in prepared_paths
        if read_json_document(path, "prepared cursor head").get("world_generation_digest")
        == recovery.get("world_generation_digest")
    ]
    if len(matching) != 1:
        raise WorldIntakeError("CACIS cursor recovery requires exactly one generation-bound prepared head.")
    transition_digest = require_string(matching[0].get("transition_digest"), "prepared cursor transition_digest")
    commit_cursor_transition(store_root, transition_digest)
    return recover_world_intake_store(store_root)
