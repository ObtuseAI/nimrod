"""Independent structural and causal verifier for World Model intake candidates."""

from __future__ import annotations

from typing import cast

from nimrod_cacis.world_intake import SOURCE_DOMAINS, validate_cursor_state, validate_world_intake_candidate
from nimrod_cacis.world_model import require_object, require_object_list, require_string, validate_world_model_generation
from nimrod_edge.continuous_observation import SOURCE_CHANNELS, validate_continuous_observation
from nimrod_simulator.errors import WorldIntakeError
from nimrod_simulator.jsonio import sha256_digest
from nimrod_simulator.model import JsonObject


VERIFIED_CLAIMS: tuple[str, ...] = (
    "source_session_digest_bound",
    "previous_cursor_digest_bound",
    "previous_generation_digest_bound",
    "source_record_monotonicity_recomputed",
    "replay_deduplication_recomputed",
    "gap_evidence_recomputed",
    "typed_health_observations_bound",
    "scenario_observations_bound",
    "successor_generation_bound",
    "cursor_generation_atomicity_recoverable",
    "non_authorizing_boundary_preserved",
)


def _source_map(value: object, label: str) -> dict[str, JsonObject]:
    return {
        require_string(item.get("source_id"), f"{label}.source_id"): item
        for item in require_object_list(value, label)
    }


def _verify_source_transitions(
    edge_document: JsonObject,
    previous_cursor: JsonObject,
    transition: JsonObject,
    current_cursor: JsonObject,
) -> None:
    edge_events = require_object_list(edge_document.get("events"), "edge.events")
    edge_sources = _source_map(edge_document.get("sources"), "edge.sources")
    previous_sources = _source_map(previous_cursor.get("sources"), "previous_cursor.sources")
    transition_sources = _source_map(transition.get("sources"), "transition.sources")
    current_sources = _source_map(current_cursor.get("sources"), "current_cursor.sources")
    if tuple(transition_sources) != tuple(SOURCE_CHANNELS) or tuple(current_sources) != tuple(SOURCE_CHANNELS):
        raise WorldIntakeError("World intake verifier found incomplete or reordered source transitions.")
    for source_id in SOURCE_CHANNELS:
        previous_record_id = cast(int | None, previous_sources[source_id].get("last_record_id"))
        source_events = sorted(
            (event for event in edge_events if event.get("source_id") == source_id),
            key=lambda event: int(cast(int, event.get("record_id"))),
        )
        record_ids = [int(cast(int, event.get("record_id"))) for event in source_events]
        accepted = [record_id for record_id in record_ids if previous_record_id is None or record_id > previous_record_id]
        accepted_event_digests = [
            event.get("evidence_digest")
            for event in source_events
            if int(cast(int, event.get("record_id"))) in accepted
        ]
        replayed_count = len(record_ids) - len(accepted)
        expected_current = max(accepted, default=previous_record_id)
        row = transition_sources[source_id]
        if row.get("previous_record_id") != previous_record_id:
            raise WorldIntakeError(f"World intake verifier found a substituted prior cursor: source_id={source_id!r}.")
        if row.get("accepted_record_ids") != accepted or row.get("accepted_event_count") != len(accepted):
            raise WorldIntakeError(f"World intake verifier found invalid accepted records: source_id={source_id!r}.")
        if row.get("accepted_event_digests") != accepted_event_digests:
            raise WorldIntakeError(f"World intake verifier found substituted event evidence: source_id={source_id!r}.")
        if row.get("replayed_event_count") != replayed_count or row.get("current_record_id") != expected_current:
            raise WorldIntakeError(f"World intake verifier found invalid deduplication counts: source_id={source_id!r}.")
        source_status = row.get("source_status")
        if source_status != edge_sources[source_id].get("status"):
            raise WorldIntakeError(f"World intake verifier found a substituted sensor-health state: source_id={source_id!r}.")
        if source_status != "observed":
            expected_continuity = source_status
            expected_missing = 0
        elif previous_record_id is None:
            expected_continuity = "baseline_established" if accepted else "empty_baseline"
            expected_missing = 0
        elif not accepted:
            expected_continuity = "no_new_events"
            expected_missing = 0
        else:
            ordered_points = [previous_record_id, *accepted]
            expected_missing = sum(
                max(current_record_id - prior_record_id - 1, 0)
                for prior_record_id, current_record_id in zip(ordered_points, ordered_points[1:])
            )
            expected_continuity = "gap_detected" if expected_missing else "contiguous"
        if row.get("continuity") != expected_continuity or row.get("missing_record_count") != expected_missing:
            raise WorldIntakeError(f"World intake verifier found invalid gap evidence: source_id={source_id!r}.")
        current = current_sources[source_id]
        if current.get("last_record_id") != expected_current or current.get("last_source_status") != source_status:
            raise WorldIntakeError(f"World intake verifier found an invalid resulting cursor: source_id={source_id!r}.")


def _verify_typed_observations(candidate: JsonObject, transition: JsonObject) -> None:
    scenario = require_object(candidate.get("scenario"), "candidate.scenario")
    observations = require_object_list(scenario.get("observations"), "scenario.observations")
    transition_sources = _source_map(transition.get("sources"), "transition.sources")
    expected_values: dict[tuple[str, str], str] = {}
    for source_id, row in transition_sources.items():
        expected_values[(source_id, "health")] = require_string(row.get("source_status"), "source_status")
        expected_values[(source_id, "continuity")] = require_string(row.get("continuity"), "continuity")
        expected_values[(source_id, "new_event_count")] = str(row.get("accepted_event_count"))
    received: dict[tuple[str, str], str] = {}
    for observation in observations:
        subject = require_object(observation.get("subject"), "observation.subject")
        source_id = require_string(subject.get("subject_id"), "observation.subject_id").removeprefix("sensor:")
        fact_key = require_string(observation.get("fact_key"), "observation.fact_key")
        metric = fact_key.rsplit(".", 1)[-1]
        assertion = require_object(observation.get("assertion"), "observation.assertion")
        value = require_string(assertion.get("value"), "observation.assertion.value")
        if observation.get("domain") != SOURCE_DOMAINS.get(source_id):
            raise WorldIntakeError(f"World intake verifier found a domain-substituted observation: source_id={source_id!r}.")
        received[(source_id, metric)] = value
    if received != expected_values:
        raise WorldIntakeError("World intake verifier found missing, duplicated, or substituted typed sensor observations.")


def build_world_intake_verification(
    edge_document: JsonObject,
    previous_cursor: JsonObject,
    previous_generation: JsonObject,
    candidate: JsonObject,
) -> JsonObject:
    validate_continuous_observation(edge_document)
    validate_cursor_state(previous_cursor)
    validate_world_model_generation(previous_generation)
    validate_world_intake_candidate(candidate)
    if edge_document.get("origin") != "replayed":
        raise WorldIntakeError("World intake verifier rejects live-origin admission in the replay-only wave.")
    if candidate.get("source_session_digest") != sha256_digest(edge_document):
        raise WorldIntakeError("World intake verifier source-session digest is invalid.")
    if candidate.get("previous_cursor_digest") != sha256_digest(previous_cursor):
        raise WorldIntakeError("World intake verifier previous-cursor digest is invalid.")
    transition_document = require_object(candidate.get("cursor_transition"), "candidate.cursor_transition")
    transition = require_object(transition_document.get("transition"), "cursor_transition.transition")
    previous_generation_digest = previous_generation.get("generation_digest")
    if transition.get("previous_generation_digest") != previous_generation_digest:
        raise WorldIntakeError("World intake verifier predecessor generation was substituted.")
    if previous_cursor.get("world_generation_digest") != previous_generation_digest:
        raise WorldIntakeError("World intake verifier predecessor cursor and generation are inconsistent.")
    current_cursor = require_object(candidate.get("current_cursor"), "candidate.current_cursor")
    expected_sequence = int(cast(int, previous_cursor.get("transition_sequence"))) + 1
    if transition.get("transition_sequence") != expected_sequence or current_cursor.get("transition_sequence") != expected_sequence:
        raise WorldIntakeError("World intake verifier transition sequence is invalid.")
    if transition.get("prior_active_transition_digest") != previous_cursor.get("active_transition_digest"):
        raise WorldIntakeError("World intake verifier active cursor lineage is invalid.")
    _verify_source_transitions(edge_document, previous_cursor, transition, current_cursor)
    _verify_typed_observations(candidate, transition)
    scenario = require_object(candidate.get("scenario"), "candidate.scenario")
    generation_document = require_object(candidate.get("generation"), "candidate.generation")
    generation = require_object(generation_document.get("generation"), "candidate.generation.generation")
    expected_observation_digests = [sha256_digest(item) for item in require_object_list(scenario.get("observations"), "scenario.observations")]
    if generation.get("observation_digests") != expected_observation_digests:
        raise WorldIntakeError("World intake verifier generation observation binding is invalid.")
    if generation.get("previous_generation_digest") != previous_generation_digest:
        raise WorldIntakeError("World intake verifier successor generation link is invalid.")
    if candidate.get("authority") != {
        "can_authorize": False,
        "can_execute": False,
        "can_change_policy": False,
        "can_contact_targets": False,
        "policy_input_ready": False,
    }:
        raise WorldIntakeError("World intake verifier found widened authority.")
    return {
        "verification_version": "0.1.0",
        "status": "causal_replay_verified",
        "scope": "continuous_observation_to_world_generation",
        "read_only": True,
        "separate_process": True,
        "production_independence_verified": False,
        "verified_claims": list(VERIFIED_CLAIMS),
        "limitations": [
            "replayed continuous observation only; live sensor admission remains blocked",
            "separate process used; separately administered OS identity or host remains unproven",
        ],
        "authority": {
            "can_authorize": False,
            "can_execute": False,
            "can_change_policy": False,
            "can_claim_truth": False,
        },
    }
