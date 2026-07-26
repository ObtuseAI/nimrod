"""Threshold-signed source governance and bounded backpressure for World Model replay intake."""

from __future__ import annotations

import copy
import uuid
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import cast

from nimrod_cacis.world_intake import (
    SOURCE_DOMAINS,
    commit_world_intake_store,
    prepare_world_intake_store,
    validate_world_intake_candidate,
)
from nimrod_edge.continuous_observation import SOURCE_CHANNELS, validate_continuous_observation
from nimrod_simulator.errors import WorldIntakeGovernanceError
from nimrod_simulator.jsonio import sha256_digest
from nimrod_simulator.key_governance import SigningConnector, validate_governance_state
from nimrod_simulator.model import JsonObject, JsonValue
from nimrod_simulator.threshold_signing import sign_threshold_document, verify_threshold_signatures


POLICY_DOMAIN = b"nimrod.world-intake-source-policy.v0.1\x00"
HEALTH_DOMAIN = b"nimrod.world-intake-source-health.v0.1\x00"
DECISION_DOMAIN = b"nimrod.world-intake-governance-decision.v0.1\x00"
GOVERNANCE_NAMESPACE = uuid.UUID("d41777da-ea99-5b31-9eec-6b8612fb1f19")
PURPOSE_ID = "local_defensive_world_model_replay"
AUTHORITY: Mapping[str, bool] = {
    "can_authorize": False,
    "can_execute": False,
    "can_change_policy": False,
    "can_contact_targets": False,
    "can_delete_evidence": False,
    "policy_input_ready": False,
}
VERIFIER_BOUNDARY: Mapping[str, object] = {
    "evidence_origin": "process_observation",
    "separate_process": True,
    "dedicated_os_account_verified": False,
    "separately_administered_host_verified": False,
    "production_independence_verified": False,
}


def _format_timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise WorldIntakeGovernanceError("World intake governance timestamps require a UTC offset.")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_timestamp(value: object, label: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise WorldIntakeGovernanceError(f"World intake governance timestamp is missing: label={label!r}.")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise WorldIntakeGovernanceError(
            f"World intake governance timestamp is invalid: label={label!r}, value={value!r}."
        ) from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise WorldIntakeGovernanceError(f"World intake governance timestamp lacks an offset: label={label!r}.")
    return parsed.astimezone(timezone.utc)


def _require_object(value: object, label: str) -> JsonObject:
    if not isinstance(value, dict):
        raise WorldIntakeGovernanceError(f"World intake governance {label} must be an object.")
    return cast(JsonObject, value)


def _require_object_list(value: object, label: str) -> tuple[JsonObject, ...]:
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise WorldIntakeGovernanceError(f"World intake governance {label} must be a list of objects.")
    return tuple(cast(JsonObject, item) for item in value)


def _require_string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise WorldIntakeGovernanceError(f"World intake governance {label} must be a non-empty string.")
    return value


def _unsigned(document: JsonObject) -> JsonObject:
    return {key: value for key, value in document.items() if key != "signatures"}


def _source_configuration(source_id: str) -> JsonObject:
    configuration: JsonObject = {
        "source_id": source_id,
        "channel": SOURCE_CHANNELS[source_id],
        "world_domain": SOURCE_DOMAINS[source_id],
        "purpose_id": PURPOSE_ID,
        "collector_interface": "wevtutil_query_events_read_only",
        "raw_event_payload_allowed": False,
        "active_probe_allowed": False,
    }
    return {
        **configuration,
        "configuration_digest": sha256_digest(configuration),
        "freshness_limit_seconds": 120,
        "maximum_clock_skew_seconds": 5,
    }


def build_source_policy(
    governance_state: JsonObject,
    connectors: list[SigningConnector],
    issued_at: datetime,
) -> JsonObject:
    validate_governance_state(governance_state)
    issued_text = _format_timestamp(issued_at)
    unsigned: JsonObject = {
        "policy_version": "0.1.0",
        "policy_id": str(uuid.uuid5(GOVERNANCE_NAMESPACE, f"policy:{issued_text}")),
        "origin": "simulated",
        "purpose_id": PURPOSE_ID,
        "governance_state_digest": sha256_digest(governance_state),
        "issued_at": issued_text,
        "not_before": issued_text,
        "expires_at": _format_timestamp(issued_at + timedelta(minutes=10)),
        "sources": [_source_configuration(source_id) for source_id in SOURCE_CHANNELS],
        "retention": {
            "raw_event_payload_retention_seconds": 0,
            "typed_event_metadata_retention_seconds": 86400,
            "maximum_cursor_transition_count": 64,
            "maximum_immutable_generation_count": 64,
            "witnessed_compaction_required_before_deletion": True,
            "automatic_deletion_authorized": False,
        },
        "ingestion_budget": {
            "maximum_events_per_session": 8,
            "maximum_accepted_events_per_transition": 4,
            "maximum_queue_depth": 4,
            "overflow_strategy": "defer_newest",
            "event_drop_allowed": False,
        },
        "live_admission_requirements": [
            "live_threshold_signed_source_health",
            "dedicated_verifier_os_account",
            "separately_administered_verifier_host",
            "production_retention_enforcement",
            "trusted_time_and_clock_skew_evidence",
            "privacy_review",
        ],
        "authority": dict(AUTHORITY),
    }
    return sign_threshold_document(
        unsigned,
        connectors,
        POLICY_DOMAIN,
        "World intake source policy",
        WorldIntakeGovernanceError,
    )


def _validate_window(document: JsonObject, now: datetime, maximum_lifetime_seconds: int, label: str) -> datetime:
    issued_at = _parse_timestamp(document.get("issued_at"), f"{label}.issued_at")
    not_before = _parse_timestamp(document.get("not_before"), f"{label}.not_before")
    expires_at = _parse_timestamp(document.get("expires_at"), f"{label}.expires_at")
    if issued_at < not_before or issued_at >= expires_at or now < not_before or now >= expires_at:
        raise WorldIntakeGovernanceError(f"World intake {label} is outside its validity window.")
    if (expires_at - not_before).total_seconds() > maximum_lifetime_seconds:
        raise WorldIntakeGovernanceError(f"World intake {label} exceeds its maximum lifetime.")
    return issued_at


def validate_source_policy(
    policy: JsonObject,
    governance_state: JsonObject,
    now: datetime,
) -> tuple[list[str], list[str]]:
    validate_governance_state(governance_state)
    expected_fields = {
        "policy_version",
        "policy_id",
        "origin",
        "purpose_id",
        "governance_state_digest",
        "issued_at",
        "not_before",
        "expires_at",
        "sources",
        "retention",
        "ingestion_budget",
        "live_admission_requirements",
        "authority",
        "signatures",
    }
    if set(policy) != expected_fields or policy.get("policy_version") != "0.1.0" or policy.get("origin") != "simulated":
        raise WorldIntakeGovernanceError("World intake source policy fields, version, or origin are invalid.")
    if policy.get("purpose_id") != PURPOSE_ID or policy.get("authority") != AUTHORITY:
        raise WorldIntakeGovernanceError("World intake source policy changed purpose or authority.")
    if policy.get("governance_state_digest") != sha256_digest(governance_state):
        raise WorldIntakeGovernanceError("World intake source policy governance binding is invalid.")
    sources = _require_object_list(policy.get("sources"), "policy.sources")
    if list(sources) != [_source_configuration(source_id) for source_id in SOURCE_CHANNELS]:
        raise WorldIntakeGovernanceError("World intake source policy configuration or source order is invalid.")
    retention = _require_object(policy.get("retention"), "policy.retention")
    expected_retention = {
        "raw_event_payload_retention_seconds": 0,
        "typed_event_metadata_retention_seconds": 86400,
        "maximum_cursor_transition_count": 64,
        "maximum_immutable_generation_count": 64,
        "witnessed_compaction_required_before_deletion": True,
        "automatic_deletion_authorized": False,
    }
    if retention != expected_retention:
        raise WorldIntakeGovernanceError("World intake retention boundary was weakened or substituted.")
    budget = _require_object(policy.get("ingestion_budget"), "policy.ingestion_budget")
    expected_budget = {
        "maximum_events_per_session": 8,
        "maximum_accepted_events_per_transition": 4,
        "maximum_queue_depth": 4,
        "overflow_strategy": "defer_newest",
        "event_drop_allowed": False,
    }
    if budget != expected_budget:
        raise WorldIntakeGovernanceError("World intake ingestion budget was weakened or substituted.")
    issued_at = _validate_window(policy, now, 600, "source policy")
    return verify_threshold_signatures(
        policy,
        governance_state,
        issued_at,
        POLICY_DOMAIN,
        "World intake source policy",
        WorldIntakeGovernanceError,
    )


def build_source_health_attestation(
    edge_document: JsonObject,
    policy: JsonObject,
    governance_state: JsonObject,
    connectors: list[SigningConnector],
    issued_at: datetime,
) -> JsonObject:
    validate_continuous_observation(edge_document)
    validate_source_policy(policy, governance_state, issued_at)
    completed_at = _parse_timestamp(edge_document.get("completed_at"), "edge.completed_at")
    policy_sources = {
        _require_string(source.get("source_id"), "policy source_id"): source
        for source in _require_object_list(policy.get("sources"), "policy.sources")
    }
    edge_sources = {
        _require_string(source.get("source_id"), "edge source_id"): source
        for source in _require_object_list(edge_document.get("sources"), "edge.sources")
    }
    events = _require_object_list(edge_document.get("events"), "edge.events")
    health_rows: list[JsonObject] = []
    for source_id in SOURCE_CHANNELS:
        source_events = [event for event in events if event.get("source_id") == source_id]
        timestamps = [_parse_timestamp(event.get("observed_at"), "edge.event.observed_at") for event in source_events]
        newest = max(timestamps, default=None)
        freshness_age = int(max((completed_at - newest).total_seconds(), 0)) if newest is not None else None
        future_skew = int(max((newest - completed_at).total_seconds(), 0)) if newest is not None else None
        configuration = policy_sources[source_id]
        status = _require_string(edge_sources[source_id].get("status"), "edge source status")
        fresh = (
            status == "observed"
            and freshness_age is not None
            and future_skew is not None
            and freshness_age <= int(cast(int, configuration["freshness_limit_seconds"]))
            and future_skew <= int(cast(int, configuration["maximum_clock_skew_seconds"]))
        )
        health_rows.append(
            {
                "source_id": source_id,
                "configuration_digest": configuration["configuration_digest"],
                "status": status,
                "event_count": len(source_events),
                "newest_observed_at": _format_timestamp(newest) if newest is not None else None,
                "freshness_age_seconds": freshness_age,
                "future_clock_skew_seconds": future_skew,
                "fresh": fresh,
                "error_digest": edge_sources[source_id].get("error_digest"),
            }
        )
    issued_text = _format_timestamp(issued_at)
    unsigned: JsonObject = {
        "health_version": "0.1.0",
        "attestation_id": str(uuid.uuid5(GOVERNANCE_NAMESPACE, f"health:{sha256_digest(edge_document)}")),
        "origin": "replayed",
        "purpose_id": PURPOSE_ID,
        "source_policy_digest": sha256_digest(policy),
        "governance_state_digest": sha256_digest(governance_state),
        "source_session_digest": sha256_digest(edge_document),
        "captured_at": edge_document["completed_at"],
        "issued_at": issued_text,
        "not_before": issued_text,
        "expires_at": _format_timestamp(issued_at + timedelta(minutes=5)),
        "sources": health_rows,
        "collector": {
            "raw_event_payload_retained": False,
            "active_probe_performed": False,
            "production_source_identity_verified": False,
        },
        "authority": dict(AUTHORITY),
    }
    return sign_threshold_document(
        unsigned,
        connectors,
        HEALTH_DOMAIN,
        "World intake source health",
        WorldIntakeGovernanceError,
    )


def validate_source_health_attestation(
    health: JsonObject,
    edge_document: JsonObject,
    policy: JsonObject,
    governance_state: JsonObject,
    now: datetime,
) -> tuple[list[str], list[str]]:
    validate_source_policy(policy, governance_state, now)
    expected = build_source_health_attestation_body(edge_document, policy, governance_state, health)
    if _unsigned(health) != expected:
        raise WorldIntakeGovernanceError("World intake source health differs from independent recomputation.")
    issued_at = _validate_window(health, now, 300, "source health")
    return verify_threshold_signatures(
        health,
        governance_state,
        issued_at,
        HEALTH_DOMAIN,
        "World intake source health",
        WorldIntakeGovernanceError,
    )


def build_source_health_attestation_body(
    edge_document: JsonObject,
    policy: JsonObject,
    governance_state: JsonObject,
    signed_health: JsonObject,
) -> JsonObject:
    validate_continuous_observation(edge_document)
    policy_sources = {
        _require_string(source.get("source_id"), "policy source_id"): source
        for source in _require_object_list(policy.get("sources"), "policy.sources")
    }
    edge_sources = {
        _require_string(source.get("source_id"), "edge source_id"): source
        for source in _require_object_list(edge_document.get("sources"), "edge.sources")
    }
    events = _require_object_list(edge_document.get("events"), "edge.events")
    completed_at = _parse_timestamp(edge_document.get("completed_at"), "edge.completed_at")
    rows: list[JsonObject] = []
    for source_id in SOURCE_CHANNELS:
        source_events = [event for event in events if event.get("source_id") == source_id]
        timestamps = [_parse_timestamp(event.get("observed_at"), "edge.event.observed_at") for event in source_events]
        newest = max(timestamps, default=None)
        age = int(max((completed_at - newest).total_seconds(), 0)) if newest is not None else None
        skew = int(max((newest - completed_at).total_seconds(), 0)) if newest is not None else None
        configuration = policy_sources[source_id]
        status = _require_string(edge_sources[source_id].get("status"), "edge source status")
        fresh = (
            status == "observed"
            and age is not None
            and skew is not None
            and age <= int(cast(int, configuration["freshness_limit_seconds"]))
            and skew <= int(cast(int, configuration["maximum_clock_skew_seconds"]))
        )
        rows.append(
            {
                "source_id": source_id,
                "configuration_digest": configuration["configuration_digest"],
                "status": status,
                "event_count": len(source_events),
                "newest_observed_at": _format_timestamp(newest) if newest is not None else None,
                "freshness_age_seconds": age,
                "future_clock_skew_seconds": skew,
                "fresh": fresh,
                "error_digest": edge_sources[source_id].get("error_digest"),
            }
        )
    return {
        "health_version": "0.1.0",
        "attestation_id": signed_health.get("attestation_id"),
        "origin": "replayed",
        "purpose_id": PURPOSE_ID,
        "source_policy_digest": sha256_digest(policy),
        "governance_state_digest": sha256_digest(governance_state),
        "source_session_digest": sha256_digest(edge_document),
        "captured_at": edge_document["completed_at"],
        "issued_at": signed_health.get("issued_at"),
        "not_before": signed_health.get("not_before"),
        "expires_at": signed_health.get("expires_at"),
        "sources": rows,
        "collector": {
            "raw_event_payload_retained": False,
            "active_probe_performed": False,
            "production_source_identity_verified": False,
        },
        "authority": dict(AUTHORITY),
    }


def validate_verifier_boundary(boundary: JsonObject) -> None:
    if boundary != VERIFIER_BOUNDARY:
        raise WorldIntakeGovernanceError(
            "World intake verifier boundary cannot claim dedicated administration or production independence in this wave."
        )


def _admitted_edge_document(edge_document: JsonObject, accepted_indexes: Sequence[int]) -> JsonObject:
    admitted = copy.deepcopy(edge_document)
    events = cast(list[JsonObject], admitted["events"])
    admitted_events = [event for index, event in enumerate(events) if index in set(accepted_indexes)]
    admitted["events"] = cast(JsonValue, admitted_events)
    admitted["event_set_digest"] = sha256_digest(cast(JsonValue, admitted_events))
    for source in cast(list[JsonObject], admitted["sources"]):
        source_id = source["source_id"]
        source["event_count"] = len([event for event in admitted_events if event["source_id"] == source_id])
    validate_continuous_observation(admitted)
    return admitted


def _decision_body(
    edge_document: JsonObject,
    admitted_edge: JsonObject,
    policy: JsonObject,
    health: JsonObject,
    governance_state: JsonObject,
    verifier_boundary: JsonObject,
    queue_depth_before: int,
    projected_generation_count: int,
    projected_cursor_transition_count: int,
    issued_at: datetime,
) -> JsonObject:
    budget = _require_object(policy.get("ingestion_budget"), "policy.ingestion_budget")
    retention = _require_object(policy.get("retention"), "policy.retention")
    events = _require_object_list(edge_document.get("events"), "edge.events")
    maximum_queue_depth = int(cast(int, budget["maximum_queue_depth"]))
    capacity = max(maximum_queue_depth - queue_depth_before, 0)
    accepted_count = min(
        len(events),
        capacity,
        int(cast(int, budget["maximum_accepted_events_per_transition"])),
    )
    accepted_indexes = list(range(accepted_count))
    deferred_indexes = list(range(accepted_count, len(events)))
    health_sources = _require_object_list(health.get("sources"), "health.sources")
    fresh_source_count = len([source for source in health_sources if source.get("fresh") is True])
    source_gap_count = len([source for source in health_sources if source.get("status") != "observed"])
    retention_within_limits = (
        projected_generation_count <= int(cast(int, retention["maximum_immutable_generation_count"]))
        and projected_cursor_transition_count <= int(cast(int, retention["maximum_cursor_transition_count"]))
    )
    issued_text = _format_timestamp(issued_at)
    status = (
        "REPLAY_INTAKE_GOVERNED_BACKPRESSURE_APPLIED_LIVE_ADMISSION_BLOCKED"
        if deferred_indexes
        else "REPLAY_INTAKE_GOVERNED_WITHIN_BUDGET_LIVE_ADMISSION_BLOCKED"
    )
    return {
        "decision_version": "0.1.0",
        "decision_id": str(uuid.uuid5(GOVERNANCE_NAMESPACE, f"decision:{sha256_digest(edge_document)}:{queue_depth_before}")),
        "origin": "replayed",
        "status": status,
        "purpose_id": PURPOSE_ID,
        "governance_state_digest": sha256_digest(governance_state),
        "source_policy_digest": sha256_digest(policy),
        "source_health_digest": sha256_digest(health),
        "source_session_digest": sha256_digest(edge_document),
        "admitted_session_digest": sha256_digest(admitted_edge),
        "verifier_boundary_digest": sha256_digest(verifier_boundary),
        "issued_at": issued_text,
        "not_before": issued_text,
        "expires_at": _format_timestamp(issued_at + timedelta(minutes=5)),
        "queue": {
            "depth_before": queue_depth_before,
            "maximum_depth": maximum_queue_depth,
            "accepted_event_count": accepted_count,
            "deferred_event_count": len(deferred_indexes),
            "dropped_event_count": 0,
            "depth_after": queue_depth_before + accepted_count,
            "overflow_strategy": "defer_newest",
            "accepted_event_indexes": accepted_indexes,
            "deferred_event_indexes": deferred_indexes,
        },
        "retention": {
            "projected_generation_count": projected_generation_count,
            "projected_cursor_transition_count": projected_cursor_transition_count,
            "within_limits": retention_within_limits,
            "raw_event_payload_retention_seconds": 0,
            "automatic_deletion_authorized": False,
        },
        "health_summary": {
            "source_count": len(health_sources),
            "fresh_source_count": fresh_source_count,
            "source_gap_count": source_gap_count,
            "production_source_identity_verified": False,
        },
        "replay_intake_allowed": retention_within_limits and accepted_count > 0,
        "live_admission_authorized": False,
        "policy_input_ready": False,
        "authority": dict(AUTHORITY),
    }


def build_governed_intake_decision(
    edge_document: JsonObject,
    policy: JsonObject,
    health: JsonObject,
    governance_state: JsonObject,
    connectors: list[SigningConnector],
    verifier_boundary: JsonObject,
    queue_depth_before: int,
    projected_generation_count: int,
    projected_cursor_transition_count: int,
    issued_at: datetime,
) -> tuple[JsonObject, JsonObject]:
    validate_continuous_observation(edge_document)
    validate_source_policy(policy, governance_state, issued_at)
    validate_source_health_attestation(health, edge_document, policy, governance_state, issued_at)
    validate_verifier_boundary(verifier_boundary)
    if edge_document.get("origin") != "replayed":
        raise WorldIntakeGovernanceError("Governed World Model intake remains replay-only.")
    if queue_depth_before < 0 or projected_generation_count <= 0 or projected_cursor_transition_count <= 0:
        raise WorldIntakeGovernanceError("World intake queue and retention projections are invalid.")
    budget = _require_object(policy.get("ingestion_budget"), "policy.ingestion_budget")
    events = _require_object_list(edge_document.get("events"), "edge.events")
    if len(events) > int(cast(int, budget["maximum_events_per_session"])):
        raise WorldIntakeGovernanceError("World intake source session exceeds its signed event budget.")
    capacity = max(int(cast(int, budget["maximum_queue_depth"])) - queue_depth_before, 0)
    accepted_count = min(len(events), capacity, int(cast(int, budget["maximum_accepted_events_per_transition"])))
    admitted_edge = _admitted_edge_document(edge_document, list(range(accepted_count)))
    body = _decision_body(
        edge_document,
        admitted_edge,
        policy,
        health,
        governance_state,
        verifier_boundary,
        queue_depth_before,
        projected_generation_count,
        projected_cursor_transition_count,
        issued_at,
    )
    decision = sign_threshold_document(
        body,
        connectors,
        DECISION_DOMAIN,
        "World intake governance decision",
        WorldIntakeGovernanceError,
    )
    validate_governed_intake_decision(
        edge_document,
        admitted_edge,
        policy,
        health,
        governance_state,
        verifier_boundary,
        decision,
        issued_at,
    )
    return decision, admitted_edge


def validate_governed_intake_decision(
    edge_document: JsonObject,
    admitted_edge: JsonObject,
    policy: JsonObject,
    health: JsonObject,
    governance_state: JsonObject,
    verifier_boundary: JsonObject,
    decision: JsonObject,
    now: datetime,
) -> tuple[list[str], list[str]]:
    validate_source_policy(policy, governance_state, now)
    validate_source_health_attestation(health, edge_document, policy, governance_state, now)
    validate_verifier_boundary(verifier_boundary)
    queue = _require_object(decision.get("queue"), "decision.queue")
    retention = _require_object(decision.get("retention"), "decision.retention")
    accepted_values = queue.get("accepted_event_indexes")
    if not isinstance(accepted_values, list) or any(
        isinstance(value, bool) or not isinstance(value, int) for value in accepted_values
    ):
        raise WorldIntakeGovernanceError(
            "World intake accepted event indexes must be an integer list."
        )
    expected_admitted = _admitted_edge_document(
        edge_document,
        [int(value) for value in accepted_values],
    )
    if expected_admitted != admitted_edge:
        raise WorldIntakeGovernanceError("World intake admitted event projection differs from its signed decision.")
    expected = _decision_body(
        edge_document,
        admitted_edge,
        policy,
        health,
        governance_state,
        verifier_boundary,
        int(cast(int, queue.get("depth_before"))),
        int(cast(int, retention.get("projected_generation_count"))),
        int(cast(int, retention.get("projected_cursor_transition_count"))),
        _parse_timestamp(decision.get("issued_at"), "decision.issued_at"),
    )
    if _unsigned(decision) != expected:
        raise WorldIntakeGovernanceError("World intake governance decision differs from independent recomputation.")
    if decision.get("authority") != AUTHORITY or decision.get("live_admission_authorized") is not False:
        raise WorldIntakeGovernanceError("World intake governance decision widened authority or live admission.")
    issued_at = _validate_window(decision, now, 300, "governance decision")
    return verify_threshold_signatures(
        decision,
        governance_state,
        issued_at,
        DECISION_DOMAIN,
        "World intake governance decision",
        WorldIntakeGovernanceError,
    )


def build_governed_world_intake(
    decision: JsonObject,
    admitted_edge: JsonObject,
    base_candidate: JsonObject,
) -> JsonObject:
    validate_continuous_observation(admitted_edge)
    validate_world_intake_candidate(base_candidate)
    if decision.get("admitted_session_digest") != sha256_digest(admitted_edge):
        raise WorldIntakeGovernanceError("Governed World Model intake decision is not bound to the admitted session.")
    if base_candidate.get("source_session_digest") != sha256_digest(admitted_edge):
        raise WorldIntakeGovernanceError("Governed World Model candidate is not bound to the admitted session.")
    if decision.get("replay_intake_allowed") is not True or decision.get("live_admission_authorized") is not False:
        raise WorldIntakeGovernanceError("Governed World Model candidate lacks replay admission or widened live admission.")
    document: JsonObject = {
        "governed_intake_version": "0.1.0",
        "origin": "replayed",
        "governance_decision_digest": sha256_digest(decision),
        "admitted_session_digest": sha256_digest(admitted_edge),
        "base_candidate_digest": sha256_digest(base_candidate),
        "base_candidate": base_candidate,
        "live_admission_authorized": False,
        "policy_input_ready": False,
        "authority": dict(AUTHORITY),
    }
    return {"governed_intake_digest": sha256_digest(document), "governed_intake": document}


def commit_governed_world_intake_store(
    store_root: Path,
    edge_document: JsonObject,
    admitted_edge: JsonObject,
    policy: JsonObject,
    health: JsonObject,
    governance_state: JsonObject,
    verifier_boundary: JsonObject,
    decision: JsonObject,
    governed_intake: JsonObject,
    verified_at: datetime,
) -> JsonObject:
    """Validate signed governance against actual store cardinality before publishing one replay successor."""
    validate_governed_intake_decision(
        edge_document,
        admitted_edge,
        policy,
        health,
        governance_state,
        verifier_boundary,
        decision,
        verified_at,
    )
    governed_body = _require_object(governed_intake.get("governed_intake"), "governed_intake")
    base_candidate = _require_object(governed_body.get("base_candidate"), "governed_intake.base_candidate")
    expected_wrapper = build_governed_world_intake(decision, admitted_edge, base_candidate)
    if governed_intake != expected_wrapper:
        raise WorldIntakeGovernanceError("Governed World Model intake wrapper was substituted before commit.")
    retention = _require_object(decision.get("retention"), "decision.retention")
    current_generation_count = len(list((store_root / "generations").glob("*.json")))
    current_transition_count = len(list((store_root / "cursor-transitions").glob("*.json")))
    if retention.get("projected_generation_count") != current_generation_count + 1:
        raise WorldIntakeGovernanceError(
            "Governed World Model generation projection does not match the immutable store."
        )
    if retention.get("projected_cursor_transition_count") != current_transition_count + 1:
        raise WorldIntakeGovernanceError(
            "Governed World Model cursor-transition projection does not match the immutable store."
        )
    if retention.get("within_limits") is not True or decision.get("replay_intake_allowed") is not True:
        raise WorldIntakeGovernanceError("Governed World Model retention or replay-admission gate is closed.")
    prepare_world_intake_store(store_root, base_candidate)
    return commit_world_intake_store(store_root, base_candidate)
