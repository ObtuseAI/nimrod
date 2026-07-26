"""Deterministic proposal-only CACIS immune-organism lifecycle replay."""

from __future__ import annotations

import uuid
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta
from typing import cast

from nimrod_cacis.world_model import parse_timestamp, require_object, require_object_list, require_string, validate_world_model_generation
from nimrod_simulator.errors import ImmuneRuntimeError, WorldModelError
from nimrod_simulator.jsonio import sha256_digest
from nimrod_simulator.model import JsonObject, JsonValue


ALLOWED_CAPABILITIES: tuple[str, ...] = (
    "read_world_model",
    "derive_observation",
    "emit_typed_contribution",
    "retain_candidate_knowledge",
)
PROHIBITED_CAPABILITIES: tuple[str, ...] = (
    "authorize",
    "execute",
    "change_policy",
    "contact_target",
    "use_credential",
    "raw_command",
    "self_verify",
    "promote_knowledge",
)
SHADOW_CONTROLS: tuple[str, ...] = ("pause", "downgrade", "spawn_challenge", "abstain", "resume", "terminate")
TERMINATION_TRIGGERS: tuple[str, ...] = ("lease_expiry", "resource_exhaustion", "authority_violation")
AUTHORITY: Mapping[str, bool] = {
    "can_authorize": False,
    "can_execute": False,
    "can_change_policy": False,
    "can_contact_targets": False,
    "can_use_credentials": False,
    "can_self_verify": False,
    "can_promote": False,
}
SECURITY_CLAIM = (
    "Replay-only organism lifecycle; typed proposals retained, organism disposed, "
    "independent verification pending, no execution or target contact"
)
RUNTIME_NAMESPACE = uuid.UUID("8de38233-24b4-5a73-aede-0f50379f9eb7")


def _runtime_error(error: WorldModelError) -> ImmuneRuntimeError:
    return ImmuneRuntimeError(f"CACIS immune runtime rejected world-model input: {error}")


def _require_int(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ImmuneRuntimeError(f"CACIS immune runtime {label} must be an integer.")
    return value


def _require_string_list(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise ImmuneRuntimeError(f"CACIS immune runtime {label} must be a list of non-empty strings.")
    return tuple(cast(list[str], value))


def _mission_cells(mission: JsonObject) -> tuple[JsonObject, ...]:
    try:
        return require_object_list(mission.get("cells"), "immune mission.cells")
    except WorldModelError as error:
        raise _runtime_error(error) from error


def validate_immune_organism_mission(mission: JsonObject) -> None:
    expected_fields = {
        "mission_version",
        "mission_id",
        "origin",
        "world_model_generation_digest",
        "incident_class",
        "issued_at",
        "not_before",
        "expires_at",
        "maximum_outcome",
        "governor",
        "capability_lease",
        "resource_lease",
        "cells",
        "shadow_policy",
        "authority",
    }
    if set(mission) != expected_fields:
        raise ImmuneRuntimeError(
            "CACIS immune mission fields must match the W2 contract exactly: "
            f"missing={sorted(expected_fields - set(mission))!r}, extra={sorted(set(mission) - expected_fields)!r}."
        )
    if mission.get("mission_version") != "0.1.0" or mission.get("origin") != "replayed":
        raise ImmuneRuntimeError("CACIS W2 accepts replayed 0.1.0 missions only.")
    if mission.get("maximum_outcome") != "typed_proposal":
        raise ImmuneRuntimeError("CACIS immune missions cannot exceed typed_proposal.")
    if mission.get("authority") != AUTHORITY:
        raise ImmuneRuntimeError(f"CACIS immune mission authority is immutable and false: received={mission.get('authority')!r}.")
    try:
        issued_at = parse_timestamp(mission.get("issued_at"), "immune mission.issued_at")
        not_before = parse_timestamp(mission.get("not_before"), "immune mission.not_before")
        expires_at = parse_timestamp(mission.get("expires_at"), "immune mission.expires_at")
        governor = require_object(mission.get("governor"), "immune mission.governor")
        capability = require_object(mission.get("capability_lease"), "immune mission.capability_lease")
        resources = require_object(mission.get("resource_lease"), "immune mission.resource_lease")
        shadow = require_object(mission.get("shadow_policy"), "immune mission.shadow_policy")
    except WorldModelError as error:
        raise _runtime_error(error) from error
    if issued_at > not_before or not_before >= expires_at:
        raise ImmuneRuntimeError("CACIS immune mission requires issued_at <= not_before < expires_at.")
    if governor.get("schedule_strategy") != "deterministic_minimum_capability":
        raise ImmuneRuntimeError("CACIS W2 Governor scheduling must be deterministic and minimum-capability.")
    if governor.get("can_authorize") is not False or governor.get("can_execute") is not False:
        raise ImmuneRuntimeError("CACIS Governor cannot authorize or execute.")
    allowed = _require_string_list(capability.get("allowed_capabilities"), "capability_lease.allowed_capabilities")
    prohibited = _require_string_list(capability.get("prohibited_capabilities"), "capability_lease.prohibited_capabilities")
    if set(allowed) != set(ALLOWED_CAPABILITIES) or len(allowed) != len(ALLOWED_CAPABILITIES):
        raise ImmuneRuntimeError(f"CACIS W2 capability lease must use the exact allowlist: received={allowed!r}.")
    if set(prohibited) != set(PROHIBITED_CAPABILITIES) or len(prohibited) != len(PROHIBITED_CAPABILITIES):
        raise ImmuneRuntimeError(f"CACIS W2 capability lease must use the exact denylist: received={prohibited!r}.")
    if capability.get("ambient_credentials_allowed") is not False or capability.get("raw_command_bridge_allowed") is not False:
        raise ImmuneRuntimeError("CACIS W2 forbids ambient credentials and raw-command bridges.")
    if parse_timestamp(resources.get("expires_at"), "resource_lease.expires_at") != expires_at:
        raise ImmuneRuntimeError("CACIS resource and mission leases must expire together.")
    for field in ("cpu_millis", "memory_mb", "storage_bytes", "telemetry_reads"):
        if _require_int(resources.get(field), f"resource_lease.{field}") <= 0:
            raise ImmuneRuntimeError(f"CACIS resource lease {field} must be positive.")
    if resources.get("model_calls") != 0 or resources.get("sandbox_runs") != 0:
        raise ImmuneRuntimeError("CACIS W2 cannot allocate model calls or sandbox runs.")
    cells = _mission_cells(mission)
    cell_ids = [require_string(item.get("cell_id"), "immune mission cell_id") for item in cells]
    roles = [require_string(item.get("role"), "immune mission cell role") for item in cells]
    if len(cell_ids) != len(set(cell_ids)) or len(roles) != len(set(roles)):
        raise ImmuneRuntimeError("CACIS W2 cells require unique identities and roles.")
    if roles.count("shadow") != 1 or shadow.get("shadow_cell_id") != cell_ids[roles.index("shadow")]:
        raise ImmuneRuntimeError("CACIS W2 requires exactly one separately identified Shadow cell.")
    for cell in cells:
        capabilities = _require_string_list(cell.get("capabilities"), "cell.capabilities")
        if not set(capabilities).issubset(set(ALLOWED_CAPABILITIES)):
            raise ImmuneRuntimeError(f"CACIS cell capability escapes the mission lease: capabilities={capabilities!r}.")
        if cell.get("can_self_verify") is not False or cell.get("can_authorize") is not False or cell.get("can_execute") is not False:
            raise ImmuneRuntimeError(f"CACIS cell authority must remain false: cell_id={cell.get('cell_id')!r}.")
    controls = _require_string_list(shadow.get("allowed_controls"), "shadow_policy.allowed_controls")
    triggers = _require_string_list(shadow.get("automatic_termination_triggers"), "shadow_policy.automatic_termination_triggers")
    if set(controls) != set(SHADOW_CONTROLS) or len(controls) != len(SHADOW_CONTROLS):
        raise ImmuneRuntimeError("CACIS Shadow policy must preserve all six bounded controls.")
    if set(triggers) != set(TERMINATION_TRIGGERS) or len(triggers) != len(TERMINATION_TRIGGERS):
        raise ImmuneRuntimeError("CACIS Shadow policy must preserve all automatic termination triggers.")
    if shadow.get("can_authorize") is not False or shadow.get("can_execute") is not False:
        raise ImmuneRuntimeError("CACIS Shadow cannot authorize or execute.")


def _cell_by_role(mission: JsonObject) -> dict[str, JsonObject]:
    return {require_string(item["role"], "cell.role"): item for item in _mission_cells(mission)}


def _domain_states(world_document: JsonObject) -> dict[str, str]:
    try:
        validate_world_model_generation(world_document)
        generation = require_object(world_document.get("generation"), "world generation")
        domains = require_object_list(generation.get("domains"), "world generation.domains")
        return {
            require_string(item.get("domain"), "world domain"): require_string(item.get("knowledge_state"), "world knowledge state")
            for item in domains
        }
    except WorldModelError as error:
        raise _runtime_error(error) from error


def _contribution(
    mission: JsonObject,
    cell: JsonObject,
    kind: str,
    status: str,
    knowledge_state: str,
) -> JsonObject:
    role = require_string(cell["role"], "cell.role")
    parent_digest = require_string(mission["world_model_generation_digest"], "mission.world_model_generation_digest")
    content: JsonObject = {
        "role": role,
        "kind": kind,
        "status": status,
        "knowledge_state": knowledge_state,
        "parent_generation_digest": parent_digest,
    }
    mission_id = require_string(mission["mission_id"], "mission.mission_id")
    return {
        "contribution_id": str(uuid.uuid5(RUNTIME_NAMESPACE, f"{mission_id}:contribution:{role}")),
        "cell_id": cell["cell_id"],
        "role": role,
        "kind": kind,
        "status": status,
        "content_digest": sha256_digest(cast(JsonValue, content)),
        "parent_generation_digest": parent_digest,
        "can_verify": False,
        "can_authorize": False,
        "can_execute": False,
    }


def _build_contributions(mission: JsonObject, world_document: JsonObject) -> list[JsonObject]:
    states = _domain_states(world_document)
    cells = _cell_by_role(mission)
    credential_theft: Sequence[tuple[str, str, str, str]] = (
        ("identity", "observation_assessment", "proposed", states["identity"]),
        ("endpoint", "coverage_gap", "proposed", states["endpoint"]),
        ("network", "observation_assessment", "proposed", states["network"]),
        ("threat", "observation_assessment", "proposed", states["threat"]),
        ("recovery", "open_question", "abstained", states["recovery"]),
        ("evidence", "coverage_gap", "proposed", states["cloud"]),
        ("historian", "investigation_pattern", "proposed", "cross_domain_candidate"),
    )
    suspicious_script: Sequence[tuple[str, str, str, str]] = (
        ("script_analysis", "observation_assessment", "proposed", states["endpoint"]),
        ("memory_analysis", "coverage_gap", "proposed", states["endpoint"]),
        ("behavior", "observation_assessment", "proposed", states["threat"]),
        ("identity", "observation_assessment", "proposed", states["identity"]),
        ("network", "observation_assessment", "proposed", states["network"]),
        ("containment", "open_question", "abstained", states["endpoint"]),
        ("recovery", "open_question", "abstained", states["recovery"]),
        ("evidence", "coverage_gap", "proposed", states["cloud"]),
        ("historian", "investigation_pattern", "proposed", "cross_domain_candidate"),
    )
    incident_class = require_string(mission.get("incident_class"), "mission.incident_class")
    by_incident: Mapping[str, Sequence[tuple[str, str, str, str]]] = {
        "credential_theft": credential_theft,
        "suspicious_script": suspicious_script,
    }
    specifications = by_incident.get(incident_class)
    if specifications is None:
        raise ImmuneRuntimeError(f"CACIS W2 incident class is unsupported: incident_class={incident_class!r}.")
    expected_roles = {role for role, _, _, _ in specifications} | {"shadow"}
    if set(cells) != expected_roles:
        raise ImmuneRuntimeError(
            "CACIS W2 mission topology does not match its incident class: "
            f"incident_class={incident_class!r}, expected={sorted(expected_roles)!r}, received={sorted(cells)!r}."
        )
    return [_contribution(mission, cells[role], kind, status, state) for role, kind, status, state in specifications]


def _event(sequence: int, timestamp: datetime, actor: str, event_type: str, reason: str, parent_digest: str | None) -> JsonObject:
    return {
        "sequence": sequence,
        "timestamp": timestamp.isoformat().replace("+00:00", "Z"),
        "actor": actor,
        "event_type": event_type,
        "reason": reason,
        "parent_event_digest": parent_digest,
    }


def _append_event(events: list[JsonObject], started_at: datetime, actor: str, event_type: str, reason: str) -> None:
    parent_digest = sha256_digest(events[-1]) if events else None
    sequence = len(events) + 1
    events.append(_event(sequence, started_at + timedelta(seconds=sequence - 1), actor, event_type, reason, parent_digest))


def _build_events(started_at: datetime, contributions: Sequence[JsonObject]) -> list[JsonObject]:
    events: list[JsonObject] = []
    _append_event(events, started_at, "governor", "spawned", "minimum capability topology leased")
    _append_event(events, started_at, "organism", "running", "replay generation admitted as read-only input")
    _append_event(events, started_at, "shadow", "shadow_paused", "identity contradiction requires preserved ambiguity")
    _append_event(events, started_at, "shadow", "shadow_resumed", "contradiction preserved without truth selection")
    for contribution in contributions:
        if contribution["status"] == "abstained":
            _append_event(events, started_at, "shadow", "abstained", "missing recovery evidence requires abstention")
        else:
            _append_event(events, started_at, "organism", "contribution_emitted", f"typed {contribution['role']} contribution emitted")
    _append_event(events, started_at, "shadow", "terminated", "typed proposal ceiling reached; ephemeral organism terminated")
    _append_event(events, started_at, "organism", "scratch_destroyed", "scratch state and conversational context destroyed")
    _append_event(events, started_at, "governor", "leases_revoked", "capability and resource leases revoked")
    _append_event(events, started_at, "organism", "disposed", "all cells terminated; candidate knowledge retained separately")
    return events


def _build_retained_knowledge(mission: JsonObject, contributions: Sequence[JsonObject]) -> list[JsonObject]:
    credential_theft_roles = {
        "identity": "evidence_reference",
        "endpoint": "open_question",
        "historian": "investigation_pattern",
    }
    suspicious_script_roles = {
        "evidence": "evidence_reference",
        "script_analysis": "open_question",
        "historian": "investigation_pattern",
    }
    incident_class = require_string(mission.get("incident_class"), "mission.incident_class")
    retained_roles = credential_theft_roles if incident_class == "credential_theft" else suspicious_script_roles
    mission_id = require_string(mission["mission_id"], "mission.mission_id")
    entries: list[JsonObject] = []
    for contribution in contributions:
        role = str(contribution["role"])
        knowledge_type = retained_roles.get(role)
        if knowledge_type is None:
            continue
        entries.append(
            {
                "knowledge_id": str(uuid.uuid5(RUNTIME_NAMESPACE, f"{mission_id}:knowledge:{role}")),
                "knowledge_type": knowledge_type,
                "content_digest": contribution["content_digest"],
                "source_contribution_id": contribution["contribution_id"],
                "status": "candidate_only",
            }
        )
    return entries


def build_immune_organism_lifecycle_receipt(mission: JsonObject, world_document: JsonObject) -> JsonObject:
    validate_immune_organism_mission(mission)
    states = _domain_states(world_document)
    if set(states) != {"identity", "endpoint", "network", "cloud", "threat", "recovery"}:
        raise ImmuneRuntimeError(f"CACIS W2 requires all six world-model domains: received={sorted(states)!r}.")
    if mission["world_model_generation_digest"] != world_document.get("generation_digest"):
        raise ImmuneRuntimeError("CACIS immune mission is not bound to the supplied world-model generation.")
    started_at = parse_timestamp(mission["not_before"], "immune mission.not_before")
    contributions = _build_contributions(mission, world_document)
    events = _build_events(started_at, contributions)
    terminated_at = parse_timestamp(events[-1]["timestamp"], "immune lifecycle terminated_at")
    if terminated_at >= parse_timestamp(mission["expires_at"], "immune mission.expires_at"):
        raise ImmuneRuntimeError("CACIS organism lifecycle exceeded its lease.")
    mission_id = require_string(mission["mission_id"], "mission.mission_id")
    receipt_body: JsonObject = {
        "receipt_id": str(uuid.uuid5(RUNTIME_NAMESPACE, f"{mission_id}:receipt")),
        "origin": "replayed",
        "mission_digest": sha256_digest(mission),
        "world_model_generation_digest": mission["world_model_generation_digest"],
        "organism_id": str(uuid.uuid5(RUNTIME_NAMESPACE, f"{mission_id}:organism")),
        "cell_count": len(_mission_cells(mission)),
        "started_at": events[0]["timestamp"],
        "terminated_at": events[-1]["timestamp"],
        "terminal_reason": "shadow_terminated",
        "events": events,
        "contributions": contributions,
        "resource_usage": {
            "cpu_millis": 240,
            "peak_memory_mb": 32,
            "storage_bytes": 12288,
            "telemetry_reads": len(contributions),
            "model_calls": 0,
            "sandbox_runs": 0,
        },
        "termination": {
            "lifecycle_state": "disposed",
            "all_cells_terminated": True,
            "capability_lease_revoked": True,
            "resource_lease_revoked": True,
            "scratch_state_destroyed": True,
            "conversational_context_destroyed": True,
            "credentials_issued": False,
            "target_contact_performed": False,
            "execution_performed": False,
        },
        "retained_knowledge": {
            "entries": _build_retained_knowledge(mission, contributions),
            "retention_ceiling": "candidate_only",
            "raw_context_retained": False,
            "authority_retained": False,
        },
        "independent_verification": {
            "required": True,
            "performed": False,
            "status": "pending_external_verification",
            "verifier_identity": None,
        },
        "authority": dict(AUTHORITY),
        "security_claim": SECURITY_CLAIM,
    }
    document: JsonObject = {
        "receipt_version": "0.1.0",
        "receipt_digest": sha256_digest(receipt_body),
        "receipt": receipt_body,
    }
    validate_immune_organism_lifecycle_receipt(document, mission)
    return document


def _validate_event_chain(events: Sequence[JsonObject]) -> None:
    previous_digest: str | None = None
    previous_timestamp: datetime | None = None
    for expected_sequence, event in enumerate(events, start=1):
        if event.get("sequence") != expected_sequence:
            raise ImmuneRuntimeError("CACIS organism event sequence must be contiguous from one.")
        if event.get("parent_event_digest") != previous_digest:
            raise ImmuneRuntimeError(f"CACIS organism event chain is broken at sequence={expected_sequence}.")
        timestamp = parse_timestamp(event.get("timestamp"), f"immune event {expected_sequence}.timestamp")
        if previous_timestamp is not None and timestamp <= previous_timestamp:
            raise ImmuneRuntimeError("CACIS organism event timestamps must be strictly increasing.")
        previous_timestamp = timestamp
        previous_digest = sha256_digest(event)
    types = [str(item.get("event_type")) for item in events]
    required = {"spawned", "running", "shadow_paused", "shadow_resumed", "abstained", "terminated", "scratch_destroyed", "leases_revoked", "disposed"}
    if not required.issubset(set(types)) or types[0] != "spawned" or types[-1] != "disposed":
        raise ImmuneRuntimeError(f"CACIS W2 lifecycle events are incomplete: received={types!r}.")


def _validate_resource_usage(usage: JsonObject, lease: JsonObject) -> None:
    comparisons = (
        ("cpu_millis", "cpu_millis"),
        ("peak_memory_mb", "memory_mb"),
        ("storage_bytes", "storage_bytes"),
        ("telemetry_reads", "telemetry_reads"),
        ("model_calls", "model_calls"),
        ("sandbox_runs", "sandbox_runs"),
    )
    for usage_field, lease_field in comparisons:
        used = _require_int(usage.get(usage_field), f"resource_usage.{usage_field}")
        allowed = _require_int(lease.get(lease_field), f"resource_lease.{lease_field}")
        if used < 0 or used > allowed:
            raise ImmuneRuntimeError(
                f"CACIS organism exceeded resource lease: resource={usage_field!r}, used={used}, allowed={allowed}."
            )


def validate_immune_organism_lifecycle_receipt(document: JsonObject, mission: JsonObject) -> None:
    validate_immune_organism_mission(mission)
    if set(document) != {"receipt_version", "receipt_digest", "receipt"} or document.get("receipt_version") != "0.1.0":
        raise ImmuneRuntimeError("CACIS lifecycle receipt wrapper must match version 0.1.0 exactly.")
    try:
        receipt = require_object(document.get("receipt"), "immune lifecycle receipt")
    except WorldModelError as error:
        raise _runtime_error(error) from error
    if document.get("receipt_digest") != sha256_digest(receipt):
        raise ImmuneRuntimeError("CACIS lifecycle receipt digest does not match canonical receipt content.")
    if receipt.get("mission_digest") != sha256_digest(mission):
        raise ImmuneRuntimeError("CACIS lifecycle receipt is not bound to the supplied mission.")
    if receipt.get("world_model_generation_digest") != mission.get("world_model_generation_digest"):
        raise ImmuneRuntimeError("CACIS lifecycle receipt substituted the world-model generation.")
    if receipt.get("cell_count") != len(_mission_cells(mission)):
        raise ImmuneRuntimeError("CACIS lifecycle receipt cell count does not match the mission topology.")
    if receipt.get("origin") != "replayed" or receipt.get("terminal_reason") != "shadow_terminated":
        raise ImmuneRuntimeError("CACIS canonical W2 receipt must be replayed and Shadow-terminated.")
    if receipt.get("authority") != AUTHORITY or receipt.get("security_claim") != SECURITY_CLAIM:
        raise ImmuneRuntimeError("CACIS lifecycle receipt widened authority or security claims.")
    events = require_object_list(receipt.get("events"), "immune lifecycle.events")
    _validate_event_chain(events)
    started_at = parse_timestamp(receipt.get("started_at"), "immune lifecycle.started_at")
    terminated_at = parse_timestamp(receipt.get("terminated_at"), "immune lifecycle.terminated_at")
    if started_at != parse_timestamp(events[0]["timestamp"], "immune lifecycle first event"):
        raise ImmuneRuntimeError("CACIS lifecycle start does not match the first event.")
    if terminated_at != parse_timestamp(events[-1]["timestamp"], "immune lifecycle final event"):
        raise ImmuneRuntimeError("CACIS lifecycle termination does not match the final event.")
    if started_at < parse_timestamp(mission["not_before"], "mission.not_before") or terminated_at >= parse_timestamp(mission["expires_at"], "mission.expires_at"):
        raise ImmuneRuntimeError("CACIS lifecycle occurred outside its mission lease.")
    contributions = require_object_list(receipt.get("contributions"), "immune lifecycle.contributions")
    cells = _cell_by_role(mission)
    cell_ids = {str(cell["cell_id"]) for cell in cells.values() if cell["role"] != "shadow"}
    contribution_ids: set[str] = set()
    abstained_count = 0
    for contribution in contributions:
        contribution_id = require_string(contribution.get("contribution_id"), "contribution.contribution_id")
        if contribution_id in contribution_ids:
            raise ImmuneRuntimeError("CACIS lifecycle contribution identifiers must be unique.")
        contribution_ids.add(contribution_id)
        if contribution.get("cell_id") not in cell_ids:
            raise ImmuneRuntimeError("CACIS contribution was emitted by an unknown or Shadow cell.")
        if contribution.get("parent_generation_digest") != mission.get("world_model_generation_digest"):
            raise ImmuneRuntimeError("CACIS contribution is not bound to the mission generation.")
        if contribution.get("can_verify") is not False or contribution.get("can_authorize") is not False or contribution.get("can_execute") is not False:
            raise ImmuneRuntimeError("CACIS contribution cannot verify, authorize, or execute.")
        if contribution.get("status") == "abstained":
            abstained_count += 1
    if abstained_count < 1:
        raise ImmuneRuntimeError("CACIS W2 must preserve at least one explicit abstention.")
    resource_usage = require_object(receipt.get("resource_usage"), "immune lifecycle.resource_usage")
    resource_lease = require_object(mission.get("resource_lease"), "immune mission.resource_lease")
    _validate_resource_usage(resource_usage, resource_lease)
    termination = require_object(receipt.get("termination"), "immune lifecycle.termination")
    required_termination: Mapping[str, object] = {
        "lifecycle_state": "disposed",
        "all_cells_terminated": True,
        "capability_lease_revoked": True,
        "resource_lease_revoked": True,
        "scratch_state_destroyed": True,
        "conversational_context_destroyed": True,
        "credentials_issued": False,
        "target_contact_performed": False,
        "execution_performed": False,
    }
    if termination != required_termination:
        raise ImmuneRuntimeError(f"CACIS organism teardown is incomplete: received={termination!r}.")
    retained = require_object(receipt.get("retained_knowledge"), "immune lifecycle.retained_knowledge")
    if retained.get("retention_ceiling") != "candidate_only" or retained.get("raw_context_retained") is not False or retained.get("authority_retained") is not False:
        raise ImmuneRuntimeError("CACIS retained knowledge exceeded the candidate-only ceiling.")
    knowledge_entries = require_object_list(retained.get("entries"), "retained_knowledge.entries")
    for knowledge in knowledge_entries:
        if knowledge.get("source_contribution_id") not in contribution_ids or knowledge.get("status") != "candidate_only":
            raise ImmuneRuntimeError("CACIS retained knowledge is not bound to a typed candidate contribution.")
    verification = require_object(receipt.get("independent_verification"), "immune lifecycle.independent_verification")
    expected_verification: Mapping[str, object] = {
        "required": True,
        "performed": False,
        "status": "pending_external_verification",
        "verifier_identity": None,
    }
    if verification != expected_verification:
        raise ImmuneRuntimeError("CACIS organism cannot self-verify or fabricate independent settlement.")
