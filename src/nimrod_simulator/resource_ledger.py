"""Tamper-evident lineage-wide resource accounting for recursive improvement."""

from __future__ import annotations

from datetime import datetime

from nimrod_simulator.authorization import parse_timestamp
from nimrod_simulator.errors import ControlStateValidationError, ResourceLedgerError
from nimrod_simulator.jsonio import require_integer, require_list, require_object, require_string, sha256_digest
from nimrod_simulator.key_governance import SigningConnector
from nimrod_simulator.model import JsonObject
from nimrod_simulator.threshold_signing import sign_threshold_document, verify_threshold_signatures


RESOURCE_LEDGER_DOMAIN = b"nimrod.lineage-resource-ledger.v0.1\x00"
RESOURCE_LEDGER_AUTHORITY = {
    "can_allocate": False,
    "can_purchase_compute": False,
    "can_extend_lease": False,
    "can_execute": False,
}
RESOURCE_DIMENSIONS = {
    "cycle_seconds": "maximum_cycle_seconds",
    "compute_units": "maximum_compute_units",
    "peak_memory_megabytes": "maximum_memory_megabytes",
    "peak_storage_megabytes": "maximum_storage_megabytes",
}


def _positive_integer(value: object, field: str) -> int:
    parsed = require_integer(value, field)
    if parsed <= 0:
        raise ResourceLedgerError(f"Resource ledger field '{field}' must be positive.")
    return parsed


def _nonnegative_integer(value: object, field: str) -> int:
    parsed = require_integer(value, field)
    if parsed < 0:
        raise ResourceLedgerError(f"Resource ledger field '{field}' cannot be negative.")
    return parsed


def _resource_reference_list(value: object, field: str) -> list[JsonObject]:
    raw = require_list(value, field)
    if not raw:
        raise ResourceLedgerError(f"Resource ledger field '{field}' requires evidence.")
    result: list[JsonObject] = []
    for index, item in enumerate(raw):
        reference = require_object(item, f"{field}[{index}]")
        require_string(reference.get("id"), f"{field}[{index}].id")
        require_string(reference.get("digest"), f"{field}[{index}].digest")
        result.append(reference)
    return result


def _entry_inputs(entries: list[JsonObject]) -> list[JsonObject]:
    return [
        {
            "candidate_id": entry["candidate_id"],
            "candidate_digest": entry["candidate_digest"],
            "parent_candidate_digest": entry["parent_candidate_digest"],
            "resource_lease_digest": entry["resource_lease_digest"],
            "lease": entry["lease"],
            "usage": entry["usage"],
            "evidence": entry["evidence"],
        }
        for entry in entries
    ]


def build_lineage_resource_ledger(
    ledger_id: str,
    lineage_id: str,
    origin: str,
    constitution: JsonObject,
    governance_state: JsonObject,
    generated_at: str,
    not_before: str,
    expires_at: str,
    entry_inputs: list[JsonObject],
) -> JsonObject:
    if origin not in {"simulated", "range", "sacrificial_replica", "live"}:
        raise ResourceLedgerError(f"Resource ledger origin '{origin}' is unsupported.")
    if not ledger_id or not lineage_id:
        raise ResourceLedgerError("Resource ledger and lineage identifiers cannot be empty.")
    if not entry_inputs:
        raise ResourceLedgerError("Resource ledger requires at least one lineage entry.")
    ceilings = require_object(constitution.get("resource_ceilings"), "constitution.resource_ceilings")
    seen_candidate_ids: set[str] = set()
    seen_candidate_digests: set[str] = set()
    candidate_inputs: list[JsonObject] = []
    child_counts: dict[str, int] = {}
    for index, raw_entry in enumerate(entry_inputs):
        candidate_id = require_string(raw_entry.get("candidate_id"), f"entries[{index}].candidate_id")
        candidate_digest = require_string(
            raw_entry.get("candidate_digest"), f"entries[{index}].candidate_digest"
        )
        parent_digest = raw_entry.get("parent_candidate_digest")
        if parent_digest is not None and not isinstance(parent_digest, str):
            raise ResourceLedgerError(f"Resource ledger parent digest at entry {index} must be a string or null.")
        if candidate_id in seen_candidate_ids or candidate_digest in seen_candidate_digests:
            raise ResourceLedgerError(f"Resource ledger repeats candidate identity at entry {index}.")
        if index == 0 and parent_digest is not None:
            raise ResourceLedgerError("Resource ledger first entry must be the lineage root.")
        if index > 0 and (parent_digest is None or parent_digest not in seen_candidate_digests):
            raise ResourceLedgerError(
                f"Resource ledger entry {index} references an absent or future parent '{parent_digest}'."
            )
        seen_candidate_ids.add(candidate_id)
        seen_candidate_digests.add(candidate_digest)
        if isinstance(parent_digest, str):
            child_counts[parent_digest] = child_counts.get(parent_digest, 0) + 1
        lease = require_object(raw_entry.get("lease"), f"entries[{index}].lease")
        usage = require_object(raw_entry.get("usage"), f"entries[{index}].usage")
        normalized_lease: JsonObject = {}
        normalized_usage: JsonObject = {}
        for usage_field, ceiling_field in RESOURCE_DIMENSIONS.items():
            lease_value = _positive_integer(lease.get(ceiling_field), f"entries[{index}].lease.{ceiling_field}")
            ceiling_value = _positive_integer(ceilings.get(ceiling_field), f"constitution.{ceiling_field}")
            if lease_value > ceiling_value:
                raise ResourceLedgerError(
                    f"Resource ledger lease '{ceiling_field}' value {lease_value} exceeds constitution {ceiling_value}."
                )
            normalized_lease[ceiling_field] = lease_value
            normalized_usage[usage_field] = _nonnegative_integer(
                usage.get(usage_field), f"entries[{index}].usage.{usage_field}"
            )
        maximum_children = _positive_integer(
            lease.get("maximum_candidate_children"), f"entries[{index}].lease.maximum_candidate_children"
        )
        constitutional_children = _positive_integer(
            ceilings.get("maximum_candidate_children"), "constitution.maximum_candidate_children"
        )
        if maximum_children > constitutional_children:
            raise ResourceLedgerError(
                f"Resource ledger child ceiling {maximum_children} exceeds constitution {constitutional_children}."
            )
        normalized_lease["maximum_candidate_children"] = maximum_children
        candidate_inputs.append(
            {
                "candidate_id": candidate_id,
                "candidate_digest": candidate_digest,
                "parent_candidate_digest": parent_digest,
                "resource_lease_digest": require_string(
                    raw_entry.get("resource_lease_digest"), f"entries[{index}].resource_lease_digest"
                ),
                "lease": normalized_lease,
                "usage": normalized_usage,
                "evidence": _resource_reference_list(raw_entry.get("evidence"), f"entries[{index}].evidence"),
            }
        )
    entries: list[JsonObject] = []
    blockers: list[str] = []
    previous_entry_digest: str | None = None
    total_cycle_seconds = 0
    total_compute_units = 0
    peak_memory_megabytes = 0
    peak_storage_megabytes = 0
    for index, candidate_input in enumerate(candidate_inputs):
        candidate_digest = require_string(candidate_input.get("candidate_digest"), "candidate_digest")
        lease = require_object(candidate_input.get("lease"), "lease")
        usage = require_object(candidate_input.get("usage"), "usage")
        entry_blockers: list[str] = []
        for usage_field, ceiling_field in RESOURCE_DIMENSIONS.items():
            if require_integer(usage.get(usage_field), usage_field) > require_integer(lease.get(ceiling_field), ceiling_field):
                entry_blockers.append(f"{usage_field.upper()}_OVERRUN")
        child_count = child_counts.get(candidate_digest, 0)
        if child_count > require_integer(lease.get("maximum_candidate_children"), "maximum_candidate_children"):
            entry_blockers.append("CANDIDATE_CHILDREN_OVERRUN")
        entry: JsonObject = {
            "sequence": index + 1,
            **candidate_input,
            "child_count": child_count,
            "previous_entry_digest": previous_entry_digest,
            "status": "within_lease" if not entry_blockers else "overrun",
            "blockers": sorted(entry_blockers),
        }
        entries.append(entry)
        previous_entry_digest = sha256_digest(entry)
        blockers.extend(f"{code}:{candidate_input['candidate_id']}" for code in entry_blockers)
        total_cycle_seconds += require_integer(usage.get("cycle_seconds"), "usage.cycle_seconds")
        total_compute_units += require_integer(usage.get("compute_units"), "usage.compute_units")
        peak_memory_megabytes = max(
            peak_memory_megabytes,
            require_integer(usage.get("peak_memory_megabytes"), "usage.peak_memory_megabytes"),
        )
        peak_storage_megabytes = max(
            peak_storage_megabytes,
            require_integer(usage.get("peak_storage_megabytes"), "usage.peak_storage_megabytes"),
        )
    return {
        "ledger_version": "0.1.0",
        "ledger_id": ledger_id,
        "lineage_id": lineage_id,
        "origin": origin,
        "constitution_digest": sha256_digest(constitution),
        "governance_state_digest": sha256_digest(governance_state),
        "root_candidate_digest": candidate_inputs[0]["candidate_digest"],
        "generated_at": generated_at,
        "not_before": not_before,
        "expires_at": expires_at,
        "entries": entries,
        "head_entry_digest": previous_entry_digest,
        "totals": {
            "total_cycle_seconds": total_cycle_seconds,
            "total_compute_units": total_compute_units,
            "peak_memory_megabytes": peak_memory_megabytes,
            "peak_storage_megabytes": peak_storage_megabytes,
            "candidate_count": len(entries),
        },
        "status": "within_constitution" if not blockers else "blocked",
        "blockers": sorted(blockers),
        "authority": RESOURCE_LEDGER_AUTHORITY,
    }


def sign_lineage_resource_ledger(
    unsigned_ledger: JsonObject,
    connectors: list[SigningConnector],
) -> JsonObject:
    return sign_threshold_document(
        unsigned_ledger,
        connectors,
        RESOURCE_LEDGER_DOMAIN,
        "lineage resource ledger",
        ResourceLedgerError,
    )


def _ledger_time(value: object, field: str) -> datetime:
    try:
        return parse_timestamp(value, field)
    except ControlStateValidationError as error:
        raise ResourceLedgerError(f"Resource ledger time '{field}' is invalid: {error}.") from error


def verify_lineage_resource_ledger(
    ledger: JsonObject,
    constitution: JsonObject,
    governance_state: JsonObject,
    now: datetime,
    maximum_lifetime_seconds: int,
) -> JsonObject:
    if maximum_lifetime_seconds <= 0 or now.tzinfo is None:
        raise ResourceLedgerError("Resource ledger verification requires a positive lifetime and aware time.")
    generated_at = _ledger_time(ledger.get("generated_at"), "ledger.generated_at")
    not_before = _ledger_time(ledger.get("not_before"), "ledger.not_before")
    expires_at = _ledger_time(ledger.get("expires_at"), "ledger.expires_at")
    if generated_at < not_before or generated_at >= expires_at or now < not_before or now >= expires_at:
        raise ResourceLedgerError("Resource ledger is outside its active validity window.")
    if (expires_at - not_before).total_seconds() > maximum_lifetime_seconds:
        raise ResourceLedgerError(f"Resource ledger lifetime exceeds {maximum_lifetime_seconds} seconds.")
    if ledger.get("constitution_digest") != sha256_digest(constitution):
        raise ResourceLedgerError("Resource ledger constitution digest mismatch.")
    if ledger.get("governance_state_digest") != sha256_digest(governance_state):
        raise ResourceLedgerError("Resource ledger governance-state digest mismatch.")
    if require_object(ledger.get("authority"), "ledger.authority") != RESOURCE_LEDGER_AUTHORITY:
        raise ResourceLedgerError("Resource ledger exposes prohibited allocation or execution authority.")
    raw_entries = require_list(ledger.get("entries"), "ledger.entries")
    entries = [require_object(value, f"ledger.entries[{index}]") for index, value in enumerate(raw_entries)]
    reconstructed = build_lineage_resource_ledger(
        require_string(ledger.get("ledger_id"), "ledger.ledger_id"),
        require_string(ledger.get("lineage_id"), "ledger.lineage_id"),
        require_string(ledger.get("origin"), "ledger.origin"),
        constitution,
        governance_state,
        require_string(ledger.get("generated_at"), "ledger.generated_at"),
        require_string(ledger.get("not_before"), "ledger.not_before"),
        require_string(ledger.get("expires_at"), "ledger.expires_at"),
        _entry_inputs(entries),
    )
    unsigned = {key: value for key, value in ledger.items() if key != "signatures"}
    if reconstructed != unsigned:
        raise ResourceLedgerError("Resource ledger content, chain, totals, status, or blockers were substituted.")
    verified_signers, verified_roles = verify_threshold_signatures(
        ledger,
        governance_state,
        generated_at,
        RESOURCE_LEDGER_DOMAIN,
        "lineage resource ledger",
        ResourceLedgerError,
    )
    return {
        "verification_version": "0.1.0",
        "ledger_digest": sha256_digest(ledger),
        "ledger_id": ledger["ledger_id"],
        "lineage_id": ledger["lineage_id"],
        "origin": ledger["origin"],
        "root_candidate_digest": ledger["root_candidate_digest"],
        "head_entry_digest": ledger["head_entry_digest"],
        "entry_count": len(entries),
        "totals": ledger["totals"],
        "status": ledger["status"],
        "within_constitution": ledger["status"] == "within_constitution",
        "blockers": ledger["blockers"],
        "verified_signer_ids": verified_signers,
        "verified_roles": verified_roles,
        "authority": RESOURCE_LEDGER_AUTHORITY,
    }
