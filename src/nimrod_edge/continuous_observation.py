"""Bounded, read-only Windows event observation for defensive Edge evidence."""

from __future__ import annotations

import hashlib
import subprocess
import time
import uuid
import xml.etree.ElementTree as ET
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime, timedelta
from pathlib import Path
from typing import Literal, TypedDict, cast

from nimrod_simulator.compiler import format_timestamp
from nimrod_simulator.errors import EdgeContinuousObservationError
from nimrod_simulator.jsonio import sha256_digest
from nimrod_simulator.model import JsonObject, JsonValue


SourceStatus = Literal["observed", "unavailable", "access_denied"]
EventReader = Callable[[str, int], "SourceRead"]
SleepOperation = Callable[[float], None]
SESSION_NAMESPACE = uuid.UUID("3ae90558-dc72-536a-8541-9a73e959ea08")
EVENT_NAMESPACE_URI = "http://schemas.microsoft.com/win/2004/08/events/event"
SOURCE_CHANNELS: Mapping[str, str] = {
    "powershell_operational": "Microsoft-Windows-PowerShell/Operational",
    "sysmon_operational": "Microsoft-Windows-Sysmon/Operational",
    "dns_client_operational": "Microsoft-Windows-DNS-Client/Operational",
}
AUTHORITY: Mapping[str, bool] = {
    "can_propose": False,
    "can_authorize": False,
    "can_execute": False,
    "can_modify_process": False,
    "can_modify_network": False,
    "can_change_policy": False,
}


class EventSummary(TypedDict):
    source_id: str
    channel: str
    provider_digest: str
    event_id: int
    record_id: int
    observed_at: str
    evidence_digest: str


class SourceRead(TypedDict):
    status: SourceStatus
    events: list[EventSummary]
    error_digest: str | None


def _text_digest(value: str) -> str:
    return f"sha256:{hashlib.sha256(value.encode('utf-8')).hexdigest()}"


def _require_positive_int(value: int, label: str) -> None:
    if value <= 0:
        raise EdgeContinuousObservationError(f"Continuous Edge {label} must be positive; received={value}.")


def _event_element_text(event: ET.Element, name: str) -> str:
    element = event.find(f"{{{EVENT_NAMESPACE_URI}}}System/{{{EVENT_NAMESPACE_URI}}}{name}")
    if element is None or element.text is None or not element.text:
        raise EdgeContinuousObservationError(f"Windows event XML is missing System/{name}.")
    return element.text


def _parse_event_xml(source_id: str, channel: str, output: str) -> list[EventSummary]:
    if not output.strip():
        return []
    wrapped = f"<Events>{output}</Events>"
    try:
        root = ET.fromstring(wrapped)
    except ET.ParseError as error:
        raise EdgeContinuousObservationError(
            f"Windows event source returned malformed XML: source_id={source_id!r}, channel={channel!r}, error={error}."
        ) from error
    events: list[EventSummary] = []
    for event in root:
        system = event.find(f"{{{EVENT_NAMESPACE_URI}}}System")
        if system is None:
            raise EdgeContinuousObservationError(f"Windows event XML lacks System metadata: source_id={source_id!r}.")
        provider = system.find(f"{{{EVENT_NAMESPACE_URI}}}Provider")
        time_created = system.find(f"{{{EVENT_NAMESPACE_URI}}}TimeCreated")
        provider_name = provider.get("Name") if provider is not None else None
        observed_at = time_created.get("SystemTime") if time_created is not None else None
        if not provider_name or not observed_at:
            raise EdgeContinuousObservationError(f"Windows event XML lacks provider or timestamp: source_id={source_id!r}.")
        canonical_event = ET.tostring(event, encoding="unicode")
        events.append(
            {
                "source_id": source_id,
                "channel": channel,
                "provider_digest": _text_digest(provider_name.casefold()),
                "event_id": int(_event_element_text(event, "EventID")),
                "record_id": int(_event_element_text(event, "EventRecordID")),
                "observed_at": observed_at,
                "evidence_digest": _text_digest(canonical_event),
            }
        )
    return events


class WindowsEventLogConnector:
    """External-system boundary for allowlisted, read-only Windows event queries."""

    def __init__(self, executable: Path, timeout_seconds: int) -> None:
        _require_positive_int(timeout_seconds, "event query timeout_seconds")
        self._executable = executable
        self._timeout_seconds = timeout_seconds

    def read(self, source_id: str, maximum_events: int) -> SourceRead:
        _require_positive_int(maximum_events, "maximum_events")
        channel = SOURCE_CHANNELS.get(source_id)
        if channel is None:
            raise EdgeContinuousObservationError(f"Continuous Edge source is not allowlisted: source_id={source_id!r}.")
        command = [
            str(self._executable),
            "qe",
            channel,
            f"/c:{maximum_events}",
            "/rd:true",
            "/f:xml",
        ]
        completed = subprocess.run(
            command,
            capture_output=True,
            check=False,
            text=True,
            timeout=self._timeout_seconds,
            encoding="utf-8",
            errors="replace",
        )
        if completed.returncode == 0:
            return {"status": "observed", "events": _parse_event_xml(source_id, channel, completed.stdout), "error_digest": None}
        error_text = f"{completed.stdout}\n{completed.stderr}".strip()
        folded = error_text.casefold()
        if "access is denied" in folded:
            return {"status": "access_denied", "events": [], "error_digest": _text_digest(error_text)}
        if "specified channel could not be found" in folded or "failed to open event query" in folded:
            return {"status": "unavailable", "events": [], "error_digest": _text_digest(error_text)}
        raise EdgeContinuousObservationError(
            "Windows event query failed outside the explicit unavailable/access-denied states: "
            f"source_id={source_id!r}, channel={channel!r}, returncode={completed.returncode}, "
            f"error_digest={_text_digest(error_text)!r}."
        )


def collect_continuous_observation(
    source_ids: Sequence[str],
    poll_cycles: int,
    poll_interval_seconds: float,
    maximum_events_per_source: int,
    started_at: datetime,
    read_operation: EventReader,
    sleep_operation: SleepOperation,
    origin: str,
) -> JsonObject:
    """Collect a bounded multi-cycle session and retain only deduplicated event metadata and digests."""
    _require_positive_int(poll_cycles, "poll_cycles")
    _require_positive_int(maximum_events_per_source, "maximum_events_per_source")
    if poll_interval_seconds < 0:
        raise EdgeContinuousObservationError("Continuous Edge poll_interval_seconds cannot be negative.")
    if origin not in {"live", "replayed"}:
        raise EdgeContinuousObservationError(f"Continuous Edge origin is unsupported: origin={origin!r}.")
    if tuple(source_ids) != tuple(SOURCE_CHANNELS):
        raise EdgeContinuousObservationError(
            f"Continuous Edge requires the exact ordered source allowlist: received={tuple(source_ids)!r}."
        )
    source_states: dict[str, SourceStatus] = {source_id: "unavailable" for source_id in source_ids}
    error_digests: dict[str, str | None] = {source_id: None for source_id in source_ids}
    unique_events: dict[tuple[str, int], EventSummary] = {}
    for cycle in range(poll_cycles):
        for source_id in source_ids:
            result = read_operation(source_id, maximum_events_per_source)
            source_states[source_id] = result["status"]
            error_digests[source_id] = result["error_digest"]
            for event in result["events"]:
                if event["source_id"] != source_id or event["channel"] != SOURCE_CHANNELS[source_id]:
                    raise EdgeContinuousObservationError(
                        f"Continuous Edge reader returned cross-source evidence: source_id={source_id!r}, event={event!r}."
                    )
                unique_events[(source_id, event["record_id"])] = event
        if cycle + 1 < poll_cycles:
            sleep_operation(poll_interval_seconds)
    events = sorted(unique_events.values(), key=lambda item: (item["observed_at"], item["source_id"], item["record_id"]))
    started_at_text = format_timestamp(started_at)
    completed_at_text = format_timestamp(started_at + timedelta(seconds=poll_interval_seconds * max(poll_cycles - 1, 0)))
    sources: list[JsonObject] = []
    for source_id in source_ids:
        sources.append(
            {
                "source_id": source_id,
                "channel": SOURCE_CHANNELS[source_id],
                "status": source_states[source_id],
                "event_count": len([event for event in events if event["source_id"] == source_id]),
                "error_digest": error_digests[source_id],
            }
        )
    status = (
        "EDGE_CONTINUOUS_OBSERVATION_COMPLETE_POLICY_AND_ACTION_BLOCKED"
        if all(source["status"] == "observed" for source in sources)
        else "EDGE_CONTINUOUS_OBSERVATION_INCOMPLETE_POLICY_AND_ACTION_BLOCKED"
    )
    session_id = str(uuid.uuid5(SESSION_NAMESPACE, f"{origin}:{started_at_text}:{poll_cycles}:{maximum_events_per_source}"))
    document: JsonObject = {
        "observation_version": "0.1.0",
        "session_id": session_id,
        "origin": origin,
        "status": status,
        "platform": "windows",
        "started_at": started_at_text,
        "completed_at": completed_at_text,
        "poll_cycles": poll_cycles,
        "poll_interval_seconds": poll_interval_seconds,
        "maximum_events_per_source": maximum_events_per_source,
        "sources": sources,
        "events": cast(JsonValue, events),
        "event_set_digest": sha256_digest(cast(JsonValue, events)),
        "collector": {
            "interface": "wevtutil_query_events_read_only" if origin == "live" else "deterministic_replay_reader",
            "allowlisted_channels_only": True,
            "raw_event_payload_retained": False,
            "writes_performed": False,
            "active_network_probe_performed": False,
        },
        "policy_input": {
            "ready": False,
            "reason": "independent verification and cross-source correlation are required",
        },
        "authority": dict(AUTHORITY),
    }
    validate_continuous_observation(document)
    return document


def validate_continuous_observation(document: JsonObject) -> None:
    expected_fields = {
        "observation_version", "session_id", "origin", "status", "platform", "started_at", "completed_at",
        "poll_cycles", "poll_interval_seconds", "maximum_events_per_source", "sources", "events", "event_set_digest",
        "collector", "policy_input", "authority",
    }
    if set(document) != expected_fields or document.get("observation_version") != "0.1.0":
        raise EdgeContinuousObservationError("Continuous Edge observation fields or version are invalid.")
    if document.get("authority") != AUTHORITY:
        raise EdgeContinuousObservationError("Continuous Edge observation exposes prohibited authority.")
    collector = document.get("collector")
    policy_input = document.get("policy_input")
    sources = document.get("sources")
    events = document.get("events")
    if not isinstance(collector, dict) or not isinstance(policy_input, dict):
        raise EdgeContinuousObservationError("Continuous Edge collector and policy input must be objects.")
    if not isinstance(sources, list) or not all(isinstance(source, dict) for source in sources):
        raise EdgeContinuousObservationError("Continuous Edge sources must be typed objects.")
    if not isinstance(events, list) or not all(isinstance(event, dict) for event in events):
        raise EdgeContinuousObservationError("Continuous Edge events must be typed objects.")
    if [source.get("source_id") for source in sources] != list(SOURCE_CHANNELS):
        raise EdgeContinuousObservationError("Continuous Edge source set is incomplete or reordered.")
    if collector.get("allowlisted_channels_only") is not True:
        raise EdgeContinuousObservationError("Continuous Edge collector did not preserve its channel allowlist.")
    for field in ("raw_event_payload_retained", "writes_performed", "active_network_probe_performed"):
        if collector.get(field) is not False:
            raise EdgeContinuousObservationError(f"Continuous Edge collector widened prohibited field: field={field!r}.")
    if policy_input.get("ready") is not False:
        raise EdgeContinuousObservationError("Continuous Edge evidence cannot self-declare policy readiness.")
    event_keys: set[tuple[object, object]] = set()
    for event in cast(list[JsonObject], events):
        if set(event) != {"source_id", "channel", "provider_digest", "event_id", "record_id", "observed_at", "evidence_digest"}:
            raise EdgeContinuousObservationError("Continuous Edge event contains raw or untyped fields.")
        key = (event.get("source_id"), event.get("record_id"))
        if key in event_keys:
            raise EdgeContinuousObservationError(f"Continuous Edge event set contains a duplicate: key={key!r}.")
        event_keys.add(key)
        source_id = str(event.get("source_id"))
        if event.get("channel") != SOURCE_CHANNELS.get(source_id):
            raise EdgeContinuousObservationError(f"Continuous Edge event channel is not source-bound: source_id={source_id!r}.")
    if document.get("event_set_digest") != sha256_digest(cast(JsonValue, events)):
        raise EdgeContinuousObservationError("Continuous Edge event-set digest is invalid.")
    for source in cast(list[JsonObject], sources):
        source_id = str(source.get("source_id"))
        expected_count = len([event for event in events if event.get("source_id") == source_id])
        if source.get("event_count") != expected_count:
            raise EdgeContinuousObservationError(f"Continuous Edge source count mismatch: source_id={source_id!r}.")


def collect_live_continuous_observation(
    poll_cycles: int,
    poll_interval_seconds: float,
    maximum_events_per_source: int,
    started_at: datetime,
    query_timeout_seconds: int,
) -> JsonObject:
    connector = WindowsEventLogConnector(Path("wevtutil.exe"), query_timeout_seconds)
    return collect_continuous_observation(
        tuple(SOURCE_CHANNELS),
        poll_cycles,
        poll_interval_seconds,
        maximum_events_per_source,
        started_at,
        connector.read,
        time.sleep,
        "live",
    )
