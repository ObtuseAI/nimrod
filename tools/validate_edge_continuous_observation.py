"""Validate bounded replay and live Windows event observation without action authority."""

from __future__ import annotations

import copy
import json
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

from nimrod_edge.continuous_observation import (
    EVENT_NAMESPACE_URI,
    SOURCE_CHANNELS,
    EventSummary,
    SourceRead,
    collect_continuous_observation,
    collect_live_continuous_observation,
    validate_continuous_observation,
)
from nimrod_simulator.errors import EdgeContinuousObservationError
from nimrod_simulator.model import JsonObject


def require_condition(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def expect_error(operation: Callable[[], object], label: str) -> None:
    try:
        operation()
    except EdgeContinuousObservationError:
        return
    raise RuntimeError(f"Expected EdgeContinuousObservationError for {label}.")


def event(source_id: str, record_id: int, observed_at: str) -> EventSummary:
    return {
        "source_id": source_id,
        "channel": SOURCE_CHANNELS[source_id],
        "provider_digest": "sha256:" + "1" * 64,
        "event_id": 4104 if source_id == "powershell_operational" else 22,
        "record_id": record_id,
        "observed_at": observed_at,
        "evidence_digest": "sha256:" + f"{record_id:064x}",
    }


def replay_reader() -> Callable[[str, int], SourceRead]:
    calls: dict[str, int] = {source_id: 0 for source_id in SOURCE_CHANNELS}

    def read(source_id: str, maximum_events: int) -> SourceRead:
        require_condition(maximum_events == 4, "Replay reader received an unexpected event bound.")
        calls[source_id] += 1
        if source_id == "sysmon_operational":
            return {"status": "unavailable", "events": [], "error_digest": "sha256:" + "9" * 64}
        record_id = calls[source_id]
        return {
            "status": "observed",
            "events": [event(source_id, record_id, f"2026-07-16T08:00:0{record_id}Z")],
            "error_digest": None,
        }

    return read


def validate_edge_continuous_observation(project_root: Path) -> JsonObject:
    del project_root
    started_at = datetime(2026, 7, 16, 8, 0, 0, tzinfo=timezone.utc)
    replay = collect_continuous_observation(
        tuple(SOURCE_CHANNELS),
        2,
        0.0,
        4,
        started_at,
        replay_reader(),
        lambda delay_seconds: None,
        "replayed",
    )
    require_condition(len(replay["events"]) == 4, "Replay observation did not deduplicate its bounded event set.")
    require_condition(replay["status"] == "EDGE_CONTINUOUS_OBSERVATION_INCOMPLETE_POLICY_AND_ACTION_BLOCKED", "Replay did not preserve optional Sysmon unavailability.")
    live = collect_live_continuous_observation(1, 0.0, 1, datetime.now(timezone.utc).replace(microsecond=0), 10)
    require_condition(len(live["sources"]) == 3, "Live observation did not inspect all three allowlisted channels.")
    require_condition(live["collector"]["interface"] == "wevtutil_query_events_read_only", "Live observation did not use the Windows event-log connector.")

    adversarial_count = 0
    widened = copy.deepcopy(replay)
    widened["authority"]["can_execute"] = True
    expect_error(lambda: validate_continuous_observation(widened), "execution authority widening")
    adversarial_count += 1
    raw_payload = copy.deepcopy(replay)
    raw_payload["events"][0]["raw_xml"] = f"<{EVENT_NAMESPACE_URI}>secret</{EVENT_NAMESPACE_URI}>"
    expect_error(lambda: validate_continuous_observation(raw_payload), "raw payload retention")
    adversarial_count += 1
    ready = copy.deepcopy(replay)
    ready["policy_input"]["ready"] = True
    expect_error(lambda: validate_continuous_observation(ready), "policy readiness laundering")
    adversarial_count += 1
    cross_source = copy.deepcopy(replay)
    cross_source["events"][0]["channel"] = SOURCE_CHANNELS["sysmon_operational"]
    cross_source["event_set_digest"] = "sha256:" + "0" * 64
    expect_error(lambda: validate_continuous_observation(cross_source), "cross-source channel substitution")
    adversarial_count += 1
    expect_error(
        lambda: collect_continuous_observation(
            ("powershell_operational",), 1, 0.0, 1, started_at, replay_reader(), lambda delay_seconds: None, "replayed"
        ),
        "source allowlist reduction",
    )
    adversarial_count += 1
    return {
        "status": "EDGE_CONTINUOUS_DEFENSIVE_OBSERVATION_VALID_POLICY_AND_ACTION_BLOCKED",
        "replay_poll_cycle_count": 2,
        "replay_event_count": len(replay["events"]),
        "live_poll_cycle_count": 1,
        "live_source_count": len(live["sources"]),
        "live_event_count": len(live["events"]),
        "live_source_statuses": {source["source_id"]: source["status"] for source in live["sources"]},
        "negative_fail_closed_case_count": adversarial_count,
        "raw_event_payload_retained": False,
        "active_network_probe_performed": False,
        "policy_input_ready": False,
        "execution_authorized": False,
        "execution_performed": False,
        "target_state_changed": False,
    }


def main() -> None:
    project_root = Path(__file__).resolve().parents[1]
    result = validate_edge_continuous_observation(project_root)
    report_path = project_root / "reports" / "EDGE_CONTINUOUS_OBSERVATION_VALIDATION.json"
    report_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
