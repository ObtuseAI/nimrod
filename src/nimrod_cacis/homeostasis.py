"""Deterministic, replay-only metabolism, homeostasis, and Chronos controls."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import cast

from nimrod_simulator.errors import HomeostasisChronosError
from nimrod_simulator.jsonio import sha256_digest
from nimrod_simulator.model import JsonObject


RESOURCE_TYPES: tuple[str, ...] = (
    "cpu",
    "memory",
    "storage",
    "telemetry",
    "model",
    "sandbox",
    "simulation",
    "verification",
    "investigation",
)
SIGNAL_TYPES: tuple[str, ...] = (
    "telemetry_freshness",
    "evidence_completeness",
    "trust_health",
    "identity_health",
    "model_diversity",
    "sensor_health",
    "recovery_health",
    "verification_backlog",
    "threat_pressure",
    "false_positive_rate",
    "confidence_inflation",
    "agent_diversity",
    "resource_pressure",
)
CLOCK_TYPES: tuple[str, ...] = (
    "endpoint_millisecond",
    "identity_second",
    "containment_minute",
    "recovery_hour",
    "threat_intelligence_day",
    "architecture_week",
    "capability_month",
)
EXPECTED_SOURCE_DIGEST = "sha256:3bd1745396c7661dc351e51f006d79e2c0385857fcadb3a00cc746ae6b5c128f"
AUTHORITY: Mapping[str, bool] = {
    "can_authorize": False,
    "can_execute": False,
    "can_change_policy": False,
    "can_contact_targets": False,
    "can_use_credentials": False,
    "can_self_verify": False,
    "can_promote": False,
    "can_modify_constitution": False,
}


def require_object(value: object, label: str) -> JsonObject:
    if not isinstance(value, dict):
        raise HomeostasisChronosError(f"Homeostasis and Chronos {label} must be an object.")
    return cast(JsonObject, value)


def require_objects(value: object, label: str) -> tuple[JsonObject, ...]:
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise HomeostasisChronosError(f"Homeostasis and Chronos {label} must be a list of objects.")
    return tuple(cast(list[JsonObject], value))


def require_strings(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise HomeostasisChronosError(f"Homeostasis and Chronos {label} must be a list of strings.")
    values = tuple(cast(Sequence[str], value))
    if len(values) != len(set(values)):
        raise HomeostasisChronosError(f"Homeostasis and Chronos {label} must not contain duplicates.")
    return values


def parse_time(value: object, label: str) -> datetime:
    if not isinstance(value, str):
        raise HomeostasisChronosError(f"Homeostasis and Chronos {label} must be a timestamp.")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise HomeostasisChronosError(f"Homeostasis and Chronos {label} is invalid: value={value!r}.") from error


def require_exact_keys(value: JsonObject, expected: Sequence[str], label: str) -> None:
    if set(value) != set(expected):
        raise HomeostasisChronosError(
            f"Homeostasis and Chronos {label} keys must match exactly: expected={sorted(expected)!r}, received={sorted(value)!r}."
        )


def validate_authority(value: object) -> None:
    authority = require_object(value, "authority")
    if authority != AUTHORITY:
        raise HomeostasisChronosError(
            f"Homeostasis and Chronos authority must remain exactly denied: expected={dict(AUTHORITY)!r}, received={authority!r}."
        )


def validate_homeostasis_chronos_mission(mission: JsonObject) -> None:
    """Validate the W4 replay boundary and every scheduling input."""

    if mission.get("origin") != "replayed" or mission.get("maximum_outcome") != "schedule_proposal":
        raise HomeostasisChronosError("Homeostasis and Chronos is replay-only and schedule-proposal-only.")
    if mission.get("source_settlement_digest") != EXPECTED_SOURCE_DIGEST:
        raise HomeostasisChronosError("Homeostasis and Chronos must bind the canonical W3 settlement digest.")
    issued = parse_time(mission.get("issued_at"), "issued_at")
    evaluated = parse_time(mission.get("evaluated_at"), "evaluated_at")
    expires = parse_time(mission.get("expires_at"), "expires_at")
    if not issued <= evaluated < expires:
        raise HomeostasisChronosError("Homeostasis and Chronos requires issued_at <= evaluated_at < expires_at.")
    budget = require_object(mission.get("resource_budget"), "resource_budget")
    require_exact_keys(budget, RESOURCE_TYPES, "resource_budget")
    if any(not isinstance(value, int) or isinstance(value, bool) or value < 0 for value in budget.values()):
        raise HomeostasisChronosError("Homeostasis and Chronos resource budgets must be non-negative integers.")
    weights = require_object(mission.get("priority_weights"), "priority_weights")
    require_exact_keys(weights, ("information_gain", "risk_reduction", "recovery_improvement"), "priority_weights")
    if round(sum(float(cast(float, value)) for value in weights.values()), 6) != 1.0:
        raise HomeostasisChronosError("Homeostasis and Chronos priority weights must sum to exactly 1.0.")
    signals = require_objects(mission.get("signals"), "signals")
    if tuple(str(signal.get("signal")) for signal in signals) != SIGNAL_TYPES:
        raise HomeostasisChronosError("Homeostasis and Chronos must preserve all thirteen health signals in canonical order.")
    for signal in signals:
        observed = float(cast(float, signal.get("observed")))
        threshold = float(cast(float, signal.get("threshold")))
        if not 0.0 <= observed <= 1.0 or not 0.0 <= threshold <= 1.0:
            raise HomeostasisChronosError("Homeostasis and Chronos normalized signal values must be between zero and one.")
    confidence = require_object(mission.get("confidence_vector"), "confidence_vector")
    require_exact_keys(
        confidence,
        ("understanding", "calibration", "generalization", "verification", "maximum_inflation"),
        "confidence_vector",
    )
    values = [float(cast(float, value)) for value in confidence.values()]
    if any(value < 0.0 or value > 1.0 for value in values):
        raise HomeostasisChronosError("Homeostasis and Chronos confidence values must be normalized.")
    clocks = require_objects(mission.get("chronos_policy"), "chronos_policy")
    if tuple(str(clock.get("clock")) for clock in clocks) != CLOCK_TYPES:
        raise HomeostasisChronosError("Homeostasis and Chronos must preserve all seven canonical clocks in order.")
    for clock in clocks:
        fresh = clock.get("freshness_ms")
        stale = clock.get("expiry_ms")
        if not isinstance(fresh, int) or not isinstance(stale, int) or isinstance(fresh, bool) or fresh <= 0 or stale <= fresh:
            raise HomeostasisChronosError("Every Chronos clock requires 0 < freshness_ms < expiry_ms.")
    work_items = require_objects(mission.get("work_items"), "work_items")
    if len(work_items) < 5 or len({item.get("work_id") for item in work_items}) != len(work_items):
        raise HomeostasisChronosError("Homeostasis and Chronos requires at least five uniquely identified work items.")
    clock_names = set(CLOCK_TYPES)
    signal_names = set(SIGNAL_TYPES)
    for item in work_items:
        if item.get("clock") not in clock_names:
            raise HomeostasisChronosError("A Homeostasis work item references an unknown Chronos clock.")
        if parse_time(item.get("observed_at"), "work_items.observed_at") > evaluated:
            raise HomeostasisChronosError("A Homeostasis work item cannot contain future evidence.")
        costs = require_object(item.get("costs"), "work_items.costs")
        require_exact_keys(costs, RESOURCE_TYPES, "work_items.costs")
        if any(not isinstance(value, int) or isinstance(value, bool) or value < 0 for value in costs.values()):
            raise HomeostasisChronosError("Work item costs must be non-negative integers.")
        responses = require_strings(item.get("responds_to"), "work_items.responds_to")
        if not responses or not set(responses).issubset(signal_names):
            raise HomeostasisChronosError("Every work item must respond to known homeostatic signals.")
    validate_authority(mission.get("authority"))


def signal_is_breached(signal: JsonObject) -> bool:
    observed = float(cast(float, signal["observed"]))
    threshold = float(cast(float, signal["threshold"]))
    return observed < threshold if signal["healthy_when"] == "at_or_above" else observed > threshold


def assess_signals(mission: JsonObject) -> list[JsonObject]:
    confidence = require_object(mission["confidence_vector"], "confidence_vector")
    reference = min(
        float(cast(float, confidence["calibration"])),
        float(cast(float, confidence["generalization"])),
        float(cast(float, confidence["verification"])),
    )
    inflation = round(float(cast(float, confidence["understanding"])) - reference, 6)
    assessments: list[JsonObject] = []
    for raw_signal in require_objects(mission["signals"], "signals"):
        signal = dict(raw_signal)
        if signal["signal"] == "confidence_inflation":
            signal["observed"] = inflation
        breached = signal_is_breached(signal)
        assessments.append(
            {
                "signal": signal["signal"],
                "observed": signal["observed"],
                "threshold": signal["threshold"],
                "healthy_when": signal["healthy_when"],
                "state": "breached" if breached else "healthy",
            }
        )
    return assessments


def assess_clock(item: JsonObject, mission: JsonObject, clocks: Mapping[str, JsonObject]) -> JsonObject:
    age_ms = int((parse_time(mission["evaluated_at"], "evaluated_at") - parse_time(item["observed_at"], "observed_at")).total_seconds() * 1000)
    policy = clocks[str(item["clock"])]
    if age_ms <= int(cast(int, policy["freshness_ms"])):
        state = "fresh"
    elif age_ms <= int(cast(int, policy["expiry_ms"])):
        state = "stale"
    else:
        state = "expired"
    return {"work_id": item["work_id"], "clock": item["clock"], "age_ms": age_ms, "state": state}


def priority_score(item: JsonObject, weights: JsonObject, breached: frozenset[str], clock_state: str) -> float:
    value = (
        float(cast(float, weights["information_gain"])) * float(cast(float, item["expected_information_gain"]))
        + float(cast(float, weights["risk_reduction"])) * float(cast(float, item["expected_risk_reduction"]))
        + float(cast(float, weights["recovery_improvement"])) * float(cast(float, item["expected_recovery_improvement"]))
    )
    matching = len(set(require_strings(item["responds_to"], "responds_to")).intersection(breached))
    clock_bonus = 0.1 if clock_state == "stale" else 0.0
    return round(min(1.0, value + 0.03 * matching + clock_bonus), 6)


def can_allocate(costs: JsonObject, used: Mapping[str, int], budget: JsonObject) -> bool:
    return all(used[name] + int(cast(int, costs[name])) <= int(cast(int, budget[name])) for name in RESOURCE_TYPES)


def build_homeostasis_chronos_receipt(mission: JsonObject) -> JsonObject:
    """Build one deterministic non-authorizing W4 scheduling receipt."""

    validate_homeostasis_chronos_mission(mission)
    assessments = assess_signals(mission)
    breached = frozenset(str(item["signal"]) for item in assessments if item["state"] == "breached")
    clock_policies = {str(item["clock"]): item for item in require_objects(mission["chronos_policy"], "chronos_policy")}
    work_items = require_objects(mission["work_items"], "work_items")
    clock_assessments = [assess_clock(item, mission, clock_policies) for item in work_items]
    clock_by_work = {str(item["work_id"]): str(item["state"]) for item in clock_assessments}
    weights = require_object(mission["priority_weights"], "priority_weights")
    scored = sorted(
        work_items,
        key=lambda item: (-priority_score(item, weights, breached, clock_by_work[str(item["work_id"])]), str(item["work_id"])),
    )
    used: dict[str, int] = {name: 0 for name in RESOURCE_TYPES}
    budget = require_object(mission["resource_budget"], "resource_budget")
    decisions: list[JsonObject] = []
    for item in scored:
        work_id = str(item["work_id"])
        clock_state = clock_by_work[work_id]
        score = priority_score(item, weights, breached, clock_state)
        costs = require_object(item["costs"], "work_items.costs")
        if clock_state == "expired":
            action, reason = "abstained", "chronos_evidence_expired"
        elif item["prerequisites_satisfied"] is not True:
            action, reason = "abstained", "prerequisites_unsatisfied"
        elif can_allocate(costs, used, budget):
            action, reason = "scheduled", "bounded_lease_available"
            used = {name: used[name] + int(cast(int, costs[name])) for name in RESOURCE_TYPES}
        else:
            action, reason = "deferred", "resource_backpressure"
        decisions.append(
            {
                "work_id": work_id,
                "work_kind": item["work_kind"],
                "action": action,
                "priority_score": score,
                "reason": reason,
                "clock_state": clock_state,
                "costs": dict(costs),
            }
        )
    ledger = {name: {"capacity": budget[name], "allocated": used[name], "remaining": int(cast(int, budget[name])) - used[name]} for name in RESOURCE_TYPES}
    pressure_values = [float(cast(float, item["observed"])) for item in assessments if item["signal"] in {"verification_backlog", "threat_pressure", "false_positive_rate", "confidence_inflation", "resource_pressure"}]
    body: JsonObject = {
        "receipt_id": "74000000-0000-4000-8000-000000000100",
        "origin": "replayed",
        "status": "replay_valid_schedule_proposal_only",
        "mission_digest": sha256_digest(mission),
        "evaluated_at": mission["evaluated_at"],
        "signal_assessments": assessments,
        "chronos_assessments": clock_assessments,
        "allocation_decisions": decisions,
        "resource_ledger": ledger,
        "homeostasis": {
            "state": "degraded_bounded" if breached else "healthy_bounded",
            "breached_signals": sorted(breached),
            "breach_count": len(breached),
            "pressure_index": round(sum(pressure_values) / len(pressure_values), 6),
            "verification_backlog": next(item["observed"] for item in assessments if item["signal"] == "verification_backlog"),
            "confidence_inflation": next(item["observed"] for item in assessments if item["signal"] == "confidence_inflation"),
            "scheduled_count": sum(item["action"] == "scheduled" for item in decisions),
            "deferred_count": sum(item["action"] == "deferred" for item in decisions),
            "abstained_count": sum(item["action"] == "abstained" for item in decisions),
        },
        "security_claim": "Replay-only W4 scheduling preserves bounded resources, homeostatic pressure, confidence inflation, verifier backlog, and per-domain clock abstention; no execution or production control is authorized",
        "authority": dict(AUTHORITY),
    }
    receipt: JsonObject = {"receipt_version": "0.1.0", "receipt": body}
    return {**receipt, "receipt_digest": sha256_digest(receipt)}


def validate_homeostasis_chronos_receipt(mission: JsonObject, receipt: JsonObject) -> None:
    """Reject any W4 receipt not exactly reproducible from its bound mission."""

    if receipt.get("receipt_version") != "0.1.0":
        raise HomeostasisChronosError("Homeostasis and Chronos receipt version is unsupported.")
    body = require_object(receipt.get("receipt"), "receipt")
    unsigned: JsonObject = {"receipt_version": receipt["receipt_version"], "receipt": body}
    if receipt.get("receipt_digest") != sha256_digest(unsigned):
        raise HomeostasisChronosError("Homeostasis and Chronos receipt digest does not match canonical content.")
    expected = build_homeostasis_chronos_receipt(mission)
    if receipt != expected:
        raise HomeostasisChronosError("Homeostasis and Chronos receipt is not the deterministic result of its bound mission.")
