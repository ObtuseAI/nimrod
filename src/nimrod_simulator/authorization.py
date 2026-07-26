"""Deterministic fail-closed lease and campaign evaluation."""

from __future__ import annotations

from datetime import datetime
from typing import cast

from nimrod_simulator.errors import (
    BudgetExceededError,
    CampaignLeaseMismatchError,
    CapabilityScopeError,
    CleanupContractError,
    ConnectorScopeError,
    ControlStateValidationError,
    EffectCeilingError,
    KillSwitchEngagedError,
    LeaseExpiredError,
    LeaseNotActiveError,
    LeaseReplayError,
    LeaseRevokedError,
    PreflightError,
    TargetScopeError,
)
from nimrod_simulator.jsonio import (
    require_boolean,
    require_integer,
    require_list,
    require_number,
    require_object,
    require_string,
    require_string_list,
)
from nimrod_simulator.model import ControlState, EffectClass, JsonObject, JsonValue


NOOP_CONNECTOR_ID = "connector.simulated.atomic"
NOOP_CAPABILITY = "range.test.simulate"
ALLOWED_ORIGINS = {"simulated"}
SAFE_REPLICA_ENVIRONMENTS = {"twin", "range", "sacrificial_replica"}
EFFECT_ALLOWLISTS: dict[str, set[str]] = {
    "observe_only": {"observe_only"},
    "reversible_local": {"observe_only", "reversible_local"},
    "reversible_distributed": {"observe_only", "reversible_local", "reversible_distributed"},
    "sacrificial_replica_only": {
        "observe_only",
        "reversible_local",
        "reversible_distributed",
        "sacrificial_replica_only",
    },
}


def parse_timestamp(value: JsonValue, field: str) -> datetime:
    raw = require_string(value, field)
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as error:
        raise ControlStateValidationError(f"Field '{field}' is not a valid ISO 8601 timestamp: {raw}") from error
    if parsed.tzinfo is None:
        raise ControlStateValidationError(f"Field '{field}' must include a UTC offset: {raw}")
    return parsed


def parse_control_state(value: JsonObject) -> ControlState:
    version = require_string(value.get("control_state_version"), "control_state_version")
    origin = require_string(value.get("origin"), "origin")
    authorization_mode = require_string(value.get("authorization_mode"), "authorization_mode")
    if version != "0.1.0":
        raise ControlStateValidationError(f"Unsupported control_state_version '{version}'; expected '0.1.0'.")
    if origin not in ALLOWED_ORIGINS:
        raise ControlStateValidationError(
            f"Control-state origin must be unambiguously 'simulated'; received '{origin}'."
        )
    if authorization_mode != "structural_fixture_only":
        raise ControlStateValidationError(
            "authorization_mode must be 'structural_fixture_only'; cryptographic authorization is not implemented."
        )
    usage = require_object(value.get("budget_usage"), "budget_usage")
    parsed: ControlState = {
        "control_state_version": version,
        "origin": "simulated",
        "authorization_mode": authorization_mode,
        "revoked_lease_ids": require_string_list(value.get("revoked_lease_ids"), "revoked_lease_ids"),
        "revoked_nonces": require_string_list(value.get("revoked_nonces"), "revoked_nonces"),
        "consumed_nonces": require_string_list(value.get("consumed_nonces"), "consumed_nonces"),
        "kill_switch_engaged": require_boolean(value.get("kill_switch_engaged"), "kill_switch_engaged"),
        "completed_preflight_requirements": require_string_list(
            value.get("completed_preflight_requirements"), "completed_preflight_requirements"
        ),
        "budget_usage": {
            "actions": require_integer(usage.get("actions"), "budget_usage.actions"),
            "seconds": require_integer(usage.get("seconds"), "budget_usage.seconds"),
            "cost_usd": require_number(usage.get("cost_usd"), "budget_usage.cost_usd"),
            "export_bytes": require_integer(usage.get("export_bytes"), "budget_usage.export_bytes"),
        },
    }
    if any(number < 0 for number in parsed["budget_usage"].values()):
        raise ControlStateValidationError("All budget_usage values must be zero or greater.")
    return parsed


def evaluate_lease_state(lease: JsonObject, control: ControlState, now: datetime) -> None:
    lease_id = require_string(lease.get("lease_id"), "lease_id")
    nonce = require_string(lease.get("nonce"), "nonce")
    not_before = parse_timestamp(lease.get("not_before"), "not_before")
    expires_at = parse_timestamp(lease.get("expires_at"), "expires_at")
    if now.tzinfo is None:
        raise ControlStateValidationError("Evaluation timestamp must include a UTC offset.")
    if now < not_before:
        raise LeaseNotActiveError(
            f"Lease '{lease_id}' is not active until {not_before.isoformat()}; evaluated at {now.isoformat()}."
        )
    if now >= expires_at:
        raise LeaseExpiredError(
            f"Lease '{lease_id}' expired at {expires_at.isoformat()}; evaluated at {now.isoformat()}."
        )
    if lease_id in control["revoked_lease_ids"] or nonce in control["revoked_nonces"]:
        raise LeaseRevokedError(f"Lease '{lease_id}' or nonce '{nonce}' is explicitly revoked.")
    if nonce in control["consumed_nonces"]:
        raise LeaseReplayError(f"Lease nonce '{nonce}' has already been consumed.")
    if control["kill_switch_engaged"]:
        kill_switch = require_object(lease.get("kill_switch"), "kill_switch")
        switch_id = require_string(kill_switch.get("id"), "kill_switch.id")
        raise KillSwitchEngagedError(
            f"Customer-controlled kill switch '{switch_id}' is engaged; no new actions are permitted."
        )


def require_preflight(lease: JsonObject, control: ControlState) -> None:
    required = set(require_string_list(lease.get("preflight_requirements"), "preflight_requirements"))
    completed = set(control["completed_preflight_requirements"])
    missing = sorted(required - completed)
    if missing:
        raise PreflightError(f"Missing explicit preflight evidence: {', '.join(missing)}")


def require_campaign_binding(lease: JsonObject, campaign: JsonObject) -> None:
    lease_id = require_string(lease.get("lease_id"), "lease_id")
    campaign_lease_id = require_string(campaign.get("authorization_lease_id"), "authorization_lease_id")
    if campaign_lease_id != lease_id:
        raise CampaignLeaseMismatchError(
            f"Campaign references lease '{campaign_lease_id}', but supplied lease is '{lease_id}'."
        )


def require_budget(lease: JsonObject, campaign: JsonObject, control: ControlState) -> None:
    budgets = require_object(lease.get("budgets"), "budgets")
    planned_actions = len(require_list(campaign.get("steps"), "steps"))
    checks: tuple[tuple[str, float, float], ...] = (
        (
            "actions",
            float(control["budget_usage"]["actions"] + planned_actions),
            float(require_integer(budgets.get("maximum_actions"), "budgets.maximum_actions")),
        ),
        (
            "seconds",
            float(control["budget_usage"]["seconds"]),
            float(require_integer(budgets.get("maximum_seconds"), "budgets.maximum_seconds")),
        ),
        (
            "cost_usd",
            control["budget_usage"]["cost_usd"],
            require_number(budgets.get("maximum_cost_usd"), "budgets.maximum_cost_usd"),
        ),
        (
            "export_bytes",
            float(control["budget_usage"]["export_bytes"]),
            float(require_integer(budgets.get("maximum_export_bytes"), "budgets.maximum_export_bytes")),
        ),
    )
    for budget_name, requested, maximum in checks:
        if requested > maximum:
            raise BudgetExceededError(
                f"Lease budget '{budget_name}' exceeded: requested total {requested:g}, maximum {maximum:g}."
            )


def target_index(lease: JsonObject) -> dict[str, JsonObject]:
    targets = require_list(lease.get("target_graph"), "target_graph")
    result: dict[str, JsonObject] = {}
    for index, target_value in enumerate(targets):
        target = require_object(target_value, f"target_graph[{index}]")
        stable_id = require_string(target.get("stable_id"), f"target_graph[{index}].stable_id")
        if stable_id in result:
            raise TargetScopeError(f"Target graph contains duplicate stable_id '{stable_id}'.")
        result[stable_id] = target
    return result


def require_effect_allowed(lease: JsonObject, target: JsonObject, effect_class: str, step_id: str) -> EffectClass:
    ceiling = require_string(lease.get("effect_ceiling"), "effect_ceiling")
    allowed = EFFECT_ALLOWLISTS.get(ceiling)
    if allowed is None or effect_class not in allowed:
        raise EffectCeilingError(
            f"Step '{step_id}' effect '{effect_class}' exceeds lease ceiling '{ceiling}'."
        )
    environment = require_string(target.get("environment_class"), "target.environment_class")
    if effect_class == "sacrificial_replica_only" and environment not in SAFE_REPLICA_ENVIRONMENTS:
        raise EffectCeilingError(
            f"Step '{step_id}' requires a twin, range, or sacrificial replica; target environment is '{environment}'."
        )
    return cast(EffectClass, effect_class)


def evaluate_step_scope(lease: JsonObject, campaign: JsonObject, step: JsonObject) -> tuple[JsonObject, EffectClass]:
    step_id = require_string(step.get("step_id"), "step.step_id")
    connector_id = require_string(step.get("connector_id"), f"{step_id}.connector_id")
    if connector_id != NOOP_CONNECTOR_ID:
        raise ConnectorScopeError(
            f"Step '{step_id}' requests connector '{connector_id}'; Stage 1 permits only '{NOOP_CONNECTOR_ID}'."
        )
    capability = require_string(step.get("capability"), f"{step_id}.capability")
    allowed_capabilities = set(require_string_list(lease.get("allowed_capabilities"), "allowed_capabilities"))
    if capability not in allowed_capabilities or capability != NOOP_CAPABILITY:
        raise CapabilityScopeError(
            f"Step '{step_id}' capability '{capability}' is not permitted by the lease and no-op connector."
        )
    targets = target_index(lease)
    target_id = require_string(step.get("target_id"), f"{step_id}.target_id")
    target = targets.get(target_id)
    if target is None:
        raise TargetScopeError(
            f"Step '{step_id}' target '{target_id}' is absent from the immutable lease target graph."
        )
    effect_class = require_string(step.get("effect_class"), f"{step_id}.effect_class")
    typed_effect = require_effect_allowed(lease, target, effect_class, step_id)
    cleanup_step_id = require_string(step.get("cleanup_step_id"), f"{step_id}.cleanup_step_id")
    cleanup_plan = require_string_list(campaign.get("cleanup_plan"), "cleanup_plan")
    if not any(cleanup_step_id in obligation for obligation in cleanup_plan):
        raise CleanupContractError(
            f"Step '{step_id}' cleanup '{cleanup_step_id}' is not represented in the campaign cleanup plan."
        )
    return target, typed_effect


def ordered_steps(campaign: JsonObject) -> list[JsonObject]:
    values = require_list(campaign.get("steps"), "steps")
    steps = [require_object(value, f"steps[{index}]") for index, value in enumerate(values)]
    return sorted(steps, key=lambda step: require_integer(step.get("sequence"), "step.sequence"))
