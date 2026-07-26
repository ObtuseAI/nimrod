"""Fail-closed semantic validation for a subject protection profile."""

from __future__ import annotations

from typing import cast

from nimrod_simulator.errors import ProtectionProfileError
from nimrod_simulator.jsonio import require_boolean, require_integer, require_list, require_object, require_string, require_string_list
from nimrod_simulator.model import JsonObject


PROTECTION_PROFILE_CONTRACT = "protection-profile.schema.json"
ACTION_ENVIRONMENTS: frozenset[str] = frozenset({"range", "sacrificial_replica", "development", "staging", "production"})
SAFE_OFFLINE_BEHAVIORS: frozenset[str] = frozenset({"observe_only", "isolate", "deny_new_actions"})


def _require_unique(values: list[str], field: str) -> None:
    if len(values) != len(set(values)):
        raise ProtectionProfileError(f"Protection profile field '{field}' contains duplicates.")


def validate_protection_profile(profile: JsonObject) -> None:
    """Validate operational invariants not expressible through structure alone."""
    environment = require_string(profile.get("environment_class"), "environment_class")
    sensors = require_string_list(profile.get("sensors"), "sensors")
    actions = require_string_list(profile.get("allowed_action_classes"), "allowed_action_classes")
    prohibited = require_string_list(profile.get("prohibited_effects"), "prohibited_effects")
    limitations = require_string_list(profile.get("known_limitations"), "known_limitations")
    _require_unique(sensors, "sensors")
    _require_unique(actions, "allowed_action_classes")
    if not limitations:
        raise ProtectionProfileError("Protection profile must preserve at least one known limitation.")
    data_policy = require_object(profile.get("data_policy"), "data_policy")
    raw_export_allowed = require_boolean(data_policy.get("raw_export_allowed"), "data_policy.raw_export_allowed")
    retention_seconds = require_integer(data_policy.get("retention_seconds"), "data_policy.retention_seconds")
    if retention_seconds < 0:
        raise ProtectionProfileError("Protection profile retention cannot be negative.")
    if environment in {"range", "sacrificial_replica", "production"} and raw_export_allowed:
        raise ProtectionProfileError(f"Protection profile environment '{environment}' cannot export raw evidence.")
    if actions:
        if environment not in ACTION_ENVIRONMENTS:
            raise ProtectionProfileError(f"Protection profile environment '{environment}' cannot declare actions.")
        if require_string(profile.get("offline_behavior"), "offline_behavior") not in SAFE_OFFLINE_BEHAVIORS:
            raise ProtectionProfileError("Action-capable protection profile must fail closed while offline.")
        if not require_list(profile.get("safety_interlocks"), "safety_interlocks"):
            raise ProtectionProfileError("Action-capable protection profile requires a safety interlock.")
        if not require_list(profile.get("oracles"), "oracles"):
            raise ProtectionProfileError("Action-capable protection profile requires an independent oracle.")
        recovery = require_object(profile.get("recovery"), "recovery")
        if require_boolean(recovery.get("snapshot_required"), "recovery.snapshot_required") is not True:
            raise ProtectionProfileError("Action-capable protection profile requires snapshot-backed recovery.")
    required_prohibitions = ("external target", "secret exfiltration", "destructive data loss")
    normalized = " ".join(prohibited).lower()
    missing = [phrase for phrase in required_prohibitions if phrase not in normalized]
    if missing:
        raise ProtectionProfileError(
            f"Protection profile is missing prohibited-effect boundaries: {', '.join(missing)}."
        )
    subject = require_object(profile.get("subject"), "subject")
    require_string(subject.get("stable_id"), "subject.stable_id")
    require_string(subject.get("owner_id"), "subject.owner_id")
    if environment == "production" and not cast(list[object], require_list(profile.get("attestation"), "attestation")):
        raise ProtectionProfileError("Production protection profile requires attestation evidence.")
