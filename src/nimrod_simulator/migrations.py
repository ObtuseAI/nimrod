"""Explicit pure migrations for versioned nimrod contracts."""

from __future__ import annotations

import copy

from nimrod_simulator.errors import ContractValidationError
from nimrod_simulator.model import JsonObject


def migrate_causal_verdict_0_1_to_0_2(value: JsonObject, origin: str) -> JsonObject:
    version = value.get("verdict_version")
    if version != "0.1.0":
        raise ContractValidationError(
            f"Causal verdict migration requires version '0.1.0'; received {version!r}."
        )
    if "origin" in value:
        raise ContractValidationError("Legacy causal verdict unexpectedly contains an origin field.")
    if origin not in {"simulated", "replayed", "range", "sacrificial_replica", "live"}:
        raise ContractValidationError(f"Unsupported causal verdict migration origin '{origin}'.")
    migrated = copy.deepcopy(value)
    migrated["verdict_version"] = "0.2.0"
    migrated["origin"] = origin
    return migrated
