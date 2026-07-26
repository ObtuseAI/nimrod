"""Strict result types for the unprivileged Edge preview."""

from __future__ import annotations

from typing import TypedDict

from nimrod_simulator.model import JsonObject


class EdgePreviewResult(TypedDict):
    result_version: str
    run_id: str
    scenario_id: str
    scenario_digest: str
    origin: str
    status: str
    evaluated_at: str
    matched_rule_id: str
    risk: JsonObject
    explanation: list[str]
    uncertainties: list[str]
    references: JsonObject
    independent_verification: JsonObject
    witness: JsonObject
    authority: JsonObject
    security_claim: str
