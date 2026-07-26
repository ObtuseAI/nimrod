"""Strict JSON and simulator data types."""

from __future__ import annotations

from typing import Literal, TypedDict


JsonScalar = str | int | float | bool | None
JsonValue = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]
JsonObject = dict[str, JsonValue]
Origin = Literal["simulated"]
EffectClass = Literal[
    "observe_only",
    "reversible_local",
    "reversible_distributed",
    "sacrificial_replica_only",
]


class BudgetUsage(TypedDict):
    actions: int
    seconds: int
    cost_usd: float
    export_bytes: int


class ControlState(TypedDict):
    control_state_version: str
    origin: Origin
    authorization_mode: str
    revoked_lease_ids: list[str]
    revoked_nonces: list[str]
    consumed_nonces: list[str]
    kill_switch_engaged: bool
    completed_preflight_requirements: list[str]
    budget_usage: BudgetUsage


class CompiledStep(TypedDict):
    step_id: str
    sequence: int
    connector_id: str
    capability: str
    target_id: str
    effect_class: EffectClass
    cleanup_step_id: str
    action_envelope: JsonObject


class ArtifactReference(TypedDict):
    id: str
    digest: str


class AuthorizationVerification(TypedDict):
    cryptographic_authorization_verified: bool
    lease_digest: str
    trust_policy_digest: str
    threshold: int
    verified_signer_ids: list[str]
    verified_roles: list[str]


class SimulationResult(TypedDict):
    run_version: str
    origin: Origin
    status: str
    live_execution_performed: bool
    cryptographic_authorization_verified: bool
    authorization_signers: list[str]
    lease_id: str
    campaign_id: str
    action_count: int
    verdict_statuses: list[str]
    artifacts: list[ArtifactReference]
    witness_journal: str


class SwarmReviewResult(TypedDict):
    review_version: str
    origin: Origin
    status: str
    mission_id: str
    cryptographic_authorization_verified: bool
    execution_authorized: bool
    distinct_role_count: int
    contribution_count: int
    dissent_count: int
    witness_entries_verified: int
    artifacts: list[ArtifactReference]
