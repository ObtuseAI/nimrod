"""Externally rooted, threshold-signed Evolution Constitution verification."""

from __future__ import annotations

from datetime import datetime

from nimrod_simulator.authorization import parse_timestamp
from nimrod_simulator.errors import ControlStateValidationError, EvolutionConstitutionError
from nimrod_simulator.jsonio import require_boolean, require_integer, require_list, require_object, require_string, sha256_digest
from nimrod_simulator.key_governance import SigningConnector, validate_governance_state
from nimrod_simulator.model import JsonObject
from nimrod_simulator.threshold_signing import sign_threshold_document, threshold_message, verify_threshold_signatures


EVOLUTION_CONSTITUTION_DOMAIN = b"nimrod.evolution-constitution.v0.1\x00"

REQUIRED_AXIOMS = {
    "CONSTITUTIONAL_ROOT_IMMUTABILITY",
    "CANDIDATE_ONLY_MUTATION",
    "NO_SELF_AUTHORIZATION",
    "AUTHORITY_MONOTONICITY",
    "CORRIGIBILITY_AND_STOP_DOMINANCE",
    "NO_AUTONOMOUS_REPLICATION_OR_RESOURCE_ACQUISITION",
    "EPISTEMIC_TYPING",
    "DECLARED_EPISTEMIC_POSTURE",
    "EVIDENCE_BEFORE_SUCCESS",
    "LEXICOGRAPHIC_HARD_GATES",
    "NO_UNIVERSAL_SUPERIORITY_CLAIM",
    "EVALUATOR_INDEPENDENCE",
    "CHAMPION_AND_REGRESSION_FLOORS",
    "BOUNDED_RESOURCES_AND_TERMINATION",
    "REVERSIBILITY_BY_CONSTRUCTION",
    "CAPABILITY_TRIGGERED_SAFEGUARDS",
    "SEPARATION_OF_DUTIES",
    "HUMAN_AND_RIGHTS_FLOOR",
    "TAMPER_EVIDENT_MEMORY",
    "NO_PRODUCTION_LEARNING_BY_DEFAULT",
}

REQUIRED_HARD_FAILURES = {
    "UNAUTHORIZED_ACTION",
    "FABRICATED_EVIDENCE",
    "SECRET_DISCLOSURE",
    "EVALUATOR_MANIPULATION",
    "SAFEGUARD_WEAKENING",
    "ROLLBACK_FAILURE",
    "RIGHTS_VIOLATION",
    "UNBOUNDED_RESOURCE_USE",
}

REQUIRED_CAPABILITY_RESPONSES = {
    "AUTONOMOUS_AI_RND": "isolated_enclave",
    "LONG_RANGE_AUTONOMY": "elevated",
    "REPLICATION_ADAPTATION": "pause",
    "PERSISTENCE_RESOURCE_ACQUISITION": "pause",
    "SANDBAGGING": "pause",
    "SAFEGUARD_UNDERMINING": "pause",
}

REQUIRED_TIER_POLICIES = {
    "A": ("shadow", False),
    "B": ("shadow", False),
    "C": ("production_candidate", True),
    "D": ("quarantine", True),
}

REQUIRED_RESOURCE_FIELDS = {
    "maximum_cycle_seconds",
    "maximum_compute_units",
    "maximum_memory_megabytes",
    "maximum_storage_megabytes",
    "maximum_candidate_children",
}


def evolution_constitution_message(constitution: JsonObject) -> bytes:
    return threshold_message(constitution, EVOLUTION_CONSTITUTION_DOMAIN)


def sign_evolution_constitution(
    unsigned_constitution: JsonObject, connectors: list[SigningConnector]
) -> JsonObject:
    return sign_threshold_document(
        unsigned_constitution,
        connectors,
        EVOLUTION_CONSTITUTION_DOMAIN,
        "evolution constitution",
        EvolutionConstitutionError,
    )


def _timestamp(value: object, field: str) -> datetime:
    try:
        return parse_timestamp(value, field)
    except ControlStateValidationError as error:
        raise EvolutionConstitutionError(f"Evolution Constitution timestamp '{field}' is invalid: {error}.") from error


def verify_evolution_constitution(
    constitution: JsonObject,
    governance_state: JsonObject,
    now: datetime,
    maximum_lifetime_seconds: int,
) -> JsonObject:
    if now.utcoffset() is None:
        raise EvolutionConstitutionError("Evolution Constitution verification time must be timezone-aware.")
    if maximum_lifetime_seconds <= 0:
        raise EvolutionConstitutionError("Evolution Constitution maximum lifetime must be positive.")
    validate_governance_state(governance_state)
    if constitution.get("constitution_version") != "0.1.0" or constitution.get("origin") != "simulated":
        raise EvolutionConstitutionError("Evolution Constitution must be version 0.1.0 and simulated.")
    if constitution.get("governance_state_digest") != sha256_digest(governance_state):
        raise EvolutionConstitutionError("Evolution Constitution governance-state digest mismatch.")
    authority = require_object(constitution.get("authority"), "constitution.authority")
    required_authority = {
        "can_modify_itself": False,
        "can_select_evaluators": False,
        "can_select_signers": False,
        "can_expand_authority": False,
        "can_execute": False,
    }
    if authority != required_authority:
        raise EvolutionConstitutionError("Evolution Constitution authority must remain exactly false.")
    axioms = [require_string(value, "constitution.axiom") for value in require_list(constitution.get("axioms"), "constitution.axioms")]
    if len(axioms) != len(set(axioms)) or set(axioms) != REQUIRED_AXIOMS:
        raise EvolutionConstitutionError("Evolution Constitution must contain each required axiom exactly once.")
    hard_failures = [require_string(value, "constitution.hard_failure") for value in require_list(constitution.get("hard_failures"), "constitution.hard_failures")]
    if len(hard_failures) != len(set(hard_failures)) or set(hard_failures) != REQUIRED_HARD_FAILURES:
        raise EvolutionConstitutionError("Evolution Constitution must contain each hard failure exactly once.")
    trigger_values = require_list(constitution.get("capability_triggers"), "constitution.capability_triggers")
    trigger_responses: dict[str, str] = {}
    for index, value in enumerate(trigger_values):
        trigger = require_object(value, f"constitution.capability_triggers[{index}]")
        trigger_id = require_string(trigger.get("trigger_id"), f"capability_triggers[{index}].trigger_id")
        if trigger_id in trigger_responses:
            raise EvolutionConstitutionError(f"Evolution Constitution repeats capability trigger '{trigger_id}'.")
        trigger_responses[trigger_id] = require_string(trigger.get("response"), f"capability_triggers[{index}].response")
    if trigger_responses != REQUIRED_CAPABILITY_RESPONSES:
        raise EvolutionConstitutionError("Evolution Constitution capability-trigger responses are incomplete or weakened.")
    tier_values = require_list(constitution.get("tier_policies"), "constitution.tier_policies")
    tier_policies: dict[str, tuple[str, bool]] = {}
    for index, value in enumerate(tier_values):
        policy = require_object(value, f"constitution.tier_policies[{index}]")
        tier = require_string(policy.get("tier"), f"tier_policies[{index}].tier")
        if tier in tier_policies:
            raise EvolutionConstitutionError(f"Evolution Constitution repeats tier policy '{tier}'.")
        tier_policies[tier] = (
            require_string(policy.get("maximum_destination"), f"tier_policies[{index}].maximum_destination"),
            require_boolean(policy.get("threshold_humans_required"), f"tier_policies[{index}].threshold_humans_required"),
        )
    if tier_policies != REQUIRED_TIER_POLICIES:
        raise EvolutionConstitutionError("Evolution Constitution tier policies are incomplete or weakened.")
    ceilings = require_object(constitution.get("resource_ceilings"), "constitution.resource_ceilings")
    if set(ceilings) != REQUIRED_RESOURCE_FIELDS:
        raise EvolutionConstitutionError("Evolution Constitution resource ceilings must use the exact required fields.")
    for field in REQUIRED_RESOURCE_FIELDS:
        if require_integer(ceilings.get(field), f"resource_ceilings.{field}") <= 0:
            raise EvolutionConstitutionError(f"Evolution Constitution resource ceiling '{field}' must be positive.")
    issued_at = _timestamp(constitution.get("issued_at"), "constitution.issued_at")
    not_before = _timestamp(constitution.get("not_before"), "constitution.not_before")
    expires_at = _timestamp(constitution.get("expires_at"), "constitution.expires_at")
    if issued_at > not_before or not_before >= expires_at:
        raise EvolutionConstitutionError("Evolution Constitution requires issued_at <= not_before < expires_at.")
    if int((expires_at - issued_at).total_seconds()) > maximum_lifetime_seconds:
        raise EvolutionConstitutionError("Evolution Constitution lifetime exceeds the configured maximum.")
    if now < not_before or now >= expires_at:
        raise EvolutionConstitutionError("Evolution Constitution is inactive or expired.")
    verified_signers, verified_roles = verify_threshold_signatures(
        constitution,
        governance_state,
        issued_at,
        EVOLUTION_CONSTITUTION_DOMAIN,
        "evolution constitution",
        EvolutionConstitutionError,
    )
    return {
        "constitution_digest": sha256_digest(constitution),
        "verified_signer_ids": verified_signers,
        "verified_roles": verified_roles,
        "expires_at": constitution["expires_at"],
        "authority": required_authority,
    }
