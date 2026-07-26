"""Fail-closed semantic checks for the CACIS target architecture roadmap."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import cast

from nimrod_simulator.errors import SimulatorError
from nimrod_simulator.model import JsonObject


EXPECTED_INVARIANTS: frozenset[str] = frozenset(
    {
        "operator_authority",
        "execution_authority",
        "constitutional_law",
        "trust_anchors",
        "threshold_signatures",
        "evidence_law",
        "recovery_verification",
        "cryptographic_trust",
        "promotion_requirements",
        "safety_ceilings",
    }
)

EXPECTED_PLANE_OUTCOMES: Mapping[str, tuple[str, bool]] = {
    "constitutional_kernel": ("deterministic_policy_decision", True),
    "sovereign_governor": ("scheduling_decision", False),
    "immune_runtime": ("typed_proposal", False),
    "world_model": ("derived_state", False),
    "hypothesis_cortex": ("ranked_hypothesis_set", False),
    "truth_recovery_settlement": ("verification_or_settlement", False),
    "genome_evolution_foundry": ("candidate_bundle", False),
    "observatory": ("display_projection", False),
}

EXPECTED_REWARD_HACKING_DEFENSES: frozenset[str] = frozenset(
    {
        "future_leakage",
        "telemetry_leakage",
        "replay_contamination",
        "simulation_exploitation",
        "verifier_exploitation",
        "authority_expansion",
        "confidence_gaming",
        "recovery_gaming",
        "complexity_inflation",
    }
)

FALSE_AUTHORITY: Mapping[str, bool] = {
    "can_authorize_execution": False,
    "can_execute": False,
    "can_modify_constitution": False,
    "can_modify_trust": False,
    "can_promote": False,
    "can_contact_targets": False,
    "can_provision": False,
}


def require_object(value: object, label: str) -> JsonObject:
    if not isinstance(value, dict):
        raise SimulatorError(f"CACIS roadmap {label} must be an object.")
    return cast(JsonObject, value)


def require_object_list(value: object, label: str) -> tuple[JsonObject, ...]:
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise SimulatorError(f"CACIS roadmap {label} must be a list of objects.")
    return tuple(cast(JsonObject, item) for item in value)


def require_string_set(value: object, label: str) -> frozenset[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise SimulatorError(f"CACIS roadmap {label} must be a list of strings.")
    strings = cast(Sequence[str], value)
    if len(strings) != len(set(strings)):
        raise SimulatorError(f"CACIS roadmap {label} must not contain duplicates.")
    return frozenset(strings)


def validate_invariants(roadmap: JsonObject) -> None:
    invariants = require_string_set(roadmap.get("constitutional_invariants"), "constitutional_invariants")
    if invariants != EXPECTED_INVARIANTS:
        raise SimulatorError(
            "CACIS roadmap constitutional invariants must match the immutable set exactly: "
            f"expected={sorted(EXPECTED_INVARIANTS)!r}, received={sorted(invariants)!r}."
        )


def validate_planes(roadmap: JsonObject) -> None:
    planes = require_object_list(roadmap.get("planes"), "planes")
    plane_ids = tuple(str(plane.get("plane_id") or "") for plane in planes)
    if len(plane_ids) != len(set(plane_ids)) or set(plane_ids) != set(EXPECTED_PLANE_OUTCOMES):
        raise SimulatorError(
            "CACIS roadmap planes must contain every constitutional plane exactly once: "
            f"received={plane_ids!r}."
        )
    for plane in planes:
        plane_id = str(plane["plane_id"])
        expected_outcome, expected_authorization = EXPECTED_PLANE_OUTCOMES[plane_id]
        if plane.get("maximum_outcome") != expected_outcome:
            raise SimulatorError(
                "CACIS roadmap plane maximum outcome widened or mismatched: "
                f"plane_id={plane_id!r}, expected={expected_outcome!r}, "
                f"received={plane.get('maximum_outcome')!r}."
            )
        if plane.get("can_authorize") is not expected_authorization:
            raise SimulatorError(
                "Only the existing constitutional kernel may authorize deterministic policy decisions: "
                f"plane_id={plane_id!r}, can_authorize={plane.get('can_authorize')!r}."
            )
        for denied_field in ("can_self_authorize", "can_execute", "can_modify_constitution"):
            if plane.get(denied_field) is not False:
                raise SimulatorError(
                    "CACIS roadmap plane violates an immutable authority denial: "
                    f"plane_id={plane_id!r}, field={denied_field!r}, value={plane.get(denied_field)!r}."
                )


def validate_waves(roadmap: JsonObject) -> None:
    waves = require_object_list(roadmap.get("waves"), "waves")
    sequences = tuple(wave.get("sequence") for wave in waves)
    if sequences != tuple(range(8)):
        raise SimulatorError(
            "CACIS roadmap waves must remain ordered and contiguous from 0 through 7: "
            f"received={sequences!r}."
        )
    wave_ids = tuple(str(wave.get("wave_id") or "") for wave in waves)
    if len(wave_ids) != len(set(wave_ids)):
        raise SimulatorError(f"CACIS roadmap wave identifiers must be unique: received={wave_ids!r}.")
    if any(wave.get("maximum_authority_delta") != "none" for wave in waves):
        raise SimulatorError("CACIS roadmap waves cannot widen authority.")
    if waves[0].get("status") != "validated_contract_only":
        raise SimulatorError("CACIS roadmap wave 0 must remain contract-only until runtime evidence exists.")
    if waves[1].get("status") != "validated_replay_only":
        raise SimulatorError("CACIS roadmap wave 1 must preserve its replay-only validated state.")
    if waves[2].get("status") != "validated_replay_only":
        raise SimulatorError("CACIS roadmap wave 2 must preserve its replay-only validated state.")
    if waves[3].get("status") != "validated_replay_only":
        raise SimulatorError("CACIS roadmap wave 3 must preserve its replay-only validated state.")
    if waves[4].get("status") != "validated_replay_only":
        raise SimulatorError("CACIS roadmap wave 4 must preserve its replay-only validated state.")
    if any(wave.get("status") != "validated_replay_only" for wave in waves[5:7]):
        raise SimulatorError("CACIS roadmap waves 5 and 6 must preserve their replay-only validated state.")
    if waves[-1].get("status") != "blocked":
        raise SimulatorError("CACIS Crucible integration must remain blocked pending existing execution gates.")


def validate_recursive_levels(roadmap: JsonObject) -> None:
    levels = require_object_list(roadmap.get("recursive_levels"), "recursive_levels")
    observed = tuple(level.get("level") for level in levels)
    if observed != tuple(range(6)):
        raise SimulatorError(f"CACIS recursive levels must be ordered from 0 through 5: received={observed!r}.")
    for level in levels:
        if level.get("maximum_outcome") != "candidate_only" or level.get("can_modify_authority") is not False:
            raise SimulatorError(
                "Every CACIS recursive level must remain candidate-only with false authority modification: "
                f"level={level.get('level')!r}."
            )


def validate_arena_policy(roadmap: JsonObject) -> None:
    policy = require_object(roadmap.get("arena_policy"), "arena_policy")
    expected: Mapping[str, object] = {
        "public_host_targeting": False,
        "owner_repositories_targetable": False,
        "unknown_ownership_targetable": False,
        "source_replica_required": True,
        "isolated_range_required": True,
        "separate_execution_authorization_required": True,
        "arbitrary_command_bridge_allowed": False,
        "destructive_effects_allowed": False,
        "production_effect_ceiling": "safe_realism",
    }
    if policy != expected:
        raise SimulatorError(
            "CACIS arena policy must preserve offline replica, isolated-range, and safe-realism boundaries: "
            f"expected={dict(expected)!r}, received={policy!r}."
        )


def validate_evaluation(roadmap: JsonObject) -> None:
    evaluation = require_object(roadmap.get("evaluation"), "evaluation")
    partitions = require_string_set(evaluation.get("partitions"), "evaluation.partitions")
    defenses = require_string_set(
        evaluation.get("reward_hacking_defenses"),
        "evaluation.reward_hacking_defenses",
    )
    if partitions != frozenset({"visible", "private", "external"}):
        raise SimulatorError("CACIS evaluation must retain visible, private, and external partitions.")
    if defenses != EXPECTED_REWARD_HACKING_DEFENSES:
        raise SimulatorError("CACIS evaluation must retain every reward-hacking defense.")
    if evaluation.get("hard_failure_overrides_aggregate") is not True:
        raise SimulatorError("CACIS hard failures cannot be averaged into an aggregate pass.")
    if evaluation.get("self_verification_allowed") is not False:
        raise SimulatorError("CACIS organisms and candidates cannot verify themselves.")
    if evaluation.get("sealed_answers_visible_to_candidate") is not False:
        raise SimulatorError("CACIS candidates cannot inspect sealed evaluation answers.")


def validate_authority(roadmap: JsonObject) -> None:
    authority = require_object(roadmap.get("authority"), "authority")
    if authority != FALSE_AUTHORITY:
        raise SimulatorError(
            "The CACIS roadmap is non-authorizing and must preserve false operational authority: "
            f"expected={dict(FALSE_AUTHORITY)!r}, received={authority!r}."
        )
    if roadmap.get("authority_change") != "none":
        raise SimulatorError("CACIS target architecture cannot create an authority change.")


def validate_cacis_roadmap(roadmap: JsonObject) -> None:
    """Validate cross-field constitutional invariants for a CACIS roadmap."""

    validate_invariants(roadmap)
    validate_planes(roadmap)
    validate_waves(roadmap)
    validate_recursive_levels(roadmap)
    validate_arena_policy(roadmap)
    validate_evaluation(roadmap)
    validate_authority(roadmap)
