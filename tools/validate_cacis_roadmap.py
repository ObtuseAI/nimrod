"""Validate the contract-only CACIS roadmap and constitutional denial cases."""

from __future__ import annotations

import copy
import hashlib
import json
from collections.abc import Callable
from pathlib import Path
from typing import cast

from nimrod_cacis.roadmap import validate_cacis_roadmap
from nimrod_simulator.errors import SimulatorError
from nimrod_simulator.jsonio import read_json_object, validate_contract
from nimrod_simulator.model import JsonObject


Mutation = Callable[[JsonObject], None]


def expect_denial(roadmap: JsonObject, label: str, mutation: Mutation) -> None:
    candidate = copy.deepcopy(roadmap)
    mutation(candidate)
    try:
        validate_cacis_roadmap(candidate)
    except SimulatorError:
        return
    raise RuntimeError(f"Expected CACIS roadmap denial for {label}.")


def object_list(value: object) -> list[JsonObject]:
    return cast(list[JsonObject], value)


def set_nested(value: JsonObject, container: str, field: str, replacement: object) -> None:
    nested = cast(JsonObject, value[container])
    nested[field] = replacement


def validate_roadmap(project_root: Path) -> JsonObject:
    roadmap_path = project_root / "specs" / "examples" / "cacis-capability-roadmap.example.json"
    schema_path = project_root / "specs" / "cacis-capability-roadmap.schema.json"
    source_brief_path = project_root / "docs" / "source" / "cacis_vnext_owner_brief.md"
    roadmap = read_json_object(roadmap_path)
    validate_contract(roadmap, schema_path, "CACIS capability roadmap")
    validate_cacis_roadmap(roadmap)

    actual_source_digest = "sha256:" + hashlib.sha256(source_brief_path.read_bytes()).hexdigest()
    if roadmap["source_brief_digest"] != actual_source_digest:
        raise RuntimeError(
            "CACIS roadmap source brief digest mismatch: "
            f"expected={actual_source_digest!r}, received={roadmap['source_brief_digest']!r}."
        )

    cases: tuple[tuple[str, Mutation], ...] = (
        ("roadmap execution authority", lambda value: set_nested(value, "authority", "can_execute", True)),
        ("roadmap target contact authority", lambda value: set_nested(value, "authority", "can_contact_targets", True)),
        ("missing immutable law", lambda value: cast(list[object], value["constitutional_invariants"]).pop()),
        ("governor authorization", lambda value: object_list(value["planes"])[1].__setitem__("can_authorize", True)),
        ("organism execution", lambda value: object_list(value["planes"])[2].__setitem__("can_execute", True)),
        ("world model truth inflation", lambda value: object_list(value["planes"])[3].__setitem__("maximum_outcome", "deterministic_policy_decision")),
        ("recursive authority mutation", lambda value: object_list(value["recursive_levels"])[5].__setitem__("can_modify_authority", True)),
        ("public host targeting", lambda value: set_nested(value, "arena_policy", "public_host_targeting", True)),
        ("owner repository targeting", lambda value: set_nested(value, "arena_policy", "owner_repositories_targetable", True)),
        ("arbitrary command bridge", lambda value: set_nested(value, "arena_policy", "arbitrary_command_bridge_allowed", True)),
        ("self verification", lambda value: set_nested(value, "evaluation", "self_verification_allowed", True)),
        ("hard failure averaging", lambda value: set_nested(value, "evaluation", "hard_failure_overrides_aggregate", False)),
        ("reward hacking defense removal", lambda value: cast(list[object], cast(JsonObject, value["evaluation"])["reward_hacking_defenses"]).pop()),
        ("wave authority growth", lambda value: object_list(value["waves"])[4].__setitem__("maximum_authority_delta", "expanded")),
        ("world model evidence downgrade", lambda value: object_list(value["waves"])[1].__setitem__("status", "planned")),
        ("immune runtime evidence downgrade", lambda value: object_list(value["waves"])[2].__setitem__("status", "planned")),
        ("hypothesis cortex evidence downgrade", lambda value: object_list(value["waves"])[3].__setitem__("status", "planned")),
        ("homeostasis evidence downgrade", lambda value: object_list(value["waves"])[4].__setitem__("status", "planned")),
        ("genome evidence downgrade", lambda value: object_list(value["waves"])[5].__setitem__("status", "planned")),
        ("arena evidence downgrade", lambda value: object_list(value["waves"])[6].__setitem__("status", "planned")),
        ("range gate laundering", lambda value: object_list(value["waves"])[7].__setitem__("status", "planned")),
    )
    for label, mutation in cases:
        expect_denial(roadmap, label, mutation)

    result: JsonObject = {
        "status": "CACIS_ROADMAP_CONTRACT_VALID_IMPLEMENTATION_GATED",
        "origin": "owner_plan",
        "roadmap_id": roadmap["roadmap_id"],
        "roadmap_version": roadmap["roadmap_version"],
        "doctrine_version": roadmap["doctrine_version"],
        "constitutional_invariant_count": len(cast(list[object], roadmap["constitutional_invariants"])),
        "architectural_plane_count": len(cast(list[object], roadmap["planes"])),
        "implementation_wave_count": len(cast(list[object], roadmap["waves"])),
        "recursive_level_count": len(cast(list[object], roadmap["recursive_levels"])),
        "negative_fail_closed_case_count": len(cases),
        "cacis_world_model_replay_implemented": True,
        "cacis_immune_runtime_implemented": True,
        "intelligence_research_hypothesis_cortex_implemented": True,
        "cacis_homeostasis_chronos_implemented": True,
        "cacis_genome_evaluation_implemented": True,
        "cacis_arenas_observatory_implemented": True,
        "authority_change": roadmap["authority_change"],
        "execution_authorized": False,
        "execution_performed": False,
        "target_contact_performed": False,
        "production_claims_authorized": False,
        "blockers": roadmap["blockers"],
    }
    return result


def main() -> None:
    project_root = Path(__file__).resolve().parents[1]
    result = validate_roadmap(project_root)
    report_path = project_root / "reports" / "CACIS_ROADMAP_VALIDATION.json"
    report_path.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
