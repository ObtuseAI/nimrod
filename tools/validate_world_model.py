"""Validate CACIS W1 world-model replay, recovery, and denial boundaries."""

from __future__ import annotations

import copy
import json
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import cast

from nimrod_cacis.world_model import (
    DOMAINS,
    build_world_model_generation,
    commit_world_model_store,
    digest_filename,
    prepare_world_model_store,
    recover_world_model_store,
    validate_observation,
    validate_replay_scenario,
    validate_world_model_generation,
)
from nimrod_simulator.errors import WorldModelError
from nimrod_simulator.jsonio import read_json_object, sha256_digest, validate_contract
from nimrod_simulator.model import JsonObject


Mutation = Callable[[JsonObject], None]


def expect_world_model_error(label: str, operation: Callable[[], object]) -> None:
    try:
        operation()
    except WorldModelError:
        return
    raise RuntimeError(f"Expected WorldModelError for {label}.")


def build_scenario_case(scenario: JsonObject, mutation: Mutation) -> Callable[[], object]:
    def operation() -> object:
        candidate = copy.deepcopy(scenario)
        mutation(candidate)
        return build_world_model_generation(candidate)

    return operation


def build_generation_case(document: JsonObject, mutation: Mutation) -> Callable[[], object]:
    def operation() -> object:
        candidate = copy.deepcopy(document)
        original_digest = candidate["generation_digest"]
        mutation(candidate)
        if candidate["generation_digest"] == original_digest:
            candidate["generation_digest"] = sha256_digest(cast(JsonObject, candidate["generation"]))
        return validate_world_model_generation(candidate)

    return operation


def observation_list(scenario: JsonObject) -> list[JsonObject]:
    return cast(list[JsonObject], scenario["observations"])


def requirement_list(scenario: JsonObject) -> list[JsonObject]:
    return cast(list[JsonObject], scenario["requirements"])


def validate_expected_world_state(document: JsonObject) -> None:
    generation = cast(JsonObject, document["generation"])
    domains = cast(list[JsonObject], generation["domains"])
    states = {str(item["domain"]): str(item["knowledge_state"]) for item in domains}
    expected = {
        "identity": "contradictory",
        "endpoint": "partially_known",
        "network": "known",
        "cloud": "unknown",
        "threat": "known",
        "recovery": "unknown",
    }
    if states != expected:
        raise RuntimeError(f"CACIS W1 domain states changed: expected={expected!r}, received={states!r}.")
    summary = cast(JsonObject, generation["summary"])
    expected_summary = {
        "known_domain_count": 2,
        "partially_known_domain_count": 1,
        "unknown_domain_count": 2,
        "contradictory_domain_count": 1,
        "known_fact_count": 4,
        "unknown_fact_count": 1,
        "stale_fact_count": 1,
        "contradictory_fact_count": 1,
    }
    if summary != expected_summary:
        raise RuntimeError(f"CACIS W1 summary changed: expected={expected_summary!r}, received={summary!r}.")


def validate_store_recovery(scenario: JsonObject, document: JsonObject) -> tuple[int, int]:
    with tempfile.TemporaryDirectory(prefix="nimrod-cacis-world-") as temporary:
        store_root = Path(temporary)
        prepare_world_model_store(store_root, scenario, document)
        prepared = recover_world_model_store(store_root)
        if prepared["status"] != "prepared_uncommitted" or prepared["active_generation_digest"] is not None:
            raise RuntimeError(f"CACIS prepared recovery was not fail-closed: state={prepared!r}.")
        generation_digest = cast(str, document["generation_digest"])
        commit_world_model_store(store_root, generation_digest)
        active = recover_world_model_store(store_root)
        if active["status"] != "active_replayed_generation" or active["active_generation_digest"] != generation_digest:
            raise RuntimeError(f"CACIS active recovery failed: state={active!r}.")
        commit_world_model_store(store_root, generation_digest)
        observation_files = int(cast(int, active["observation_file_count"]))
        generation_files = int(cast(int, active["generation_file_count"]))
    return observation_files, generation_files


def validate_store_tamper(scenario: JsonObject, document: JsonObject) -> int:
    cases = 0
    with tempfile.TemporaryDirectory(prefix="nimrod-cacis-observation-tamper-") as temporary:
        store_root = Path(temporary)
        prepare_world_model_store(store_root, scenario, document)
        commit_world_model_store(store_root, cast(str, document["generation_digest"]))
        observation_path = sorted((store_root / "observations").glob("*.json"))[0]
        observation_path.write_text("{}\n", encoding="utf-8", newline="\n")
        expect_world_model_error("immutable observation tamper", lambda: recover_world_model_store(store_root))
        cases += 1
    with tempfile.TemporaryDirectory(prefix="nimrod-cacis-generation-tamper-") as temporary:
        store_root = Path(temporary)
        prepare_world_model_store(store_root, scenario, document)
        commit_world_model_store(store_root, cast(str, document["generation_digest"]))
        generation_path = store_root / "generations" / digest_filename(cast(str, document["generation_digest"]))
        generation_path.write_text("{}\n", encoding="utf-8", newline="\n")
        expect_world_model_error("immutable generation tamper", lambda: recover_world_model_store(store_root))
        cases += 1
    with tempfile.TemporaryDirectory(prefix="nimrod-cacis-missing-generation-") as temporary:
        store_root = Path(temporary)
        prepare_world_model_store(store_root, scenario, document)
        commit_world_model_store(store_root, cast(str, document["generation_digest"]))
        generation_path = store_root / "generations" / digest_filename(cast(str, document["generation_digest"]))
        generation_path.unlink()
        expect_world_model_error("missing active generation", lambda: recover_world_model_store(store_root))
        cases += 1
    return cases


def validate_world_model(project_root: Path) -> JsonObject:
    scenario = read_json_object(project_root / "tests" / "fixtures" / "cacis" / "world-model-replay-credential-theft.json")
    observation_schema = project_root / "specs" / "world-observation-envelope.schema.json"
    for index, observation in enumerate(observation_list(scenario)):
        validate_contract(observation, observation_schema, f"CACIS W1 observation {index + 1}")
        validate_observation(observation)
    validate_replay_scenario(scenario)
    document = build_world_model_generation(scenario)
    validate_contract(
        document,
        project_root / "specs" / "world-model-generation.schema.json",
        "CACIS W1 world-model generation",
    )
    validate_world_model_generation(document)
    if document != build_world_model_generation(copy.deepcopy(scenario)):
        raise RuntimeError("CACIS world-model replay is not deterministic.")
    validate_expected_world_state(document)
    observation_file_count, generation_file_count = validate_store_recovery(scenario, document)

    scenario_cases: tuple[tuple[str, Mutation], ...] = (
        ("observation authority widening", lambda value: cast(JsonObject, observation_list(value)[0]["authority"]).__setitem__("can_execute", True)),
        ("unknown confidence inflation", lambda value: observation_list(value)[7].__setitem__("confidence", 0.5)),
        ("unknown value fabrication", lambda value: cast(JsonObject, observation_list(value)[7]["assertion"]).__setitem__("value", "healthy")),
        ("duplicate observation identity", lambda value: observation_list(value)[1].__setitem__("observation_id", observation_list(value)[0]["observation_id"])),
        ("out-of-order replay", lambda value: observation_list(value)[1].__setitem__("replay_sequence", 7)),
        ("future observation", lambda value: observation_list(value)[0].__setitem__("collected_at", "2026-07-15T07:00:00Z")),
        ("collection before observation", lambda value: observation_list(value)[0].__setitem__("collected_at", "2026-07-15T05:59:00Z")),
        ("invalid validity interval", lambda value: observation_list(value)[0].__setitem__("valid_until", "2026-07-15T05:59:00Z")),
        ("undeclared observation", lambda value: observation_list(value)[0].__setitem__("fact_key", "privilege.hidden")),
        ("missing domain requirement", lambda value: requirement_list(value).__setitem__(slice(None), [item for item in requirement_list(value) if item["domain"] != "cloud"])),
        ("duplicate requirement", lambda value: requirement_list(value).append(copy.deepcopy(requirement_list(value)[0]))),
        ("malformed prior-generation digest", lambda value: value.__setitem__("previous_generation_digest", "sha256:" + "x" * 64)),
        ("live-origin laundering", lambda value: value.__setitem__("origin", "live")),
        ("extra scenario authority", lambda value: value.__setitem__("authority", {"can_execute": True})),
    )
    adversarial_count = 0
    for label, mutation in scenario_cases:
        expect_world_model_error(label, build_scenario_case(scenario, mutation))
        adversarial_count += 1

    generation_cases: tuple[tuple[str, Mutation], ...] = (
        ("generation digest substitution", lambda value: value.__setitem__("generation_digest", "sha256:" + "0" * 64)),
        ("generation execution authority", lambda value: cast(JsonObject, cast(JsonObject, value["generation"])["authority"]).__setitem__("can_execute", True)),
        ("policy input laundering", lambda value: cast(JsonObject, cast(JsonObject, value["generation"])["authority"]).__setitem__("policy_input_ready", True)),
        ("production truth laundering", lambda value: cast(JsonObject, cast(JsonObject, value["generation"])["authority"]).__setitem__("production_truth_claimed", True)),
        ("target-contact widening", lambda value: cast(JsonObject, cast(JsonObject, value["generation"])["authority"]).__setitem__("can_contact_targets", True)),
        ("domain reorder", lambda value: cast(list[JsonObject], cast(JsonObject, value["generation"])["domains"]).reverse()),
        ("domain summary inflation", lambda value: cast(JsonObject, cast(JsonObject, value["generation"])["summary"]).__setitem__("known_domain_count", 6)),
        ("fact summary inflation", lambda value: cast(JsonObject, cast(JsonObject, value["generation"])["summary"]).__setitem__("known_fact_count", 7)),
        ("security claim widening", lambda value: cast(JsonObject, value["generation"]).__setitem__("security_claim", "production truth established")),
    )
    for label, mutation in generation_cases:
        expect_world_model_error(label, build_generation_case(document, mutation))
        adversarial_count += 1
    adversarial_count += validate_store_tamper(scenario, document)

    generation = cast(JsonObject, document["generation"])
    summary = cast(JsonObject, generation["summary"])
    result: JsonObject = {
        "status": "CACIS_WORLD_MODEL_W1_REPLAY_VALID_NON_AUTHORIZING",
        "origin": "replayed",
        "generation_digest": document["generation_digest"],
        "domain_count": len(DOMAINS),
        "observation_count": len(observation_list(scenario)),
        "immutable_observation_file_count": observation_file_count,
        "immutable_generation_file_count": generation_file_count,
        "known_domain_count": summary["known_domain_count"],
        "partially_known_domain_count": summary["partially_known_domain_count"],
        "unknown_domain_count": summary["unknown_domain_count"],
        "contradictory_domain_count": summary["contradictory_domain_count"],
        "stale_fact_count": summary["stale_fact_count"],
        "negative_fail_closed_case_count": adversarial_count,
        "prepared_crash_recovery_verified": True,
        "active_generation_recovery_verified": True,
        "deterministic_replay_verified": True,
        "live_sensing_performed": False,
        "policy_input_ready": False,
        "execution_authorized": False,
        "execution_performed": False,
        "target_contact_performed": False,
        "production_truth_claimed": False,
    }
    return result


def main() -> None:
    project_root = Path(__file__).resolve().parents[1]
    result = validate_world_model(project_root)
    report_path = project_root / "reports" / "CACIS_WORLD_MODEL_VALIDATION.json"
    report_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
