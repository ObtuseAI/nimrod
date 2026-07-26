"""Command-line entry point for the offline CACIS world-model replay."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import cast

from nimrod_cacis.world_model import (
    build_world_model_generation,
    commit_world_model_store,
    prepare_world_model_store,
    recover_world_model_store,
)
from nimrod_simulator.jsonio import canonical_json_bytes, read_json_object, validate_contract
from nimrod_simulator.model import JsonObject


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Replay a deterministic CACIS world-model generation")
    parser.add_argument("--project-root", required=True, type=Path)
    parser.add_argument("--scenario", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    return parser.parse_args()


def run_replay(project_root: Path, scenario_path: Path, output_root: Path) -> JsonObject:
    scenario = read_json_object(scenario_path)
    observations = scenario.get("observations")
    if not isinstance(observations, list) or not all(isinstance(item, dict) for item in observations):
        raise TypeError("CACIS replay scenario observations must be a list of objects.")
    observation_schema = project_root / "specs" / "world-observation-envelope.schema.json"
    for index, observation in enumerate(observations):
        validate_contract(cast(JsonObject, observation), observation_schema, f"CACIS observation {index + 1}")
    document = build_world_model_generation(scenario)
    validate_contract(
        document,
        project_root / "specs" / "world-model-generation.schema.json",
        "CACIS world-model generation",
    )
    prepare_world_model_store(output_root, scenario, document)
    prepared_recovery = recover_world_model_store(output_root)
    commit_world_model_store(output_root, cast(str, document["generation_digest"]))
    active_recovery = recover_world_model_store(output_root)
    (output_root / "world-model-generation.json").write_bytes(canonical_json_bytes(document) + b"\n")
    return {
        "status": "CACIS_WORLD_MODEL_REPLAY_ACTIVE_NON_AUTHORIZING",
        "generation_digest": document["generation_digest"],
        "prepared_recovery_status": prepared_recovery["status"],
        "active_recovery_status": active_recovery["status"],
        "summary": cast(JsonObject, document["generation"])["summary"],
        "authority": cast(JsonObject, document["generation"])["authority"],
    }


def main() -> None:
    args = parse_args()
    result = run_replay(args.project_root.resolve(), args.scenario.resolve(), args.output.resolve())
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
