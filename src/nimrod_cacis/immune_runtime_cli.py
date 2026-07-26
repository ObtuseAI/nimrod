"""Command-line entry point for the replay-only CACIS immune runtime."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import cast

from nimrod_cacis.immune_runtime import build_immune_organism_lifecycle_receipt
from nimrod_simulator.jsonio import canonical_json_bytes, read_json_object, validate_contract
from nimrod_simulator.model import JsonObject


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run a deterministic proposal-only CACIS immune organism")
    parser.add_argument("--project-root", required=True, type=Path)
    parser.add_argument("--mission", required=True, type=Path)
    parser.add_argument("--world-model", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    return parser.parse_args()


def run_immune_replay(project_root: Path, mission_path: Path, world_model_path: Path, output_path: Path) -> JsonObject:
    mission = read_json_object(mission_path)
    world_model = read_json_object(world_model_path)
    validate_contract(
        mission,
        project_root / "specs" / "immune-organism-mission.schema.json",
        "CACIS immune organism mission",
    )
    validate_contract(
        world_model,
        project_root / "specs" / "world-model-generation.schema.json",
        "CACIS world-model generation",
    )
    document = build_immune_organism_lifecycle_receipt(mission, world_model)
    validate_contract(
        document,
        project_root / "specs" / "immune-organism-lifecycle-receipt.schema.json",
        "CACIS immune organism lifecycle receipt",
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(canonical_json_bytes(document) + b"\n")
    receipt = cast(JsonObject, document["receipt"])
    return {
        "status": "CACIS_IMMUNE_RUNTIME_W2_REPLAY_VALID_PROPOSAL_ONLY",
        "receipt_digest": document["receipt_digest"],
        "terminal_reason": receipt["terminal_reason"],
        "lifecycle_state": cast(JsonObject, receipt["termination"])["lifecycle_state"],
        "contribution_count": len(cast(list[object], receipt["contributions"])),
        "retained_knowledge_count": len(cast(list[object], cast(JsonObject, receipt["retained_knowledge"])["entries"])),
        "independent_verification_performed": False,
        "execution_authorized": False,
        "execution_performed": False,
        "target_contact_performed": False,
    }


def main() -> None:
    args = parse_args()
    result = run_immune_replay(
        args.project_root.resolve(),
        args.mission.resolve(),
        args.world_model.resolve(),
        args.output.resolve(),
    )
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
