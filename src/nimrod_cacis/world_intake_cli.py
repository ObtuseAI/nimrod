"""Command-line entry point for verified continuous-observation World Model intake."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from nimrod_cacis.world_intake import (
    build_world_intake_candidate,
    commit_world_intake_store,
    prepare_world_intake_store,
)
from nimrod_cacis.world_intake_process import run_world_intake_verification
from nimrod_simulator.jsonio import canonical_json_bytes, read_json_object, sha256_digest
from nimrod_simulator.model import JsonObject


def run_world_intake(
    project_root: Path,
    edge_document_path: Path,
    previous_cursor_path: Path,
    previous_generation_path: Path,
    store_root: Path,
    output_path: Path,
) -> JsonObject:
    edge_document = read_json_object(edge_document_path)
    previous_cursor = read_json_object(previous_cursor_path)
    previous_generation = read_json_object(previous_generation_path)
    candidate = build_world_intake_candidate(edge_document, previous_cursor, previous_generation)
    verification = run_world_intake_verification(
        project_root,
        edge_document,
        previous_cursor,
        previous_generation,
        candidate,
    )
    prepare_world_intake_store(store_root, candidate)
    recovery = commit_world_intake_store(store_root, candidate)
    receipt: JsonObject = {
        "receipt_version": "0.1.0",
        "status": "CACIS_WORLD_INTAKE_REPLAY_ACTIVE_NON_AUTHORIZING",
        "candidate_digest": sha256_digest(candidate),
        "source_session_digest": candidate["source_session_digest"],
        "generation_digest": candidate["generation"]["generation_digest"],
        "cursor_transition_digest": candidate["cursor_transition"]["transition_digest"],
        "verification": verification,
        "recovery": recovery,
        "authority": candidate["authority"],
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(canonical_json_bytes(receipt) + b"\n")
    return receipt


def main() -> None:
    parser = argparse.ArgumentParser(description="Admit one replayed continuous-observation session into CACIS World Model")
    parser.add_argument("--project-root", required=True, type=Path)
    parser.add_argument("--edge-document", required=True, type=Path)
    parser.add_argument("--previous-cursor", required=True, type=Path)
    parser.add_argument("--previous-generation", required=True, type=Path)
    parser.add_argument("--store", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    receipt = run_world_intake(
        arguments.project_root.resolve(),
        arguments.edge_document.resolve(),
        arguments.previous_cursor.resolve(),
        arguments.previous_generation.resolve(),
        arguments.store.resolve(),
        arguments.output.resolve(),
    )
    print(json.dumps(receipt, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
