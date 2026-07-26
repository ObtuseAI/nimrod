"""Separate-process entry point for CACIS World Model intake verification."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from nimrod_cacis.world_intake_verifier import build_world_intake_verification
from nimrod_simulator.jsonio import canonical_json_bytes, read_json_object, sha256_digest
from nimrod_simulator.model import JsonObject


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify one CACIS World Model intake candidate")
    parser.add_argument("--edge-document", required=True, type=Path)
    parser.add_argument("--previous-cursor", required=True, type=Path)
    parser.add_argument("--previous-generation", required=True, type=Path)
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    edge_document = read_json_object(arguments.edge_document)
    previous_cursor = read_json_object(arguments.previous_cursor)
    previous_generation = read_json_object(arguments.previous_generation)
    candidate = read_json_object(arguments.candidate)
    verification = build_world_intake_verification(edge_document, previous_cursor, previous_generation, candidate)
    envelope: JsonObject = {
        "worker_process_id": os.getpid(),
        "edge_document_digest": sha256_digest(edge_document),
        "previous_cursor_digest": sha256_digest(previous_cursor),
        "previous_generation_digest": sha256_digest(previous_generation),
        "candidate_digest": sha256_digest(candidate),
        "verification": verification,
    }
    arguments.output.write_bytes(canonical_json_bytes(envelope) + b"\n")
    print(json.dumps({"status": "CACIS_WORLD_INTAKE_CAUSAL_REPLAY_VERIFIED", "worker_process_id": os.getpid()}, sort_keys=True))


if __name__ == "__main__":
    main()
