"""Read-only separate-process verifier for CIRE structural replay evidence."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from nimrod_research.verifier import build_structural_verification
from nimrod_simulator.jsonio import canonical_json_bytes, read_json_object, sha256_digest
from nimrod_simulator.model import JsonObject


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify one CIRE candidate body in a separate read-only process.")
    parser.add_argument("--mission", required=True, type=Path)
    parser.add_argument("--candidate-body", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    mission = read_json_object(arguments.mission)
    body = read_json_object(arguments.candidate_body)
    verification = build_structural_verification(mission, body, True)
    envelope: JsonObject = {
        "worker_process_id": os.getpid(),
        "mission_digest": sha256_digest(mission),
        "candidate_body_digest": sha256_digest(body),
        "verification": verification,
    }
    arguments.output.write_bytes(canonical_json_bytes(envelope) + b"\n")
    print(json.dumps({"status": "CIRE_SEPARATE_PROCESS_VERIFIED", "worker_process_id": os.getpid()}, sort_keys=True))


if __name__ == "__main__":
    main()
