from __future__ import annotations

import argparse
import json
import os
from datetime import datetime
from pathlib import Path

from nimrod_simulator.evolution_foundry import EvolutionArtifactStore, compile_cognitive_candidate
from nimrod_simulator.jsonio import read_json_object


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-candidate", type=Path, required=True)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--constitution", type=Path, required=True)
    parser.add_argument("--governance", type=Path, required=True)
    parser.add_argument("--posture", type=Path, required=True)
    parser.add_argument("--resource-lease", type=Path, required=True)
    parser.add_argument("--uncertainty", type=Path, required=True)
    parser.add_argument("--artifact-root", type=Path, required=True)
    parser.add_argument("--now", required=True)
    parser.add_argument("--maximum-constitution-lifetime-seconds", type=int, required=True)
    args = parser.parse_args()
    candidate = compile_cognitive_candidate(
        read_json_object(args.source_candidate),
        read_json_object(args.baseline),
        read_json_object(args.constitution),
        read_json_object(args.governance),
        read_json_object(args.posture),
        read_json_object(args.resource_lease),
        read_json_object(args.uncertainty),
        parse_time(args.now),
        args.maximum_constitution_lifetime_seconds,
    )
    digest = EvolutionArtifactStore(args.artifact_root).publish(candidate, "cognitive_candidate")
    print(json.dumps({"process_id": os.getpid(), "artifact_digest": digest, "document": candidate}, sort_keys=True))


if __name__ == "__main__":
    main()
