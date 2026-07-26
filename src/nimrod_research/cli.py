"""Command-line entry point for the replay-only intelligence research engine."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from nimrod_research.intelligence_lab import build_intelligence_research_settlement
from nimrod_simulator.jsonio import read_json_object, validate_contract
from nimrod_simulator.model import JsonObject


def run_research_replay(project_root: Path, mission_path: Path, output_path: Path) -> JsonObject:
    mission = read_json_object(mission_path)
    validate_contract(
        mission,
        project_root / "specs" / "intelligence-research-mission.schema.json",
        "intelligence research mission",
    )
    settlement = build_intelligence_research_settlement(mission, project_root)
    validate_contract(
        settlement,
        project_root / "specs" / "intelligence-research-settlement.schema.json",
        "intelligence research settlement",
    )
    output_path.write_text(json.dumps(settlement, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    body = settlement["settlement"]
    assert isinstance(body, dict)
    aggregate = body["aggregate_comparison"]
    assert isinstance(aggregate, dict)
    theory = body["candidate_theory"]
    assert isinstance(theory, dict)
    return {
        "status": "INTELLIGENCE_RESEARCH_W3_REPLAY_VALID_CANDIDATE_THEORY_ONLY",
        "settlement_digest": settlement["settlement_digest"],
        "candidate_theory_status": theory["status"],
        "coverage_delta": aggregate["mean_required_operation_coverage_delta"],
        "generalization_allowed": False,
        "promotion_authorized": False,
        "execution_performed": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Replay one constitutional intelligence-research mission.")
    parser.add_argument("--mission", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    project_root = Path(__file__).resolve().parents[2]
    result = run_research_replay(project_root, arguments.mission, arguments.output)
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
