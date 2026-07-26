"""Command-line replay for bounded W4 metabolism, homeostasis, and Chronos."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from nimrod_cacis.homeostasis import build_homeostasis_chronos_receipt
from nimrod_simulator.jsonio import read_json_object, validate_contract
from nimrod_simulator.model import JsonObject


def run_homeostasis_replay(project_root: Path, mission_path: Path, output_path: Path) -> JsonObject:
    mission = read_json_object(mission_path)
    validate_contract(mission, project_root / "specs" / "homeostasis-chronos-mission.schema.json", "W4 mission")
    receipt = build_homeostasis_chronos_receipt(mission)
    validate_contract(receipt, project_root / "specs" / "homeostasis-chronos-receipt.schema.json", "W4 receipt")
    output_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    body = receipt["receipt"]
    assert isinstance(body, dict)
    health = body["homeostasis"]
    assert isinstance(health, dict)
    return {
        "status": "CACIS_W4_HOMEOSTASIS_CHRONOS_REPLAY_VALID_SCHEDULE_PROPOSAL_ONLY",
        "receipt_digest": receipt["receipt_digest"],
        "breach_count": health["breach_count"],
        "scheduled_count": health["scheduled_count"],
        "deferred_count": health["deferred_count"],
        "abstained_count": health["abstained_count"],
        "execution_authorized": False,
        "execution_performed": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Replay one non-authorizing W4 scheduling mission.")
    parser.add_argument("--mission", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    project_root = Path(__file__).resolve().parents[2]
    print(json.dumps(run_homeostasis_replay(project_root, arguments.mission, arguments.output), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
