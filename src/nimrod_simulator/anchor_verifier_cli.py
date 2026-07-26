"""Independent process verifier for signed Witness checkpoints and external anchor state."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from nimrod_simulator.authorization import parse_timestamp
from nimrod_simulator.errors import AnchorIntegrityError, SimulatorError
from nimrod_simulator.jsonio import read_json_object, validate_contract
from nimrod_simulator.witness_checkpoint import verify_external_anchor_store


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nimrod-verify-anchor",
        description="Independently verify simulated Witness checkpoints, external receipts, and a pinned head.",
    )
    parser.add_argument("--project-root", type=Path, required=True)
    parser.add_argument("--witness-root", type=Path, required=True)
    parser.add_argument("--anchor-root", type=Path, required=True)
    parser.add_argument("--governance-state", type=Path, required=True)
    parser.add_argument("--anchor-policy", type=Path, required=True)
    parser.add_argument("--pinned-head", type=Path, required=True)
    parser.add_argument("--expected-origin", type=str, required=True)
    parser.add_argument("--now", type=str, required=True)
    return parser


def main() -> None:
    arguments = build_parser().parse_args()
    try:
        governance_state = read_json_object(arguments.governance_state)
        anchor_policy = read_json_object(arguments.anchor_policy)
        pinned_head = read_json_object(arguments.pinned_head)
        specs = arguments.project_root / "specs"
        validate_contract(
            governance_state,
            specs / "key-governance-state.schema.json",
            "key governance state",
        )
        validate_contract(anchor_policy, specs / "witness-anchor-policy.schema.json", "anchor policy")
        validate_contract(pinned_head, specs / "witness-anchor-head.schema.json", "pinned anchor head")
        if (
            governance_state.get("origin") != arguments.expected_origin
            or anchor_policy.get("origin") != arguments.expected_origin
            or pinned_head.get("origin") != arguments.expected_origin
        ):
            raise AnchorIntegrityError(
                f"Governance, policy, and pinned-head origins must equal '{arguments.expected_origin}'."
            )
        result = verify_external_anchor_store(
            arguments.witness_root,
            arguments.anchor_root,
            governance_state,
            anchor_policy,
            pinned_head,
            parse_timestamp(arguments.now, "--now"),
        )
    except SimulatorError as error:
        print(
            json.dumps(
                {
                    "status": "INDEPENDENT_ANCHOR_VERIFICATION_FAILED",
                    "error_type": type(error).__name__,
                    "message": str(error),
                }
            )
        )
        raise SystemExit(2) from error
    print(
        json.dumps(
            {
                **result,
                "status": "INDEPENDENT_EXTERNAL_WITNESS_ANCHOR_VALID",
                "process_id": os.getpid(),
                "origin": arguments.expected_origin,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
