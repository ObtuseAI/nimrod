"""Independent process command for authorization and Witness verification."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from nimrod_simulator.authorization import parse_timestamp
from nimrod_simulator.authorization_crypto import verify_authorization
from nimrod_simulator.errors import SimulatorError, WitnessIntegrityError
from nimrod_simulator.jsonio import read_json_object, validate_contract
from nimrod_simulator.witness import verify_witness_store


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nimrod-verify-witness",
        description="Independently verify a simulated Witness and its threshold authorization proof.",
    )
    parser.add_argument("--project-root", type=Path, required=True)
    parser.add_argument("--witness-root", type=Path, required=True)
    parser.add_argument("--lease", type=Path, required=True)
    parser.add_argument("--authorization-proof", type=Path, required=True)
    parser.add_argument("--trust-policy", type=Path, required=True)
    parser.add_argument("--expected-origin", type=str, required=True)
    parser.add_argument("--now", type=str, required=True)
    return parser


def verify_artifact_origins(witness_root: Path, expected_origin: str) -> int:
    artifact_root = witness_root / "artifacts" / "sha256"
    artifact_paths = sorted(artifact_root.glob("*.json"))
    if not artifact_paths:
        raise WitnessIntegrityError(f"No Witness artifacts found at '{artifact_root}'.")
    verified = 0
    for artifact_path in artifact_paths:
        artifact = read_json_object(artifact_path)
        origin = artifact.get("origin")
        if origin != expected_origin:
            raise WitnessIntegrityError(
                f"Artifact '{artifact_path}' origin is {origin!r}; expected '{expected_origin}'."
            )
        verified += 1
    return verified


def main() -> None:
    parser = build_parser()
    arguments = parser.parse_args()
    try:
        lease = read_json_object(arguments.lease)
        proof_bundle = read_json_object(arguments.authorization_proof)
        trust_policy = read_json_object(arguments.trust_policy)
        specs_root = arguments.project_root / "specs"
        validate_contract(lease, specs_root / "authorization-lease.schema.json", "authorization lease")
        validate_contract(
            proof_bundle,
            specs_root / "authorization-proof-bundle.schema.json",
            "authorization proof bundle",
        )
        validate_contract(
            trust_policy,
            specs_root / "authorization-trust-policy.schema.json",
            "authorization trust policy",
        )
        verification = verify_authorization(
            lease,
            proof_bundle,
            trust_policy,
            parse_timestamp(arguments.now, "--now"),
        )
        witness_entries = verify_witness_store(arguments.witness_root)
        artifact_count = verify_artifact_origins(arguments.witness_root, arguments.expected_origin)
    except SimulatorError as error:
        print(json.dumps({"status": "INDEPENDENT_VERIFICATION_FAILED", "error_type": type(error).__name__, "message": str(error)}))
        raise SystemExit(2) from error
    print(
        json.dumps(
            {
                "status": "INDEPENDENT_WITNESS_VALID",
                "process_id": os.getpid(),
                "origin": arguments.expected_origin,
                "cryptographic_authorization_verified": True,
                "verified_signer_ids": verification["verified_signer_ids"],
                "witness_entries_verified": witness_entries,
                "artifacts_verified": artifact_count,
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
