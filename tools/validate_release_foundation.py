"""Validate signed offline update, anti-rollback, rollback, and plugin sandbox boundaries."""

from __future__ import annotations

import base64
import copy
import json
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TypeVar

from nimrod_release.verification import (
    artifact_digest,
    sign_release_manifest,
    verify_plugin_manifest,
    verify_release_candidate,
)
from nimrod_simulator.errors import SimulatorError
from nimrod_simulator.jsonio import read_json_object, sha256_digest, validate_contract
from nimrod_simulator.model import JsonObject
from validate_evolution_assurance import governance_connectors, governance_state


TError = TypeVar("TError", bound=Exception)


def expect_error(
    error_type: type[TError],
    operation: Callable[[], object],
    label: str,
) -> None:
    try:
        operation()
    except error_type:
        return
    raise RuntimeError(f"Expected {error_type.__name__} for {label}.")


def tamper_signature(manifest: JsonObject) -> JsonObject:
    mutated = copy.deepcopy(manifest)
    signatures = mutated["signatures"]
    signature = signatures[0]
    raw = bytearray(base64.b64decode(signature["signature_base64"]))
    raw[0] ^= 0x01
    signature["signature_base64"] = base64.b64encode(bytes(raw)).decode("ascii")
    return mutated


def validate_release_foundation(project_root: Path) -> JsonObject:
    plugin = read_json_object(
        project_root / "specs" / "examples" / "plugin-capability-manifest.example.json"
    )
    validate_contract(
        plugin,
        project_root / "specs" / "plugin-capability-manifest.schema.json",
        "plugin capability manifest",
    )
    verify_plugin_manifest(plugin)
    connectors = governance_connectors()
    governance = governance_state(connectors, "simulated")
    verification_time = datetime(2026, 7, 15, 20, 1, tzinfo=timezone.utc)
    artifact_content = b"nimrod Edge candidate artifact: validation only; not executable"
    trusted_release_digest = "sha256:" + "6" * 64
    unsigned_manifest = read_json_object(
        project_root / "specs" / "examples" / "edge-update-manifest.example.json"
    )
    unsigned_manifest.pop("signatures")
    unsigned_manifest["governance_state_digest"] = sha256_digest(governance)
    unsigned_manifest["artifact"]["digest"] = artifact_digest(artifact_content)
    unsigned_manifest["artifact"]["size_bytes"] = len(artifact_content)
    unsigned_manifest["previous_release"]["manifest_digest"] = trusted_release_digest
    unsigned_manifest["rollback"]["target_release_manifest_digest"] = trusted_release_digest
    unsigned_manifest["plugins"][0]["manifest_digest"] = sha256_digest(plugin)
    manifest = sign_release_manifest(unsigned_manifest, connectors[:2])
    validate_contract(
        manifest,
        project_root / "specs" / "edge-update-manifest.schema.json",
        "threshold-signed Edge update manifest",
    )
    receipt = verify_release_candidate(
        manifest,
        [plugin],
        artifact_content,
        trusted_release_digest,
        1,
        governance,
        verification_time,
    )
    validate_contract(
        receipt,
        project_root / "specs" / "edge-update-verification-receipt.schema.json",
        "Edge update verification receipt",
    )

    adversarial_count = 0
    expect_error(
        SimulatorError,
        lambda: verify_release_candidate(
            manifest,
            [plugin],
            artifact_content + b"tampered",
            trusted_release_digest,
            1,
            governance,
            verification_time,
        ),
        "artifact tamper",
    )
    adversarial_count += 1
    signature_tamper = tamper_signature(manifest)
    expect_error(
        SimulatorError,
        lambda: verify_release_candidate(
            signature_tamper,
            [plugin],
            artifact_content,
            trusted_release_digest,
            1,
            governance,
            verification_time,
        ),
        "signature tamper",
    )
    adversarial_count += 1
    one_signer = sign_release_manifest(unsigned_manifest, connectors[:1])
    expect_error(
        SimulatorError,
        lambda: verify_release_candidate(
            one_signer,
            [plugin],
            artifact_content,
            trusted_release_digest,
            1,
            governance,
            verification_time,
        ),
        "signer threshold collapse",
    )
    adversarial_count += 1
    sequence_skip = copy.deepcopy(manifest)
    sequence_skip["release_sequence"] = 3
    expect_error(
        SimulatorError,
        lambda: verify_release_candidate(sequence_skip, [plugin], artifact_content, trusted_release_digest, 1, governance, verification_time),
        "release sequence skip",
    )
    adversarial_count += 1
    predecessor_substitution = copy.deepcopy(manifest)
    predecessor_substitution["previous_release"]["manifest_digest"] = "sha256:" + "9" * 64
    expect_error(
        SimulatorError,
        lambda: verify_release_candidate(predecessor_substitution, [plugin], artifact_content, trusted_release_digest, 1, governance, verification_time),
        "predecessor substitution",
    )
    adversarial_count += 1
    rollback_unproven = copy.deepcopy(manifest)
    rollback_unproven["rollback"]["rollback_tested"] = False
    expect_error(
        SimulatorError,
        lambda: verify_release_candidate(rollback_unproven, [plugin], artifact_content, trusted_release_digest, 1, governance, verification_time),
        "rollback evidence removal",
    )
    adversarial_count += 1
    network_plugin = copy.deepcopy(plugin)
    network_plugin["network"]["allowed_destinations"] = ["telemetry.invalid:443"]
    expect_error(SimulatorError, lambda: verify_plugin_manifest(network_plugin), "plugin network widening")
    adversarial_count += 1
    loadable_plugin = copy.deepcopy(plugin)
    loadable_plugin["lifecycle"]["load_authorized"] = True
    expect_error(SimulatorError, lambda: verify_plugin_manifest(loadable_plugin), "plugin load authority")
    adversarial_count += 1
    plugin_digest_substitution = copy.deepcopy(manifest)
    plugin_digest_substitution["plugins"][0]["manifest_digest"] = "sha256:" + "8" * 64
    expect_error(
        SimulatorError,
        lambda: verify_release_candidate(plugin_digest_substitution, [plugin], artifact_content, trusted_release_digest, 1, governance, verification_time),
        "plugin manifest substitution",
    )
    adversarial_count += 1
    installation_authority = copy.deepcopy(manifest)
    installation_authority["authority"]["can_install"] = True
    expect_error(
        SimulatorError,
        lambda: verify_release_candidate(installation_authority, [plugin], artifact_content, trusted_release_digest, 1, governance, verification_time),
        "installation authority widening",
    )
    adversarial_count += 1
    governance_substitution = copy.deepcopy(manifest)
    governance_substitution["governance_state_digest"] = "sha256:" + "7" * 64
    expect_error(
        SimulatorError,
        lambda: verify_release_candidate(governance_substitution, [plugin], artifact_content, trusted_release_digest, 1, governance, verification_time),
        "governance substitution",
    )
    adversarial_count += 1
    expect_error(
        SimulatorError,
        lambda: verify_release_candidate(
            manifest,
            [plugin],
            artifact_content,
            trusted_release_digest,
            1,
            governance,
            verification_time + timedelta(days=2),
        ),
        "expired release manifest",
    )
    adversarial_count += 1
    return {
        "status": "EDGE_UPDATE_AND_PLUGIN_TRUST_FOUNDATION_VALID_INSTALLATION_BLOCKED",
        "origin": "simulated",
        "verified_signer_count": len(receipt["verified_signer_ids"]),
        "verified_role_count": len(receipt["verified_roles"]),
        "anti_rollback_verified": True,
        "previous_release_bound": True,
        "artifact_verified": True,
        "provenance_present": True,
        "sbom_present": True,
        "rollback_contract_verified": True,
        "plugin_manifest_count": 1,
        "plugin_allowed_capability_count": 1,
        "plugin_denied_capability_count": 7,
        "plugin_code_executed": False,
        "installation_authorized": False,
        "installation_performed": False,
        "network_access_performed": False,
        "negative_fail_closed_case_count": adversarial_count,
    }


def main() -> None:
    project_root = Path(__file__).resolve().parents[1]
    result = validate_release_foundation(project_root)
    report_path = project_root / "reports" / "RELEASE_FOUNDATION_VALIDATION.json"
    report_path.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
