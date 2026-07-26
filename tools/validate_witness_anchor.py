from __future__ import annotations

import copy
import json
import os
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from uuid import NAMESPACE_URL, uuid5

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from nimrod_simulator.errors import (
    AnchorIntegrityError,
    AnchorRollbackError,
    SimulatorError,
    WitnessCheckpointError,
    WitnessIntegrityError,
)
from nimrod_simulator.jsonio import canonical_json_bytes, read_json_object, sha256_digest, validate_contract
from nimrod_simulator.key_governance import (
    EphemeralEd25519SigningConnector,
    SigningConnector,
    governance_key,
)
from nimrod_simulator.model import JsonObject
from nimrod_simulator.witness import FileWitnessStore
from nimrod_simulator.witness_checkpoint import (
    FileAnchorPinStore,
    FileExternalAnchorStore,
    build_witness_checkpoint,
    verify_external_anchor_store,
    verify_witness_checkpoint,
)


GOVERNANCE_ID = "77777777-8888-4999-8aaa-bbbbbbbbbbbb"
WITNESS_ID = "witness:simulated-anchor-validation"
NOW = datetime.fromisoformat("2026-07-12T22:00:00+00:00")


def require_condition(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def expect_error(expected: type[SimulatorError], operation: Callable[[], object], label: str) -> None:
    try:
        operation()
    except expected:
        return
    except SimulatorError as error:
        raise AssertionError(
            f"{label} raised {type(error).__name__}; expected {expected.__name__}: {error}"
        ) from error
    raise AssertionError(f"{label} did not fail closed with {expected.__name__}.")


def connector(key_id: str, role: str) -> EphemeralEd25519SigningConnector:
    return EphemeralEd25519SigningConnector(key_id, role, Ed25519PrivateKey.generate())


def governed_key(item: SigningConnector) -> JsonObject:
    return governance_key(
        item,
        "active",
        "2026-07-12T21:00:00Z",
        None,
        "test_ephemeral",
        f"connector:custody:{item.key_id}",
        f"memory:{item.key_id}",
        False,
        None,
    )


def governance_state(signers: list[SigningConnector]) -> JsonObject:
    return {
        "state_version": "0.1.0",
        "governance_id": GOVERNANCE_ID,
        "origin": "simulated",
        "epoch": 1,
        "issued_at": "2026-07-12T21:00:00Z",
        "previous_state_digest": None,
        "threshold": 2,
        "ceremony_key_count": 3,
        "minimum_distinct_roles": 2,
        "keys": [governed_key(item) for item in signers],
    }


def anchor_policy(anchor: SigningConnector) -> JsonObject:
    return {
        "policy_version": "0.1.0",
        "policy_id": "88888888-9999-4aaa-8bbb-cccccccccccc",
        "origin": "simulated",
        "anchor_store_id": "anchor:simulated-independent",
        "not_before": "2026-07-12T21:00:00Z",
        "expires_at": "2026-07-13T21:00:00Z",
        "minimum_head_sequence": 0,
        "allowed_witness_ids": [WITNESS_ID],
        "anchor_key": {
            "key_id": anchor.key_id,
            "algorithm": "Ed25519",
            "public_key_base64": anchor.public_key_base64,
        },
    }


def write_object(path: Path, value: JsonObject) -> None:
    path.write_bytes(canonical_json_bytes(value) + b"\n")


def copied_case(source: Path, destination: Path) -> Path:
    shutil.copytree(source, destination)
    return destination


def verify_case(
    witness_root: Path,
    anchor_root: Path,
    state: JsonObject,
    policy: JsonObject,
    pinned_head: JsonObject,
) -> JsonObject:
    return verify_external_anchor_store(witness_root, anchor_root, state, policy, pinned_head, NOW)


def validate_witness_anchor(project_root: Path) -> JsonObject:
    specs = project_root / "specs"
    customer = connector("key:checkpoint-customer", "customer_authority")
    safety = connector("key:checkpoint-safety", "safety_officer")
    recovery = connector("key:checkpoint-recovery", "recovery_officer")
    anchor_signer = connector("key:external-anchor", "recovery_officer")
    state = governance_state([customer, safety, recovery])
    policy = anchor_policy(anchor_signer)
    validate_contract(state, specs / "key-governance-state.schema.json", "checkpoint governance state")
    validate_contract(policy, specs / "witness-anchor-policy.schema.json", "generated anchor policy")
    with tempfile.TemporaryDirectory(prefix="nimrod-witness-anchor-") as temporary:
        root = Path(temporary)
        witness_root = root / "witness"
        anchor_root = root / "external-anchor"
        pin_root = root / "independent-pin"
        witness = FileWitnessStore(witness_root)
        for index in range(3):
            witness.append(
                "anchor-validation-event",
                {"origin": "simulated", "event_id": f"event-{index + 1}", "effect": "none"},
                f"2026-07-12T21:0{index}:00Z",
            )
        checkpoint_1 = build_witness_checkpoint(
            witness_root,
            WITNESS_ID,
            str(uuid5(NAMESPACE_URL, f"{WITNESS_ID}:checkpoint:1")),
            "2026-07-12T21:10:00Z",
            None,
            state,
            [customer, safety],
        )
        validate_contract(checkpoint_1, specs / "witness-checkpoint.schema.json", "checkpoint one")
        anchor_store = FileExternalAnchorStore(anchor_root, witness_root, pin_root, policy, anchor_signer)
        receipt_1, head_1 = anchor_store.anchor(checkpoint_1, state, "2026-07-12T21:11:00Z")
        pin_store = FileAnchorPinStore(pin_root, witness_root, anchor_root)
        pin_store.pin(head_1, policy)
        for index in range(3, 5):
            witness.append(
                "anchor-validation-event",
                {"origin": "simulated", "event_id": f"event-{index + 1}", "effect": "none"},
                f"2026-07-12T21:0{index}:00Z",
            )
        checkpoint_2 = build_witness_checkpoint(
            witness_root,
            WITNESS_ID,
            str(uuid5(NAMESPACE_URL, f"{WITNESS_ID}:checkpoint:2")),
            "2026-07-12T21:20:00Z",
            sha256_digest(checkpoint_1),
            state,
            [safety, recovery],
        )
        validate_contract(checkpoint_2, specs / "witness-checkpoint.schema.json", "checkpoint two")
        receipt_2, head_2 = anchor_store.anchor(checkpoint_2, state, "2026-07-12T21:21:00Z")
        pin_store.pin(head_2, policy)
        for document, schema_name, label in (
            (receipt_1, "witness-anchor-receipt.schema.json", "receipt one"),
            (receipt_2, "witness-anchor-receipt.schema.json", "receipt two"),
            (head_1, "witness-anchor-head.schema.json", "head one"),
            (head_2, "witness-anchor-head.schema.json", "head two"),
        ):
            validate_contract(document, specs / schema_name, label)
        positive = verify_case(witness_root, anchor_root, state, policy, head_2)
        require_condition(positive["receipt_count"] == 2, "Positive anchor verification did not cover two receipts.")
        require_condition(positive["latest_tree_size"] == 5, "Positive anchor tree size is not five.")
        stale_pin_positive = verify_case(witness_root, anchor_root, state, policy, head_1)
        require_condition(
            stale_pin_positive["latest_sequence"] == 2,
            "Older valid pin did not verify forward consistency to the current head.",
        )
        governance_path = root / "governance-state.json"
        policy_path = root / "anchor-policy.json"
        write_object(governance_path, state)
        write_object(policy_path, policy)
        verifier_process = subprocess.run(
            [
                sys.executable,
                "-m",
                "nimrod_simulator.anchor_verifier_cli",
                "--project-root",
                str(project_root),
                "--witness-root",
                str(witness_root),
                "--anchor-root",
                str(anchor_root),
                "--governance-state",
                str(governance_path),
                "--anchor-policy",
                str(policy_path),
                "--pinned-head",
                str(pin_root / "pinned-anchor-head.json"),
                "--expected-origin",
                "simulated",
                "--now",
                "2026-07-12T22:00:00Z",
            ],
            cwd=project_root,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        require_condition(
            verifier_process.returncode == 0,
            f"Independent anchor verifier failed: stdout={verifier_process.stdout!r}, stderr={verifier_process.stderr!r}",
        )
        verifier_result_value: object = json.loads(verifier_process.stdout)
        if not isinstance(verifier_result_value, dict):
            raise TypeError("Independent anchor verifier output must be an object.")
        require_condition(
            verifier_result_value.get("status") == "INDEPENDENT_EXTERNAL_WITNESS_ANCHOR_VALID",
            "Independent anchor verifier returned the wrong status.",
        )
        require_condition(
            verifier_result_value.get("process_id") != os.getpid(),
            "Independent anchor verification did not run in a separate process.",
        )

        negative_count = 0
        tampered_witness = copied_case(witness_root, root / "tampered-witness")
        tamper_artifact = sorted((tampered_witness / "artifacts" / "sha256").glob("*.json"))[0]
        write_object(tamper_artifact, {"origin": "simulated", "tampered": True})
        expect_error(
            WitnessIntegrityError,
            lambda: verify_case(tampered_witness, anchor_root, state, policy, head_2),
            "Witness artifact tamper",
        )
        negative_count += 1

        truncated_witness = copied_case(witness_root, root / "truncated-witness")
        journal_path = truncated_witness / "witness.jsonl"
        journal_lines = journal_path.read_text(encoding="utf-8").splitlines()
        journal_path.write_text(
            "\n".join(journal_lines[:-1]) + "\n", encoding="utf-8", newline="\n"
        )
        expect_error(
            WitnessCheckpointError,
            lambda: verify_case(truncated_witness, anchor_root, state, policy, head_2),
            "Witness truncation behind anchored head",
        )
        negative_count += 1

        reordered_witness = copied_case(witness_root, root / "reordered-witness")
        reorder_path = reordered_witness / "witness.jsonl"
        reordered_lines = reorder_path.read_text(encoding="utf-8").splitlines()
        reordered_lines[0], reordered_lines[1] = reordered_lines[1], reordered_lines[0]
        reorder_path.write_text(
            "\n".join(reordered_lines) + "\n", encoding="utf-8", newline="\n"
        )
        expect_error(
            WitnessIntegrityError,
            lambda: verify_case(reordered_witness, anchor_root, state, policy, head_2),
            "Witness entry reorder",
        )
        negative_count += 1

        tampered_receipt_anchor = copied_case(anchor_root, root / "tampered-receipt-anchor")
        receipt_path = tampered_receipt_anchor / "receipts" / "00000002.json"
        tampered_receipt = read_json_object(receipt_path)
        tampered_receipt["anchored_at"] = "2026-07-12T21:22:00Z"
        write_object(receipt_path, tampered_receipt)
        expect_error(
            AnchorIntegrityError,
            lambda: verify_case(witness_root, tampered_receipt_anchor, state, policy, head_2),
            "anchor receipt tamper",
        )
        negative_count += 1

        tampered_checkpoint_anchor = copied_case(anchor_root, root / "tampered-checkpoint-anchor")
        checkpoint_path = (
            tampered_checkpoint_anchor
            / "checkpoints"
            / "sha256"
            / f"{sha256_digest(checkpoint_2).removeprefix('sha256:')}.json"
        )
        anchored_checkpoint = read_json_object(checkpoint_path)
        anchored_checkpoint["witness_id"] = "witness:substituted"
        write_object(checkpoint_path, anchored_checkpoint)
        expect_error(
            AnchorIntegrityError,
            lambda: verify_case(witness_root, tampered_checkpoint_anchor, state, policy, head_2),
            "anchored checkpoint tamper",
        )
        negative_count += 1

        rollback_anchor = copied_case(anchor_root, root / "rollback-anchor")
        (rollback_anchor / "receipts" / "00000002.json").unlink()
        (rollback_anchor / "heads" / "00000002.json").unlink()
        shutil.copyfile(rollback_anchor / "heads" / "00000001.json", rollback_anchor / "anchor-head.json")
        expect_error(
            AnchorRollbackError,
            lambda: verify_case(witness_root, rollback_anchor, state, policy, head_2),
            "external anchor rollback",
        )
        negative_count += 1

        forked_anchor = copied_case(anchor_root, root / "forked-anchor")
        fork_path = forked_anchor / "receipts" / "00000002.json"
        forked_receipt = read_json_object(fork_path)
        forked_receipt["previous_receipt_digest"] = "sha256:" + ("0" * 64)
        write_object(fork_path, forked_receipt)
        expect_error(
            AnchorIntegrityError,
            lambda: verify_case(witness_root, forked_anchor, state, policy, head_2),
            "anchor receipt fork",
        )
        negative_count += 1

        tampered_head_anchor = copied_case(anchor_root, root / "tampered-head-anchor")
        head_path = tampered_head_anchor / "anchor-head.json"
        tampered_head = read_json_object(head_path)
        tampered_head["tree_size"] = 4
        write_object(head_path, tampered_head)
        expect_error(
            AnchorIntegrityError,
            lambda: verify_case(witness_root, tampered_head_anchor, state, policy, head_2),
            "anchor head tamper",
        )
        negative_count += 1

        tampered_pin = copy.deepcopy(head_2)
        tampered_pin["sequence"] = 3
        expect_error(
            AnchorIntegrityError,
            lambda: verify_case(witness_root, anchor_root, state, policy, tampered_pin),
            "pinned head signature tamper",
        )
        negative_count += 1

        mismatched_governance = copy.deepcopy(state)
        mismatched_governance["issued_at"] = "2026-07-12T21:00:01Z"
        expect_error(
            WitnessCheckpointError,
            lambda: verify_case(witness_root, anchor_root, mismatched_governance, policy, head_2),
            "checkpoint governance substitution",
        )
        negative_count += 1

        merkle_checkpoint = copy.deepcopy(checkpoint_2)
        merkle_checkpoint["merkle_root_sha256"] = "sha256:" + ("0" * 64)
        expect_error(
            WitnessCheckpointError,
            lambda: verify_witness_checkpoint(witness_root, merkle_checkpoint, state),
            "checkpoint Merkle root substitution",
        )
        negative_count += 1

        insufficient_checkpoint = copy.deepcopy(checkpoint_2)
        checkpoint_signatures = insufficient_checkpoint.get("signatures")
        if not isinstance(checkpoint_signatures, list):
            raise TypeError("Checkpoint signatures must be a list.")
        insufficient_checkpoint["signatures"] = checkpoint_signatures[:1]
        expect_error(
            WitnessCheckpointError,
            lambda: verify_witness_checkpoint(witness_root, insufficient_checkpoint, state),
            "checkpoint one-of-three signature",
        )
        negative_count += 1

        strict_policy = copy.deepcopy(policy)
        strict_policy["minimum_head_sequence"] = 3
        expect_error(
            AnchorIntegrityError,
            lambda: verify_case(witness_root, anchor_root, state, strict_policy, head_2),
            "anchor policy substitution",
        )
        negative_count += 1

        wrong_key_policy = copy.deepcopy(policy)
        wrong_anchor_key = wrong_key_policy.get("anchor_key")
        if not isinstance(wrong_anchor_key, dict):
            raise TypeError("Anchor policy key must be an object.")
        wrong_anchor_key["public_key_base64"] = customer.public_key_base64
        expect_error(
            AnchorIntegrityError,
            lambda: verify_case(witness_root, anchor_root, state, wrong_key_policy, head_2),
            "anchor policy key substitution",
        )
        negative_count += 1

        expect_error(
            AnchorIntegrityError,
            lambda: FileExternalAnchorStore(
                witness_root / "nested-anchor",
                witness_root,
                pin_root,
                policy,
                anchor_signer,
            ),
            "nested external anchor root",
        )
        negative_count += 1

        missing_head_anchor = copied_case(anchor_root, root / "missing-head-anchor")
        (missing_head_anchor / "anchor-head.json").unlink()
        expect_error(
            AnchorIntegrityError,
            lambda: verify_case(witness_root, missing_head_anchor, state, policy, head_2),
            "missing current anchor head",
        )
        negative_count += 1

    return {
        "status": "WITNESS_EXTERNAL_ANCHOR_VALID",
        "origin": "simulated",
        "checkpoint_count": 2,
        "checkpoint_threshold": 2,
        "governance_key_count": 3,
        "anchor_receipt_count": 2,
        "latest_tree_size": 5,
        "independent_pin_verified": True,
        "independent_verifier_process_count": 1,
        "older_pin_forward_consistency_verified": True,
        "merkle_construction": "rfc9162_sha256_domain_separated",
        "negative_fail_closed_case_count": negative_count,
        "tamper_truncation_reorder_rollback_covered": True,
        "external_network_service_called": False,
        "live_execution_performed": False,
    }


def main() -> None:
    project_root = Path(__file__).resolve().parent.parent
    result = validate_witness_anchor(project_root)
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
