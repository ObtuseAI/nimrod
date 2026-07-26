from __future__ import annotations

import copy
import json
import shutil
import tempfile
import time
import uuid
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import cast

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from nimrod_simulator.control_board_ingress import (
    FileControlBoardIngressStore,
    no_ingress_failure,
    sign_control_board_snapshot,
)
from nimrod_simulator.errors import (
    ControlBoardIngressIntegrityError,
    ControlBoardIngressReplayError,
    ControlBoardIngressRollbackError,
    ControlBoardSnapshotError,
    ControlBoardSnapshotSignatureError,
    InjectedControlBoardIngressCrashError,
    SimulatorError,
)
from nimrod_simulator.jsonio import read_json_object, sha256_digest, validate_contract
from nimrod_simulator.key_governance import EphemeralEd25519SigningConnector, SigningConnector, governance_key
from nimrod_simulator.model import JsonObject


ISSUER = "verifier-supervisor-primary"
NOW = datetime(2026, 7, 12, 23, 0, 4, tzinfo=timezone.utc)
MAXIMUM_LIFETIME_SECONDS = 30
MAXIMUM_FUTURE_SKEW_SECONDS = 2


def require_condition(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def expect_error(expected: type[SimulatorError], operation: Callable[[], object], label: str) -> None:
    try:
        operation()
    except expected:
        return
    raise AssertionError(f"Expected {expected.__name__} for {label}.")


def connector(key_id: str, role: str) -> EphemeralEd25519SigningConnector:
    return EphemeralEd25519SigningConnector(key_id, role, Ed25519PrivateKey.generate())


def governance_state(connectors: list[SigningConnector]) -> JsonObject:
    keys = [
        governance_key(
            value,
            "active",
            "2026-07-12T22:00:00Z",
            None,
            "test_ephemeral",
            f"connector:{value.key_id}",
            f"memory:{value.key_id}",
            False,
            None,
        )
        for value in connectors
    ]
    return {
        "state_version": "0.1.0",
        "governance_id": "f90ddb67-512d-4a96-a0bc-1d9d47e975f3",
        "origin": "simulated",
        "epoch": 1,
        "issued_at": "2026-07-12T22:00:00Z",
        "previous_state_digest": None,
        "threshold": 2,
        "ceremony_key_count": 3,
        "minimum_distinct_roles": 2,
        "keys": keys,
    }


def build_snapshot(
    projection: JsonObject,
    state: JsonObject,
    connectors: list[SigningConnector],
    sequence: int,
    previous_snapshot_digest: str | None,
    issued_at: str,
    not_before: str,
    expires_at: str,
    issuer: str,
    audience: str,
) -> JsonObject:
    snapshot_id = str(uuid.uuid5(uuid.UUID("927e9a54-1eca-4ac9-9a6a-eed35b24630d"), str(sequence)))
    unsigned: JsonObject = {
        "snapshot_version": "0.1.0",
        "snapshot_id": snapshot_id,
        "snapshot_kind": "verifier_projection",
        "origin": "simulated",
        "issuer_service_id": issuer,
        "audience": audience,
        "sequence": sequence,
        "issued_at": issued_at,
        "not_before": not_before,
        "expires_at": expires_at,
        "previous_snapshot_digest": previous_snapshot_digest,
        "projection_digest": sha256_digest(projection),
        "governance_state_digest": sha256_digest(state),
        "authority": {"can_authorize": False, "can_execute": False},
    }
    return sign_control_board_snapshot(unsigned, connectors)


def failure_at(target_phase: str) -> Callable[[str], None]:
    triggered = False

    def inject(phase: str) -> None:
        nonlocal triggered
        if phase == target_phase and not triggered:
            triggered = True
            raise InjectedControlBoardIngressCrashError(
                f"Injected control-board ingress crash after '{phase}'."
            )

    return inject


def accept(
    root: Path,
    snapshot: JsonObject,
    projection: JsonObject,
    state: JsonObject,
    failure_injector: Callable[[str], None],
) -> JsonObject:
    store = FileControlBoardIngressStore(root, ISSUER, failure_injector)
    return store.accept(
        snapshot,
        projection,
        state,
        NOW,
        MAXIMUM_LIFETIME_SECONDS,
        MAXIMUM_FUTURE_SKEW_SECONDS,
    )


def validate_crash_recovery(
    root: Path,
    snapshot: JsonObject,
    projection: JsonObject,
    state: JsonObject,
) -> int:
    phases = ["prepared_durable", "owner_durable", "record_durable", "head_published"]
    recovered_count = 0
    for phase in phases:
        phase_root = root / phase
        injector = failure_at(phase)
        expect_error(
            InjectedControlBoardIngressCrashError,
            lambda: accept(phase_root, snapshot, projection, state, injector),
            f"crash at {phase}",
        )
        recovered = FileControlBoardIngressStore(phase_root, ISSUER, no_ingress_failure)
        report = recovered.inspect()
        if phase == "prepared_durable":
            require_condition(report["accepted_sequence"] == 0, "Unowned preparation must not become accepted.")
            accept(phase_root, snapshot, projection, state, no_ingress_failure)
        else:
            require_condition(report["accepted_sequence"] == 1, f"Crash recovery failed after {phase}.")
            expect_error(
                ControlBoardIngressReplayError,
                lambda: accept(phase_root, snapshot, projection, state, no_ingress_failure),
                f"replay after recovered {phase}",
            )
        final_report = FileControlBoardIngressStore(phase_root, ISSUER, no_ingress_failure).inspect()
        require_condition(final_report["accepted_sequence"] == 1, f"Final recovery failed after {phase}.")
        recovered_count += 1
    return recovered_count


def concurrent_attempt(
    root: Path, snapshot: JsonObject, projection: JsonObject, state: JsonObject
) -> str:
    try:
        accept(root, snapshot, projection, state, delay_after_record_publication)
        return "accepted"
    except ControlBoardIngressReplayError:
        return "replayed"


def delay_after_record_publication(phase: str) -> None:
    if phase == "record_durable":
        time.sleep(0.05)


def validate_concurrency(
    root: Path, snapshot: JsonObject, projection: JsonObject, state: JsonObject
) -> tuple[int, int]:
    with ThreadPoolExecutor(max_workers=16) as executor:
        results = list(
            executor.map(
                lambda _: concurrent_attempt(root, snapshot, projection, state),
                range(16),
            )
        )
    return results.count("accepted"), results.count("replayed")


def write_json(path: Path, value: JsonObject) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def validate_durable_tamper_detection(source_root: Path, scratch_root: Path) -> int:
    record_tamper_root = scratch_root / "record-tamper"
    shutil.copytree(source_root, record_tamper_root)
    record_path = sorted(record_tamper_root.rglob("records/*.json"))[-1]
    record = read_json_object(record_path)
    snapshot = record.get("snapshot")
    if not isinstance(snapshot, dict):
        raise TypeError("Ingress test record snapshot must be an object.")
    snapshot["audience"] = "attacker-board"
    write_json(record_path, record)
    expect_error(
        ControlBoardIngressIntegrityError,
        lambda: FileControlBoardIngressStore(record_tamper_root, ISSUER, no_ingress_failure),
        "durable record tamper",
    )
    head_tamper_root = scratch_root / "head-tamper"
    shutil.copytree(source_root, head_tamper_root)
    head_path = next(head_tamper_root.rglob("head.json"))
    head = read_json_object(head_path)
    head["snapshot_digest"] = "sha256:" + "0" * 64
    write_json(head_path, head)
    expect_error(
        ControlBoardIngressIntegrityError,
        lambda: FileControlBoardIngressStore(head_tamper_root, ISSUER, no_ingress_failure),
        "durable head tamper",
    )
    return 2


def validate_control_board_ingress(project_root: Path) -> JsonObject:
    projection = read_json_object(
        project_root / "specs" / "examples" / "control-board-verifier-projection.example.json"
    )
    connectors: list[SigningConnector] = [
        connector("key:board-a", "release"),
        connector("key:board-b", "security"),
        connector("key:board-c", "recovery"),
    ]
    state = governance_state(connectors)
    first = build_snapshot(
        projection,
        state,
        connectors[:2],
        1,
        None,
        "2026-07-12T23:00:02Z",
        "2026-07-12T23:00:02Z",
        "2026-07-12T23:00:32Z",
        ISSUER,
        "nimrod-control-board",
    )
    with tempfile.TemporaryDirectory(prefix="nimrod-board-ingress-") as temporary:
        root = Path(temporary)
        receipt_one = accept(root / "chain", first, projection, state, no_ingress_failure)
        validate_contract(
            first,
            project_root / "specs" / "control-board-snapshot.schema.json",
            "generated signed control-board snapshot",
        )
        validate_contract(
            receipt_one,
            project_root / "specs" / "control-board-ingress-receipt.schema.json",
            "generated control-board ingress receipt",
        )
        first_digest = cast(str, receipt_one["snapshot_digest"])
        second = build_snapshot(
            projection,
            state,
            connectors[:2],
            2,
            first_digest,
            "2026-07-12T23:00:03Z",
            "2026-07-12T23:00:03Z",
            "2026-07-12T23:00:33Z",
            ISSUER,
            "nimrod-control-board",
        )
        receipt_two = accept(root / "chain", second, projection, state, no_ingress_failure)
        chain_report = FileControlBoardIngressStore(root / "chain", ISSUER, no_ingress_failure).inspect()
        require_condition(chain_report["accepted_sequence"] == 2, "Ingress chain did not persist sequence two.")
        expect_error(
            ControlBoardIngressReplayError,
            lambda: accept(root / "chain", second, projection, state, no_ingress_failure),
            "same snapshot replay",
        )
        expect_error(
            ControlBoardIngressReplayError,
            lambda: accept(root / "chain", first, projection, state, no_ingress_failure),
            "older sequence rollback",
        )
        gap = build_snapshot(
            projection,
            state,
            connectors[:2],
            4,
            cast(str, receipt_two["snapshot_digest"]),
            "2026-07-12T23:00:03Z",
            "2026-07-12T23:00:03Z",
            "2026-07-12T23:00:33Z",
            ISSUER,
            "nimrod-control-board",
        )
        expect_error(
            ControlBoardIngressRollbackError,
            lambda: accept(root / "chain", gap, projection, state, no_ingress_failure),
            "sequence gap",
        )
        substituted_chain = build_snapshot(
            projection,
            state,
            connectors[:2],
            3,
            "sha256:" + "9" * 64,
            "2026-07-12T23:00:03Z",
            "2026-07-12T23:00:03Z",
            "2026-07-12T23:00:33Z",
            ISSUER,
            "nimrod-control-board",
        )
        expect_error(
            ControlBoardIngressRollbackError,
            lambda: accept(root / "chain", substituted_chain, projection, state, no_ingress_failure),
            "previous digest substitution",
        )
        tampered_signature = copy.deepcopy(first)
        signatures = tampered_signature.get("signatures")
        if not isinstance(signatures, list) or not signatures or not isinstance(signatures[0], dict):
            raise TypeError("Snapshot signatures must contain an object.")
        signatures[0]["signature_base64"] = "A" * 86 + "=="
        expect_error(
            ControlBoardSnapshotSignatureError,
            lambda: accept(root / "signature-tamper", tampered_signature, projection, state, no_ingress_failure),
            "signature tamper",
        )
        insufficient = copy.deepcopy(first)
        insufficient["signatures"] = cast(list[JsonObject], insufficient["signatures"])[:1]
        expect_error(
            ControlBoardSnapshotSignatureError,
            lambda: accept(root / "threshold", insufficient, projection, state, no_ingress_failure),
            "signature threshold",
        )
        duplicate = copy.deepcopy(first)
        duplicate_signatures = cast(list[JsonObject], duplicate["signatures"])
        duplicate_signatures[1] = copy.deepcopy(duplicate_signatures[0])
        expect_error(
            ControlBoardSnapshotSignatureError,
            lambda: accept(root / "duplicate", duplicate, projection, state, no_ingress_failure),
            "duplicate signer",
        )
        substituted_projection = copy.deepcopy(projection)
        substituted_projection["summary"] = "Substituted board state."
        expect_error(
            ControlBoardSnapshotError,
            lambda: accept(root / "projection", first, substituted_projection, state, no_ingress_failure),
            "projection substitution",
        )
        authority_projection = copy.deepcopy(projection)
        authority_value = authority_projection.get("authority")
        if not isinstance(authority_value, dict):
            raise TypeError("Verifier projection authority must be an object.")
        authority_value["can_execute"] = True
        authority_snapshot = build_snapshot(
            authority_projection,
            state,
            connectors[:2],
            1,
            None,
            "2026-07-12T23:00:02Z",
            "2026-07-12T23:00:02Z",
            "2026-07-12T23:00:32Z",
            ISSUER,
            "nimrod-control-board",
        )
        expect_error(
            ControlBoardSnapshotError,
            lambda: accept(root / "projection-authority", authority_snapshot, authority_projection, state, no_ingress_failure),
            "projection authority injection",
        )
        altered_state = copy.deepcopy(state)
        altered_state["governance_id"] = "4d35a4b4-f807-4dce-93bc-d7cb9a260df4"
        expect_error(
            ControlBoardSnapshotError,
            lambda: accept(root / "governance", first, projection, altered_state, no_ingress_failure),
            "governance substitution",
        )
        stale = build_snapshot(
            projection,
            state,
            connectors[:2],
            1,
            None,
            "2026-07-12T22:59:00Z",
            "2026-07-12T22:59:00Z",
            "2026-07-12T22:59:30Z",
            ISSUER,
            "nimrod-control-board",
        )
        expect_error(
            ControlBoardSnapshotError,
            lambda: accept(root / "stale", stale, projection, state, no_ingress_failure),
            "stale snapshot",
        )
        future = build_snapshot(
            projection,
            state,
            connectors[:2],
            1,
            None,
            "2026-07-12T23:00:10Z",
            "2026-07-12T23:00:10Z",
            "2026-07-12T23:00:30Z",
            ISSUER,
            "nimrod-control-board",
        )
        expect_error(
            ControlBoardSnapshotError,
            lambda: accept(root / "future", future, projection, state, no_ingress_failure),
            "future snapshot",
        )
        naive_time = build_snapshot(
            projection,
            state,
            connectors[:2],
            1,
            None,
            "2026-07-12T23:00:02",
            "2026-07-12T23:00:02",
            "2026-07-12T23:00:32",
            ISSUER,
            "nimrod-control-board",
        )
        expect_error(
            ControlBoardSnapshotError,
            lambda: accept(root / "naive-time", naive_time, projection, state, no_ingress_failure),
            "timezone-free snapshot",
        )
        long_lived = build_snapshot(
            projection,
            state,
            connectors[:2],
            1,
            None,
            "2026-07-12T23:00:02Z",
            "2026-07-12T23:00:02Z",
            "2026-07-12T23:01:02Z",
            ISSUER,
            "nimrod-control-board",
        )
        expect_error(
            ControlBoardSnapshotError,
            lambda: accept(root / "long-lived", long_lived, projection, state, no_ingress_failure),
            "overlong snapshot lifetime",
        )
        wrong_audience = build_snapshot(
            projection,
            state,
            connectors[:2],
            1,
            None,
            "2026-07-12T23:00:02Z",
            "2026-07-12T23:00:02Z",
            "2026-07-12T23:00:32Z",
            ISSUER,
            "attacker-board",
        )
        expect_error(
            ControlBoardSnapshotError,
            lambda: accept(root / "audience", wrong_audience, projection, state, no_ingress_failure),
            "audience substitution",
        )
        wrong_issuer = build_snapshot(
            projection,
            state,
            connectors[:2],
            1,
            None,
            "2026-07-12T23:00:02Z",
            "2026-07-12T23:00:02Z",
            "2026-07-12T23:00:32Z",
            "attacker-supervisor",
            "nimrod-control-board",
        )
        expect_error(
            ControlBoardSnapshotError,
            lambda: accept(root / "issuer", wrong_issuer, projection, state, no_ingress_failure),
            "issuer substitution",
        )
        recovered_count = validate_crash_recovery(root / "crash", first, projection, state)
        concurrent_accepted, concurrent_replayed = validate_concurrency(
            root / "concurrency", first, projection, state
        )
        require_condition(concurrent_accepted == 1, "Concurrent ingress must accept exactly one snapshot.")
        require_condition(concurrent_replayed == 15, "Concurrent ingress must reject fifteen replays.")
        tamper_count = validate_durable_tamper_detection(root / "chain", root / "tamper")
    result: JsonObject = {
        "status": "CONTROL_BOARD_SIGNED_INGRESS_VALID",
        "origin": "simulated",
        "live_execution_performed": False,
        "signed_snapshot_contract": "0.1.0",
        "ingress_receipt_contract": "0.1.0",
        "threshold": 2,
        "governance_key_count": 3,
        "verified_role_count": len(cast(list[str], receipt_two["verified_roles"])),
        "accepted_chain_length": chain_report["accepted_sequence"],
        "crash_recovery_phase_count": recovered_count,
        "concurrent_attempt_count": 16,
        "concurrent_accept_count": concurrent_accepted,
        "concurrent_replay_denial_count": concurrent_replayed,
        "adversarial_case_count": 16 + tamper_count,
        "freshness_seconds": receipt_two["freshness_seconds"],
        "durable_replay_guard": True,
        "stale_state_guard": True,
        "can_authorize": False,
        "can_execute": False,
        "production_os_boundary_proven": False,
    }
    return result


def main() -> None:
    project_root = Path(__file__).resolve().parent.parent
    result = validate_control_board_ingress(project_root)
    report_path = project_root / "reports" / "CONTROL_BOARD_INGRESS_VALIDATION.json"
    report_path.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n"
    )
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
