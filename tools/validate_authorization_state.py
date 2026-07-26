from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import cast

from nimrod_simulator.errors import AuthorizationStateIntegrityError, JsonDocumentError, LeaseReplayError, SimulatorError
from nimrod_simulator.jsonio import canonical_json_bytes, read_json_object
from nimrod_simulator.model import JsonObject
from nimrod_simulator.state_journal import (
    FileLeaseStateStore,
    claim_key_for,
    no_state_failure,
    publish_file_with_windows_retry,
    read_json_object_with_windows_retry,
)


WORKER_COUNT = 32
CONCURRENCY_ROUNDS = 4
CRASH_EXIT_CODE = 91
CLAIMED_AT = "2026-07-12T21:00:00Z"
POST_OWNERSHIP_FAILURE_POINTS = (
    "owner_created",
    "owner_durable",
    "commit_prepared",
    "commit_published",
)


def windows_access_denied(path: Path) -> PermissionError:
    return PermissionError(13, "Access is denied", str(path), 5)


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


def worker_command(
    project_root: Path,
    state_root: Path,
    lease_id: str,
    nonce: str,
    start_gate: Path,
    result_path: Path,
    failure_point: str,
) -> list[str]:
    return [
        sys.executable,
        str(project_root / "tools" / "authorization_state_worker.py"),
        "--state-root",
        str(state_root),
        "--lease-id",
        lease_id,
        "--nonce",
        nonce,
        "--claimed-at",
        CLAIMED_AT,
        "--start-gate",
        str(start_gate),
        "--result",
        str(result_path),
        "--failure-injection-point",
        failure_point,
    ]


def run_crash_worker(
    project_root: Path,
    state_root: Path,
    lease_id: str,
    nonce: str,
    failure_point: str,
    case_root: Path,
) -> None:
    start_gate = case_root / "start.gate"
    result_path = case_root / "result.json"
    start_gate.write_text("released\n", encoding="utf-8", newline="\n")
    process = subprocess.run(
        worker_command(
            project_root,
            state_root,
            lease_id,
            nonce,
            start_gate,
            result_path,
            failure_point,
        ),
        cwd=project_root,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    require_condition(
        process.returncode == CRASH_EXIT_CODE,
        f"Failure point '{failure_point}' did not terminate abruptly with exit {CRASH_EXIT_CODE}: "
        f"returncode={process.returncode}, stdout={process.stdout!r}, stderr={process.stderr!r}",
    )
    require_condition(not result_path.exists(), f"Crashed worker unexpectedly emitted success for '{failure_point}'.")


def validate_preownership_crash(project_root: Path, root: Path) -> None:
    state_root = root / "preownership-state"
    case_root = root / "preownership-worker"
    case_root.mkdir(parents=True)
    lease_id = "lease:preownership-crash"
    nonce = "nonce-preownership-crash"
    run_crash_worker(project_root, state_root, lease_id, nonce, "prepared_durable", case_root)
    recovered_store = FileLeaseStateStore(state_root, no_state_failure)
    preclaim_report = recovered_store.inspect()
    require_condition(preclaim_report["owner_count"] == 0, "Pre-ownership crash created an owner marker.")
    require_condition(preclaim_report["committed_count"] == 0, "Pre-ownership crash consumed the nonce.")
    require_condition(
        preclaim_report["orphan_preparation_count"] == 1,
        "Pre-ownership crash did not preserve its durable orphan preparation.",
    )
    recovered_store.claim(lease_id, nonce, CLAIMED_AT)
    expect_error(
        LeaseReplayError,
        lambda: recovered_store.claim(lease_id, nonce, CLAIMED_AT),
        "pre-ownership retry replay",
    )


def validate_postownership_crashes(project_root: Path, root: Path) -> int:
    validated = 0
    for failure_point in POST_OWNERSHIP_FAILURE_POINTS:
        case_root = root / failure_point
        state_root = case_root / "state"
        worker_root = case_root / "worker"
        worker_root.mkdir(parents=True)
        lease_id = f"lease:{failure_point}"
        nonce = f"nonce-{failure_point}"
        run_crash_worker(project_root, state_root, lease_id, nonce, failure_point, worker_root)
        recovered_store = FileLeaseStateStore(state_root, no_state_failure)
        report = recovered_store.inspect()
        require_condition(report["owner_count"] == 1, f"Crash '{failure_point}' lost the owner marker.")
        require_condition(report["committed_count"] == 1, f"Crash '{failure_point}' was not recovered.")
        expect_error(
            LeaseReplayError,
            lambda: recovered_store.claim(lease_id, nonce, CLAIMED_AT),
            f"post-ownership replay after {failure_point}",
        )
        validated += 1
    return validated


def validate_ambiguous_owner_tombstone(root: Path) -> None:
    state_root = root / "ambiguous-state"
    lease_id = "lease:ambiguous-owner"
    nonce = "nonce-ambiguous-owner"
    claim_key = claim_key_for(lease_id, nonce)
    owner_root = state_root / "authorization-state" / "v1" / "owners"
    owner_root.mkdir(parents=True)
    (owner_root / f"{claim_key}.owner").write_bytes(b"")
    recovered_store = FileLeaseStateStore(state_root, no_state_failure)
    report = recovered_store.inspect()
    require_condition(report["ambiguous_count"] == 1, "Missing owner identity was not tombstoned.")
    expect_error(
        LeaseReplayError,
        lambda: recovered_store.claim(lease_id, nonce, CLAIMED_AT),
        "ambiguous owner replay",
    )


def validate_corrupt_commit(root: Path) -> None:
    state_root = root / "corrupt-state"
    store = FileLeaseStateStore(state_root, no_state_failure)
    committed_path = store.claim("lease:corrupt", "nonce-corrupt", CLAIMED_AT)
    committed_path.write_text('{"record_type":"tampered"}\n', encoding="utf-8", newline="\n")
    expect_error(
        AuthorizationStateIntegrityError,
        lambda: FileLeaseStateStore(state_root, no_state_failure),
        "corrupt committed authorization state",
    )


def validate_cross_record_mismatch(root: Path) -> None:
    state_root = root / "mismatch-state"
    store = FileLeaseStateStore(state_root, no_state_failure)
    committed_path = store.claim("lease:mismatch", "nonce-mismatch", CLAIMED_AT)
    committed = read_json_object(committed_path)
    committed["claimed_at"] = "2026-07-12T21:00:01Z"
    committed_path.write_bytes(canonical_json_bytes(committed) + b"\n")
    expect_error(
        AuthorizationStateIntegrityError,
        lambda: FileLeaseStateStore(state_root, no_state_failure),
        "authorization owner preparation commit mismatch",
    )


def validate_bounded_windows_publication_retry(root: Path) -> tuple[int, int]:
    transient_source = root / "transient.tmp"
    transient_destination = root / "transient.json"
    transient_source.write_text("transient\n", encoding="utf-8", newline="\n")
    transient_attempts = 0
    transient_sleeps = 0

    def replace_after_two_access_denials(source: Path, destination: Path) -> None:
        nonlocal transient_attempts
        transient_attempts += 1
        if transient_attempts < 3:
            raise windows_access_denied(source)
        source.replace(destination)

    def record_transient_sleep(delay_seconds: float) -> None:
        nonlocal transient_sleeps
        require_condition(delay_seconds == 0.0, "Deterministic retry validation received an unexpected delay.")
        transient_sleeps += 1

    publish_file_with_windows_retry(
        transient_source,
        transient_destination,
        3,
        0.0,
        replace_after_two_access_denials,
        record_transient_sleep,
    )
    require_condition(transient_attempts == 3, "Transient publication did not use the bounded third attempt.")
    require_condition(transient_sleeps == 2, "Transient publication did not sleep between retry attempts.")
    require_condition(transient_destination.is_file(), "Transient publication did not publish the file.")

    exhausted_source = root / "exhausted.tmp"
    exhausted_destination = root / "exhausted.json"
    exhausted_source.write_text("exhausted\n", encoding="utf-8", newline="\n")
    exhausted_attempts = 0

    def always_access_denied(source: Path, destination: Path) -> None:
        del destination
        nonlocal exhausted_attempts
        exhausted_attempts += 1
        raise windows_access_denied(source)

    expect_error(
        AuthorizationStateIntegrityError,
        lambda: publish_file_with_windows_retry(
            exhausted_source,
            exhausted_destination,
            3,
            0.0,
            always_access_denied,
            lambda delay_seconds: None,
        ),
        "exhausted Windows publication retry",
    )
    require_condition(exhausted_attempts == 3, "Exhausted publication exceeded or skipped its retry bound.")

    nonretryable_source = root / "nonretryable.tmp"
    nonretryable_destination = root / "nonretryable.json"
    nonretryable_source.write_text("nonretryable\n", encoding="utf-8", newline="\n")
    nonretryable_attempts = 0

    def nonretryable_permission_error(source: Path, destination: Path) -> None:
        del destination
        nonlocal nonretryable_attempts
        nonretryable_attempts += 1
        raise PermissionError(13, "Permission denied", str(source))

    expect_error(
        AuthorizationStateIntegrityError,
        lambda: publish_file_with_windows_retry(
            nonretryable_source,
            nonretryable_destination,
            3,
            0.0,
            nonretryable_permission_error,
            lambda delay_seconds: None,
        ),
        "non-retryable publication permission error",
    )
    require_condition(nonretryable_attempts == 1, "Non-WinError-5 publication was incorrectly retried.")
    return transient_attempts, exhausted_attempts


def validate_bounded_windows_read_retry(root: Path) -> tuple[int, int]:
    transient_path = root / "transient-read.json"
    transient_path.write_text('{"status":"readable"}\n', encoding="utf-8", newline="\n")
    transient_attempts = 0
    transient_sleeps = 0

    def read_after_two_access_denials(path: Path) -> JsonObject:
        nonlocal transient_attempts
        transient_attempts += 1
        if transient_attempts < 3:
            try:
                raise windows_access_denied(path)
            except PermissionError as error:
                raise JsonDocumentError(f"Unable to read JSON object at '{path}': {error}") from error
        return read_json_object(path)

    def record_transient_sleep(delay_seconds: float) -> None:
        nonlocal transient_sleeps
        require_condition(delay_seconds == 0.0, "Deterministic read retry received an unexpected delay.")
        transient_sleeps += 1

    result = read_json_object_with_windows_retry(
        transient_path,
        3,
        0.0,
        read_after_two_access_denials,
        record_transient_sleep,
    )
    require_condition(result.get("status") == "readable", "Transient read did not return the document.")
    require_condition(transient_attempts == 3, "Transient read did not use the bounded third attempt.")
    require_condition(transient_sleeps == 2, "Transient read did not sleep between retry attempts.")

    exhausted_attempts = 0

    def always_access_denied(path: Path) -> JsonObject:
        nonlocal exhausted_attempts
        exhausted_attempts += 1
        try:
            raise windows_access_denied(path)
        except PermissionError as error:
            raise JsonDocumentError(f"Unable to read JSON object at '{path}': {error}") from error

    expect_error(
        AuthorizationStateIntegrityError,
        lambda: read_json_object_with_windows_retry(
            transient_path,
            3,
            0.0,
            always_access_denied,
            lambda delay_seconds: None,
        ),
        "exhausted Windows read retry",
    )
    require_condition(exhausted_attempts == 3, "Exhausted read exceeded or skipped its retry bound.")

    nonretryable_attempts = 0

    def malformed_document(path: Path) -> JsonObject:
        nonlocal nonretryable_attempts
        nonretryable_attempts += 1
        raise JsonDocumentError(f"Malformed JSON object at '{path}'.")

    expect_error(
        JsonDocumentError,
        lambda: read_json_object_with_windows_retry(
            transient_path,
            3,
            0.0,
            malformed_document,
            lambda delay_seconds: None,
        ),
        "non-retryable malformed read",
    )
    require_condition(nonretryable_attempts == 1, "Malformed JSON was incorrectly retried.")
    return transient_attempts, exhausted_attempts


def read_worker_result(path: Path) -> JsonObject:
    return read_json_object(path)


def run_contention_round(project_root: Path, root: Path, round_index: int) -> tuple[int, int]:
    round_root = root / f"round-{round_index}"
    state_root = round_root / "state"
    result_root = round_root / "results"
    result_root.mkdir(parents=True)
    start_gate = round_root / "start.gate"
    lease_id = f"lease:contention:{round_index}"
    nonce = f"nonce-contention-{round_index}"
    processes: list[subprocess.Popen[str]] = []
    result_paths: list[Path] = []
    for worker_index in range(WORKER_COUNT):
        result_path = result_root / f"worker-{worker_index}.json"
        result_paths.append(result_path)
        processes.append(
            subprocess.Popen(
                worker_command(
                    project_root,
                    state_root,
                    lease_id,
                    nonce,
                    start_gate,
                    result_path,
                    "none",
                ),
                cwd=project_root,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        )
    start_gate.write_text("released\n", encoding="utf-8", newline="\n")
    failures: list[str] = []
    for process in processes:
        stdout, stderr = process.communicate(timeout=60)
        if process.returncode != 0:
            failures.append(
                f"pid={process.pid}, returncode={process.returncode}, stdout={stdout!r}, stderr={stderr!r}"
            )
    require_condition(not failures, f"Contention workers failed in round {round_index}: {'; '.join(failures)}")
    results = [read_worker_result(path) for path in result_paths]
    claimed = [result for result in results if result.get("status") == "claimed"]
    replayed = [result for result in results if result.get("status") == "replay_denied"]
    require_condition(len(claimed) == 1, f"Round {round_index} produced {len(claimed)} successful claims.")
    require_condition(
        len(replayed) == WORKER_COUNT - 1,
        f"Round {round_index} produced {len(replayed)} replay denials; expected {WORKER_COUNT - 1}.",
    )
    process_ids = {cast(int, result.get("process_id")) for result in results}
    require_condition(len(process_ids) == WORKER_COUNT, f"Round {round_index} did not use distinct OS processes.")
    report = FileLeaseStateStore(state_root, no_state_failure).inspect()
    require_condition(report["owner_count"] == 1, f"Round {round_index} has multiple owner markers.")
    require_condition(report["committed_count"] == 1, f"Round {round_index} has multiple committed claims.")
    return len(claimed), len(replayed)


def validate_authorization_state(project_root: Path) -> JsonObject:
    total_claimed = 0
    total_replayed = 0
    with tempfile.TemporaryDirectory(prefix="nimrod-authorization-state-") as temporary:
        root = Path(temporary)
        validate_preownership_crash(project_root, root)
        postownership_count = validate_postownership_crashes(project_root, root)
        validate_ambiguous_owner_tombstone(root)
        validate_corrupt_commit(root)
        validate_cross_record_mismatch(root)
        transient_retry_attempts, exhausted_retry_attempts = validate_bounded_windows_publication_retry(root)
        transient_read_retry_attempts, exhausted_read_retry_attempts = validate_bounded_windows_read_retry(root)
        contention_root = root / "contention"
        for round_index in range(CONCURRENCY_ROUNDS):
            claimed, replayed = run_contention_round(project_root, contention_root, round_index)
            total_claimed += claimed
            total_replayed += replayed
    return {
        "status": "AUTHORIZATION_STATE_RECOVERY_AND_CONCURRENCY_VALID",
        "state_version": "0.1.0",
        "process_crash_failure_points": 1 + postownership_count,
        "postownership_fail_closed_points": postownership_count,
        "ambiguous_owner_tombstone_case_count": 1,
        "corrupt_commit_fail_closed_case_count": 1,
        "cross_record_mismatch_fail_closed_case_count": 1,
        "transient_windows_retry_attempt_count": transient_retry_attempts,
        "exhausted_windows_retry_attempt_count": exhausted_retry_attempts,
        "transient_windows_read_retry_attempt_count": transient_read_retry_attempts,
        "exhausted_windows_read_retry_attempt_count": exhausted_read_retry_attempts,
        "concurrency_round_count": CONCURRENCY_ROUNDS,
        "workers_per_round": WORKER_COUNT,
        "os_process_claim_attempt_count": CONCURRENCY_ROUNDS * WORKER_COUNT,
        "successful_claim_count": total_claimed,
        "replay_denial_count": total_replayed,
        "exactly_one_success_per_round": total_claimed == CONCURRENCY_ROUNDS,
        "live_execution_performed": False,
        "offensive_tools_installed_or_launched": False,
        "scope": "process-crash recovery; power-loss durability remains unproven",
    }


def main() -> None:
    project_root = Path(__file__).resolve().parent.parent
    result = validate_authorization_state(project_root)
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
