from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from functools import partial
from pathlib import Path
from typing import cast

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from nimrod_simulator.errors import (
    RangeKillConflictError,
    RangeKillReplayError,
    RangeKillSignatureError,
    RangeKillStateError,
    RangeRecoveryError,
    RangeTopologyError,
    SimulatorError,
)
from nimrod_simulator.jsonio import read_json_object, sha256_digest, validate_contract
from nimrod_simulator.key_governance import EphemeralEd25519SigningConnector, governance_key
from nimrod_simulator.model import JsonObject
from nimrod_simulator.range_kill import RangeKillStateStore, no_range_kill_failure, sign_range_kill_command, verify_range_kill_command
from nimrod_simulator.range_recovery import (
    REQUIRED_CLEANUP_OBLIGATIONS,
    evaluate_range_recovery,
    range_cleanup_subject_digest,
)
from nimrod_simulator.range_topology import validate_range_topology


VALIDATION_TIME = datetime(2026, 7, 12, 23, 41, 0, tzinfo=timezone.utc)
KILL_LIFETIME_SECONDS = 300
RECOVERY_EVIDENCE_AGE_SECONDS = 120
WORKER_COUNT = 16


def require_condition(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def expect_error(expected: type[SimulatorError], operation: Callable[[], object], label: str) -> None:
    try:
        operation()
    except expected:
        return
    raise AssertionError(f"Expected {expected.__name__} for {label}.")


def signing_connectors() -> list[EphemeralEd25519SigningConnector]:
    return [
        EphemeralEd25519SigningConnector("key:range-owner", "customer_authority", Ed25519PrivateKey.generate()),
        EphemeralEd25519SigningConnector("key:range-safety", "safety_officer", Ed25519PrivateKey.generate()),
        EphemeralEd25519SigningConnector("key:range-recovery", "recovery_officer", Ed25519PrivateKey.generate()),
    ]


def governance_state(connectors: list[EphemeralEd25519SigningConnector]) -> JsonObject:
    issued_at = "2026-07-12T23:00:00Z"
    return {
        "state_version": "0.1.0",
        "governance_id": "6fd887f0-73bc-45f0-b151-45b973e55119",
        "origin": "simulated",
        "epoch": 1,
        "issued_at": issued_at,
        "previous_state_digest": None,
        "threshold": 2,
        "ceremony_key_count": 3,
        "minimum_distinct_roles": 2,
        "keys": [
            governance_key(
                connector,
                "active",
                issued_at,
                None,
                "test_ephemeral",
                f"connector:custody:{connector.key_id}",
                f"memory:{connector.key_id}",
                False,
                None,
            )
            for connector in connectors
        ],
    }


def signed_kill_command(
    topology: JsonObject,
    governance: JsonObject,
    connectors: list[EphemeralEd25519SigningConnector],
    command_id: str,
    reason_code: str,
    issued_at: datetime,
    not_before: datetime,
    expires_at: datetime,
) -> JsonObject:
    unsigned: JsonObject = {
        "command_version": "0.1.0",
        "command_id": command_id,
        "origin": "simulated",
        "topology_id": topology["topology_id"],
        "topology_digest": sha256_digest(topology),
        "generation": topology["generation"],
        "sequence": topology["generation"],
        "command": "engage",
        "reason_code": reason_code,
        "governance_state_digest": sha256_digest(governance),
        "issued_at": issued_at.isoformat().replace("+00:00", "Z"),
        "not_before": not_before.isoformat().replace("+00:00", "Z"),
        "expires_at": expires_at.isoformat().replace("+00:00", "Z"),
        "authority": {"can_disengage": False, "can_connect": False, "can_execute": False},
    }
    return sign_range_kill_command(unsigned, connectors[:2])


def evidence_reference(identifier: str) -> JsonObject:
    return {"id": identifier, "digest": sha256_digest({"fixture": identifier})}


def blocked_recovery_evidence(topology: JsonObject, state: JsonObject, captured_at: datetime) -> JsonObject:
    evidence: JsonObject = {
        "evidence_version": "0.1.0",
        "evidence_id": "143d5819-884d-47ed-a9c3-d907fefa5322",
        "origin": "simulated",
        "captured_at": captured_at.isoformat().replace("+00:00", "Z"),
        "topology_digest": sha256_digest(topology),
        "kill_state_digest": sha256_digest(state),
        "baseline_snapshot_digest": sha256_digest({"snapshot": "baseline"}),
        "observed_post_cleanup_snapshot_digest": sha256_digest({"snapshot": "baseline"}),
        "cleanup_obligations": [
            {"obligation_id": obligation_id, "status": "unproven", "evidence": []}
            for obligation_id in sorted(REQUIRED_CLEANUP_OBLIGATIONS)
        ],
        "cleanup_subject_digest": "sha256:" + "0" * 64,
        "verifier_observations": [],
        "authority": {"can_reset_kill": False, "can_reuse_range": False, "can_execute": False},
    }
    subject_digest = range_cleanup_subject_digest(evidence)
    evidence["cleanup_subject_digest"] = subject_digest
    evidence["verifier_observations"] = [
        {"verifier_id": "verifier:range-a", "logical_principal": "principal:range-a", "process_id": 5101, "status": "rejected", "subject_digest": subject_digest},
        {"verifier_id": "verifier:range-b", "logical_principal": "principal:range-b", "process_id": 5102, "status": "rejected", "subject_digest": subject_digest},
    ]
    return evidence


def verified_recovery_evidence(topology: JsonObject, state: JsonObject, captured_at: datetime) -> JsonObject:
    evidence: JsonObject = {
        "evidence_version": "0.1.0",
        "evidence_id": "5bbfccee-5a22-4f9a-bcd1-39a33c4edab3",
        "origin": "simulated",
        "captured_at": captured_at.isoformat().replace("+00:00", "Z"),
        "topology_digest": sha256_digest(topology),
        "kill_state_digest": sha256_digest(state),
        "baseline_snapshot_digest": sha256_digest({"snapshot": "baseline"}),
        "observed_post_cleanup_snapshot_digest": sha256_digest({"snapshot": "baseline"}),
        "cleanup_obligations": [
            {"obligation_id": obligation_id, "status": "verified", "evidence": [evidence_reference(f"evidence:{obligation_id.casefold()}")]}
            for obligation_id in sorted(REQUIRED_CLEANUP_OBLIGATIONS)
        ],
        "cleanup_subject_digest": "sha256:" + "0" * 64,
        "verifier_observations": [],
        "authority": {"can_reset_kill": False, "can_reuse_range": False, "can_execute": False},
    }
    subject_digest = range_cleanup_subject_digest(evidence)
    evidence["cleanup_subject_digest"] = subject_digest
    evidence["verifier_observations"] = [
        {"verifier_id": "verifier:range-a", "logical_principal": "principal:range-a", "process_id": 5101, "status": "verified", "subject_digest": subject_digest},
        {"verifier_id": "verifier:range-b", "logical_principal": "principal:range-b", "process_id": 5102, "status": "verified", "subject_digest": subject_digest},
    ]
    return evidence


def write_json(path: Path, value: JsonObject) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def worker_command(
    project_root: Path,
    state_root: Path,
    topology_path: Path,
    command_path: Path,
    governance_path: Path,
    failure_point: str,
) -> list[str]:
    return [
        sys.executable,
        str(project_root / "tools" / "range_kill_worker.py"),
        "--state-root", str(state_root),
        "--topology", str(topology_path),
        "--command", str(command_path),
        "--governance", str(governance_path),
        "--now", VALIDATION_TIME.isoformat().replace("+00:00", "Z"),
        "--maximum-lifetime-seconds", str(KILL_LIFETIME_SECONDS),
        "--failure-point", failure_point,
    ]


def run_worker(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=False, capture_output=True, text=True, timeout=30)


def validate_range_lifecycle(project_root: Path) -> JsonObject:
    topology = read_json_object(project_root / "specs" / "examples" / "range-topology.example.json")
    topology_verdict = validate_range_topology(topology)
    canonical_topology_verdict = read_json_object(
        project_root / "specs" / "examples" / "range-topology-verdict.example.json"
    )
    require_condition(topology_verdict == canonical_topology_verdict, "Generated topology verdict differs from its canonical example.")
    validate_contract(topology_verdict, project_root / "specs" / "range-topology-verdict.schema.json", "generated topology verdict")
    connectors = signing_connectors()
    governance = governance_state(connectors)
    command = signed_kill_command(
        topology,
        governance,
        connectors,
        "15192a77-f787-4f92-b1ab-4c253f3e3049",
        "test_fixture",
        VALIDATION_TIME - timedelta(seconds=30),
        VALIDATION_TIME - timedelta(seconds=30),
        VALIDATION_TIME + timedelta(seconds=120),
    )
    verify_range_kill_command(command, topology, governance, VALIDATION_TIME, KILL_LIFETIME_SECONDS)
    validate_contract(command, project_root / "specs" / "range-kill-command.schema.json", "generated range kill command")

    adversarial_count = 0
    with tempfile.TemporaryDirectory(prefix="nimrod-range-lifecycle-") as temporary:
        root = Path(temporary)
        store = RangeKillStateStore(root / "primary", no_range_kill_failure)
        state = store.engage(command, topology, governance, VALIDATION_TIME, KILL_LIFETIME_SECONDS)
        validate_contract(state, project_root / "specs" / "range-kill-state.schema.json", "generated range kill state")
        require_condition(store.inspect(cast(str, topology["topology_id"]), cast(int, topology["generation"])) == state, "Durable range kill state changed after readback.")
        expect_error(RangeKillReplayError, lambda: store.engage(command, topology, governance, VALIDATION_TIME, KILL_LIFETIME_SECONDS), "kill replay")
        adversarial_count += 1
        conflicting = signed_kill_command(
            topology,
            governance,
            connectors,
            "0d21bb38-64dc-44a5-a27d-1b5cb06ac1ed",
            "operator_emergency",
            VALIDATION_TIME - timedelta(seconds=30),
            VALIDATION_TIME - timedelta(seconds=30),
            VALIDATION_TIME + timedelta(seconds=120),
        )
        expect_error(RangeKillConflictError, lambda: store.engage(conflicting, topology, governance, VALIDATION_TIME, KILL_LIFETIME_SECONDS), "conflicting kill command")
        adversarial_count += 1

        topology_path = root / "topology.json"
        command_path = root / "command.json"
        governance_path = root / "governance.json"
        write_json(topology_path, topology)
        write_json(command_path, command)
        write_json(governance_path, governance)

        prepublish_root = root / "crash-before-publish"
        before = run_worker(worker_command(project_root, prepublish_root, topology_path, command_path, governance_path, "temporary_durable"))
        require_condition(before.returncode == 91, "Pre-publication crash worker did not exit at the injected boundary.")
        retry_before = run_worker(worker_command(project_root, prepublish_root, topology_path, command_path, governance_path, "none"))
        require_condition(retry_before.returncode == 0 and json.loads(retry_before.stdout)["status"] == "accepted", "Pre-publication crash did not remain safely retryable.")
        adversarial_count += 1

        postpublish_root = root / "crash-after-publish"
        after = run_worker(worker_command(project_root, postpublish_root, topology_path, command_path, governance_path, "state_published"))
        require_condition(after.returncode == 92, "Post-publication crash worker did not exit at the injected boundary.")
        retry_after = run_worker(worker_command(project_root, postpublish_root, topology_path, command_path, governance_path, "none"))
        require_condition(retry_after.returncode == 0 and json.loads(retry_after.stdout)["status"] == "replay_denied", "Published kill state was not durable across process crash.")
        adversarial_count += 1

        contention_root = root / "contention"
        processes = [
            subprocess.Popen(
                worker_command(project_root, contention_root, topology_path, command_path, governance_path, "none"),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            for _ in range(WORKER_COUNT)
        ]
        worker_results: list[JsonObject] = []
        for process in processes:
            stdout, stderr = process.communicate(timeout=30)
            require_condition(process.returncode == 0, f"Range kill contention worker failed: {stderr}")
            worker_results.append(cast(JsonObject, json.loads(stdout)))
        accepted_count = sum(1 for value in worker_results if value.get("status") == "accepted")
        replay_count = sum(1 for value in worker_results if value.get("status") == "replay_denied")
        require_condition(accepted_count == 1 and replay_count == WORKER_COUNT - 1, "Range kill contention did not produce one irreversible winner.")
        adversarial_count += 1

        corrupt_root = root / "corrupt"
        corrupt_store = RangeKillStateStore(corrupt_root, no_range_kill_failure)
        corrupt_store.engage(command, topology, governance, VALIDATION_TIME, KILL_LIFETIME_SECONDS)
        state_paths = tuple((corrupt_root / "range-kill" / "v1" / "states").glob("*.json"))
        require_condition(len(state_paths) == 1, "Corrupt-state fixture did not create exactly one state record.")
        state_paths[0].write_text("{}\n", encoding="utf-8", newline="\n")
        expect_error(RangeKillStateError, lambda: corrupt_store.inspect(cast(str, topology["topology_id"]), cast(int, topology["generation"])), "corrupt kill state")
        adversarial_count += 1

        blocked_evidence = blocked_recovery_evidence(topology, state, VALIDATION_TIME - timedelta(seconds=30))
        blocked_receipt = evaluate_range_recovery(blocked_evidence, topology, state, VALIDATION_TIME, RECOVERY_EVIDENCE_AGE_SECONDS)
        validate_contract(blocked_evidence, project_root / "specs" / "range-recovery-evidence.schema.json", "generated blocked range recovery evidence")
        validate_contract(blocked_receipt, project_root / "specs" / "range-recovery-receipt.schema.json", "generated blocked range recovery receipt")
        require_condition(blocked_receipt["status"] == "blocked", "Unproven cleanup evidence did not remain blocked.")

        verified_evidence = verified_recovery_evidence(topology, state, VALIDATION_TIME - timedelta(seconds=30))
        verified_receipt = evaluate_range_recovery(verified_evidence, topology, state, VALIDATION_TIME, RECOVERY_EVIDENCE_AGE_SECONDS)
        validate_contract(verified_evidence, project_root / "specs" / "range-recovery-evidence.schema.json", "generated verified range recovery evidence")
        validate_contract(verified_receipt, project_root / "specs" / "range-recovery-receipt.schema.json", "generated verified range recovery receipt")
        require_condition(
            verified_receipt["status"] == "verified_contract_only"
            and verified_receipt["kill_remains_engaged"] is True
            and verified_receipt["range_reuse_authorized"] is False,
            "Contract-only cleanup verification reset or reused the range.",
        )

        topology_mutations: list[tuple[JsonObject, str]] = []
        topology_authority = copy.deepcopy(topology)
        cast(JsonObject, topology_authority["authority"])["can_provision"] = True
        topology_mutations.append((topology_authority, "topology authority"))
        topology_internet = copy.deepcopy(topology)
        cast(list[JsonObject], topology_internet["zones"])[0]["internet_access"] = True
        topology_mutations.append((topology_internet, "topology internet access"))
        topology_duplicate_zone = copy.deepcopy(topology)
        duplicate_zones = cast(list[JsonObject], topology_duplicate_zone["zones"])
        duplicate_zones[1]["zone_id"] = duplicate_zones[0]["zone_id"]
        topology_mutations.append((topology_duplicate_zone, "duplicate topology zone"))
        topology_duplicate_credential = copy.deepcopy(topology)
        duplicate_nodes = cast(list[JsonObject], topology_duplicate_credential["nodes"])
        duplicate_nodes[1]["credential_scope"] = duplicate_nodes[0]["credential_scope"]
        topology_mutations.append((topology_duplicate_credential, "credential scope reuse"))
        topology_nondisposable = copy.deepcopy(topology)
        cast(list[JsonObject], topology_nondisposable["nodes"])[0]["disposable"] = False
        topology_mutations.append((topology_nondisposable, "non-disposable target"))
        topology_shared_credentials = copy.deepcopy(topology)
        cast(list[JsonObject], topology_shared_credentials["nodes"])[0]["dedicated_credentials"] = False
        topology_mutations.append((topology_shared_credentials, "shared target credentials"))
        topology_reverse_route = copy.deepcopy(topology)
        cast(list[JsonObject], topology_reverse_route["routes"])[0]["source_zone_id"] = "zone:telemetry"
        topology_mutations.append((topology_reverse_route, "reverse telemetry route"))
        topology_control_widening = copy.deepcopy(topology)
        cast(JsonObject, topology_control_widening["controls"])["target_to_control_plane_permitted"] = True
        topology_mutations.append((topology_control_widening, "target control-plane route widening"))
        topology_environment = copy.deepcopy(topology)
        topology_environment["environment_class"] = "production"
        topology_mutations.append((topology_environment, "topology environment widening"))
        for mutated, label in topology_mutations:
            expect_error(RangeTopologyError, partial(validate_range_topology, mutated), label)
            adversarial_count += 1

        signature_tamper = copy.deepcopy(command)
        signatures = cast(list[JsonObject], signature_tamper["signatures"])
        encoded = cast(str, signatures[0]["signature_base64"])
        signatures[0]["signature_base64"] = ("A" if encoded[0] != "A" else "B") + encoded[1:]
        expect_error(RangeKillSignatureError, lambda: verify_range_kill_command(signature_tamper, topology, governance, VALIDATION_TIME, KILL_LIFETIME_SECONDS), "kill signature tamper")
        adversarial_count += 1
        kill_mutations: list[tuple[JsonObject, str]] = []
        one_signer = copy.deepcopy(command)
        one_signer["signatures"] = cast(list[JsonObject], one_signer["signatures"])[:1]
        kill_mutations.append((one_signer, "kill threshold underflow"))
        duplicate_signer = copy.deepcopy(command)
        duplicate_signatures = cast(list[JsonObject], duplicate_signer["signatures"])
        duplicate_signatures[1]["signer_id"] = duplicate_signatures[0]["signer_id"]
        kill_mutations.append((duplicate_signer, "duplicate kill signer"))
        topology_substitution = copy.deepcopy(command)
        topology_substitution["topology_digest"] = "sha256:" + "0" * 64
        kill_mutations.append((topology_substitution, "kill topology substitution"))
        governance_substitution = copy.deepcopy(command)
        governance_substitution["governance_state_digest"] = "sha256:" + "0" * 64
        kill_mutations.append((governance_substitution, "kill governance substitution"))
        sequence_substitution = copy.deepcopy(command)
        sequence_substitution["sequence"] = 2
        kill_mutations.append((sequence_substitution, "kill sequence substitution"))
        command_widening = copy.deepcopy(command)
        command_widening["command"] = "disengage"
        kill_mutations.append((command_widening, "kill disengage command"))
        command_authority = copy.deepcopy(command)
        cast(JsonObject, command_authority["authority"])["can_disengage"] = True
        kill_mutations.append((command_authority, "kill disengage authority"))
        for mutated, label in kill_mutations:
            expect_error(
                RangeKillSignatureError,
                partial(
                    verify_range_kill_command,
                    mutated,
                    topology,
                    governance,
                    VALIDATION_TIME,
                    KILL_LIFETIME_SECONDS,
                ),
                label,
            )
            adversarial_count += 1
        expired = signed_kill_command(topology, governance, connectors, "b2ea13d9-5fd9-4313-8e49-bcd13c59e055", "test_fixture", VALIDATION_TIME - timedelta(seconds=200), VALIDATION_TIME - timedelta(seconds=200), VALIDATION_TIME - timedelta(seconds=1))
        expect_error(RangeKillSignatureError, lambda: verify_range_kill_command(expired, topology, governance, VALIDATION_TIME, KILL_LIFETIME_SECONDS), "expired kill command")
        adversarial_count += 1
        future = signed_kill_command(topology, governance, connectors, "a105f55f-9cba-4383-96f6-509f58f56650", "test_fixture", VALIDATION_TIME, VALIDATION_TIME + timedelta(seconds=1), VALIDATION_TIME + timedelta(seconds=100))
        expect_error(RangeKillSignatureError, lambda: verify_range_kill_command(future, topology, governance, VALIDATION_TIME, KILL_LIFETIME_SECONDS), "future kill command")
        adversarial_count += 1
        overlong = signed_kill_command(topology, governance, connectors, "c91252cc-bec6-492f-b381-9749161414ee", "test_fixture", VALIDATION_TIME - timedelta(seconds=1), VALIDATION_TIME - timedelta(seconds=1), VALIDATION_TIME + timedelta(seconds=KILL_LIFETIME_SECONDS + 1))
        expect_error(RangeKillSignatureError, lambda: verify_range_kill_command(overlong, topology, governance, VALIDATION_TIME, KILL_LIFETIME_SECONDS), "overlong kill command")
        adversarial_count += 1

        recovery_mutations: list[tuple[JsonObject, str]] = []
        recovery_topology = copy.deepcopy(verified_evidence)
        recovery_topology["topology_digest"] = "sha256:" + "0" * 64
        recovery_mutations.append((recovery_topology, "recovery topology substitution"))
        recovery_kill = copy.deepcopy(verified_evidence)
        recovery_kill["kill_state_digest"] = "sha256:" + "0" * 64
        recovery_mutations.append((recovery_kill, "recovery kill substitution"))
        recovery_authority = copy.deepcopy(verified_evidence)
        cast(JsonObject, recovery_authority["authority"])["can_reset_kill"] = True
        recovery_mutations.append((recovery_authority, "recovery reset authority"))
        recovery_subject = copy.deepcopy(verified_evidence)
        recovery_subject["cleanup_subject_digest"] = "sha256:" + "0" * 64
        recovery_mutations.append((recovery_subject, "recovery subject substitution"))
        recovery_missing = copy.deepcopy(verified_evidence)
        recovery_missing["cleanup_obligations"] = cast(list[JsonObject], recovery_missing["cleanup_obligations"])[:-1]
        recovery_missing["cleanup_subject_digest"] = range_cleanup_subject_digest(recovery_missing)
        recovery_mutations.append((recovery_missing, "missing cleanup obligation"))
        recovery_no_evidence = copy.deepcopy(verified_evidence)
        cast(list[JsonObject], recovery_no_evidence["cleanup_obligations"])[0]["evidence"] = []
        recovery_no_evidence["cleanup_subject_digest"] = range_cleanup_subject_digest(recovery_no_evidence)
        recovery_mutations.append((recovery_no_evidence, "verified cleanup without evidence"))
        recovery_same_verifier = copy.deepcopy(verified_evidence)
        recovery_observations = cast(list[JsonObject], recovery_same_verifier["verifier_observations"])
        recovery_observations[1]["verifier_id"] = recovery_observations[0]["verifier_id"]
        recovery_mutations.append((recovery_same_verifier, "duplicate recovery verifier"))
        recovery_same_process = copy.deepcopy(verified_evidence)
        recovery_processes = cast(list[JsonObject], recovery_same_process["verifier_observations"])
        recovery_processes[1]["process_id"] = recovery_processes[0]["process_id"]
        recovery_mutations.append((recovery_same_process, "duplicate recovery process"))
        recovery_observation_subject = copy.deepcopy(verified_evidence)
        cast(list[JsonObject], recovery_observation_subject["verifier_observations"])[0]["subject_digest"] = "sha256:" + "0" * 64
        recovery_mutations.append((recovery_observation_subject, "recovery verifier subject substitution"))
        for mutated, label in recovery_mutations:
            expect_error(
                RangeRecoveryError,
                partial(
                    evaluate_range_recovery,
                    mutated,
                    topology,
                    state,
                    VALIDATION_TIME,
                    RECOVERY_EVIDENCE_AGE_SECONDS,
                ),
                label,
            )
            adversarial_count += 1
        stale = verified_recovery_evidence(topology, state, VALIDATION_TIME - timedelta(seconds=RECOVERY_EVIDENCE_AGE_SECONDS + 1))
        expect_error(RangeRecoveryError, lambda: evaluate_range_recovery(stale, topology, state, VALIDATION_TIME, RECOVERY_EVIDENCE_AGE_SECONDS), "stale recovery evidence")
        adversarial_count += 1
        future_evidence = verified_recovery_evidence(topology, state, VALIDATION_TIME + timedelta(seconds=1))
        expect_error(RangeRecoveryError, lambda: evaluate_range_recovery(future_evidence, topology, state, VALIDATION_TIME, RECOVERY_EVIDENCE_AGE_SECONDS), "future recovery evidence")
        adversarial_count += 1
        mismatched_snapshot = verified_recovery_evidence(topology, state, VALIDATION_TIME)
        mismatched_snapshot["observed_post_cleanup_snapshot_digest"] = sha256_digest({"snapshot": "drifted"})
        mismatched_snapshot["cleanup_subject_digest"] = range_cleanup_subject_digest(mismatched_snapshot)
        for observation in cast(list[JsonObject], mismatched_snapshot["verifier_observations"]):
            observation["subject_digest"] = mismatched_snapshot["cleanup_subject_digest"]
        mismatch_receipt = evaluate_range_recovery(mismatched_snapshot, topology, state, VALIDATION_TIME, RECOVERY_EVIDENCE_AGE_SECONDS)
        require_condition(mismatch_receipt["status"] == "blocked" and "SNAPSHOT_STATE_MISMATCH" in cast(list[object], mismatch_receipt["blockers"]), "Snapshot mismatch did not block recovery.")
        adversarial_count += 1

    return {
        "status": "RANGE_LIFECYCLE_GATES_VALID_NO_PROVISIONING_CONNECTION_OR_EXECUTION",
        "origin": "simulated",
        "topology_status": topology_verdict["status"],
        "topology_zone_count": topology_verdict["zone_count"],
        "topology_node_count": topology_verdict["node_count"],
        "topology_route_count": topology_verdict["route_count"],
        "environment_verified": False,
        "kill_threshold": 2,
        "kill_state": state["state"],
        "kill_remains_engaged": True,
        "kill_contention_worker_count": WORKER_COUNT,
        "kill_contention_accept_count": 1,
        "kill_contention_replay_denial_count": WORKER_COUNT - 1,
        "kill_crash_boundary_count": 2,
        "cleanup_obligation_count": len(REQUIRED_CLEANUP_OBLIGATIONS),
        "recovery_verifier_count": 2,
        "current_recovery_status": blocked_receipt["status"],
        "contract_only_recovery_status": verified_receipt["status"],
        "adversarial_case_count": adversarial_count,
        "provisioning_performed": False,
        "network_contact_performed": False,
        "offensive_tools_installed_or_launched": False,
        "range_reuse_authorized": False,
        "range_connection_authorized": False,
        "live_execution_performed": False,
        "execution_authorized": False,
        "can_connect": False,
        "can_execute": False,
    }


def main() -> None:
    project_root = Path(__file__).resolve().parent.parent
    result = validate_range_lifecycle(project_root)
    report_path = project_root / "reports" / "RANGE_LIFECYCLE_VALIDATION.json"
    report_path.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n"
    )
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
