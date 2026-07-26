from __future__ import annotations

import copy
import getpass
import json
import os
import subprocess
import sys
import tempfile
from collections.abc import Mapping
from pathlib import Path
from uuid import NAMESPACE_URL, uuid5

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from nimrod_simulator.errors import VerifierDisagreementError
from nimrod_simulator.jsonio import canonical_json_bytes, read_json_object, validate_contract
from nimrod_simulator.key_governance import EphemeralEd25519SigningConnector, SigningConnector, governance_key
from nimrod_simulator.model import JsonObject
from nimrod_simulator.verifier_service import build_observation, read_only_snapshot, reconcile_observations
from nimrod_simulator.witness import FileWitnessStore
from nimrod_simulator.witness_checkpoint import (
    FileAnchorPinStore,
    FileExternalAnchorStore,
    build_witness_checkpoint,
)


GOVERNANCE_ID = "dddddddd-eeee-4fff-8000-111111111111"
WITNESS_ID = "witness:supervised-verifier-fixture"
NOW = "2026-07-12T22:30:00Z"
ENVIRONMENT_ALLOWLIST = [
    "PYTHONIOENCODING",
    "PYTHONPATH",
    "SYSTEMROOT",
    "TEMP",
    "TMP",
    "USERDOMAIN",
    "USERNAME",
    "WINDIR",
]


def require_condition(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def connector(key_id: str, role: str) -> EphemeralEd25519SigningConnector:
    return EphemeralEd25519SigningConnector(key_id, role, Ed25519PrivateKey.generate())


def governed_key(item: SigningConnector) -> JsonObject:
    return governance_key(
        item,
        "active",
        "2026-07-12T22:00:00Z",
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
        "issued_at": "2026-07-12T22:00:00Z",
        "previous_state_digest": None,
        "threshold": 2,
        "ceremony_key_count": 3,
        "minimum_distinct_roles": 2,
        "keys": [governed_key(item) for item in signers],
    }


def anchor_policy(anchor: SigningConnector) -> JsonObject:
    return {
        "policy_version": "0.1.0",
        "policy_id": "eeeeeeee-ffff-4000-8111-222222222222",
        "origin": "simulated",
        "anchor_store_id": "anchor:supervised-verifier-fixture",
        "not_before": "2026-07-12T22:00:00Z",
        "expires_at": "2026-07-13T22:00:00Z",
        "minimum_head_sequence": 0,
        "allowed_witness_ids": [WITNESS_ID],
        "anchor_key": {
            "key_id": anchor.key_id,
            "algorithm": "Ed25519",
            "public_key_base64": anchor.public_key_base64,
        },
    }


def service_policy(service_id: str, logical_principal: str) -> JsonObject:
    return {
        "policy_version": "0.1.0",
        "policy_id": str(uuid5(NAMESPACE_URL, f"{service_id}:policy")),
        "origin": "simulated",
        "service_id": service_id,
        "logical_principal": logical_principal,
        "process_boundary_required": True,
        "read_only_inputs_required": True,
        "production_distinct_os_account_required": True,
        "expected_os_account_identifier": None,
        "os_account_boundary_status": "required_unproven",
        "allowed_capabilities": ["health.report", "witness.verify", "anchor.verify"],
        "prohibited_capabilities": ["plan", "authorize", "execute", "sign", "write_evidence", "read_credentials"],
        "environment_allowlist": ENVIRONMENT_ALLOWLIST,
        "denied_environment_prefixes": [
            "AWS_",
            "AZURE_",
            "GOOGLE_",
            "OPENAI_",
            "ANTHROPIC_",
            "GITHUB_TOKEN",
            "GH_TOKEN",
            "KUBECONFIG",
            "DOCKER_",
        ],
        "request_timeout_ms": 5000,
    }


def write_object(path: Path, value: JsonObject) -> None:
    path.write_bytes(canonical_json_bytes(value) + b"\n")


def minimal_environment(project_root: Path) -> dict[str, str]:
    environment: dict[str, str] = {
        "PYTHONIOENCODING": "utf-8",
        "PYTHONPATH": str(project_root / "src"),
    }
    for key in ("SYSTEMROOT", "TEMP", "TMP", "USERDOMAIN", "USERNAME", "WINDIR"):
        value = os.environ.get(key)
        if value is not None:
            environment[key] = value
    return environment


def verify_request(
    request_id: str,
    witness_root: Path,
    anchor_root: Path,
    governance_path: Path,
    anchor_policy_path: Path,
    pinned_head_path: Path,
) -> JsonObject:
    return {
        "request_type": "verify",
        "request_id": request_id,
        "witness_root": str(witness_root),
        "anchor_root": str(anchor_root),
        "governance_state": str(governance_path),
        "anchor_policy": str(anchor_policy_path),
        "pinned_head": str(pinned_head_path),
        "expected_origin": "simulated",
        "now": NOW,
    }


def parse_output_lines(stdout: str) -> list[JsonObject]:
    results: list[JsonObject] = []
    for line_number, line in enumerate(stdout.splitlines(), start=1):
        parsed: object = json.loads(line)
        if not isinstance(parsed, dict):
            raise TypeError(f"Verifier output line {line_number} must be an object.")
        results.append(parsed)
    return results


def run_service_session(
    project_root: Path,
    policy_path: Path,
    request: JsonObject,
    environment: Mapping[str, str],
    timeout_seconds: float,
) -> tuple[JsonObject, JsonObject, JsonObject]:
    input_documents: list[JsonObject] = [
        {"request_type": "health", "request_id": f"health:{request['request_id']}"},
        request,
        {"request_type": "shutdown", "request_id": f"shutdown:{request['request_id']}"},
    ]
    input_text = "".join(canonical_json_bytes(document).decode("utf-8") + "\n" for document in input_documents)
    process = subprocess.run(
        [
            sys.executable,
            "-m",
            "nimrod_simulator.verifier_service_cli",
            "--project-root",
            str(project_root),
            "--service-policy",
            str(policy_path),
        ],
        cwd=project_root,
        env=dict(environment),
        input=input_text,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
    )
    require_condition(
        process.returncode == 0,
        f"Verifier service session failed: returncode={process.returncode}, stdout={process.stdout!r}, stderr={process.stderr!r}",
    )
    outputs = parse_output_lines(process.stdout)
    require_condition(len(outputs) == 3, f"Verifier service emitted {len(outputs)} responses; expected three.")
    return outputs[0], outputs[1], outputs[2]


def assert_service_source_read_only(project_root: Path) -> None:
    prohibited = (
        "write_text(",
        "write_bytes(",
        "os.replace(",
        ".unlink(",
        ".mkdir(",
        "open(\"w",
        "open('w",
        "import subprocess",
    )
    for relative in (
        Path("src/nimrod_simulator/verifier_service.py"),
        Path("src/nimrod_simulator/verifier_service_cli.py"),
    ):
        source = (project_root / relative).read_text(encoding="utf-8")
        for token in prohibited:
            require_condition(token not in source, f"Verifier service source contains write/process token '{token}'.")


def terminal_observation(
    policy: JsonObject,
    request_id: str,
    status: str,
    subject_digest: str | None,
    error_type: str,
    message: str,
) -> JsonObject:
    return build_observation(
        policy,
        request_id,
        NOW,
        status,
        subject_digest,
        error_type,
        message,
        False,
        None,
        None,
    )


def run_credential_denial(
    project_root: Path,
    policy_path: Path,
    environment: dict[str, str],
) -> JsonObject:
    contaminated = dict(environment)
    contaminated["AWS_SECRET_ACCESS_KEY"] = "validation-fixture-not-a-secret"
    process = subprocess.run(
        [
            sys.executable,
            "-m",
            "nimrod_simulator.verifier_service_cli",
            "--project-root",
            str(project_root),
            "--service-policy",
            str(policy_path),
        ],
        cwd=project_root,
        env=contaminated,
        input='{"request_type":"health","request_id":"credential-health"}\n',
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    require_condition(process.returncode == 2, "Credential-contaminated verifier did not fail startup.")
    outputs = parse_output_lines(process.stdout)
    require_condition(len(outputs) == 1, "Credential startup denial must emit one response.")
    return outputs[0]


def run_stall_timeout(project_root: Path, environment: dict[str, str]) -> bool:
    try:
        subprocess.run(
            [sys.executable, str(project_root / "tools" / "verifier_stall_worker.py")],
            cwd=project_root,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
            timeout=0.2,
        )
    except subprocess.TimeoutExpired:
        return True
    return False


def run_unavailable_worker(project_root: Path, environment: dict[str, str]) -> bool:
    process = subprocess.run(
        [sys.executable, str(project_root / "tools" / "verifier_unavailable_worker.py")],
        cwd=project_root,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    return process.returncode == 3 and not process.stdout


def validate_supervised_verifier(project_root: Path) -> JsonObject:
    specs = project_root / "specs"
    assert_service_source_read_only(project_root)
    customer = connector("key:supervisor-customer", "customer_authority")
    safety = connector("key:supervisor-safety", "safety_officer")
    recovery = connector("key:supervisor-recovery", "recovery_officer")
    anchor_signer = connector("key:supervisor-anchor", "recovery_officer")
    state = governance_state([customer, safety, recovery])
    anchor_policy_document = anchor_policy(anchor_signer)
    primary_policy = service_policy(
        "verifier:anchor-primary", "service:nimrod-independent-verifier-primary"
    )
    secondary_policy = service_policy(
        "verifier:anchor-secondary", "service:nimrod-independent-verifier-secondary"
    )
    with tempfile.TemporaryDirectory(prefix="nimrod-supervised-verifier-") as temporary:
        root = Path(temporary)
        witness_root = root / "witness"
        anchor_root = root / "anchor"
        pin_root = root / "pin"
        witness = FileWitnessStore(witness_root)
        for index in range(3):
            witness.append(
                "supervised-verifier-event",
                {"origin": "simulated", "event_id": f"service-event-{index + 1}", "effect": "none"},
                f"2026-07-12T22:0{index}:00Z",
            )
        checkpoint = build_witness_checkpoint(
            witness_root,
            WITNESS_ID,
            str(uuid5(NAMESPACE_URL, f"{WITNESS_ID}:checkpoint")),
            "2026-07-12T22:10:00Z",
            None,
            state,
            [customer, safety],
        )
        anchor_store = FileExternalAnchorStore(anchor_root, witness_root, pin_root, anchor_policy_document, anchor_signer)
        _, head = anchor_store.anchor(checkpoint, state, "2026-07-12T22:11:00Z")
        pin_store = FileAnchorPinStore(pin_root, witness_root, anchor_root)
        pinned_path = pin_store.pin(head, anchor_policy_document)
        governance_path = root / "governance-state.json"
        anchor_policy_path = root / "anchor-policy.json"
        primary_policy_path = root / "primary-service-policy.json"
        secondary_policy_path = root / "secondary-service-policy.json"
        write_object(governance_path, state)
        write_object(anchor_policy_path, anchor_policy_document)
        write_object(primary_policy_path, primary_policy)
        write_object(secondary_policy_path, secondary_policy)
        for value, schema_name, label in (
            (primary_policy, "verifier-service-policy.schema.json", "primary verifier policy"),
            (secondary_policy, "verifier-service-policy.schema.json", "secondary verifier policy"),
        ):
            validate_contract(value, specs / schema_name, label)
        environment = minimal_environment(project_root)
        request = verify_request(
            "verify-baseline",
            witness_root,
            anchor_root,
            governance_path,
            anchor_policy_path,
            pinned_path,
        )
        input_paths = [witness_root, anchor_root, governance_path, anchor_policy_path, pinned_path]
        before_sessions = read_only_snapshot(input_paths)
        primary_health, primary_observation, primary_shutdown = run_service_session(
            project_root, primary_policy_path, request, environment, 10.0
        )
        secondary_health, secondary_observation, secondary_shutdown = run_service_session(
            project_root, secondary_policy_path, request, environment, 10.0
        )
        after_sessions = read_only_snapshot(input_paths)
        require_condition(before_sessions == after_sessions, "Verifier service changed read-only input files.")
        for health in (primary_health, secondary_health):
            validate_contract(health, specs / "verifier-health.schema.json", "generated verifier health")
            require_condition(health.get("status") == "healthy_reference_boundary", "Verifier health is not healthy.")
            require_condition(health.get("production_ready") is False, "Verifier falsely claims production readiness.")
            require_condition(
                health.get("os_account_boundary_verified") is False,
                "Desktop validation unexpectedly claims a dedicated OS account.",
            )
        for observation in (primary_observation, secondary_observation):
            validate_contract(
                observation,
                specs / "verifier-observation.schema.json",
                "generated verifier observation",
            )
            require_condition(observation.get("status") == "valid", "Baseline verifier observation is not valid.")
            require_condition(
                observation.get("read_only_behavior_verified") is True,
                "Baseline verifier did not prove read-only behavior.",
            )
        primary_pid = int(str(primary_health["process_id"]))
        secondary_pid = int(str(secondary_health["process_id"]))
        require_condition(primary_pid != secondary_pid, "Primary and secondary verifiers share a process ID.")
        require_condition(primary_pid != os.getpid() and secondary_pid != os.getpid(), "Verifier ran in supervisor process.")
        require_condition(primary_shutdown.get("status") == "shutdown_complete", "Primary shutdown failed.")
        require_condition(secondary_shutdown.get("status") == "shutdown_complete", "Secondary shutdown failed.")
        reference_consensus = reconcile_observations(primary_observation, secondary_observation, NOW)
        validate_contract(reference_consensus, specs / "verifier-consensus.schema.json", "reference consensus")
        require_condition(
            reference_consensus.get("state") == "agreed_valid_boundary_unproven",
            "Reference consensus did not preserve the OS-account isolation blocker.",
        )
        require_condition(
            reference_consensus.get("verification_accepted") is False,
            "Reference consensus accepted verification without OS-account isolation.",
        )

        tampered_pin = copy.deepcopy(read_json_object(pinned_path))
        tampered_pin["sequence"] = 2
        tampered_pin_path = root / "tampered-pin.json"
        write_object(tampered_pin_path, tampered_pin)
        invalid_request = verify_request(
            "verify-tampered-pin",
            witness_root,
            anchor_root,
            governance_path,
            anchor_policy_path,
            tampered_pin_path,
        )
        _, invalid_secondary, _ = run_service_session(
            project_root, secondary_policy_path, invalid_request, environment, 10.0
        )
        require_condition(invalid_secondary.get("status") == "invalid", "Tampered pin was not invalid.")
        disagreement = reconcile_observations(primary_observation, invalid_secondary, NOW)
        validate_contract(disagreement, specs / "verifier-consensus.schema.json", "verifier disagreement")
        require_condition(disagreement.get("state") == "disagreement", "Valid/invalid split was not disagreement.")
        require_condition(disagreement.get("verification_accepted") is False, "Disagreement was accepted.")

        _, invalid_primary, _ = run_service_session(
            project_root, primary_policy_path, invalid_request, environment, 10.0
        )
        agreed_invalid = reconcile_observations(invalid_primary, invalid_secondary, NOW)
        validate_contract(agreed_invalid, specs / "verifier-consensus.schema.json", "agreed invalid")
        require_condition(agreed_invalid.get("state") == "agreed_invalid", "Invalid verifiers did not agree invalid.")
        require_condition(agreed_invalid.get("verification_accepted") is False, "Agreed invalid was accepted.")

        timeout_exercised = run_stall_timeout(project_root, environment)
        require_condition(timeout_exercised, "Real verifier timeout was not exercised.")
        timeout_observation = terminal_observation(
            secondary_policy,
            "timeout-worker",
            "timeout",
            str(primary_observation["subject_digest"]),
            "TimeoutExpired",
            "Verifier process exceeded the 200ms validation deadline",
        )
        validate_contract(timeout_observation, specs / "verifier-observation.schema.json", "timeout observation")
        timeout_consensus = reconcile_observations(primary_observation, timeout_observation, NOW)
        validate_contract(timeout_consensus, specs / "verifier-consensus.schema.json", "timeout consensus")
        require_condition(timeout_consensus.get("state") == "verifier_timeout", "Timeout state was softened.")

        unavailable_exercised = run_unavailable_worker(project_root, environment)
        require_condition(unavailable_exercised, "Real verifier outage was not exercised.")
        unavailable_observation = terminal_observation(
            secondary_policy,
            "unavailable-worker",
            "unavailable",
            str(primary_observation["subject_digest"]),
            "ProcessExit",
            "Verifier process exited with code 3 before producing an observation",
        )
        validate_contract(
            unavailable_observation,
            specs / "verifier-observation.schema.json",
            "unavailable observation",
        )
        unavailable_consensus = reconcile_observations(primary_observation, unavailable_observation, NOW)
        validate_contract(unavailable_consensus, specs / "verifier-consensus.schema.json", "unavailable consensus")
        require_condition(
            unavailable_consensus.get("state") == "verifier_unavailable",
            "Verifier outage state was softened.",
        )

        credential_denial = run_credential_denial(project_root, primary_policy_path, environment)
        require_condition(
            credential_denial.get("error_type") == "VerifierCredentialExposureError",
            "Credential-like environment variable was not denied.",
        )

        identity_policy = copy.deepcopy(primary_policy)
        identity_policy["expected_os_account_identifier"] = "different-domain\\dedicated-verifier"
        identity_policy["os_account_boundary_status"] = "verified"
        identity_policy_path = root / "identity-mismatch-policy.json"
        write_object(identity_policy_path, identity_policy)
        validate_contract(identity_policy, specs / "verifier-service-policy.schema.json", "identity mismatch policy")
        identity_health, _, _ = run_service_session(
            project_root,
            identity_policy_path,
            request,
            environment,
            10.0,
        )
        require_condition(
            identity_health.get("status") == "blocked_identity_mismatch",
            "Expected OS-account mismatch was not blocked in health.",
        )

        duplicate_identity_denied = False
        try:
            reconcile_observations(primary_observation, primary_observation, NOW)
        except VerifierDisagreementError:
            duplicate_identity_denied = True
        require_condition(duplicate_identity_denied, "Duplicate verifier service identity was accepted.")

        same_process_observation = copy.deepcopy(secondary_observation)
        same_process_observation["process_id"] = primary_observation["process_id"]
        same_process_denied = False
        try:
            reconcile_observations(primary_observation, same_process_observation, NOW)
        except VerifierDisagreementError:
            same_process_denied = True
        require_condition(same_process_denied, "Two verifier identities sharing one process were accepted.")

        actual_account = str(primary_health["os_account_identifier"])
        require_condition(
            actual_account.casefold().endswith(getpass.getuser().casefold()),
            "Verifier OS-account evidence does not match the desktop validation account.",
        )

    return {
        "status": "SUPERVISED_VERIFIER_REFERENCE_VALID_OS_ACCOUNT_BLOCKED",
        "origin": "simulated",
        "separate_verifier_process_count": 5,
        "distinct_logical_verifier_identity_count": 2,
        "distinct_process_ids_verified": True,
        "read_only_input_hash_equality_verified": True,
        "service_source_write_capability_exposed": False,
        "credential_environment_variable_count": 0,
        "credential_contamination_denied": True,
        "real_timeout_case_count": 1,
        "real_unavailable_case_count": 1,
        "negative_fail_closed_case_count": 8,
        "disagreement_state_verified": True,
        "agreed_invalid_state_verified": True,
        "timeout_state_verified": True,
        "unavailable_state_verified": True,
        "reference_valid_state": "agreed_valid_boundary_unproven",
        "verification_accepted": False,
        "production_distinct_os_account_required": True,
        "distinct_os_account_verified": False,
        "os_enforced_read_only_acl_verified": False,
        "planner_or_executor_credentials_provided": False,
        "live_execution_performed": False,
    }


def main() -> None:
    project_root = Path(__file__).resolve().parent.parent
    result = validate_supervised_verifier(project_root)
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
