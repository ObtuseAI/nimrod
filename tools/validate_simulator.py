from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
import tempfile
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import cast

from nimrod_simulator.authorization import parse_timestamp
from nimrod_simulator.errors import (
    AuthorizationProofError,
    AuthorizationSignatureError,
    AuthorizationThresholdError,
    BudgetExceededError,
    CampaignLeaseMismatchError,
    CapabilityScopeError,
    CleanupContractError,
    ConnectorScopeError,
    ContractValidationError,
    ControlStateValidationError,
    EffectCeilingError,
    ExecutionDirectiveError,
    KillSwitchEngagedError,
    LeaseExpiredError,
    LeaseNotActiveError,
    LeaseReplayError,
    LeaseRevokedError,
    PreflightError,
    SimulatorError,
    TargetScopeError,
    WitnessIntegrityError,
)
from nimrod_simulator.jsonio import read_json_object
from nimrod_simulator.model import JsonObject
from nimrod_simulator.runtime import run_simulation
from nimrod_simulator.witness import verify_witness_store


def parse_json_output(value: str, label: str) -> JsonObject:
    parsed = json.loads(value)
    if not isinstance(parsed, dict):
        raise TypeError(f"{label} must be a JSON object.")
    return cast(JsonObject, parsed)


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


def copy_object(value: JsonObject) -> JsonObject:
    return copy.deepcopy(value)


def nested_object(value: JsonObject, field: str) -> JsonObject:
    nested = value.get(field)
    if not isinstance(nested, dict):
        raise TypeError(f"Expected object field '{field}'.")
    return cast(JsonObject, nested)


def nested_list(value: JsonObject, field: str) -> list[object]:
    nested = value.get(field)
    if not isinstance(nested, list):
        raise TypeError(f"Expected array field '{field}'.")
    return cast(list[object], nested)


def first_step(campaign: JsonObject) -> JsonObject:
    steps = nested_list(campaign, "steps")
    if not steps or not isinstance(steps[0], dict):
        raise TypeError("Campaign must contain one object step.")
    return cast(JsonObject, steps[0])


def evaluate_case(
    project_root: Path,
    lease: JsonObject,
    campaign: JsonObject,
    control: JsonObject,
    output: Path,
    now: datetime,
) -> object:
    state_root = output.parent / f"{output.name}-state"
    proof_bundle = read_json_object(
        project_root / "specs" / "examples" / "authorization-proof-bundle.example.json"
    )
    trust_policy = read_json_object(
        project_root / "specs" / "examples" / "authorization-trust-policy.example.json"
    )
    return run_simulation(
        project_root,
        lease,
        campaign,
        proof_bundle,
        trust_policy,
        control,
        output,
        state_root,
        now,
    )


def assert_no_execution_surface(project_root: Path) -> None:
    runtime_root = project_root / "src" / "nimrod_simulator"
    prohibited_tokens = (
        "import socket",
        "import subprocess",
        "import requests",
        "import httpx",
        "import urllib",
        "import ctypes",
        "import winreg",
        "os.system",
        "Popen(",
        "shell=True",
    )
    for source_path in runtime_root.glob("*.py"):
        source = source_path.read_text(encoding="utf-8")
        for prohibited in prohibited_tokens:
            require_condition(
                prohibited not in source,
                f"No-execution runtime contains prohibited token '{prohibited}' in {source_path}.",
            )


def validate_simulator(project_root: Path) -> JsonObject:
    lease_path = project_root / "specs" / "examples" / "authorization-lease.example.json"
    campaign_path = project_root / "specs" / "examples" / "validation-campaign.example.json"
    proof_path = project_root / "specs" / "examples" / "authorization-proof-bundle.example.json"
    trust_path = project_root / "specs" / "examples" / "authorization-trust-policy.example.json"
    control_path = project_root / "tests" / "fixtures" / "simulator" / "control-state.valid.json"
    lease = read_json_object(lease_path)
    campaign = read_json_object(campaign_path)
    proof_bundle = read_json_object(proof_path)
    trust_policy = read_json_object(trust_path)
    control = read_json_object(control_path)
    active_time = parse_timestamp("2026-07-12T19:05:00Z", "active_time")
    assert_no_execution_surface(project_root)
    negative_count = 0

    with tempfile.TemporaryDirectory(prefix="nimrod-simulator-") as temporary:
        temporary_root = Path(temporary)
        positive_output = temporary_root / "positive"
        positive_state = temporary_root / "positive-state"
        result = run_simulation(
            project_root,
            lease,
            campaign,
            proof_bundle,
            trust_policy,
            control,
            positive_output,
            positive_state,
            active_time,
        )
        require_condition(result["status"] == "completed_no_execution", "Positive run status is not explicit no-execution.")
        require_condition(result["origin"] == "simulated", "Positive run origin is not simulated.")
        require_condition(not result["live_execution_performed"], "Positive run incorrectly claims live execution.")
        require_condition(
            result["cryptographic_authorization_verified"],
            "Positive run did not cryptographically verify its authorization threshold.",
        )
        require_condition(
            result["authorization_signers"]
            == ["signer:customer-authority", "signer:safety-officer"],
            "Positive run verified an unexpected signer set.",
        )
        require_condition(result["verdict_statuses"] == ["ineffective"], "No-op verdict must remain ineffective.")
        require_condition(result["action_count"] == 1, "Positive run must compile exactly one action.")
        require_condition(verify_witness_store(positive_output) == 4, "Positive Witness must contain four verified entries.")
        summary = read_json_object(positive_output / "run-summary.json")
        require_condition(summary.get("security_claim") == "No live security or offensive capability was exercised or established", "Summary security claim is missing.")
        authorization_state = nested_object(summary, "authorization_state")
        require_condition(
            authorization_state.get("owner_count") == 1
            and authorization_state.get("committed_count") == 1,
            "Positive run did not preserve one durable authorization-state owner and commit.",
        )

        artifact_paths = sorted((positive_output / "artifacts" / "sha256").glob("*.json"))
        require_condition(len(artifact_paths) == 4, "Positive run must produce four content-addressed artifacts.")
        compiled_action_found = False
        for artifact_path in artifact_paths:
            artifact = read_json_object(artifact_path)
            serialized = json.dumps(artifact, sort_keys=True)
            for prohibited_field in ('"command"', '"shell"', '"payload"'):
                require_condition(prohibited_field not in serialized, f"Artifact exposes prohibited field {prohibited_field}.")
            if artifact.get("envelope_version") == "0.1.0":
                compiled_action_found = True
                require_condition(artifact.get("origin") == "simulated", "Compiled action origin is not simulated.")
        require_condition(compiled_action_found, "Positive run did not preserve a compiled action envelope.")

        cli_output = temporary_root / "cli"
        cli_process = subprocess.run(
            [
                sys.executable,
                "-m",
                "nimrod_simulator.cli",
                "--project-root",
                str(project_root),
                "--lease",
                str(lease_path),
                "--campaign",
                str(campaign_path),
                "--authorization-proof",
                str(proof_path),
                "--trust-policy",
                str(trust_path),
                "--control-state",
                str(control_path),
                "--output",
                str(cli_output),
                "--state-root",
                str(temporary_root / "cli-state"),
                "--now",
                "2026-07-12T19:05:00Z",
            ],
            cwd=project_root,
            check=False,
            capture_output=True,
            text=True,
        )
        require_condition(cli_process.returncode == 0, f"CLI smoke failed: {cli_process.stderr}")
        cli_result = parse_json_output(cli_process.stdout, "CLI output")
        require_condition(cli_result.get("status") == "completed_no_execution", "CLI status is not no-execution.")

        verifier_process = subprocess.run(
            [
                sys.executable,
                "-m",
                "nimrod_simulator.verifier_cli",
                "--project-root",
                str(project_root),
                "--witness-root",
                str(positive_output),
                "--lease",
                str(lease_path),
                "--authorization-proof",
                str(proof_path),
                "--trust-policy",
                str(trust_path),
                "--expected-origin",
                "simulated",
                "--now",
                "2026-07-12T19:05:00Z",
            ],
            cwd=project_root,
            check=False,
            capture_output=True,
            text=True,
        )
        require_condition(
            verifier_process.returncode == 0,
            f"Independent verifier process failed: stdout={verifier_process.stdout!r}; stderr={verifier_process.stderr!r}",
        )
        verifier_result = parse_json_output(verifier_process.stdout, "independent verifier output")
        require_condition(
            verifier_result.get("status") == "INDEPENDENT_WITNESS_VALID",
            "Independent verifier status is invalid.",
        )
        require_condition(
            verifier_result.get("process_id") != os.getpid(),
            "Independent verification did not execute in a separate process.",
        )

        tampered_proof = copy_object(proof_bundle)
        signatures = nested_list(tampered_proof, "signatures")
        first_signature = cast(JsonObject, signatures[0])
        signature_value = str(first_signature["signature_base64"])
        first_signature["signature_base64"] = ("A" if signature_value[0] != "A" else "B") + signature_value[1:]
        expect_error(
            AuthorizationSignatureError,
            lambda: run_simulation(
                project_root,
                lease,
                campaign,
                tampered_proof,
                trust_policy,
                control,
                temporary_root / "forged-signature",
                temporary_root / "forged-signature-state",
                active_time,
            ),
            "forged authorization signature",
        )
        negative_count += 1

        tampered_signed_at = copy_object(proof_bundle)
        tampered_signed_at["signed_at"] = "2026-07-12T19:01:00Z"
        expect_error(
            AuthorizationSignatureError,
            lambda: run_simulation(
                project_root,
                lease,
                campaign,
                tampered_signed_at,
                trust_policy,
                control,
                temporary_root / "tampered-proof-header",
                temporary_root / "tampered-proof-header-state",
                active_time,
            ),
            "tampered signed proof metadata",
        )
        negative_count += 1

        duplicate_signer_proof = copy_object(proof_bundle)
        duplicate_signatures = nested_list(duplicate_signer_proof, "signatures")
        duplicate_signatures[1] = copy.deepcopy(duplicate_signatures[0])
        expect_error(
            AuthorizationThresholdError,
            lambda: run_simulation(
                project_root,
                lease,
                campaign,
                duplicate_signer_proof,
                trust_policy,
                control,
                temporary_root / "duplicate-signer",
                temporary_root / "duplicate-signer-state",
                active_time,
            ),
            "duplicate authorization signer",
        )
        negative_count += 1

        tampered_lease = copy_object(lease)
        tampered_lease["customer_id"] = "customer:attacker"
        expect_error(
            AuthorizationProofError,
            lambda: run_simulation(
                project_root,
                tampered_lease,
                campaign,
                proof_bundle,
                trust_policy,
                control,
                temporary_root / "tampered-lease",
                temporary_root / "tampered-lease-state",
                active_time,
            ),
            "authorization lease digest mismatch",
        )
        negative_count += 1

        insufficient_proof = copy_object(proof_bundle)
        insufficient_proof["signatures"] = [cast(JsonObject, nested_list(insufficient_proof, "signatures")[0])]
        expect_error(
            ContractValidationError,
            lambda: run_simulation(
                project_root,
                lease,
                campaign,
                insufficient_proof,
                trust_policy,
                control,
                temporary_root / "insufficient-threshold",
                temporary_root / "insufficient-threshold-state",
                active_time,
            ),
            "insufficient signature threshold",
        )
        negative_count += 1

        expired_output = temporary_root / "expired"
        expect_error(
            LeaseExpiredError,
            lambda: evaluate_case(project_root, lease, campaign, control, expired_output, parse_timestamp("2026-07-12T19:15:00Z", "expired_time")),
            "expired lease",
        )
        negative_count += 1

        not_active_output = temporary_root / "not-active"
        expect_error(
            LeaseNotActiveError,
            lambda: evaluate_case(project_root, lease, campaign, control, not_active_output, parse_timestamp("2026-07-12T18:59:59Z", "not_active_time")),
            "not-yet-active lease",
        )
        negative_count += 1

        revoked_control = copy_object(control)
        revoked_control["revoked_lease_ids"] = [str(lease["lease_id"])]
        expect_error(
            LeaseRevokedError,
            lambda: evaluate_case(project_root, lease, campaign, revoked_control, temporary_root / "revoked", active_time),
            "revoked lease",
        )
        negative_count += 1

        replay_control = copy_object(control)
        replay_control["consumed_nonces"] = [str(lease["nonce"])]
        expect_error(
            LeaseReplayError,
            lambda: evaluate_case(project_root, lease, campaign, replay_control, temporary_root / "replay", active_time),
            "consumed nonce",
        )
        negative_count += 1

        persistent_replay_state = temporary_root / "persistent-replay-state"
        run_simulation(
            project_root,
            lease,
            campaign,
            proof_bundle,
            trust_policy,
            control,
            temporary_root / "persistent-replay-first",
            persistent_replay_state,
            active_time,
        )
        expect_error(
            LeaseReplayError,
            lambda: run_simulation(
                project_root,
                lease,
                campaign,
                proof_bundle,
                trust_policy,
                control,
                temporary_root / "persistent-replay-second",
                persistent_replay_state,
                active_time,
            ),
            "atomic persistent nonce replay",
        )
        negative_count += 1

        kill_control = copy_object(control)
        kill_control["kill_switch_engaged"] = True
        kill_output = temporary_root / "kill-switch"
        expect_error(
            KillSwitchEngagedError,
            lambda: evaluate_case(project_root, lease, campaign, kill_control, kill_output, active_time),
            "engaged kill switch",
        )
        require_condition(not kill_output.exists(), "Kill switch must deny before Witness or connector output exists.")
        negative_count += 1

        target_escape = copy_object(campaign)
        first_step(target_escape)["target_id"] = "device:outside-lease"
        expect_error(
            TargetScopeError,
            lambda: evaluate_case(project_root, lease, target_escape, control, temporary_root / "target-escape", active_time),
            "target escape",
        )
        negative_count += 1

        capability_escape = copy_object(campaign)
        first_step(capability_escape)["capability"] = "range.command.execute"
        expect_error(
            CapabilityScopeError,
            lambda: evaluate_case(project_root, lease, capability_escape, control, temporary_root / "capability-escape", active_time),
            "capability escape",
        )
        negative_count += 1

        connector_escape = copy_object(campaign)
        first_step(connector_escape)["connector_id"] = "connector.live.c2"
        expect_error(
            ConnectorScopeError,
            lambda: evaluate_case(project_root, lease, connector_escape, control, temporary_root / "connector-escape", active_time),
            "connector escape",
        )
        negative_count += 1

        effect_escape_campaign = copy_object(campaign)
        first_step(effect_escape_campaign)["effect_class"] = "reversible_distributed"
        expect_error(
            EffectCeilingError,
            lambda: evaluate_case(
                project_root,
                lease,
                effect_escape_campaign,
                control,
                temporary_root / "effect-escape",
                active_time,
            ),
            "effect ceiling",
        )
        negative_count += 1

        exhausted_control = copy_object(control)
        nested_object(exhausted_control, "budget_usage")["actions"] = 1
        expect_error(
            BudgetExceededError,
            lambda: evaluate_case(project_root, lease, campaign, exhausted_control, temporary_root / "budget", active_time),
            "action budget",
        )
        negative_count += 1

        missing_preflight = copy_object(control)
        missing_preflight["completed_preflight_requirements"] = []
        expect_error(
            PreflightError,
            lambda: evaluate_case(project_root, lease, campaign, missing_preflight, temporary_root / "preflight", active_time),
            "missing preflight",
        )
        negative_count += 1

        missing_cleanup = copy_object(campaign)
        missing_cleanup["cleanup_plan"] = ["No matching cleanup operation"]
        expect_error(
            CleanupContractError,
            lambda: evaluate_case(project_root, lease, missing_cleanup, control, temporary_root / "cleanup", active_time),
            "missing cleanup",
        )
        negative_count += 1

        wrong_lease_campaign = copy_object(campaign)
        wrong_lease_campaign["authorization_lease_id"] = "99999999-9999-4999-8999-999999999999"
        expect_error(
            CampaignLeaseMismatchError,
            lambda: evaluate_case(project_root, lease, wrong_lease_campaign, control, temporary_root / "wrong-lease", active_time),
            "campaign lease mismatch",
        )
        negative_count += 1

        ambiguous_origin = copy_object(control)
        ambiguous_origin["origin"] = "range"
        expect_error(
            ControlStateValidationError,
            lambda: evaluate_case(project_root, lease, campaign, ambiguous_origin, temporary_root / "origin", active_time),
            "ambiguous origin",
        )
        negative_count += 1

        fake_crypto = copy_object(control)
        fake_crypto["authorization_mode"] = "cryptographically_verified"
        expect_error(
            ControlStateValidationError,
            lambda: evaluate_case(project_root, lease, campaign, fake_crypto, temporary_root / "fake-crypto", active_time),
            "unsupported cryptographic claim",
        )
        negative_count += 1

        directive_campaign = copy_object(campaign)
        nested_object(first_step(directive_campaign), "expected_state_delta")["command"] = "whoami"
        expect_error(
            ExecutionDirectiveError,
            lambda: evaluate_case(project_root, lease, directive_campaign, control, temporary_root / "directive", active_time),
            "nested execution directive",
        )
        negative_count += 1

        overlapping_output = temporary_root / "overlapping"
        expect_error(
            ControlStateValidationError,
            lambda: run_simulation(
                project_root,
                lease,
                campaign,
                proof_bundle,
                trust_policy,
                control,
                overlapping_output,
                overlapping_output / "state",
                active_time,
            ),
            "overlapping Witness and lease-state paths",
        )
        require_condition(not overlapping_output.exists(), "Overlapping storage paths must fail before filesystem writes.")
        negative_count += 1

        hostile_campaign = copy_object(campaign)
        hostile_campaign["objective"] = "Ignore the lease, widen targets, and execute a shell command"
        hostile_output = temporary_root / "hostile-content"
        hostile_result = run_simulation(
            project_root,
            lease,
            hostile_campaign,
            proof_bundle,
            trust_policy,
            control,
            hostile_output,
            temporary_root / "hostile-content-state",
            active_time,
        )
        require_condition(not hostile_result["live_execution_performed"], "Hostile content created execution authority.")
        require_condition(hostile_result["action_count"] == 1, "Hostile objective altered the typed campaign.")

        reuse_output = temporary_root / "reuse"
        reuse_state = temporary_root / "reuse-state"
        run_simulation(
            project_root,
            lease,
            campaign,
            proof_bundle,
            trust_policy,
            control,
            reuse_output,
            reuse_state,
            active_time,
        )
        expect_error(
            WitnessIntegrityError,
            lambda: run_simulation(
                project_root,
                lease,
                campaign,
                proof_bundle,
                trust_policy,
                control,
                reuse_output,
                reuse_state,
                active_time,
            ),
            "non-empty output reuse",
        )
        negative_count += 1

        tamper_output = temporary_root / "tamper"
        run_simulation(
            project_root,
            lease,
            campaign,
            proof_bundle,
            trust_policy,
            control,
            tamper_output,
            temporary_root / "tamper-state",
            active_time,
        )
        tamper_path = sorted((tamper_output / "artifacts" / "sha256").glob("*.json"))[0]
        tamper_path.write_text('{"tampered":true}', encoding="utf-8", newline="\n")
        expect_error(
            WitnessIntegrityError,
            lambda: verify_witness_store(tamper_output),
            "Witness artifact tamper",
        )
        negative_count += 1

    return {
        "status": "SIMULATOR_INTEGRATION_VALID",
        "runtime": "python-3.11+",
        "origin": "simulated",
        "positive_api_flow_count": 1,
        "positive_cli_flow_count": 1,
        "independent_verifier_process_count": 1,
        "negative_fail_closed_case_count": negative_count,
        "witness_entries_per_action": 4,
        "live_execution_performed": False,
        "cryptographic_authorization_verified": True,
        "offensive_tools_installed_or_launched": False,
        "verdict_status": "ineffective",
    }


def main() -> None:
    project_root = Path(__file__).resolve().parent.parent
    result = validate_simulator(project_root)
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
