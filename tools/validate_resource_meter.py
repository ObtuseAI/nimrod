"""Validate live Windows Job Object metering, crash recovery, and lineage binding."""

from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TypeVar, cast

from jsonschema import Draft202012Validator, FormatChecker

from nimrod_simulator.errors import (
    InjectedResourceMeterCrashError,
    ResourceLedgerError,
    ResourceMeterError,
    ResourceMeterStateError,
)
from nimrod_simulator.evolution_constitution import (
    REQUIRED_AXIOMS,
    REQUIRED_CAPABILITY_RESPONSES,
    REQUIRED_HARD_FAILURES,
    sign_evolution_constitution,
)
from nimrod_simulator.jsonio import sha256_digest
from nimrod_simulator.key_governance import EphemeralEd25519SigningConnector, governance_key
from nimrod_simulator.model import JsonObject
from nimrod_simulator.resource_ledger import (
    build_lineage_resource_ledger,
    sign_lineage_resource_ledger,
    verify_lineage_resource_ledger,
)
from nimrod_platform_assurance.resource_meter import (
    recover_resource_measurement,
    resource_ledger_entry_from_receipt,
    run_resource_measurement,
    run_resource_measurement_until_observation,
)
from validate_evolution_assurance import governance_connectors


TError = TypeVar("TError", bound=Exception)


def require_condition(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def expect_error(error_type: type[TError], operation: Callable[[], object], label: str) -> None:
    try:
        operation()
    except error_type:
        return
    raise RuntimeError(f"Expected {error_type.__name__} for {label}.")


def validate_contract(value: JsonObject, schema_path: Path, label: str) -> None:
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors = sorted(validator.iter_errors(value), key=lambda item: list(item.absolute_path))
    if errors:
        rendered = "; ".join(error.message for error in errors)
        raise RuntimeError(f"{label} failed schema validation: {rendered}")


def iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def live_governance_and_constitution(
    now: datetime,
) -> tuple[JsonObject, JsonObject, list[EphemeralEd25519SigningConnector]]:
    signers = governance_connectors()
    issued_at = iso(now - timedelta(minutes=2))
    governance: JsonObject = {
        "state_version": "0.1.0",
        "governance_id": "4bb3e2f2-267a-45fb-b50a-761bd2c29a40",
        "origin": "live",
        "epoch": 1,
        "issued_at": issued_at,
        "previous_state_digest": None,
        "threshold": 2,
        "ceremony_key_count": 3,
        "minimum_distinct_roles": 2,
        "keys": [
            governance_key(
                signer,
                "active",
                issued_at,
                None,
                "test_ephemeral",
                f"connector:custody:{signer.key_id}",
                f"memory:{signer.key_id}",
                False,
                None,
            )
            for signer in signers
        ],
    }
    unsigned_constitution: JsonObject = {
        "constitution_version": "0.1.0",
        "constitution_id": "d595b0fa-3f56-424c-8e0d-8b171c8207bb",
        "origin": "live",
        "governance_state_digest": sha256_digest(governance),
        "issued_at": iso(now - timedelta(seconds=30)),
        "not_before": iso(now - timedelta(seconds=30)),
        "expires_at": iso(now + timedelta(minutes=10)),
        "axioms": sorted(REQUIRED_AXIOMS),
        "hard_failures": sorted(REQUIRED_HARD_FAILURES),
        "capability_triggers": [
            {"trigger_id": trigger_id, "response": response}
            for trigger_id, response in sorted(REQUIRED_CAPABILITY_RESPONSES.items())
        ],
        "tier_policies": [
            {"tier": "A", "maximum_destination": "shadow", "threshold_humans_required": False},
            {"tier": "B", "maximum_destination": "shadow", "threshold_humans_required": False},
            {"tier": "C", "maximum_destination": "production_candidate", "threshold_humans_required": True},
            {"tier": "D", "maximum_destination": "quarantine", "threshold_humans_required": True},
        ],
        "resource_ceilings": {
            "maximum_cycle_seconds": 60,
            "maximum_compute_units": 100,
            "maximum_memory_megabytes": 512,
            "maximum_storage_megabytes": 64,
            "maximum_candidate_children": 2,
        },
        "authority": {
            "can_modify_itself": False,
            "can_select_evaluators": False,
            "can_select_signers": False,
            "can_expand_authority": False,
            "can_execute": False,
        },
    }
    return governance, sign_evolution_constitution(unsigned_constitution, signers[:2]), signers


def worker_command(project_root: Path, output_path: Path) -> list[str]:
    return [
        sys.executable,
        str(project_root / "tools" / "resource_meter_worker.py"),
        "--output",
        str(output_path),
        "--allocation-megabytes",
        "4",
        "--iterations",
        "250000",
        "--output-bytes",
        "65536",
    ]


def validate_resource_meter(project_root: Path) -> JsonObject:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    candidate_id = "candidate:live-resource-meter-probe"
    candidate_digest = sha256_digest({"candidate_id": candidate_id, "candidate_executed": False})
    lease: JsonObject = {
        "maximum_cycle_seconds": 30,
        "maximum_compute_units": 50,
        "maximum_memory_megabytes": 256,
        "maximum_storage_megabytes": 8,
        "maximum_candidate_children": 1,
    }
    lease_digest = sha256_digest(lease)
    schema_path = project_root / "specs" / "resource-meter-receipt.schema.json"
    with tempfile.TemporaryDirectory(prefix="nimrod-resource-meter-") as temporary_directory:
        temporary_root = Path(temporary_directory)
        normal_state = temporary_root / "normal-state"
        normal_output = temporary_root / "normal-output"
        normal_meter_id = "77777777-8888-4999-aaaa-bbbbbbbbbbbb"
        normal_receipt = run_resource_measurement(
            normal_state,
            normal_meter_id,
            candidate_digest,
            lease_digest,
            worker_command(project_root, normal_output / "measurement.bin"),
            normal_output,
            256 * 1024 * 1024,
            20,
            iso(now),
            iso(now + timedelta(seconds=1)),
            iso(now + timedelta(seconds=2)),
            iso(now + timedelta(seconds=3)),
        )
        validate_contract(normal_receipt, schema_path, "live OS resource-meter receipt")
        require_condition(normal_receipt["origin"] == "live", "Resource meter did not preserve live origin.")
        require_condition(normal_receipt["job"]["job_object_assigned"] is True, "Worker was not assigned to a Job Object.")
        require_condition(normal_receipt["job"]["kill_on_close_configured"] is True, "Kill-on-close was not configured.")
        require_condition(normal_receipt["job"]["created_suspended"] is True, "Worker was not created suspended.")
        require_condition(
            normal_receipt["job"]["assigned_before_first_resume"] is True,
            "Worker was resumed before Job Object assignment.",
        )
        require_condition(normal_receipt["job"]["assignment_race_closed"] is True, "Job Object assignment race remained open.")
        require_condition(normal_receipt["job"]["active_processes_after_completion"] == 0, "Worker remained active after completion.")
        require_condition(normal_receipt["candidate_executed"] is False, "Resource meter claimed candidate execution.")
        require_condition(normal_receipt["network_access_performed"] is False, "Resource meter claimed network activity.")

        governance, signed_constitution, raw_signers = live_governance_and_constitution(now)
        signers = raw_signers
        entry = resource_ledger_entry_from_receipt(
            normal_receipt,
            candidate_id,
            candidate_digest,
            lease_digest,
            lease,
        )
        unsigned_ledger = build_lineage_resource_ledger(
            "88888888-9999-4aaa-bbbb-cccccccccccc",
            "99999999-aaaa-4bbb-cccc-dddddddddddd",
            "live",
            signed_constitution,
            governance,
            iso(now + timedelta(seconds=4)),
            iso(now - timedelta(seconds=10)),
            iso(now + timedelta(minutes=5)),
            [entry],
        )
        signed_ledger = sign_lineage_resource_ledger(unsigned_ledger, signers[:2])
        ledger_verification = verify_lineage_resource_ledger(
            signed_ledger,
            signed_constitution,
            governance,
            now + timedelta(seconds=5),
            600,
        )
        require_condition(ledger_verification["within_constitution"] is True, "Measured resource entry exceeded its lease.")

        crash_state = temporary_root / "crash-state"
        crash_output = temporary_root / "crash-output"
        crash_meter_id = "aaaaaaaa-bbbb-4ccc-dddd-eeeeeeeeeeee"
        crash_config_path = temporary_root / "abrupt-crash-config.json"
        crash_config: JsonObject = {
            "state_root": str(crash_state),
            "meter_id": crash_meter_id,
            "candidate_digest": candidate_digest,
            "resource_lease_digest": lease_digest,
            "command": worker_command(project_root, crash_output / "measurement.bin"),
            "output_root": str(crash_output),
            "memory_limit_bytes": 256 * 1024 * 1024,
            "timeout_seconds": 20,
            "prepared_at": iso(now),
            "started_at": iso(now + timedelta(seconds=1)),
            "completed_at": iso(now + timedelta(seconds=2)),
        }
        crash_config_path.write_text(
            json.dumps(crash_config, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        crash_process = subprocess.run(
            [
                sys.executable,
                str(project_root / "tools" / "resource_meter_abrupt_crash_driver.py"),
                "--config",
                str(crash_config_path),
            ],
            capture_output=True,
            check=False,
            text=True,
            timeout=30,
            encoding="utf-8",
            errors="replace",
        )
        require_condition(
            crash_process.returncode == 86,
            "Resource meter abrupt-crash driver did not exit at the expected durable boundary: "
            f"returncode={crash_process.returncode}, stdout={crash_process.stdout!r}, stderr={crash_process.stderr!r}.",
        )
        recovery_process = subprocess.run(
            [
                sys.executable,
                str(project_root / "tools" / "resource_meter_recovery_driver.py"),
                "--state-root",
                str(crash_state),
                "--meter-id",
                crash_meter_id,
                "--recovered-at",
                iso(now + timedelta(seconds=4)),
            ],
            capture_output=True,
            check=True,
            text=True,
            timeout=30,
            encoding="utf-8",
            errors="replace",
        )
        recovered_value: object = json.loads(recovery_process.stdout)
        if not isinstance(recovered_value, dict):
            raise TypeError("Separate resource-meter recovery process did not emit an object receipt.")
        recovered_receipt = cast(JsonObject, recovered_value)
        validate_contract(recovered_receipt, schema_path, "recovered resource-meter receipt")
        require_condition(recovered_receipt["durability"]["crash_recovered"] is True, "Crash recovery was not recorded.")
        require_condition(
            recovered_receipt["durability"]["injected_process_crash_recovery_verified"] is True,
            "Injected crash recovery evidence was not preserved.",
        )
        require_condition(
            recovered_receipt["durability"]["abrupt_process_crash_recovery_verified"] is True,
            "Abrupt process-crash recovery evidence was not preserved.",
        )
        require_condition(
            recovered_receipt["durability"]["file_data_flush_verified"] is True
            and recovered_receipt["durability"]["write_through_publish_verified"] is True,
            "Write-through durability evidence was not preserved.",
        )
        require_condition(
            recovered_receipt["durability"]["power_loss_durability_verified"] is False,
            "Injected crash recovery claimed power-loss durability.",
        )

        adversarial_count = 0
        expect_error(
            ResourceMeterStateError,
            lambda: run_resource_measurement(
                normal_state,
                normal_meter_id,
                candidate_digest,
                lease_digest,
                worker_command(project_root, normal_output / "replay.bin"),
                normal_output,
                256 * 1024 * 1024,
                20,
                iso(now),
                iso(now + timedelta(seconds=1)),
                iso(now + timedelta(seconds=2)),
                iso(now + timedelta(seconds=3)),
            ),
            "meter replay",
        )
        adversarial_count += 1
        expect_error(
            ResourceMeterStateError,
            lambda: recover_resource_measurement(crash_state, crash_meter_id, iso(now + timedelta(seconds=5))),
            "duplicate crash recovery",
        )
        adversarial_count += 1

        tamper_state = temporary_root / "tamper-state"
        tamper_output = temporary_root / "tamper-output"
        tamper_meter_id = "bbbbbbbb-cccc-4ddd-eeee-ffffffffffff"
        expect_error(
            InjectedResourceMeterCrashError,
            lambda: run_resource_measurement_until_observation(
                tamper_state,
                tamper_meter_id,
                candidate_digest,
                lease_digest,
                worker_command(project_root, tamper_output / "measurement.bin"),
                tamper_output,
                256 * 1024 * 1024,
                20,
                iso(now),
                iso(now + timedelta(seconds=1)),
                iso(now + timedelta(seconds=2)),
            ),
            "tamper setup crash",
        )
        tamper_observation_path = tamper_state / "observations" / f"{tamper_meter_id}.json"
        tamper_observation = json.loads(tamper_observation_path.read_text(encoding="utf-8"))
        tamper_observation["worker"]["command_digest"] = "sha256:" + "0" * 64
        tamper_observation_path.write_text(
            json.dumps(tamper_observation, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        expect_error(
            ResourceMeterStateError,
            lambda: recover_resource_measurement(tamper_state, tamper_meter_id, iso(now + timedelta(seconds=5))),
            "durable observation tamper",
        )
        adversarial_count += 1

        substituted_receipt = copy.deepcopy(normal_receipt)
        substituted_receipt["candidate_digest"] = "sha256:" + "0" * 64
        expect_error(
            ResourceMeterError,
            lambda: resource_ledger_entry_from_receipt(
                substituted_receipt,
                candidate_id,
                candidate_digest,
                lease_digest,
                lease,
            ),
            "candidate substitution",
        )
        adversarial_count += 1
        lease_substitution = copy.deepcopy(normal_receipt)
        lease_substitution["resource_lease_digest"] = "sha256:" + "0" * 64
        expect_error(
            ResourceMeterError,
            lambda: resource_ledger_entry_from_receipt(
                lease_substitution,
                candidate_id,
                candidate_digest,
                lease_digest,
                lease,
            ),
            "lease substitution",
        )
        adversarial_count += 1
        authority_widening = copy.deepcopy(normal_receipt)
        authority_widening["authority"]["can_allocate"] = True
        expect_error(
            ResourceMeterError,
            lambda: resource_ledger_entry_from_receipt(
                authority_widening,
                candidate_id,
                candidate_digest,
                lease_digest,
                lease,
            ),
            "resource authority widening",
        )
        adversarial_count += 1
        ledger_tamper = copy.deepcopy(signed_ledger)
        ledger_tamper["totals"]["total_compute_units"] += 1
        expect_error(
            ResourceLedgerError,
            lambda: verify_lineage_resource_ledger(
                ledger_tamper,
                signed_constitution,
                governance,
                now + timedelta(seconds=5),
                600,
            ),
            "signed ledger total tamper",
        )
        adversarial_count += 1
        overrun_lease = copy.deepcopy(lease)
        overrun_lease["maximum_memory_megabytes"] = 1
        overrun_entry = resource_ledger_entry_from_receipt(
            normal_receipt,
            candidate_id,
            candidate_digest,
            lease_digest,
            overrun_lease,
        )
        overrun_unsigned = build_lineage_resource_ledger(
            "cccccccc-dddd-4eee-ffff-000000000000",
            "dddddddd-eeee-4fff-8000-111111111111",
            "live",
            signed_constitution,
            governance,
            iso(now + timedelta(seconds=4)),
            iso(now - timedelta(seconds=10)),
            iso(now + timedelta(minutes=5)),
            [overrun_entry],
        )
        require_condition(overrun_unsigned["status"] == "blocked", "Metered resource overrun was not blocked.")
        adversarial_count += 1

    usage = normal_receipt["usage"]
    return {
        "status": "WINDOWS_RESOURCE_METER_SUSPENDED_ASSIGNMENT_DURABLE_RECOVERY_VALID_PHYSICAL_POWER_LOSS_BLOCKED",
        "origin": "live",
        "platform": "windows",
        "job_object_assigned": True,
        "kill_on_close_configured": True,
        "process_memory_limit_bytes": normal_receipt["job"]["process_memory_limit_bytes"],
        "created_suspended": True,
        "assigned_before_first_resume": True,
        "assignment_race_closed": True,
        "measured_cpu_time_milliseconds": usage["cpu_time_milliseconds"],
        "measured_peak_memory_bytes": usage["peak_memory_bytes"],
        "measured_peak_storage_bytes": usage["peak_storage_bytes"],
        "lineage_ledger_within_constitution": True,
        "injected_process_crash_boundary_count": 1,
        "injected_process_crash_recovery_verified": True,
        "abrupt_process_crash_recovery_verified": True,
        "separate_recovery_process_verified": True,
        "file_data_flush_verified": True,
        "write_through_publish_verified": True,
        "physical_power_loss_test_performed": False,
        "power_loss_durability_verified": False,
        "adversarial_case_count": adversarial_count,
        "network_access_performed": False,
        "candidate_executed": False,
        "production_promotion_authorized": False,
    }


def main() -> None:
    project_root = Path(__file__).resolve().parent.parent
    result = validate_resource_meter(project_root)
    report_path = project_root / "reports" / "RESOURCE_METER_VALIDATION.json"
    report_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
