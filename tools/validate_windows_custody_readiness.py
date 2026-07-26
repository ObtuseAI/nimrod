"""Validate read-only Windows custody readiness without provisioning key material."""

from __future__ import annotations

import copy
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, TypeVar

from jsonschema import Draft202012Validator, FormatChecker

from nimrod_platform_assurance.windows_custody_readiness import (
    CUSTODY_READINESS_AUTHORITY,
    collect_windows_custody_readiness,
    validate_custody_readiness_measurement,
)
from nimrod_simulator.errors import WindowsCustodyReadinessError
from nimrod_simulator.model import JsonObject


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
    schema: object = json.loads(schema_path.read_text(encoding="utf-8"))
    if not isinstance(schema, dict):
        raise RuntimeError(f"{label} schema must be an object.")
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors = sorted(validator.iter_errors(value), key=lambda item: list(item.absolute_path))
    if errors:
        rendered = "; ".join(error.message for error in errors)
        raise RuntimeError(f"{label} failed schema validation: {rendered}")


def validate_windows_custody_readiness(project_root: Path) -> JsonObject:
    collected_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    measurement = collect_windows_custody_readiness(collected_at, 15, 2)
    validate_contract(
        measurement,
        project_root / "specs" / "windows-custody-readiness.schema.json",
        "live Windows custody-readiness measurement",
    )
    validate_custody_readiness_measurement(measurement)
    require_condition(measurement["origin"] == "live", "Custody collector did not preserve live origin.")
    require_condition(measurement["status"] == "blocked", "Custody collector did not preserve blocked status.")
    require_condition(measurement["production_custody_verified"] is False, "Custody collector claimed production custody.")
    require_condition(measurement["authority"] == CUSTODY_READINESS_AUTHORITY, "Custody collector widened authority.")
    require_condition(
        all(value is False for value in measurement["key_material"].values()),
        "Custody collector claimed a key or signing operation.",
    )

    adversarial_count = 0
    widened_authority = copy.deepcopy(measurement)
    widened_authority["authority"]["can_sign"] = True
    expect_error(
        WindowsCustodyReadinessError,
        lambda: validate_custody_readiness_measurement(widened_authority),
        "authority widening",
    )
    adversarial_count += 1
    inconsistent_provider_count = copy.deepcopy(measurement)
    inconsistent_provider_count["cng"]["provider_count"] += 1
    expect_error(
        WindowsCustodyReadinessError,
        lambda: validate_custody_readiness_measurement(inconsistent_provider_count),
        "provider count mismatch",
    )
    adversarial_count += 1
    missing_blocker = copy.deepcopy(measurement)
    missing_blocker["blockers"].pop()
    expect_error(
        WindowsCustodyReadinessError,
        lambda: validate_custody_readiness_measurement(missing_blocker),
        "missing custody blocker",
    )
    adversarial_count += 1
    production_laundering = copy.deepcopy(measurement)
    production_laundering["production_custody_verified"] = True
    expect_error(
        WindowsCustodyReadinessError,
        lambda: validate_custody_readiness_measurement(production_laundering),
        "production custody laundering",
    )
    adversarial_count += 1
    key_creation_laundering = copy.deepcopy(measurement)
    key_creation_laundering["key_material"]["hardware_key_created"] = True
    expect_error(
        WindowsCustodyReadinessError,
        lambda: validate_custody_readiness_measurement(key_creation_laundering),
        "key creation laundering",
    )
    adversarial_count += 1
    tpm_laundering = copy.deepcopy(measurement)
    tpm_laundering["tpm"]["query_succeeded"] = True
    expect_error(
        WindowsCustodyReadinessError,
        lambda: validate_custody_readiness_measurement(tpm_laundering),
        "TPM state laundering",
    )
    adversarial_count += 1
    return {
        "status": "WINDOWS_CUSTODY_READINESS_LIVE_READ_ONLY_HARDWARE_CUSTODY_BLOCKED",
        "origin": "live",
        "platform": "windows",
        "provider_count": measurement["cng"]["provider_count"],
        "platform_crypto_provider_present": measurement["cng"]["platform_crypto_provider_present"],
        "software_key_storage_provider_present": measurement["cng"]["software_key_storage_provider_present"],
        "tpm_management_query_succeeded": measurement["tpm"]["query_succeeded"],
        "tpm_hresult_recorded": measurement["tpm"]["hresult"] is not None,
        "blockers": measurement["blockers"],
        "blocker_count": len(measurement["blockers"]),
        "key_reference_configured": False,
        "key_created": False,
        "signing_operation_performed": False,
        "private_key_material_accessed": False,
        "provider_attestation_collected": False,
        "production_custody_verified": False,
        "adversarial_case_count": adversarial_count,
        "candidate_executed": False,
        "production_promotion_authorized": False,
    }


def main() -> None:
    project_root = Path(__file__).resolve().parent.parent
    result = validate_windows_custody_readiness(project_root)
    report_path = project_root / "reports" / "WINDOWS_CUSTODY_READINESS_VALIDATION.json"
    report_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
