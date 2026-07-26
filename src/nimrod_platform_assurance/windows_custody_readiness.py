"""Read-only Windows CNG and TPM custody-readiness measurement."""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import subprocess
import sys
import uuid
import warnings
from ctypes import wintypes
from pathlib import Path

from nimrod_simulator.errors import WindowsCustodyReadinessError
from nimrod_simulator.model import JsonObject


PLATFORM_CRYPTO_PROVIDER = "Microsoft Platform Crypto Provider"
SOFTWARE_KEY_STORAGE_PROVIDER = "Microsoft Software Key Storage Provider"
CUSTODY_READINESS_AUTHORITY = {
    "can_create_key": False,
    "can_delete_key": False,
    "can_sign": False,
    "can_export_private_key": False,
    "can_authorize_production": False,
}


class NCryptProviderName(ctypes.Structure):
    _fields_ = [("name", wintypes.LPWSTR), ("comment", wintypes.LPWSTR)]


def _require_windows() -> None:
    if sys.platform != "win32":
        raise WindowsCustodyReadinessError(
            f"Windows custody readiness requires win32; received '{sys.platform}'."
        )


def _string_digest(value: str) -> str:
    return f"sha256:{hashlib.sha256(value.encode('utf-8')).hexdigest()}"


def _tpm_timeout_observation(attempt_count: int) -> JsonObject:
    return {
        "inspection_method": "cim_win32_tpm_read_only",
        "query_succeeded": False,
        "tpm_present": None,
        "tpm_enabled": None,
        "tpm_activated": None,
        "tpm_owned": None,
        "error_id_digest": _string_digest("subprocess.TimeoutExpired"),
        "hresult": None,
        "attempt_count": attempt_count,
    }


def enumerate_cng_storage_providers() -> JsonObject:
    _require_windows()
    ncrypt = ctypes.WinDLL("ncrypt", use_last_error=True)
    ncrypt.NCryptEnumStorageProviders.argtypes = [
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(ctypes.POINTER(NCryptProviderName)),
        wintypes.DWORD,
    ]
    ncrypt.NCryptEnumStorageProviders.restype = wintypes.LONG
    ncrypt.NCryptFreeBuffer.argtypes = [ctypes.c_void_p]
    ncrypt.NCryptFreeBuffer.restype = wintypes.LONG
    provider_count = wintypes.DWORD(0)
    provider_pointer = ctypes.POINTER(NCryptProviderName)()
    status = ncrypt.NCryptEnumStorageProviders(
        ctypes.byref(provider_count),
        ctypes.byref(provider_pointer),
        0,
    )
    if status != 0:
        raise WindowsCustodyReadinessError(
            f"NCryptEnumStorageProviders failed with security_status={status}."
        )
    try:
        providers = sorted(
            str(provider_pointer[index].name)
            for index in range(provider_count.value)
            if provider_pointer[index].name
        )
        return {
            "enumeration_method": "ncrypt_enum_storage_providers",
            "provider_count": len(providers),
            "provider_name_digests": sorted(_string_digest(name) for name in providers),
            "platform_crypto_provider_present": PLATFORM_CRYPTO_PROVIDER in providers,
            "software_key_storage_provider_present": SOFTWARE_KEY_STORAGE_PROVIDER in providers,
            "raw_provider_set_digest": _string_digest("\n".join(providers)),
        }
    finally:
        if provider_pointer:
            free_status = ncrypt.NCryptFreeBuffer(provider_pointer)
            if free_status != 0:
                raise WindowsCustodyReadinessError(
                    f"NCryptFreeBuffer failed with security_status={free_status}."
                )


def collect_tpm_management_state(timeout_seconds: int, retry_count: int) -> JsonObject:
    _require_windows()
    if timeout_seconds <= 0 or retry_count <= 0:
        raise WindowsCustodyReadinessError("TPM management inspection requires positive timeout and retry counts.")
    system_root = os.environ.get("SystemRoot")
    if not system_root:
        raise WindowsCustodyReadinessError("TPM management inspection requires SystemRoot.")
    powershell_path = Path(system_root) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    if not powershell_path.is_file():
        raise WindowsCustodyReadinessError(
            f"TPM management inspection cannot locate powershell.exe: '{powershell_path}'."
        )
    operation_timeout_seconds = max(1, timeout_seconds // 2)
    script = r"""
$ErrorActionPreference = 'Stop'
try {
    $tpm = Get-CimInstance -Namespace 'root\CIMV2\Security\MicrosoftTpm' -ClassName 'Win32_Tpm' -OperationTimeoutSec __OPERATION_TIMEOUT_SECONDS__ -ErrorAction Stop
    [pscustomobject]@{
        query_succeeded = $true
        tpm_present = ($null -ne $tpm)
        tpm_enabled = [bool]$tpm.IsEnabled_InitialValue
        tpm_activated = [bool]$tpm.IsActivated_InitialValue
        tpm_owned = [bool]$tpm.IsOwned_InitialValue
        error_id = $null
        hresult = $null
    } | ConvertTo-Json -Compress
} catch {
    [pscustomobject]@{
        query_succeeded = $false
        tpm_present = $null
        tpm_enabled = $null
        tpm_activated = $null
        tpm_owned = $null
        error_id = [string]$_.FullyQualifiedErrorId
        hresult = [int]$_.Exception.HResult
    } | ConvertTo-Json -Compress
}
""".replace("__OPERATION_TIMEOUT_SECONDS__", str(operation_timeout_seconds))
    command = [
        str(powershell_path),
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "RemoteSigned",
        "-Command",
        script,
    ]
    minimal_environment = {
        "SystemRoot": system_root,
        "WINDIR": system_root,
        "PATH": str(Path(system_root) / "System32"),
    }
    last_error: Exception | None = None
    for attempt in range(1, retry_count + 1):
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                check=True,
                text=True,
                timeout=timeout_seconds,
                encoding="utf-8",
                errors="replace",
                env=minimal_environment,
            )
            value: object = json.loads(completed.stdout)
            if not isinstance(value, dict):
                raise WindowsCustodyReadinessError("TPM management inspection returned a non-object result.")
            error_id = value.get("error_id")
            return {
                "inspection_method": "cim_win32_tpm_read_only",
                "query_succeeded": value.get("query_succeeded") is True,
                "tpm_present": value.get("tpm_present"),
                "tpm_enabled": value.get("tpm_enabled"),
                "tpm_activated": value.get("tpm_activated"),
                "tpm_owned": value.get("tpm_owned"),
                "error_id_digest": None if error_id is None else _string_digest(str(error_id)),
                "hresult": value.get("hresult"),
                "attempt_count": attempt,
            }
        except (
            json.JSONDecodeError,
            subprocess.CalledProcessError,
            subprocess.TimeoutExpired,
            WindowsCustodyReadinessError,
        ) as error:
            last_error = error
            warnings.warn(
                f"TPM management inspection attempt failed: attempt={attempt}, "
                f"retry_count={retry_count}, error={error}.",
                RuntimeWarning,
                stacklevel=2,
            )
    if last_error is None:
        raise WindowsCustodyReadinessError("TPM management inspection failed without an error record.")
    if isinstance(last_error, subprocess.TimeoutExpired):
        return _tpm_timeout_observation(retry_count)
    raise WindowsCustodyReadinessError(
        f"TPM management inspection failed after {retry_count} attempts: {last_error}."
    ) from last_error


def validate_custody_readiness_measurement(measurement: JsonObject) -> None:
    if measurement.get("authority") != CUSTODY_READINESS_AUTHORITY:
        raise WindowsCustodyReadinessError("Custody-readiness measurement exposes prohibited authority.")
    cng = measurement.get("cng")
    tpm = measurement.get("tpm")
    key_material = measurement.get("key_material")
    blockers = measurement.get("blockers")
    if not isinstance(cng, dict) or not isinstance(tpm, dict) or not isinstance(key_material, dict):
        raise WindowsCustodyReadinessError("Custody-readiness measurement is missing CNG, TPM, or key state.")
    if not isinstance(blockers, list) or not all(isinstance(item, str) for item in blockers):
        raise WindowsCustodyReadinessError("Custody-readiness blockers must be a string list.")
    provider_digests = cng.get("provider_name_digests")
    if not isinstance(provider_digests, list) or cng.get("provider_count") != len(provider_digests):
        raise WindowsCustodyReadinessError("Custody-readiness CNG provider count is inconsistent.")
    required_blockers = {
        "HARDWARE_KEY_REFERENCE_MISSING",
        "PROVIDER_ATTESTATION_MISSING",
        "INDEPENDENT_CUSTODY_OPERATOR_MISSING",
    }
    if tpm.get("query_succeeded") is not True:
        required_blockers.add("TPM_MANAGEMENT_STATE_UNAVAILABLE")
        unavailable_state = (
            tpm.get("tpm_present"),
            tpm.get("tpm_enabled"),
            tpm.get("tpm_activated"),
            tpm.get("tpm_owned"),
        )
        if any(value is not None for value in unavailable_state) or tpm.get("error_id_digest") is None:
            raise WindowsCustodyReadinessError(
                "Unavailable TPM management state must preserve null observations and a typed error digest."
            )
    if cng.get("platform_crypto_provider_present") is not True:
        required_blockers.add("PLATFORM_CRYPTO_PROVIDER_MISSING")
    if set(blockers) != required_blockers:
        raise WindowsCustodyReadinessError("Custody-readiness blocker set is inconsistent with observed state.")
    if any(
        key_material.get(field) is not False
        for field in (
            "hardware_key_reference_configured",
            "hardware_key_created",
            "signing_operation_performed",
            "provider_attestation_collected",
            "private_key_material_accessed",
        )
    ):
        raise WindowsCustodyReadinessError("Custody-readiness measurement claims prohibited key activity.")
    if measurement.get("production_custody_verified") is not False or measurement.get("status") != "blocked":
        raise WindowsCustodyReadinessError("Custody-readiness measurement launders readiness into production custody.")


def collect_windows_custody_readiness(
    collected_at: str,
    timeout_seconds: int,
    retry_count: int,
) -> JsonObject:
    cng = enumerate_cng_storage_providers()
    tpm = collect_tpm_management_state(timeout_seconds, retry_count)
    blockers = {
        "HARDWARE_KEY_REFERENCE_MISSING",
        "PROVIDER_ATTESTATION_MISSING",
        "INDEPENDENT_CUSTODY_OPERATOR_MISSING",
    }
    if tpm["query_succeeded"] is not True:
        blockers.add("TPM_MANAGEMENT_STATE_UNAVAILABLE")
    if cng["platform_crypto_provider_present"] is not True:
        blockers.add("PLATFORM_CRYPTO_PROVIDER_MISSING")
    measurement: JsonObject = {
        "custody_version": "0.1.0",
        "measurement_id": str(uuid.uuid4()),
        "origin": "live",
        "collected_at": collected_at,
        "platform": "windows",
        "cng": cng,
        "tpm": tpm,
        "key_material": {
            "hardware_key_reference_configured": False,
            "hardware_key_created": False,
            "signing_operation_performed": False,
            "provider_attestation_collected": False,
            "private_key_material_accessed": False,
        },
        "status": "blocked",
        "blockers": sorted(blockers),
        "production_custody_verified": False,
        "authority": CUSTODY_READINESS_AUTHORITY,
    }
    validate_custody_readiness_measurement(measurement)
    return measurement
