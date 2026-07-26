"""Read-only Windows process, identity, ACL, credential-boundary, and egress measurement."""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import re
import subprocess
import sys
import uuid
import warnings
from ctypes import wintypes
from datetime import datetime, timedelta, timezone
from pathlib import Path

from nimrod_simulator.errors import WindowsIsolationCollectionError
from nimrod_simulator.isolation_boundary import (
    ISOLATION_AUTHORITY,
    REQUIRED_ISOLATION_CONTROLS,
    sign_isolation_attestation,
)
from nimrod_simulator.jsonio import sha256_digest
from nimrod_simulator.key_governance import SigningConnector
from nimrod_simulator.model import JsonObject


PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
TOKEN_QUERY = 0x0008
TOKEN_USER_INFORMATION_CLASS = 1
ERROR_INSUFFICIENT_BUFFER = 122
SE_FILE_OBJECT = 1
OWNER_SECURITY_INFORMATION = 0x00000001
DACL_SECURITY_INFORMATION = 0x00000004
SDDL_REVISION_1 = 1
NO_MULTIPLE_TRUSTEE = 0
TRUSTEE_IS_SID = 0
TRUSTEE_IS_USER = 1
FILE_GENERIC_READ = 0x00120089
FILE_GENERIC_WRITE = 0x00120116
FILE_GENERIC_EXECUTE = 0x001200A0
FILE_ALL_ACCESS = 0x001F01FF
FILE_READ_DATA = 0x00000001
FILE_WRITE_DATA = 0x00000002
FILE_APPEND_DATA = 0x00000004
FILE_WRITE_EA = 0x00000010
FILE_EXECUTE = 0x00000020
FILE_DELETE_CHILD = 0x00000040
FILE_WRITE_ATTRIBUTES = 0x00000100
DELETE_ACCESS = 0x00010000
WRITE_DAC = 0x00040000
WRITE_OWNER = 0x00080000
WRITE_LIKE_ACCESS = (
    FILE_WRITE_DATA
    | FILE_APPEND_DATA
    | FILE_WRITE_EA
    | FILE_DELETE_CHILD
    | FILE_WRITE_ATTRIBUTES
    | DELETE_ACCESS
    | WRITE_DAC
    | WRITE_OWNER
)
WINDOWS_MEASUREMENT_AUTHORITY = {
    "can_authorize": False,
    "can_execute": False,
    "can_modify_acl": False,
    "can_modify_firewall": False,
    "can_read_credential_values": False,
}
CREDENTIAL_PREFIXES = (
    "AWS_",
    "AZURE_",
    "DOCKER_",
    "GITHUB_",
    "GOOGLE_",
    "KUBECONFIG",
    "OPENAI_",
    "ANTHROPIC_",
)


class SidAndAttributes(ctypes.Structure):
    _fields_ = [("sid", ctypes.c_void_p), ("attributes", wintypes.DWORD)]


class TokenUser(ctypes.Structure):
    _fields_ = [("user", SidAndAttributes)]


class TrusteeW(ctypes.Structure):
    _fields_ = [
        ("multiple_trustee", ctypes.c_void_p),
        ("multiple_trustee_operation", wintypes.DWORD),
        ("trustee_form", wintypes.DWORD),
        ("trustee_type", wintypes.DWORD),
        ("name", ctypes.c_void_p),
    ]


class GenericMapping(ctypes.Structure):
    _fields_ = [
        ("generic_read", wintypes.DWORD),
        ("generic_write", wintypes.DWORD),
        ("generic_execute", wintypes.DWORD),
        ("generic_all", wintypes.DWORD),
    ]


def _require_windows() -> None:
    if sys.platform != "win32":
        raise WindowsIsolationCollectionError(
            f"Windows isolation collection requires win32; received platform '{sys.platform}'."
        )


def _close_handle(handle: int) -> None:
    if handle:
        ctypes.WinDLL("kernel32", use_last_error=True).CloseHandle(wintypes.HANDLE(handle))


def _file_digest(path: Path) -> str:
    if not path.is_file():
        raise WindowsIsolationCollectionError(f"Executable identity path is not a file: '{path}'.")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def _string_digest(value: str) -> str:
    return f"sha256:{hashlib.sha256(value.encode('utf-8')).hexdigest()}"


def _open_process(process_id: int) -> int:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, process_id)
    if not handle:
        error_code = ctypes.get_last_error()
        raise WindowsIsolationCollectionError(
            f"OpenProcess failed for process_id={process_id} with win32_error={error_code}."
        )
    return int(handle)


def _process_image_path(process_handle: int, process_id: int) -> Path:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
    kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
    capacity = 32768
    buffer = ctypes.create_unicode_buffer(capacity)
    size = wintypes.DWORD(capacity)
    if not kernel32.QueryFullProcessImageNameW(wintypes.HANDLE(process_handle), 0, buffer, ctypes.byref(size)):
        error_code = ctypes.get_last_error()
        raise WindowsIsolationCollectionError(
            f"QueryFullProcessImageNameW failed for process_id={process_id} with win32_error={error_code}."
        )
    return Path(buffer.value)


def _lookup_account_name(sid: int) -> str:
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    advapi32.LookupAccountSidW.argtypes = [
        wintypes.LPCWSTR,
        ctypes.c_void_p,
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.LookupAccountSidW.restype = wintypes.BOOL
    name_size = wintypes.DWORD(0)
    domain_size = wintypes.DWORD(0)
    sid_type = wintypes.DWORD(0)
    advapi32.LookupAccountSidW(
        None,
        ctypes.c_void_p(sid),
        None,
        ctypes.byref(name_size),
        None,
        ctypes.byref(domain_size),
        ctypes.byref(sid_type),
    )
    if ctypes.get_last_error() != ERROR_INSUFFICIENT_BUFFER:
        error_code = ctypes.get_last_error()
        raise WindowsIsolationCollectionError(
            f"LookupAccountSidW size query failed with win32_error={error_code}."
        )
    name = ctypes.create_unicode_buffer(name_size.value)
    domain = ctypes.create_unicode_buffer(domain_size.value)
    if not advapi32.LookupAccountSidW(
        None,
        ctypes.c_void_p(sid),
        name,
        ctypes.byref(name_size),
        domain,
        ctypes.byref(domain_size),
        ctypes.byref(sid_type),
    ):
        error_code = ctypes.get_last_error()
        raise WindowsIsolationCollectionError(f"LookupAccountSidW failed with win32_error={error_code}.")
    return f"{domain.value}\\{name.value}" if domain.value else name.value


def _process_account(process_handle: int, process_id: int) -> tuple[str, str]:
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    advapi32.GetTokenInformation.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    advapi32.GetTokenInformation.restype = wintypes.BOOL
    advapi32.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(wintypes.HANDLE(process_handle), TOKEN_QUERY, ctypes.byref(token)):
        error_code = ctypes.get_last_error()
        raise WindowsIsolationCollectionError(
            f"OpenProcessToken failed for process_id={process_id} with win32_error={error_code}."
        )
    try:
        required = wintypes.DWORD(0)
        advapi32.GetTokenInformation(token, TOKEN_USER_INFORMATION_CLASS, None, 0, ctypes.byref(required))
        if ctypes.get_last_error() != ERROR_INSUFFICIENT_BUFFER:
            error_code = ctypes.get_last_error()
            raise WindowsIsolationCollectionError(
                f"GetTokenInformation size query failed for process_id={process_id} with win32_error={error_code}."
            )
        token_buffer = ctypes.create_string_buffer(required.value)
        if not advapi32.GetTokenInformation(
            token,
            TOKEN_USER_INFORMATION_CLASS,
            token_buffer,
            required,
            ctypes.byref(required),
        ):
            error_code = ctypes.get_last_error()
            raise WindowsIsolationCollectionError(
                f"GetTokenInformation failed for process_id={process_id} with win32_error={error_code}."
            )
        token_user = ctypes.cast(token_buffer, ctypes.POINTER(TokenUser)).contents
        sid_pointer = token_user.user.sid
        sid_text = wintypes.LPWSTR()
        if not advapi32.ConvertSidToStringSidW(ctypes.c_void_p(sid_pointer), ctypes.byref(sid_text)):
            error_code = ctypes.get_last_error()
            raise WindowsIsolationCollectionError(
                f"ConvertSidToStringSidW failed for process_id={process_id} with win32_error={error_code}."
            )
        try:
            account_name = _lookup_account_name(sid_pointer)
            return f"account-sha256:{hashlib.sha256(account_name.casefold().encode('utf-8')).hexdigest()}", sid_text.value
        finally:
            kernel32.LocalFree(sid_text)
    finally:
        _close_handle(int(token.value))


def collect_process_identity(process_id: int) -> JsonObject:
    _require_windows()
    if process_id <= 0:
        raise WindowsIsolationCollectionError(f"Process identity requires a positive process_id; received {process_id}.")
    handle = _open_process(process_id)
    try:
        image_path = _process_image_path(handle, process_id)
        account_identifier, account_sid = _process_account(handle, process_id)
        return {
            "process_id": process_id,
            "executable_path_digest": _string_digest(str(image_path.resolve()).casefold()),
            "executable_digest": _file_digest(image_path),
            "os_account_identifier": account_identifier,
            "os_account_sid": account_sid,
        }
    finally:
        _close_handle(handle)


def collect_process_image_path(process_id: int) -> Path:
    _require_windows()
    if process_id <= 0:
        raise WindowsIsolationCollectionError(
            f"Process image collection requires a positive process_id; received {process_id}."
        )
    handle = _open_process(process_id)
    try:
        return _process_image_path(handle, process_id).resolve(strict=True)
    finally:
        _close_handle(handle)


def collect_security_descriptor(path: Path) -> JsonObject:
    _require_windows()
    resolved = path.resolve(strict=True)
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    security_descriptor = ctypes.c_void_p()
    advapi32.GetNamedSecurityInfoW.argtypes = [
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    advapi32.GetNamedSecurityInfoW.restype = wintypes.DWORD
    result = advapi32.GetNamedSecurityInfoW(
        str(resolved),
        SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        None,
        None,
        None,
        None,
        ctypes.byref(security_descriptor),
    )
    if result != 0:
        raise WindowsIsolationCollectionError(
            f"GetNamedSecurityInfoW failed for path_digest={_string_digest(str(resolved))} with win32_error={result}."
        )
    sddl = wintypes.LPWSTR()
    length = wintypes.DWORD(0)
    advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPWSTR),
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW.restype = wintypes.BOOL
    try:
        if not advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW(
            security_descriptor,
            SDDL_REVISION_1,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            ctypes.byref(sddl),
            ctypes.byref(length),
        ):
            error_code = ctypes.get_last_error()
            raise WindowsIsolationCollectionError(
                f"ConvertSecurityDescriptorToStringSecurityDescriptorW failed with win32_error={error_code}."
            )
        try:
            return {
                "path_digest": _string_digest(str(resolved).casefold()),
                "security_descriptor_digest": _string_digest(sddl.value),
                "security_descriptor_length": len(sddl.value),
            }
        finally:
            kernel32.LocalFree(sddl)
    finally:
        kernel32.LocalFree(security_descriptor)


def collect_effective_access(path: Path, account_sid: str) -> JsonObject:
    _require_windows()
    if not account_sid:
        raise WindowsIsolationCollectionError("Effective-access collection requires a non-empty account SID.")
    resolved = path.resolve(strict=True)
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32.ConvertStringSidToSidW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p)]
    advapi32.ConvertStringSidToSidW.restype = wintypes.BOOL
    advapi32.GetNamedSecurityInfoW.argtypes = [
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    advapi32.GetNamedSecurityInfoW.restype = wintypes.DWORD
    advapi32.GetEffectiveRightsFromAclW.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(TrusteeW),
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.GetEffectiveRightsFromAclW.restype = wintypes.DWORD
    advapi32.MapGenericMask.argtypes = [ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(GenericMapping)]
    sid_pointer = ctypes.c_void_p()
    if not advapi32.ConvertStringSidToSidW(account_sid, ctypes.byref(sid_pointer)):
        error_code = ctypes.get_last_error()
        raise WindowsIsolationCollectionError(
            f"ConvertStringSidToSidW failed for sid_digest={_string_digest(account_sid)} "
            f"with win32_error={error_code}."
        )
    security_descriptor = ctypes.c_void_p()
    dacl = ctypes.c_void_p()
    try:
        result = advapi32.GetNamedSecurityInfoW(
            str(resolved),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            ctypes.byref(dacl),
            None,
            ctypes.byref(security_descriptor),
        )
        if result != 0:
            raise WindowsIsolationCollectionError(
                f"GetNamedSecurityInfoW effective-access query failed for "
                f"path_digest={_string_digest(str(resolved).casefold())} with win32_error={result}."
            )
        access_mask = wintypes.DWORD(FILE_ALL_ACCESS if not dacl.value else 0)
        if dacl.value:
            trustee = TrusteeW(
                None,
                NO_MULTIPLE_TRUSTEE,
                TRUSTEE_IS_SID,
                TRUSTEE_IS_USER,
                sid_pointer,
            )
            result = advapi32.GetEffectiveRightsFromAclW(dacl, ctypes.byref(trustee), ctypes.byref(access_mask))
            if result != 0:
                raise WindowsIsolationCollectionError(
                    f"GetEffectiveRightsFromAclW failed for path_digest={_string_digest(str(resolved).casefold())}, "
                    f"sid_digest={_string_digest(account_sid)} with win32_error={result}."
                )
        mapping = GenericMapping(
            FILE_GENERIC_READ,
            FILE_GENERIC_WRITE,
            FILE_GENERIC_EXECUTE,
            FILE_ALL_ACCESS,
        )
        advapi32.MapGenericMask(ctypes.byref(access_mask), ctypes.byref(mapping))
        normalized_mask = int(access_mask.value)
        return {
            "account_sid_digest": _string_digest(account_sid.casefold()),
            "access_mask_hex": f"0x{normalized_mask:08x}",
            "read_allowed": bool(normalized_mask & FILE_READ_DATA),
            "write_allowed": bool(normalized_mask & WRITE_LIKE_ACCESS),
            "execute_allowed": bool(normalized_mask & FILE_EXECUTE),
            "delete_allowed": bool(normalized_mask & (DELETE_ACCESS | FILE_DELETE_CHILD)),
            "evaluation_method": "get_effective_rights_from_acl",
        }
    finally:
        if security_descriptor.value:
            kernel32.LocalFree(security_descriptor)
        if sid_pointer.value:
            kernel32.LocalFree(sid_pointer)


def collect_firewall_egress(timeout_seconds: int, retry_count: int) -> JsonObject:
    _require_windows()
    if timeout_seconds <= 0 or retry_count <= 0:
        raise WindowsIsolationCollectionError("Firewall inspection requires positive timeout and retry counts.")
    last_error: subprocess.SubprocessError | None = None
    for attempt in range(1, retry_count + 1):
        try:
            completed = subprocess.run(
                ["netsh", "advfirewall", "show", "allprofiles"],
                capture_output=True,
                check=True,
                text=True,
                timeout=timeout_seconds,
                encoding="utf-8",
                errors="replace",
            )
            output = completed.stdout
            outbound_actions = sorted(
                {value.casefold() for value in re.findall(r"Outbound\s+connections\s+(Allow|Block)", output, re.IGNORECASE)}
            )
            profile_states = re.findall(r"State\s+(ON|OFF)", output, re.IGNORECASE)
            return {
                "inspection_method": "netsh_advfirewall_read_only",
                "active_profile_count": sum(1 for state in profile_states if state.casefold() == "on"),
                "default_outbound_actions": outbound_actions,
                "raw_evidence_digest": _string_digest(output),
                "active_probe_performed": False,
                "attempt_count": attempt,
            }
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
            last_error = error
    if last_error is None:
        raise WindowsIsolationCollectionError("Firewall inspection failed without an error record.")
    raise WindowsIsolationCollectionError(
        f"Read-only firewall inspection failed after {retry_count} attempts: {last_error}."
    ) from last_error


def collect_target_firewall_egress(
    target_executable: Path,
    timeout_seconds: int,
    retry_count: int,
) -> JsonObject:
    _require_windows()
    if timeout_seconds <= 0 or retry_count <= 0:
        raise WindowsIsolationCollectionError(
            "Target-specific firewall inspection requires positive timeout and retry counts."
        )
    resolved_executable = target_executable.resolve(strict=True)
    system_root = os.environ.get("SystemRoot")
    if not system_root:
        raise WindowsIsolationCollectionError("Target-specific firewall inspection requires SystemRoot.")
    powershell_path = Path(system_root) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    if not powershell_path.is_file():
        raise WindowsIsolationCollectionError(
            f"Target-specific firewall inspection cannot locate powershell.exe: '{powershell_path}'."
        )
    script = r"""
$ErrorActionPreference = 'Stop'
$target = [IO.Path]::GetFullPath($env:nimrod_target_program)
$results = @()
Get-NetFirewallRule -Direction Outbound -Action Block -Enabled True -ErrorAction Stop | ForEach-Object {
    $rule = $_
    @($rule | Get-NetFirewallApplicationFilter -ErrorAction Stop) | ForEach-Object {
        $app = $_
        if ([string]$app.Program -ne 'Any' -and -not [string]::IsNullOrWhiteSpace([string]$app.Program)) {
            $program = [IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables([string]$app.Program))
            if ([string]::Equals($program, $target, [StringComparison]::OrdinalIgnoreCase)) {
                $addresses = @($rule | Get-NetFirewallAddressFilter -ErrorAction Stop)
                $ports = @($rule | Get-NetFirewallPortFilter -ErrorAction Stop)
                $services = @($rule | Get-NetFirewallServiceFilter -ErrorAction Stop)
                $interfaces = @($rule | Get-NetFirewallInterfaceFilter -ErrorAction Stop)
                $allProfiles = ([int]$rule.Profile -eq 0)
                $anyAddress = (@($addresses.LocalAddress) | Where-Object { [string]$_ -ne 'Any' }).Count -eq 0 -and (@($addresses.RemoteAddress) | Where-Object { [string]$_ -ne 'Any' }).Count -eq 0
                $anyProtocol = (@($ports.Protocol) | Where-Object { [string]$_ -notin @('Any', '256') }).Count -eq 0
                $anyPort = (@($ports.LocalPort) | Where-Object { [string]$_ -ne 'Any' }).Count -eq 0 -and (@($ports.RemotePort) | Where-Object { [string]$_ -ne 'Any' }).Count -eq 0
                $anyService = (@($services.Service) | Where-Object { [string]$_ -ne 'Any' }).Count -eq 0
                $anyInterface = (@($interfaces.InterfaceAlias) | Where-Object { [string]$_ -ne 'Any' }).Count -eq 0
                $results += [pscustomobject]@{
                    rule_id = [string]$rule.Name
                    all_profiles = $allProfiles
                    any_address = $anyAddress
                    any_protocol = $anyProtocol
                    any_port = $anyPort
                    any_service = $anyService
                    any_interface = $anyInterface
                    all_traffic = $allProfiles -and $anyAddress -and $anyProtocol -and $anyPort -and $anyService -and $anyInterface
                }
            }
        }
    }
}
ConvertTo-Json -InputObject @($results) -Compress
"""
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
        "nimrod_target_program": str(resolved_executable),
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
            parsed: object = json.loads(completed.stdout)
            if not isinstance(parsed, list) or not all(isinstance(item, dict) for item in parsed):
                raise WindowsIsolationCollectionError(
                    "Target-specific firewall inspection returned a non-list result."
                )
            rules = [item for item in parsed if isinstance(item, dict)]
            all_traffic_rules = [item for item in rules if item.get("all_traffic") is True]
            return {
                "inspection_method": "powershell_netsecurity_read_only",
                "inspection_succeeded": True,
                "target_executable_digest": _file_digest(resolved_executable),
                "matching_block_rule_count": len(rules),
                "all_traffic_block_rule_count": len(all_traffic_rules),
                "rule_evidence_digests": sorted(_string_digest(str(item.get("rule_id"))) for item in rules),
                "raw_evidence_digest": sha256_digest(rules),
                "active_probe_performed": False,
                "firewall_modified": False,
                "attempt_count": attempt,
            }
        except (
            json.JSONDecodeError,
            subprocess.CalledProcessError,
            subprocess.TimeoutExpired,
            WindowsIsolationCollectionError,
        ) as error:
            last_error = error
            warnings.warn(
                f"Target-specific firewall inspection attempt failed: attempt={attempt}, "
                f"retry_count={retry_count}, error={error}.",
                RuntimeWarning,
                stacklevel=2,
            )
    if last_error is None:
        raise WindowsIsolationCollectionError("Target-specific firewall inspection failed without an error record.")
    if isinstance(last_error, subprocess.TimeoutExpired):
        return {
            "inspection_method": "powershell_netsecurity_read_only",
            "inspection_succeeded": False,
            "target_executable_digest": _file_digest(resolved_executable),
            "matching_block_rule_count": 0,
            "all_traffic_block_rule_count": 0,
            "rule_evidence_digests": [],
            "raw_evidence_digest": sha256_digest(
                {"status": "unavailable", "error_id": "subprocess.TimeoutExpired"}
            ),
            "active_probe_performed": False,
            "firewall_modified": False,
            "attempt_count": retry_count,
        }
    raise WindowsIsolationCollectionError(
        f"Target-specific firewall inspection failed after {retry_count} attempts: {last_error}."
    ) from last_error


def collect_credential_boundary() -> JsonObject:
    matching_categories = sorted(
        prefix
        for prefix in CREDENTIAL_PREFIXES
        if any(name.upper().startswith(prefix) for name in os.environ)
    )
    return {
        "credential_like_variable_count": sum(
            1 for name in os.environ if any(name.upper().startswith(prefix) for prefix in CREDENTIAL_PREFIXES)
        ),
        "matching_prefix_categories": matching_categories,
        "credential_value_accessed": False,
        "target_environment_inspected": False,
    }


def _control(control_id: str, status: str, measurement: JsonObject) -> JsonObject:
    evidence_value = {
        "control_id": control_id,
        "target": measurement["target"],
        "collector": measurement["collector"],
        "environment": measurement["environment"],
        "filesystem": measurement["filesystem"],
        "network": measurement["network"],
    }
    return {
        "control_id": control_id,
        "status": status,
        "evidence": [{"id": f"windows-measurement:{control_id}", "digest": sha256_digest(evidence_value)}],
    }


def _derive_controls(measurement: JsonObject, expected_os_account_sid: str) -> list[JsonObject]:
    target = measurement["target"]
    collector = measurement["collector"]
    network = measurement["network"]
    filesystem = measurement["filesystem"]
    same_account = target["os_account_sid"].casefold() == collector["os_account_sid"].casefold()
    expected_match = target["os_account_sid"].casefold() == expected_os_account_sid.casefold()
    outbound_actions = set(network["default_outbound_actions"])
    if network["target_inspection_succeeded"] is not True:
        network_status = "unproven"
    elif network["all_traffic_block_rule_count"] > 0:
        network_status = "verified"
    elif "allow" in outbound_actions or network["matching_block_rule_count"] == 0:
        network_status = "violated"
    else:
        network_status = "unproven"
    input_access = filesystem["input"]["target_effective_access"]
    input_read_only = (
        input_access["read_allowed"] is True
        and input_access["write_allowed"] is False
        and input_access["delete_allowed"] is False
    )
    output_target_access = filesystem["output"]["target_effective_access"]
    output_collector_access = filesystem["output"]["collector_effective_access"]
    separate_output = (
        same_account is False
        and output_target_access["write_allowed"] is True
        and output_collector_access["write_allowed"] is False
    )
    status_by_control = {
        "CREDENTIAL_ISOLATION": "unproven",
        "DEDICATED_OS_ACCOUNT": "verified" if expected_match and not same_account else "violated",
        "DISTINCT_PROCESS": "verified" if target["process_id"] != collector["process_id"] else "violated",
        "EXECUTABLE_IDENTITY": "verified",
        "NETWORK_EGRESS_DENIED": network_status,
        "READ_ONLY_INPUT_ACL": "verified" if input_read_only else "violated",
        "SEPARATE_OUTPUT_ACL": "verified" if separate_output else "violated",
    }
    return [_control(control_id, status_by_control[control_id], measurement) for control_id in sorted(REQUIRED_ISOLATION_CONTROLS)]


def collect_windows_isolation_measurement(
    target_process_id: int,
    input_path: Path,
    output_path: Path,
    expected_os_account_sid: str,
    collected_at: str,
    firewall_timeout_seconds: int,
    firewall_retry_count: int,
) -> JsonObject:
    if not expected_os_account_sid:
        raise WindowsIsolationCollectionError("Expected OS account SID cannot be empty.")
    target = collect_process_identity(target_process_id)
    collector = collect_process_identity(os.getpid())
    input_descriptor = collect_security_descriptor(input_path)
    output_descriptor = collect_security_descriptor(output_path)
    input_target_access = collect_effective_access(input_path, str(target["os_account_sid"]))
    output_target_access = collect_effective_access(output_path, str(target["os_account_sid"]))
    output_collector_access = collect_effective_access(output_path, str(collector["os_account_sid"]))
    profile_egress = collect_firewall_egress(firewall_timeout_seconds, firewall_retry_count)
    target_egress = collect_target_firewall_egress(
        collect_process_image_path(target_process_id),
        firewall_timeout_seconds,
        firewall_retry_count,
    )
    measurement: JsonObject = {
        "measurement_version": "0.2.0",
        "measurement_id": str(uuid.uuid4()),
        "origin": "live",
        "collected_at": collected_at,
        "platform": "windows",
        "target": target,
        "collector": {
            **collector,
            "collector_id": "collector:windows-access-check",
            "independent_process": collector["process_id"] != target["process_id"],
            "account_name_exposed": False,
        },
        "environment": collect_credential_boundary(),
        "filesystem": {
            "input": {**input_descriptor, "target_effective_access": input_target_access},
            "output": {
                **output_descriptor,
                "target_effective_access": output_target_access,
                "collector_effective_access": output_collector_access,
            },
            "effective_rights_computed": True,
            "acl_modified": False,
        },
        "network": {
            **profile_egress,
            "target_inspection_method": target_egress["inspection_method"],
            "target_inspection_succeeded": target_egress["inspection_succeeded"],
            "target_executable_digest": target_egress["target_executable_digest"],
            "matching_block_rule_count": target_egress["matching_block_rule_count"],
            "all_traffic_block_rule_count": target_egress["all_traffic_block_rule_count"],
            "rule_evidence_digests": target_egress["rule_evidence_digests"],
            "target_rule_evidence_digest": target_egress["raw_evidence_digest"],
            "firewall_modified": target_egress["firewall_modified"],
            "target_inspection_attempt_count": target_egress["attempt_count"],
        },
        "controls": [],
        "status": "boundary_unproven",
        "blockers": [],
        "authority": WINDOWS_MEASUREMENT_AUTHORITY,
    }
    controls = _derive_controls(measurement, expected_os_account_sid)
    blockers = sorted(control["control_id"] for control in controls if control["status"] != "verified")
    violated = any(control["status"] == "violated" for control in controls)
    return {
        **measurement,
        "controls": controls,
        "status": "violated" if violated else ("verified" if not blockers else "boundary_unproven"),
        "blockers": blockers,
    }


def build_signed_windows_isolation_attestation(
    measurement: JsonObject,
    component_id: str,
    logical_principal: str,
    governance_state: JsonObject,
    connectors: list[SigningConnector],
    issued_at: datetime,
    lifetime_seconds: int,
) -> JsonObject:
    if measurement.get("origin") != "live" or measurement.get("platform") != "windows":
        raise WindowsIsolationCollectionError("Windows isolation attestation requires a live Windows measurement.")
    if lifetime_seconds <= 0 or issued_at.tzinfo is None:
        raise WindowsIsolationCollectionError("Windows isolation attestation requires aware time and positive lifetime.")
    controls = measurement.get("controls")
    if not isinstance(controls, list) or {value.get("control_id") for value in controls if isinstance(value, dict)} != REQUIRED_ISOLATION_CONTROLS:
        raise WindowsIsolationCollectionError("Windows isolation measurement has an incomplete control set.")
    blockers = sorted(value["control_id"] for value in controls if value["status"] != "verified")
    violated = any(value["status"] == "violated" for value in controls)
    collected_at = measurement.get("collected_at")
    if not isinstance(collected_at, str):
        raise WindowsIsolationCollectionError("Windows isolation measurement collected_at is missing.")
    target = measurement["target"]
    unsigned: JsonObject = {
        "attestation_version": "0.1.0",
        "attestation_id": str(uuid.uuid4()),
        "origin": "live",
        "component_kind": "evaluator",
        "component_id": component_id,
        "logical_principal": logical_principal,
        "governance_state_digest": sha256_digest(governance_state),
        "captured_at": collected_at,
        "issued_at": issued_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        "not_before": issued_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        "expires_at": (issued_at + timedelta(seconds=lifetime_seconds)).astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        "process": {
            "process_id": target["process_id"],
            "os_account_identifier": target["os_account_identifier"],
            "os_account_sid": target["os_account_sid"],
            "executable_digest": target["executable_digest"],
        },
        "collector": {
            "collector_id": measurement["collector"]["collector_id"],
            "kind": "windows_access_check",
            "raw_evidence_digest": sha256_digest(measurement),
        },
        "controls": controls,
        "status": "violated" if violated else ("verified" if not blockers else "boundary_unproven"),
        "blockers": blockers,
        "authority": ISOLATION_AUTHORITY,
    }
    return sign_isolation_attestation(unsigned, connectors)
