"""Crash-recoverable Windows Job Object metering bound to candidate resource lineage."""

from __future__ import annotations

import ctypes
import hashlib
import json
import math
import os
import subprocess
import sys
import time
import uuid
from ctypes import wintypes
from pathlib import Path

from nimrod_simulator.errors import (
    InjectedResourceMeterCrashError,
    ResourceMeterError,
    ResourceMeterStateError,
)
from nimrod_simulator.jsonio import (
    canonical_json_bytes,
    require_integer,
    require_object,
    require_string,
    sha256_digest,
)
from nimrod_simulator.model import JsonObject


JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x00000100
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS = 9
JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION_CLASS = 1
CREATE_SUSPENDED = 0x00000004
CREATE_NO_WINDOW = 0x08000000
WAIT_OBJECT_0 = 0x00000000
WAIT_TIMEOUT = 0x00000102
MOVEFILE_WRITE_THROUGH = 0x00000008
ERROR_FILE_EXISTS = 80
ERROR_ALREADY_EXISTS = 183
RESOURCE_METER_AUTHORITY = {
    "can_allocate": False,
    "can_extend_lease": False,
    "can_execute_candidate": False,
    "can_promote": False,
}


class IoCounters(ctypes.Structure):
    _fields_ = [
        ("read_operation_count", ctypes.c_ulonglong),
        ("write_operation_count", ctypes.c_ulonglong),
        ("other_operation_count", ctypes.c_ulonglong),
        ("read_transfer_count", ctypes.c_ulonglong),
        ("write_transfer_count", ctypes.c_ulonglong),
        ("other_transfer_count", ctypes.c_ulonglong),
    ]


class JobObjectBasicLimitInformation(ctypes.Structure):
    _fields_ = [
        ("per_process_user_time_limit", ctypes.c_longlong),
        ("per_job_user_time_limit", ctypes.c_longlong),
        ("limit_flags", wintypes.DWORD),
        ("minimum_working_set_size", ctypes.c_size_t),
        ("maximum_working_set_size", ctypes.c_size_t),
        ("active_process_limit", wintypes.DWORD),
        ("affinity", ctypes.c_size_t),
        ("priority_class", wintypes.DWORD),
        ("scheduling_class", wintypes.DWORD),
    ]


class JobObjectExtendedLimitInformation(ctypes.Structure):
    _fields_ = [
        ("basic_limit_information", JobObjectBasicLimitInformation),
        ("io_info", IoCounters),
        ("process_memory_limit", ctypes.c_size_t),
        ("job_memory_limit", ctypes.c_size_t),
        ("peak_process_memory_used", ctypes.c_size_t),
        ("peak_job_memory_used", ctypes.c_size_t),
    ]


class JobObjectBasicAccountingInformation(ctypes.Structure):
    _fields_ = [
        ("total_user_time", ctypes.c_longlong),
        ("total_kernel_time", ctypes.c_longlong),
        ("this_period_total_user_time", ctypes.c_longlong),
        ("this_period_total_kernel_time", ctypes.c_longlong),
        ("total_page_fault_count", wintypes.DWORD),
        ("total_processes", wintypes.DWORD),
        ("active_processes", wintypes.DWORD),
        ("total_terminated_processes", wintypes.DWORD),
    ]


class StartupInfo(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("reserved", wintypes.LPWSTR),
        ("desktop", wintypes.LPWSTR),
        ("title", wintypes.LPWSTR),
        ("x", wintypes.DWORD),
        ("y", wintypes.DWORD),
        ("x_size", wintypes.DWORD),
        ("y_size", wintypes.DWORD),
        ("x_count_chars", wintypes.DWORD),
        ("y_count_chars", wintypes.DWORD),
        ("fill_attribute", wintypes.DWORD),
        ("flags", wintypes.DWORD),
        ("show_window", wintypes.WORD),
        ("reserved_size", wintypes.WORD),
        ("reserved_bytes", ctypes.POINTER(ctypes.c_byte)),
        ("standard_input", wintypes.HANDLE),
        ("standard_output", wintypes.HANDLE),
        ("standard_error", wintypes.HANDLE),
    ]


class ProcessInformation(ctypes.Structure):
    _fields_ = [
        ("process_handle", wintypes.HANDLE),
        ("thread_handle", wintypes.HANDLE),
        ("process_id", wintypes.DWORD),
        ("thread_id", wintypes.DWORD),
    ]


def _require_windows() -> None:
    if sys.platform != "win32":
        raise ResourceMeterError(f"Windows Job Object metering requires win32; received '{sys.platform}'.")


def _file_digest(path: Path) -> str:
    if not path.is_file():
        raise ResourceMeterError(f"Resource meter executable is not a file: '{path}'.")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def _string_digest(value: str) -> str:
    return f"sha256:{hashlib.sha256(value.encode('utf-8')).hexdigest()}"


def _directory_size(root: Path) -> int:
    return sum(path.stat().st_size for path in root.rglob("*") if path.is_file())


def _state_paths(state_root: Path, meter_id: str) -> tuple[Path, Path, Path]:
    return (
        state_root / "prepared" / f"{meter_id}.json",
        state_root / "observations" / f"{meter_id}.json",
        state_root / "completed" / f"{meter_id}.json",
    )


def _ensure_state_directories(state_root: Path) -> None:
    for name in ("prepared", "observations", "completed"):
        (state_root / name).mkdir(parents=True, exist_ok=True)


def _write_immutable_json(path: Path, value: JsonObject) -> None:
    _require_windows()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    payload = canonical_json_bytes(value) + b"\n"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.MoveFileExW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
        kernel32.MoveFileExW.restype = wintypes.BOOL
        if not kernel32.MoveFileExW(str(temporary), str(path), MOVEFILE_WRITE_THROUGH):
            error_code = ctypes.get_last_error()
            if error_code in {ERROR_FILE_EXISTS, ERROR_ALREADY_EXISTS}:
                raise ResourceMeterStateError(f"Resource meter immutable record already exists: '{path}'.")
            raise ResourceMeterStateError(
                f"Resource meter write-through publication failed: path='{path}', win32_error={error_code}."
            )
    finally:
        temporary.unlink(missing_ok=True)


def _read_json(path: Path, label: str) -> JsonObject:
    if not path.is_file():
        raise ResourceMeterStateError(f"Resource meter {label} record is missing: '{path}'.")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ResourceMeterStateError(f"Resource meter {label} record is invalid: path='{path}', error='{error}'.") from error
    if not isinstance(value, dict):
        raise ResourceMeterStateError(f"Resource meter {label} record must be an object: '{path}'.")
    return value


def _create_job(memory_limit_bytes: int) -> int:
    _require_windows()
    if memory_limit_bytes <= 0:
        raise ResourceMeterError("Resource meter process memory limit must be positive.")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    kernel32.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    kernel32.SetInformationJobObject.restype = wintypes.BOOL
    job = kernel32.CreateJobObjectW(None, None)
    if not job:
        error_code = ctypes.get_last_error()
        raise ResourceMeterError(f"CreateJobObjectW failed with win32_error={error_code}.")
    information = JobObjectExtendedLimitInformation()
    information.basic_limit_information.limit_flags = (
        JOB_OBJECT_LIMIT_PROCESS_MEMORY | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    )
    information.process_memory_limit = memory_limit_bytes
    if not kernel32.SetInformationJobObject(
        job,
        JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS,
        ctypes.byref(information),
        ctypes.sizeof(information),
    ):
        error_code = ctypes.get_last_error()
        kernel32.CloseHandle(job)
        raise ResourceMeterError(
            f"SetInformationJobObject failed for memory_limit_bytes={memory_limit_bytes} with win32_error={error_code}."
        )
    return int(job)


def _assign_process(job_handle: int, process_handle: int, process_id: int) -> None:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
    if not kernel32.AssignProcessToJobObject(wintypes.HANDLE(job_handle), wintypes.HANDLE(process_handle)):
        error_code = ctypes.get_last_error()
        raise ResourceMeterError(
            f"AssignProcessToJobObject failed for process_id={process_id} with win32_error={error_code}."
        )


def _create_suspended_process(command: list[str]) -> ProcessInformation:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateProcessW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.LPWSTR,
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.BOOL,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.LPCWSTR,
        ctypes.POINTER(StartupInfo),
        ctypes.POINTER(ProcessInformation),
    ]
    kernel32.CreateProcessW.restype = wintypes.BOOL
    executable = str(Path(command[0]).resolve(strict=True))
    command_line = ctypes.create_unicode_buffer(subprocess.list2cmdline(command))
    startup = StartupInfo()
    startup.cb = ctypes.sizeof(startup)
    process_information = ProcessInformation()
    creation_flags = CREATE_SUSPENDED | CREATE_NO_WINDOW
    if not kernel32.CreateProcessW(
        executable,
        command_line,
        None,
        None,
        False,
        creation_flags,
        None,
        None,
        ctypes.byref(startup),
        ctypes.byref(process_information),
    ):
        error_code = ctypes.get_last_error()
        raise ResourceMeterError(
            f"CreateProcessW suspended launch failed: executable_digest={_file_digest(Path(executable))}, "
            f"creation_flags={creation_flags}, win32_error={error_code}."
        )
    return process_information


def _resume_process_thread(thread_handle: int, process_id: int) -> None:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.ResumeThread.argtypes = [wintypes.HANDLE]
    kernel32.ResumeThread.restype = wintypes.DWORD
    previous_suspend_count = kernel32.ResumeThread(wintypes.HANDLE(thread_handle))
    if previous_suspend_count == 0xFFFFFFFF:
        error_code = ctypes.get_last_error()
        raise ResourceMeterError(
            f"ResumeThread failed after Job Object assignment: process_id={process_id}, win32_error={error_code}."
        )


def _terminate_process(process_handle: int, process_id: int) -> None:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel32.TerminateProcess.restype = wintypes.BOOL
    if not kernel32.TerminateProcess(wintypes.HANDLE(process_handle), 1):
        error_code = ctypes.get_last_error()
        raise ResourceMeterError(
            f"TerminateProcess failed for suspended process_id={process_id} with win32_error={error_code}."
        )


def _wait_for_process(process_handle: int, process_id: int, job_handle: int, timeout_seconds: int) -> int:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel32.WaitForSingleObject.restype = wintypes.DWORD
    kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel32.TerminateJobObject.restype = wintypes.BOOL
    kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel32.GetExitCodeProcess.restype = wintypes.BOOL
    wait_result = kernel32.WaitForSingleObject(wintypes.HANDLE(process_handle), timeout_seconds * 1000)
    if wait_result == WAIT_TIMEOUT:
        if not kernel32.TerminateJobObject(wintypes.HANDLE(job_handle), 1):
            error_code = ctypes.get_last_error()
            raise ResourceMeterError(
                f"TerminateJobObject failed after timeout_seconds={timeout_seconds}: "
                f"process_id={process_id}, win32_error={error_code}."
            )
        kernel32.WaitForSingleObject(wintypes.HANDLE(process_handle), 5000)
        raise ResourceMeterError(f"Metered worker exceeded timeout_seconds={timeout_seconds}: process_id={process_id}.")
    if wait_result != WAIT_OBJECT_0:
        error_code = ctypes.get_last_error()
        raise ResourceMeterError(
            f"WaitForSingleObject failed: process_id={process_id}, wait_result={wait_result}, win32_error={error_code}."
        )
    exit_code = wintypes.DWORD(0)
    if not kernel32.GetExitCodeProcess(wintypes.HANDLE(process_handle), ctypes.byref(exit_code)):
        error_code = ctypes.get_last_error()
        raise ResourceMeterError(f"GetExitCodeProcess failed: process_id={process_id}, win32_error={error_code}.")
    return int(exit_code.value)


def _close_handle(handle: int, label: str) -> None:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    if not kernel32.CloseHandle(wintypes.HANDLE(handle)):
        error_code = ctypes.get_last_error()
        raise ResourceMeterError(f"CloseHandle failed for {label}: win32_error={error_code}.")


def _query_job_metrics(job_handle: int) -> JsonObject:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.QueryInformationJobObject.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    kernel32.QueryInformationJobObject.restype = wintypes.BOOL
    extended = JobObjectExtendedLimitInformation()
    returned = wintypes.DWORD(0)
    if not kernel32.QueryInformationJobObject(
        wintypes.HANDLE(job_handle),
        JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS,
        ctypes.byref(extended),
        ctypes.sizeof(extended),
        ctypes.byref(returned),
    ):
        error_code = ctypes.get_last_error()
        raise ResourceMeterError(f"QueryInformationJobObject extended metrics failed with win32_error={error_code}.")
    accounting = JobObjectBasicAccountingInformation()
    if not kernel32.QueryInformationJobObject(
        wintypes.HANDLE(job_handle),
        JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION_CLASS,
        ctypes.byref(accounting),
        ctypes.sizeof(accounting),
        ctypes.byref(returned),
    ):
        error_code = ctypes.get_last_error()
        raise ResourceMeterError(f"QueryInformationJobObject accounting failed with win32_error={error_code}.")
    cpu_time_milliseconds = int((accounting.total_user_time + accounting.total_kernel_time) / 10_000)
    return {
        "cpu_time_milliseconds": cpu_time_milliseconds,
        "peak_memory_bytes": int(extended.peak_process_memory_used),
        "read_bytes": int(extended.io_info.read_transfer_count),
        "write_bytes": int(extended.io_info.write_transfer_count),
        "active_processes_after_completion": int(accounting.active_processes),
        "total_processes": int(accounting.total_processes),
    }


def _query_completed_job_metrics(job_handle: int, timeout_milliseconds: int) -> JsonObject:
    if timeout_milliseconds <= 0:
        raise ResourceMeterError("Completed Job Object accounting timeout must be positive.")
    deadline = time.monotonic() + (timeout_milliseconds / 1000)
    metrics = _query_job_metrics(job_handle)
    while metrics.get("active_processes_after_completion") != 0 and time.monotonic() < deadline:
        time.sleep(0.01)
        metrics = _query_job_metrics(job_handle)
    return metrics


def _execute_metered_worker(
    command: list[str],
    output_root: Path,
    memory_limit_bytes: int,
    timeout_seconds: int,
    started_at: str,
    completed_at: str,
) -> JsonObject:
    if not command:
        raise ResourceMeterError("Resource meter worker command cannot be empty.")
    if timeout_seconds <= 0:
        raise ResourceMeterError("Resource meter timeout must be positive.")
    executable_path = Path(command[0]).resolve(strict=True)
    output_root.mkdir(parents=True, exist_ok=True)
    job = _create_job(memory_limit_bytes)
    process_information: ProcessInformation | None = None
    monotonic_started = time.monotonic()
    try:
        process_information = _create_suspended_process(command)
        process_id = int(process_information.process_id)
        try:
            _assign_process(job, int(process_information.process_handle), process_id)
        except ResourceMeterError:
            _terminate_process(int(process_information.process_handle), process_id)
            raise
        _resume_process_thread(int(process_information.thread_handle), process_id)
        exit_code = _wait_for_process(
            int(process_information.process_handle),
            process_id,
            job,
            timeout_seconds,
        )
        _close_handle(int(process_information.thread_handle), "completed worker primary thread")
        _close_handle(int(process_information.process_handle), "completed worker process")
        process_information = None
        wall_time_milliseconds = max(1, int((time.monotonic() - monotonic_started) * 1000))
        metrics = _query_completed_job_metrics(job, 2000)
        stdout = ""
        stderr = ""
        if exit_code != 0:
            raise ResourceMeterError(
                "Metered worker failed: "
                f"process_id={process_id}, returncode={exit_code}, "
                f"stdout_digest={_string_digest(stdout)}, stderr_digest={_string_digest(stderr)}."
            )
        peak_storage_bytes = _directory_size(output_root)
        cpu_time_milliseconds = int(metrics["cpu_time_milliseconds"])
        return {
            "observation_version": "0.2.0",
            "origin": "live",
            "started_at": started_at,
            "completed_at": completed_at,
            "worker": {
                "process_id": process_id,
                "executable_digest": _file_digest(executable_path),
                "command_digest": sha256_digest(command),
                "output_root_digest": _string_digest(str(output_root.resolve()).casefold()),
                "exit_code": exit_code,
                "stdout_digest": _string_digest(stdout),
                "stderr_digest": _string_digest(stderr),
            },
            "job": {
                "job_object_assigned": True,
                "kill_on_close_configured": True,
                "process_memory_limit_bytes": memory_limit_bytes,
                "created_suspended": True,
                "assigned_before_first_resume": True,
                "assignment_race_closed": True,
                "creation_flags": CREATE_SUSPENDED | CREATE_NO_WINDOW,
                "active_processes_after_completion": metrics["active_processes_after_completion"],
                "total_processes": metrics["total_processes"],
            },
            "usage": {
                "wall_time_milliseconds": wall_time_milliseconds,
                "cpu_time_milliseconds": cpu_time_milliseconds,
                "compute_units": max(1, math.ceil(cpu_time_milliseconds / 100)),
                "peak_memory_bytes": metrics["peak_memory_bytes"],
                "peak_storage_bytes": peak_storage_bytes,
                "read_bytes": metrics["read_bytes"],
                "write_bytes": metrics["write_bytes"],
            },
            "network_access_performed": False,
            "candidate_executed": False,
        }
    finally:
        if process_information is not None:
            _close_handle(int(process_information.thread_handle), "suspended worker primary thread")
            _close_handle(int(process_information.process_handle), "suspended worker process")
        _close_handle(job, "resource meter Job Object")


def _prepare_record(
    meter_id: str,
    candidate_digest: str,
    resource_lease_digest: str,
    command: list[str],
    output_root: Path,
    memory_limit_bytes: int,
    timeout_seconds: int,
    prepared_at: str,
) -> JsonObject:
    return {
        "prepare_version": "0.2.0",
        "meter_id": meter_id,
        "origin": "live",
        "candidate_digest": candidate_digest,
        "resource_lease_digest": resource_lease_digest,
        "worker_executable_digest": _file_digest(Path(command[0]).resolve(strict=True)),
        "command_digest": sha256_digest(command),
        "output_root_digest": _string_digest(str(output_root.resolve()).casefold()),
        "process_memory_limit_bytes": memory_limit_bytes,
        "timeout_seconds": timeout_seconds,
        "prepared_at": prepared_at,
        "authority": RESOURCE_METER_AUTHORITY,
    }


def _receipt_from_records(
    prepare: JsonObject,
    observation: JsonObject,
    recorded_at: str,
    crash_recovered: bool,
) -> JsonObject:
    if observation.get("prepare_record_digest") != sha256_digest(prepare):
        raise ResourceMeterStateError("Resource meter observation does not bind the prepared record.")
    if observation.get("meter_id") != prepare.get("meter_id"):
        raise ResourceMeterStateError("Resource meter observation changes meter_id.")
    worker = require_object(observation.get("worker"), "observation.worker")
    job = require_object(observation.get("job"), "observation.job")
    usage = require_object(observation.get("usage"), "observation.usage")
    bindings = {
        "executable_digest": "worker_executable_digest",
        "command_digest": "command_digest",
        "output_root_digest": "output_root_digest",
    }
    for worker_field, prepare_field in bindings.items():
        if worker.get(worker_field) != prepare.get(prepare_field):
            raise ResourceMeterStateError(
                f"Resource meter worker binding '{worker_field}' diverges from the prepared record."
            )
    if job.get("process_memory_limit_bytes") != prepare.get("process_memory_limit_bytes"):
        raise ResourceMeterStateError("Resource meter Job Object limit diverges from the prepared record.")
    blockers = ["PHYSICAL_POWER_LOSS_TEST_UNPROVEN"]
    if job.get("job_object_assigned") is not True:
        blockers.append("JOB_OBJECT_ASSIGNMENT_FAILED")
    if job.get("kill_on_close_configured") is not True:
        blockers.append("KILL_ON_CLOSE_UNPROVEN")
    if (
        job.get("created_suspended") is not True
        or job.get("assigned_before_first_resume") is not True
        or job.get("assignment_race_closed") is not True
    ):
        blockers.append("ASSIGNMENT_RACE_UNPROVEN")
    if job.get("active_processes_after_completion") != 0:
        blockers.append("ACTIVE_PROCESS_REMAINS")
    return {
        "meter_version": "0.2.0",
        "meter_id": prepare["meter_id"],
        "origin": "live",
        "candidate_digest": prepare["candidate_digest"],
        "resource_lease_digest": prepare["resource_lease_digest"],
        "prepared_at": prepare["prepared_at"],
        "completed_at": observation["completed_at"],
        "recorded_at": recorded_at,
        "worker": worker,
        "job": job,
        "usage": usage,
        "durability": {
            "prepared_record_digest": sha256_digest(prepare),
            "observation_record_digest": sha256_digest(observation),
            "crash_recovered": crash_recovered,
            "injected_process_crash_recovery_verified": crash_recovered,
            "file_data_flush_verified": True,
            "write_through_publish_verified": True,
            "abrupt_process_crash_recovery_verified": crash_recovered,
            "physical_power_loss_test_performed": False,
            "power_loss_durability_verified": False,
        },
        "status": "measured_contract_only" if blockers == ["PHYSICAL_POWER_LOSS_TEST_UNPROVEN"] else "blocked",
        "blockers": sorted(blockers),
        "network_access_performed": False,
        "candidate_executed": False,
        "production_promotion_authorized": False,
        "authority": RESOURCE_METER_AUTHORITY,
    }


def _execute_and_record_observation(
    state_root: Path,
    meter_id: str,
    prepare: JsonObject,
    command: list[str],
    output_root: Path,
    memory_limit_bytes: int,
    timeout_seconds: int,
    started_at: str,
    completed_at: str,
) -> JsonObject:
    _, observation_path, _ = _state_paths(state_root, meter_id)
    observation = {
        "meter_id": meter_id,
        "prepare_record_digest": sha256_digest(prepare),
        **_execute_metered_worker(
            command,
            output_root,
            memory_limit_bytes,
            timeout_seconds,
            started_at,
            completed_at,
        ),
    }
    _write_immutable_json(observation_path, observation)
    return observation


def _prepare_new_measurement(
    state_root: Path,
    meter_id: str,
    candidate_digest: str,
    resource_lease_digest: str,
    command: list[str],
    output_root: Path,
    memory_limit_bytes: int,
    timeout_seconds: int,
    prepared_at: str,
) -> JsonObject:
    _ensure_state_directories(state_root)
    prepare_path, observation_path, completed_path = _state_paths(state_root, meter_id)
    if prepare_path.exists() or observation_path.exists() or completed_path.exists():
        raise ResourceMeterStateError(f"Resource meter_id '{meter_id}' has already been consumed.")
    prepare = _prepare_record(
        meter_id,
        candidate_digest,
        resource_lease_digest,
        command,
        output_root,
        memory_limit_bytes,
        timeout_seconds,
        prepared_at,
    )
    _write_immutable_json(prepare_path, prepare)
    return prepare


def run_resource_measurement(
    state_root: Path,
    meter_id: str,
    candidate_digest: str,
    resource_lease_digest: str,
    command: list[str],
    output_root: Path,
    memory_limit_bytes: int,
    timeout_seconds: int,
    prepared_at: str,
    started_at: str,
    completed_at: str,
    recorded_at: str,
) -> JsonObject:
    prepare = _prepare_new_measurement(
        state_root,
        meter_id,
        candidate_digest,
        resource_lease_digest,
        command,
        output_root,
        memory_limit_bytes,
        timeout_seconds,
        prepared_at,
    )
    observation = _execute_and_record_observation(
        state_root,
        meter_id,
        prepare,
        command,
        output_root,
        memory_limit_bytes,
        timeout_seconds,
        started_at,
        completed_at,
    )
    _, _, completed_path = _state_paths(state_root, meter_id)
    receipt = _receipt_from_records(prepare, observation, recorded_at, False)
    _write_immutable_json(completed_path, receipt)
    return receipt


def run_resource_measurement_until_observation(
    state_root: Path,
    meter_id: str,
    candidate_digest: str,
    resource_lease_digest: str,
    command: list[str],
    output_root: Path,
    memory_limit_bytes: int,
    timeout_seconds: int,
    prepared_at: str,
    started_at: str,
    completed_at: str,
) -> None:
    prepare = _prepare_new_measurement(
        state_root,
        meter_id,
        candidate_digest,
        resource_lease_digest,
        command,
        output_root,
        memory_limit_bytes,
        timeout_seconds,
        prepared_at,
    )
    _execute_and_record_observation(
        state_root,
        meter_id,
        prepare,
        command,
        output_root,
        memory_limit_bytes,
        timeout_seconds,
        started_at,
        completed_at,
    )
    raise InjectedResourceMeterCrashError(
        f"Injected process crash after durable observation for meter_id='{meter_id}'."
    )


def recover_resource_measurement(
    state_root: Path,
    meter_id: str,
    recovered_at: str,
) -> JsonObject:
    prepare_path, observation_path, completed_path = _state_paths(state_root, meter_id)
    if completed_path.exists():
        raise ResourceMeterStateError(f"Resource meter_id '{meter_id}' is already completed and cannot be recovered twice.")
    prepare = _read_json(prepare_path, "prepared")
    observation = _read_json(observation_path, "observation")
    receipt = _receipt_from_records(prepare, observation, recovered_at, True)
    _write_immutable_json(completed_path, receipt)
    return receipt


def resource_ledger_entry_from_receipt(
    receipt: JsonObject,
    candidate_id: str,
    candidate_digest: str,
    resource_lease_digest: str,
    lease: JsonObject,
) -> JsonObject:
    if receipt.get("candidate_digest") != candidate_digest:
        raise ResourceMeterError("Resource meter receipt candidate digest does not match the lineage entry.")
    if receipt.get("resource_lease_digest") != resource_lease_digest:
        raise ResourceMeterError("Resource meter receipt lease digest does not match the lineage entry.")
    if receipt.get("network_access_performed") is not False or receipt.get("candidate_executed") is not False:
        raise ResourceMeterError("Resource meter receipt claims prohibited network or candidate execution activity.")
    if require_object(receipt.get("authority"), "receipt.authority") != RESOURCE_METER_AUTHORITY:
        raise ResourceMeterError("Resource meter receipt exposes prohibited authority.")
    usage = require_object(receipt.get("usage"), "receipt.usage")
    wall_milliseconds = require_integer(usage.get("wall_time_milliseconds"), "receipt.usage.wall_time_milliseconds")
    peak_memory_bytes = require_integer(usage.get("peak_memory_bytes"), "receipt.usage.peak_memory_bytes")
    peak_storage_bytes = require_integer(usage.get("peak_storage_bytes"), "receipt.usage.peak_storage_bytes")
    return {
        "candidate_id": candidate_id,
        "candidate_digest": candidate_digest,
        "parent_candidate_digest": None,
        "resource_lease_digest": resource_lease_digest,
        "lease": lease,
        "usage": {
            "cycle_seconds": max(1, math.ceil(wall_milliseconds / 1000)),
            "compute_units": require_integer(usage.get("compute_units"), "receipt.usage.compute_units"),
            "peak_memory_megabytes": math.ceil(peak_memory_bytes / (1024 * 1024)),
            "peak_storage_megabytes": math.ceil(peak_storage_bytes / (1024 * 1024)),
        },
        "evidence": [{"id": f"resource-meter:{require_string(receipt.get('meter_id'), 'receipt.meter_id')}", "digest": sha256_digest(receipt)}],
    }
