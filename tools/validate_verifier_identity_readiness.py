"""Collect live read-only identity readiness for three CACIS verifier surfaces."""

from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable
from pathlib import Path
from typing import cast

from nimrod_platform_assurance.verifier_identity_readiness import AUTHORITY, SURFACE_IDS, validate_verifier_identity_readiness
from nimrod_platform_assurance.windows_isolation_collector import collect_effective_access, collect_process_identity
from nimrod_simulator.errors import VerifierIdentityReadinessError
from nimrod_simulator.jsonio import canonical_json_bytes, read_json_object, sha256_digest
from nimrod_simulator.model import JsonObject


def _environment(temporary_root: Path) -> dict[str, str]:
    allowed_names = ("SystemRoot", "WINDIR")
    environment = {name: os.environ[name] for name in allowed_names if name in os.environ}
    environment.update({"TEMP": str(temporary_root), "TMP": str(temporary_root), "PYTHONIOENCODING": "utf-8"})
    return environment


def _wait_for_file(path: Path, timeout_seconds: int) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if path.is_file():
            return
        time.sleep(0.02)
    raise RuntimeError(f"Verifier identity probe did not create '{path}' within {timeout_seconds} seconds.")


def _probe(project_root: Path, temporary_root: Path, surface_id: str, supervisor: JsonObject) -> JsonObject:
    surface_root = temporary_root / surface_id
    input_root = surface_root / "input"
    input_root.mkdir(parents=True)
    evidence_path = input_root / "evidence.json"
    ready_path = surface_root / "ready.json"
    release_path = surface_root / "release"
    evidence_path.write_bytes(canonical_json_bytes({"surface_id": surface_id, "authority": dict(AUTHORITY)}) + b"\n")
    command = [
        sys.executable,
        str(project_root / "tools" / "verifier_identity_probe_worker.py"),
        "--component-id",
        surface_id,
        "--ready-file",
        str(ready_path),
        "--release-file",
        str(release_path),
        "--timeout-seconds",
        "20",
    ]
    process = subprocess.Popen(
        command,
        cwd=project_root,
        env=_environment(surface_root),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        _wait_for_file(ready_path, 5)
        ready = read_json_object(ready_path)
        identity = collect_process_identity(process.pid)
        access = collect_effective_access(evidence_path, str(identity["os_account_sid"]))
        credential_names = ready.get("credential_environment_names")
        if credential_names != []:
            raise RuntimeError(f"Verifier identity probe inherited credential-like environment names: {credential_names!r}.")
        release_path.write_text("release\n", encoding="utf-8", newline="\n")
        stdout, stderr = process.communicate(timeout=5)
        if process.returncode != 0:
            raise RuntimeError(
                f"Verifier identity probe failed: surface={surface_id!r}, returncode={process.returncode}, stdout={stdout!r}, stderr={stderr!r}."
            )
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
    worker_sid_digest = sha256_digest(str(identity["os_account_sid"]).casefold())
    supervisor_sid_digest = sha256_digest(str(supervisor["os_account_sid"]).casefold())
    dedicated = worker_sid_digest != supervisor_sid_digest
    read_only = access["read_allowed"] is True and access["write_allowed"] is False
    return {
        "surface_id": surface_id,
        "origin": "live_read_only_probe",
        "worker_process_id": process.pid,
        "worker_executable_digest": identity["executable_digest"],
        "worker_account_identifier": identity["os_account_identifier"],
        "worker_account_sid_digest": worker_sid_digest,
        "supervisor_account_sid_digest": supervisor_sid_digest,
        "distinct_process_observed": process.pid != os.getpid(),
        "dedicated_os_account_verified": dedicated,
        "input_evidence_digest": sha256_digest(read_json_object(evidence_path)),
        "input_effective_access": access,
        "read_only_input_acl_verified": read_only,
        "credential_environment_allowlisted": True,
        "credential_value_accessed": False,
        "active_network_probe_performed": False,
        "network_egress_denied_verified": False,
        "production_signing_custody_verified": False,
        "separate_administrator_verified": False,
        "production_eligible": False,
    }


def _expect_error(operation: Callable[[], object], label: str) -> None:
    try:
        operation()
    except VerifierIdentityReadinessError:
        return
    raise RuntimeError(f"Expected VerifierIdentityReadinessError for {label}.")


def validate_readiness(project_root: Path) -> JsonObject:
    supervisor = collect_process_identity(os.getpid())
    with tempfile.TemporaryDirectory(prefix="nimrod-verifier-identity-readiness-") as temporary:
        temporary_root = Path(temporary)
        surfaces = [_probe(project_root, temporary_root, surface_id, supervisor) for surface_id in SURFACE_IDS]
    document: JsonObject = {
        "readiness_version": "0.1.0",
        "origin": "live_read_only_probe",
        "surfaces": surfaces,
        "summary": {
            "surface_count": len(surfaces),
            "dedicated_os_account_verified_count": len([surface for surface in surfaces if surface["dedicated_os_account_verified"] is True]),
            "read_only_input_acl_verified_count": len([surface for surface in surfaces if surface["read_only_input_acl_verified"] is True]),
            "production_eligible_count": 0,
            "status": "LIVE_IDENTITY_OBSERVED_DEDICATED_ACCOUNT_CUSTODY_AND_EGRESS_BLOCKED",
        },
        "authority": dict(AUTHORITY),
    }
    validate_verifier_identity_readiness(document)
    mutations: tuple[tuple[str, Callable[[JsonObject], None]], ...] = (
        ("surface removal", lambda value: cast(list[object], value["surfaces"]).pop()),
        ("process reuse", lambda value: cast(JsonObject, cast(list[object], value["surfaces"])[1]).__setitem__("worker_process_id", cast(JsonObject, cast(list[object], value["surfaces"])[0])["worker_process_id"])),
        ("dedicated account fabrication", lambda value: cast(JsonObject, cast(list[object], value["surfaces"])[0]).__setitem__("dedicated_os_account_verified", True)),
        ("read-only ACL fabrication", lambda value: cast(JsonObject, cast(list[object], value["surfaces"])[0]).__setitem__("read_only_input_acl_verified", True)),
        ("egress fabrication", lambda value: cast(JsonObject, cast(list[object], value["surfaces"])[0]).__setitem__("network_egress_denied_verified", True)),
        ("custody fabrication", lambda value: cast(JsonObject, cast(list[object], value["surfaces"])[0]).__setitem__("production_signing_custody_verified", True)),
        ("production fabrication", lambda value: cast(JsonObject, cast(list[object], value["surfaces"])[0]).__setitem__("production_eligible", True)),
        ("authority widening", lambda value: cast(JsonObject, value["authority"]).__setitem__("can_execute", True)),
    )
    for label, mutate in mutations:
        candidate = copy.deepcopy(document)
        mutate(candidate)
        _expect_error(lambda candidate=candidate: validate_verifier_identity_readiness(candidate), label)
    summary = cast(JsonObject, document["summary"])
    return {
        "status": summary["status"],
        "origin": "live_read_only_probe",
        "surface_count": summary["surface_count"],
        "dedicated_os_account_verified_count": summary["dedicated_os_account_verified_count"],
        "read_only_input_acl_verified_count": summary["read_only_input_acl_verified_count"],
        "distinct_process_observed_count": len(surfaces),
        "credential_environment_allowlisted_count": len(surfaces),
        "network_egress_denied_verified_count": 0,
        "production_signing_custody_verified_count": 0,
        "separate_administrator_verified_count": 0,
        "production_eligible_count": 0,
        "negative_fail_closed_case_count": len(mutations),
        "execution_authorized": False,
        "execution_performed": False,
        "surfaces": surfaces,
    }


def main() -> None:
    project_root = Path(__file__).resolve().parents[1]
    result = validate_readiness(project_root)
    report_path = project_root / "reports" / "VERIFIER_IDENTITY_READINESS_VALIDATION.json"
    report_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({key: value for key, value in result.items() if key != "surfaces"}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
