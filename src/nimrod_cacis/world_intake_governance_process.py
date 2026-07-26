"""Supervisor for separately launched governed World Model intake verification."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path
from typing import cast

from nimrod_simulator.errors import WorldIntakeGovernanceError
from nimrod_simulator.jsonio import canonical_json_bytes, read_json_object, sha256_digest
from nimrod_simulator.model import JsonObject


def _environment() -> dict[str, str]:
    allowed_names = ("SystemRoot", "WINDIR", "TEMP", "TMP")
    environment = {name: os.environ[name] for name in allowed_names if name in os.environ}
    environment["PYTHONIOENCODING"] = "utf-8"
    return environment


def run_governed_world_intake_verification(
    project_root: Path,
    edge_document: JsonObject,
    admitted_edge: JsonObject,
    policy: JsonObject,
    health: JsonObject,
    decision: JsonObject,
    governance_state: JsonObject,
    verifier_boundary: JsonObject,
    previous_cursor: JsonObject,
    previous_generation: JsonObject,
    governed_intake: JsonObject,
    verified_at: datetime,
) -> JsonObject:
    values = {
        "edge-document": edge_document,
        "admitted-edge": admitted_edge,
        "policy": policy,
        "health": health,
        "decision": decision,
        "governance-state": governance_state,
        "verifier-boundary": verifier_boundary,
        "previous-cursor": previous_cursor,
        "previous-generation": previous_generation,
        "governed-intake": governed_intake,
    }
    with tempfile.TemporaryDirectory(prefix="nimrod-governed-world-intake-") as temporary:
        root = Path(temporary)
        paths: dict[str, Path] = {}
        for name, value in values.items():
            path = root / f"{name}.json"
            path.write_bytes(canonical_json_bytes(value) + b"\n")
            paths[name] = path
        output_path = root / "verification.json"
        command = [sys.executable, "-m", "nimrod_cacis.world_intake_governance_verifier_cli"]
        for name, path in paths.items():
            command.extend([f"--{name}", str(path)])
        command.extend(
            [
                "--verified-at",
                verified_at.isoformat().replace("+00:00", "Z"),
                "--output",
                str(output_path),
            ]
        )
        completed = subprocess.run(
            command,
            cwd=project_root,
            env=_environment(),
            capture_output=True,
            check=False,
            text=True,
            timeout=30,
        )
        if completed.returncode != 0:
            raise WorldIntakeGovernanceError(
                "Governed World Model intake verifier failed: "
                f"command={command!r}, returncode={completed.returncode}, "
                f"stdout={completed.stdout!r}, stderr={completed.stderr!r}."
            )
        envelope = read_json_object(output_path)
        for name, value in values.items():
            if read_json_object(paths[name]) != value:
                raise WorldIntakeGovernanceError(f"Governed intake verifier modified input evidence: name={name!r}.")
    process_id = envelope.get("worker_process_id")
    if not isinstance(process_id, int) or isinstance(process_id, bool) or process_id == os.getpid():
        raise WorldIntakeGovernanceError("Governed intake verifier did not prove a distinct OS process.")
    input_digests = envelope.get("input_digests")
    if not isinstance(input_digests, dict):
        raise WorldIntakeGovernanceError("Governed intake verifier omitted input digests.")
    for name, value in values.items():
        if input_digests.get(name.replace("-", "_")) != sha256_digest(value):
            raise WorldIntakeGovernanceError(f"Governed intake verifier input binding is invalid: name={name!r}.")
    verification = envelope.get("verification")
    if not isinstance(verification, dict):
        raise WorldIntakeGovernanceError("Governed intake verifier returned an untyped result.")
    return cast(JsonObject, verification)
