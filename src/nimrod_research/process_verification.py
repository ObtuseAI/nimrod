"""Supervisor boundary for separately launched CIRE verification."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import cast

from nimrod_simulator.errors import IntelligenceResearchError
from nimrod_simulator.jsonio import canonical_json_bytes, read_json_object, sha256_digest
from nimrod_simulator.model import JsonObject


def _verifier_environment() -> dict[str, str]:
    allowed_names = ("SystemRoot", "WINDIR", "TEMP", "TMP")
    environment = {name: os.environ[name] for name in allowed_names if name in os.environ}
    environment["PYTHONIOENCODING"] = "utf-8"
    return environment


def run_separate_process_verification(project_root: Path, mission: JsonObject, body: JsonObject) -> JsonObject:
    """Launch the read-only verifier with no credential-like ambient environment."""
    with tempfile.TemporaryDirectory(prefix="nimrod-cire-verifier-") as temporary:
        root = Path(temporary)
        mission_path = root / "mission.json"
        body_path = root / "candidate-body.json"
        output_path = root / "verification.json"
        mission_path.write_bytes(canonical_json_bytes(mission) + b"\n")
        body_path.write_bytes(canonical_json_bytes(body) + b"\n")
        command = [
            sys.executable,
            "-m",
            "nimrod_research.verifier_cli",
            "--mission",
            str(mission_path),
            "--candidate-body",
            str(body_path),
            "--output",
            str(output_path),
        ]
        completed = subprocess.run(
            command,
            cwd=project_root,
            env=_verifier_environment(),
            capture_output=True,
            check=False,
            text=True,
            timeout=30,
        )
        if completed.returncode != 0:
            raise IntelligenceResearchError(
                "CIRE separate-process verifier failed: "
                f"command={command!r}, returncode={completed.returncode}, stdout={completed.stdout!r}, stderr={completed.stderr!r}."
            )
        envelope = read_json_object(output_path)
        if read_json_object(mission_path) != mission or read_json_object(body_path) != body:
            raise IntelligenceResearchError("CIRE separate-process verifier modified its read-only input evidence.")
    worker_process_id = envelope.get("worker_process_id")
    if not isinstance(worker_process_id, int) or isinstance(worker_process_id, bool) or worker_process_id == os.getpid():
        raise IntelligenceResearchError(
            f"CIRE verifier did not prove a distinct operating-system process: worker_process_id={worker_process_id!r}."
        )
    if envelope.get("mission_digest") != sha256_digest(mission) or envelope.get("candidate_body_digest") != sha256_digest(body):
        raise IntelligenceResearchError("CIRE verifier input digest binding is invalid.")
    verification = envelope.get("verification")
    if not isinstance(verification, dict):
        raise IntelligenceResearchError("CIRE verifier did not return a typed verification object.")
    return cast(JsonObject, verification)
