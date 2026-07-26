"""Supervisor boundary for separately launched World Model intake verification."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import cast

from nimrod_simulator.errors import WorldIntakeError
from nimrod_simulator.jsonio import canonical_json_bytes, read_json_object, sha256_digest
from nimrod_simulator.model import JsonObject


def _verifier_environment() -> dict[str, str]:
    allowed_names = ("SystemRoot", "WINDIR", "TEMP", "TMP")
    environment = {name: os.environ[name] for name in allowed_names if name in os.environ}
    environment["PYTHONIOENCODING"] = "utf-8"
    return environment


def run_world_intake_verification(
    project_root: Path,
    edge_document: JsonObject,
    previous_cursor: JsonObject,
    previous_generation: JsonObject,
    candidate: JsonObject,
) -> JsonObject:
    values = {
        "edge-document": edge_document,
        "previous-cursor": previous_cursor,
        "previous-generation": previous_generation,
        "candidate": candidate,
    }
    with tempfile.TemporaryDirectory(prefix="nimrod-world-intake-verifier-") as temporary:
        root = Path(temporary)
        paths: dict[str, Path] = {}
        for name, value in values.items():
            path = root / f"{name}.json"
            path.write_bytes(canonical_json_bytes(value) + b"\n")
            paths[name] = path
        output_path = root / "verification.json"
        command = [
            sys.executable,
            "-m",
            "nimrod_cacis.world_intake_verifier_cli",
            "--edge-document",
            str(paths["edge-document"]),
            "--previous-cursor",
            str(paths["previous-cursor"]),
            "--previous-generation",
            str(paths["previous-generation"]),
            "--candidate",
            str(paths["candidate"]),
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
            raise WorldIntakeError(
                "CACIS World Model intake verifier failed: "
                f"command={command!r}, returncode={completed.returncode}, "
                f"stdout={completed.stdout!r}, stderr={completed.stderr!r}."
            )
        envelope = read_json_object(output_path)
        for name, value in values.items():
            if read_json_object(paths[name]) != value:
                raise WorldIntakeError(f"CACIS World Model intake verifier modified input evidence: name={name!r}.")
    process_id = envelope.get("worker_process_id")
    if not isinstance(process_id, int) or isinstance(process_id, bool) or process_id == os.getpid():
        raise WorldIntakeError("CACIS World Model intake verifier did not prove a distinct OS process.")
    expected_digests = {
        "edge_document_digest": sha256_digest(edge_document),
        "previous_cursor_digest": sha256_digest(previous_cursor),
        "previous_generation_digest": sha256_digest(previous_generation),
        "candidate_digest": sha256_digest(candidate),
    }
    for field, expected in expected_digests.items():
        if envelope.get(field) != expected:
            raise WorldIntakeError(f"CACIS World Model intake verifier digest binding is invalid: field={field!r}.")
    verification = envelope.get("verification")
    if not isinstance(verification, dict):
        raise WorldIntakeError("CACIS World Model intake verifier returned an untyped result.")
    return cast(JsonObject, verification)
