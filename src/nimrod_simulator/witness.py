"""Content-addressed append-only Witness filesystem connector."""

from __future__ import annotations

import json
import os
from pathlib import Path

from nimrod_simulator.errors import JsonDocumentError, WitnessIntegrityError
from nimrod_simulator.jsonio import canonical_json_bytes, read_json_object, sha256_digest
from nimrod_simulator.model import ArtifactReference, JsonObject


class FileWitnessStore:
    """External filesystem boundary for content-addressed simulator evidence."""

    def __init__(self, root: Path) -> None:
        self._root = root
        self._artifact_root = root / "artifacts" / "sha256"
        self._journal_path = root / "witness.jsonl"
        if root.exists() and any(root.iterdir()):
            raise WitnessIntegrityError(f"Witness output directory must be new or empty: '{root}'.")
        self._artifact_root.mkdir(parents=True, exist_ok=True)
        self._sequence = 0
        self._previous_entry_digest: str | None = None

    @property
    def journal_path(self) -> Path:
        return self._journal_path

    def append(self, kind: str, payload: JsonObject, observed_at: str) -> ArtifactReference:
        digest = sha256_digest(payload)
        digest_hex = digest.removeprefix("sha256:")
        artifact_path = self._artifact_root / f"{digest_hex}.json"
        payload_bytes = canonical_json_bytes(payload)
        self._write_artifact(artifact_path, payload_bytes)
        reference: ArtifactReference = {"id": f"witness:{kind}:{self._sequence + 1}", "digest": digest}
        entry: JsonObject = {
            "journal_version": "0.1.0",
            "sequence": self._sequence + 1,
            "kind": kind,
            "observed_at": observed_at,
            "artifact": {"id": reference["id"], "digest": reference["digest"]},
            "previous_entry_digest": self._previous_entry_digest,
        }
        self._append_journal(entry)
        self._sequence += 1
        self._previous_entry_digest = sha256_digest(entry)
        return reference

    def _write_artifact(self, artifact_path: Path, payload_bytes: bytes) -> None:
        if artifact_path.exists():
            existing = artifact_path.read_bytes()
            if existing != payload_bytes:
                raise WitnessIntegrityError(
                    f"Content-address collision or tamper at '{artifact_path}'."
                )
            return
        temporary_path = artifact_path.with_suffix(".tmp")
        with temporary_path.open("xb") as handle:
            handle.write(payload_bytes)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, artifact_path)

    def _append_journal(self, entry: JsonObject) -> None:
        serialized = canonical_json_bytes(entry) + b"\n"
        with self._journal_path.open("ab") as handle:
            handle.write(serialized)
            handle.flush()
            os.fsync(handle.fileno())


def verify_witness_store(root: Path) -> int:
    journal_path = root / "witness.jsonl"
    if not journal_path.is_file():
        raise WitnessIntegrityError(f"Witness journal is missing: '{journal_path}'.")
    previous_entry_digest: str | None = None
    verified = 0
    for line_number, raw_line in enumerate(journal_path.read_text(encoding="utf-8").splitlines(), start=1):
        try:
            parsed = json.loads(raw_line)
        except json.JSONDecodeError as error:
            raise WitnessIntegrityError(
                f"Witness journal line {line_number} is invalid JSON: {error.msg}."
            ) from error
        if not isinstance(parsed, dict):
            raise WitnessIntegrityError(f"Witness journal line {line_number} is not an object.")
        entry = read_json_object_from_value(parsed, line_number)
        sequence = entry.get("sequence")
        if sequence != line_number:
            raise WitnessIntegrityError(
                f"Witness journal sequence mismatch at line {line_number}: received {sequence!r}."
            )
        if entry.get("previous_entry_digest") != previous_entry_digest:
            raise WitnessIntegrityError(f"Witness hash chain mismatch at line {line_number}.")
        artifact = entry.get("artifact")
        if not isinstance(artifact, dict):
            raise WitnessIntegrityError(f"Witness artifact reference missing at line {line_number}.")
        digest = artifact.get("digest")
        if not isinstance(digest, str) or not digest.startswith("sha256:"):
            raise WitnessIntegrityError(f"Witness artifact digest invalid at line {line_number}.")
        artifact_path = root / "artifacts" / "sha256" / f"{digest.removeprefix('sha256:')}.json"
        try:
            artifact_payload = read_json_object(artifact_path)
        except JsonDocumentError as error:
            raise WitnessIntegrityError(
                f"Witness artifact is missing or malformed at line {line_number}: '{artifact_path}'."
            ) from error
        if sha256_digest(artifact_payload) != digest:
            raise WitnessIntegrityError(
                f"Witness artifact hash mismatch at line {line_number}: '{artifact_path}'."
            )
        previous_entry_digest = sha256_digest(entry)
        verified += 1
    if verified == 0:
        raise WitnessIntegrityError(f"Witness journal contains no evidence entries: '{journal_path}'.")
    return verified


def read_json_object_from_value(value: object, line_number: int) -> JsonObject:
    if not isinstance(value, dict):
        raise WitnessIntegrityError(f"Witness journal line {line_number} is not an object.")
    result: JsonObject = {}
    for key, item in value.items():
        if not isinstance(key, str):
            raise WitnessIntegrityError(f"Witness journal line {line_number} contains a non-string key.")
        result[key] = item
    return result
