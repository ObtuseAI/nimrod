from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path
from typing import TypedDict, cast


class ManifestEntry(TypedDict):
    path: str
    bytes: int
    sha256: str


class FoundationManifest(TypedDict):
    manifest_version: str
    file_count: int
    project_file_count: int
    files: list[ManifestEntry]


EXCLUDED_DIRECTORY_NAMES: frozenset[str] = frozenset(
    {".git", ".venv", "artifacts", "build", "__pycache__", "node_modules", "dist"}
)
MANIFEST_PATH = "reports/FOUNDATION_MANIFEST.json"


def is_excluded_directory(name: str) -> bool:
    return name in EXCLUDED_DIRECTORY_NAMES or name.endswith(".egg-info")


def list_project_files(project_root: Path) -> tuple[str, ...]:
    relative_paths: list[str] = []
    for current_root, directory_names, file_names in os.walk(project_root):
        directory_names[:] = [
            name for name in directory_names if not is_excluded_directory(name)
        ]
        current_path = Path(current_root)
        for file_name in file_names:
            absolute_path = current_path / file_name
            relative_path = absolute_path.relative_to(project_root).as_posix()
            if relative_path != MANIFEST_PATH:
                relative_paths.append(relative_path)
    return tuple(sorted(relative_paths))


def load_manifest(project_root: Path) -> FoundationManifest:
    manifest_path = project_root / MANIFEST_PATH
    payload = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    if not isinstance(payload, dict):
        raise TypeError(f"Foundation manifest must be an object: {manifest_path}")
    return cast(FoundationManifest, payload)


def read_git_attributes(
    project_root: Path, relative_paths: tuple[str, ...]
) -> dict[str, dict[str, str]]:
    command = ["git", "check-attr", "--stdin", "text", "eol"]
    result = subprocess.run(
        command,
        cwd=project_root,
        input=("\n".join(relative_paths) + "\n").encode("utf-8"),
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            "Git attribute inspection failed: "
            f"command={command!r} returncode={result.returncode} "
            f"stderr={result.stderr.decode('utf-8').strip()!r}"
        )
    attributes: dict[str, dict[str, str]] = {
        path: {} for path in relative_paths
    }
    for line in result.stdout.decode("utf-8").splitlines():
        parts = line.split(": ", maxsplit=2)
        if len(parts) != 3:
            raise ValueError(f"Unexpected git check-attr output: {line!r}")
        path, attribute, value = parts
        if path not in attributes:
            raise ValueError(f"Git returned an undeclared manifest path: {path!r}")
        attributes[path][attribute] = value
    return attributes


def canonical_repository_bytes(
    raw_bytes: bytes, attributes: dict[str, str]
) -> bytes:
    text_attribute = attributes.get("text", "unspecified")
    eol_attribute = attributes.get("eol", "unspecified")
    if text_attribute != "unset" and eol_attribute == "lf":
        return raw_bytes.replace(b"\r\n", b"\n")
    return raw_bytes


def validate_manifest(project_root: Path) -> dict[str, object]:
    manifest = load_manifest(project_root)
    project_files = list_project_files(project_root)
    entries = manifest["files"]
    entry_paths = tuple(entry["path"] for entry in entries)
    if len(entry_paths) != len(set(entry_paths)):
        raise ValueError("Foundation manifest contains duplicate file paths")
    if set(entry_paths) != set(project_files):
        missing = sorted(set(project_files) - set(entry_paths))
        extra = sorted(set(entry_paths) - set(project_files))
        raise ValueError(
            "Foundation manifest file set differs from the project tree: "
            f"missing={missing!r} extra={extra!r}"
        )
    expected_file_count = len(project_files)
    if manifest["file_count"] != expected_file_count:
        raise ValueError(
            "Foundation manifest file_count is invalid: "
            f"expected={expected_file_count} actual={manifest['file_count']}"
        )
    if manifest["project_file_count"] != expected_file_count + 1:
        raise ValueError(
            "Foundation manifest project_file_count is invalid: "
            f"expected={expected_file_count + 1} "
            f"actual={manifest['project_file_count']}"
        )
    attributes = read_git_attributes(project_root, project_files)
    normalization_required: list[str] = []
    mismatches: list[str] = []
    for entry in entries:
        relative_path = entry["path"]
        raw_bytes = (project_root / relative_path).read_bytes()
        canonical_bytes = canonical_repository_bytes(
            raw_bytes, attributes[relative_path]
        )
        if raw_bytes != canonical_bytes:
            normalization_required.append(relative_path)
        actual_digest = hashlib.sha256(canonical_bytes).hexdigest().upper()
        if entry["bytes"] != len(canonical_bytes) or entry["sha256"] != actual_digest:
            mismatches.append(relative_path)
    if normalization_required:
        raise ValueError(
            "Tracked text files require LF normalization before publication: "
            f"paths={normalization_required!r}"
        )
    if mismatches:
        raise ValueError(
            "Foundation manifest does not match canonical repository bytes: "
            f"paths={mismatches!r}"
        )
    return {
        "status": "FOUNDATION_MANIFEST_CANONICAL_REPOSITORY_BYTES_VALID",
        "manifest_version": manifest["manifest_version"],
        "indexed_file_count": expected_file_count,
        "project_file_count": expected_file_count + 1,
        "hash_algorithm": "SHA256",
        "git_attribute_aware": True,
        "normalization_required_count": 0,
        "hash_mismatch_count": 0,
    }


def main() -> None:
    project_root = Path(__file__).resolve().parents[1]
    result = validate_manifest(project_root)
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
