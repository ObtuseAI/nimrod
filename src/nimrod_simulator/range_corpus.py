"""Read-only compatibility scanning for local Atomic and Caldera corpus snapshots."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path

from nimrod_simulator.errors import JsonDocumentError, RangeAdapterImportError, RangeAdapterPolicyError, RangeCorpusError
from nimrod_simulator.jsonio import require_list, require_object, require_string, sha256_digest
from nimrod_simulator.model import JsonObject
from nimrod_simulator.range_adapter import (
    import_atomic_definition,
    import_caldera_ability,
    require_exact_source_mapping,
)
from nimrod_simulator.range_policy import verify_range_adapter_policy_envelope


def _utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _relative_yaml_files(root: Path) -> list[str]:
    result: list[str] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.casefold() not in {".yaml", ".yml"}:
            continue
        if path.is_symlink():
            raise RangeCorpusError(f"Corpus source cannot be a symbolic link: '{path}'.")
        result.append(path.relative_to(root).as_posix())
    return result


def _entry_import(root: Path, entry: JsonObject) -> JsonObject:
    relative_path = require_string(entry.get("relative_path"), "entry.relative_path")
    candidate = (root / relative_path).resolve()
    resolved_root = root.resolve()
    if candidate == resolved_root or resolved_root not in candidate.parents:
        raise RangeCorpusError(f"Corpus entry escapes the snapshot root: '{relative_path}'.")
    source_kind = require_string(entry.get("source_kind"), "entry.source_kind")
    source_object_id = require_string(entry.get("source_object_id"), "entry.source_object_id")
    if source_kind == "atomic_red_team":
        return import_atomic_definition(candidate, source_object_id)
    if source_kind == "caldera_ability":
        return import_caldera_ability(
            candidate,
            source_object_id,
            require_string(entry.get("platform"), "entry.platform"),
            require_string(entry.get("executor"), "entry.executor"),
        )
    raise RangeCorpusError(f"Unsupported corpus source kind '{source_kind}'.")


def scan_range_corpus(
    corpus_root: Path,
    manifest: JsonObject,
    policy: JsonObject,
    policy_envelope: JsonObject,
    governance_state: JsonObject,
    scanned_at: datetime,
    maximum_policy_lifetime_seconds: int,
) -> JsonObject:
    if not corpus_root.is_dir():
        raise RangeCorpusError(f"Range corpus root is not a directory: '{corpus_root}'.")
    policy_verification = verify_range_adapter_policy_envelope(
        policy_envelope,
        policy,
        governance_state,
        scanned_at,
        maximum_policy_lifetime_seconds,
    )
    if manifest.get("manifest_version") != "0.1.0" or manifest.get("origin") != "simulated":
        raise RangeCorpusError("Range corpus manifest must be version 0.1.0 and simulated.")
    manifest_authority = require_object(manifest.get("authority"), "manifest.authority")
    if manifest_authority != {"can_fetch": False, "can_compile": False, "can_execute": False}:
        raise RangeCorpusError("Range corpus manifest cannot grant fetch, compilation, or execution authority.")
    entries = require_list(manifest.get("entries"), "manifest.entries")
    if manifest.get("snapshot_digest") != sha256_digest(entries):
        raise RangeCorpusError("Range corpus manifest snapshot digest does not bind its ordered entries.")
    declared_paths: list[str] = []
    entry_ids: list[str] = []
    entry_objects: list[JsonObject] = []
    for index, value in enumerate(entries):
        entry = require_object(value, f"manifest.entries[{index}]")
        declared_paths.append(require_string(entry.get("relative_path"), f"manifest.entries[{index}].relative_path"))
        entry_ids.append(require_string(entry.get("entry_id"), f"manifest.entries[{index}].entry_id"))
        entry_objects.append(entry)
    if len(declared_paths) != len(set(declared_paths)):
        raise RangeCorpusError("Range corpus manifest repeats a relative path.")
    if len(entry_ids) != len(set(entry_ids)):
        raise RangeCorpusError("Range corpus manifest repeats an entry ID.")
    actual_paths = _relative_yaml_files(corpus_root)
    missing_files = sorted(set(declared_paths) - set(actual_paths))
    unexpected_files = sorted(set(actual_paths) - set(declared_paths))
    items: list[JsonObject] = []
    compatible_count = 0
    blocked_count = 0
    for entry in entry_objects:
        entry_id = require_string(entry.get("entry_id"), "entry.entry_id")
        expected_digest = require_string(entry.get("expected_artifact_digest"), "entry.expected_artifact_digest")
        try:
            imported = _entry_import(corpus_root, entry)
            digest_match = imported.get("source_artifact_digest") == expected_digest
            mapping_status = "blocked"
            if digest_match and imported.get("quarantine_status") == "eligible_for_no_execution_mapping":
                require_exact_source_mapping(imported, policy)
                mapping_status = "pinned_exact"
            compatible = digest_match and mapping_status == "pinned_exact"
            if compatible:
                compatible_count += 1
            else:
                blocked_count += 1
            items.append(
                {
                    "entry_id": entry_id,
                    "source_kind": imported["source_kind"],
                    "source_object_id": imported["source_object_id"],
                    "artifact_digest": imported["source_artifact_digest"],
                    "import_receipt_digest": sha256_digest(imported),
                    "digest_match": digest_match,
                    "quarantine_status": imported["quarantine_status"],
                    "mapping_status": mapping_status,
                    "findings": imported["findings"],
                    "error": None,
                }
            )
        except (RangeAdapterImportError, RangeAdapterPolicyError, JsonDocumentError) as error:
            blocked_count += 1
            items.append(
                {
                    "entry_id": entry_id,
                    "source_kind": entry["source_kind"],
                    "source_object_id": entry["source_object_id"],
                    "artifact_digest": expected_digest,
                    "import_receipt_digest": None,
                    "digest_match": False,
                    "quarantine_status": "blocked",
                    "mapping_status": "blocked",
                    "findings": [type(error).__name__],
                    "error": str(error),
                }
            )
    status = "compatible_no_execution"
    if missing_files or unexpected_files or blocked_count > 0 or compatible_count != len(entry_objects):
        status = "blocked"
    report_id = str(
        uuid.uuid5(
            uuid.UUID("1b96c805-2bd4-44f0-a64e-e6e32e071695"),
            f"{sha256_digest(manifest)}:{policy_verification['envelope_digest']}:{_utc(scanned_at)}",
        )
    )
    return {
        "report_version": "0.1.0",
        "report_id": report_id,
        "origin": "simulated",
        "scanned_at": _utc(scanned_at),
        "status": status,
        "manifest_digest": sha256_digest(manifest),
        "policy_envelope_digest": policy_verification["envelope_digest"],
        "policy_digest": policy_verification["policy_digest"],
        "declared_entry_count": len(entry_objects),
        "compatible_entry_count": compatible_count,
        "blocked_entry_count": blocked_count,
        "missing_files": missing_files,
        "unexpected_files": unexpected_files,
        "items": items,
        "compilation_performed": False,
        "source_tool_contacted": False,
        "network_access_performed": False,
        "live_execution_performed": False,
        "authority": {"can_connect": False, "can_compile": False, "can_execute": False},
    }
