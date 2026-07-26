"""Canonical JSON and contract-loading functions."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import cast

from jsonschema import Draft202012Validator, FormatChecker

from nimrod_simulator.errors import ContractValidationError, JsonDocumentError
from nimrod_simulator.model import JsonObject, JsonValue


def canonical_json_bytes(value: JsonValue) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


def sha256_digest(value: JsonValue) -> str:
    return f"sha256:{hashlib.sha256(canonical_json_bytes(value)).hexdigest()}"


def read_json_object(path: Path) -> JsonObject:
    try:
        parsed: JsonValue = cast(JsonValue, json.loads(path.read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError) as error:
        raise JsonDocumentError(f"Unable to read JSON object at '{path}': {error}") from error
    if not isinstance(parsed, dict):
        raise JsonDocumentError(f"Expected a JSON object at '{path}'; received {type(parsed).__name__}.")
    return parsed


def validate_contract(document: JsonObject, schema_path: Path, document_label: str) -> None:
    schema = read_json_object(schema_path)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors = sorted(validator.iter_errors(document), key=lambda error: tuple(error.absolute_path))
    if not errors:
        return
    messages = "; ".join(
        f"{'/'.join(str(part) for part in error.absolute_path) or '<root>'}: {error.message}" for error in errors
    )
    raise ContractValidationError(
        f"{document_label} failed contract '{schema_path.name}': {messages}"
    )


def require_object(value: JsonValue, field: str) -> JsonObject:
    if not isinstance(value, dict):
        raise JsonDocumentError(f"Field '{field}' must be an object; received {type(value).__name__}.")
    return value


def require_list(value: JsonValue, field: str) -> list[JsonValue]:
    if not isinstance(value, list):
        raise JsonDocumentError(f"Field '{field}' must be an array; received {type(value).__name__}.")
    return value


def require_string(value: JsonValue, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise JsonDocumentError(f"Field '{field}' must be a non-empty string.")
    return value


def require_integer(value: JsonValue, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise JsonDocumentError(f"Field '{field}' must be an integer.")
    return value


def require_number(value: JsonValue, field: str) -> float:
    if not isinstance(value, int | float) or isinstance(value, bool):
        raise JsonDocumentError(f"Field '{field}' must be numeric.")
    return float(value)


def require_boolean(value: JsonValue, field: str) -> bool:
    if not isinstance(value, bool):
        raise JsonDocumentError(f"Field '{field}' must be a boolean.")
    return value


def require_string_list(value: JsonValue, field: str) -> list[str]:
    values = require_list(value, field)
    result: list[str] = []
    for index, item in enumerate(values):
        result.append(require_string(item, f"{field}[{index}]"))
    return result
