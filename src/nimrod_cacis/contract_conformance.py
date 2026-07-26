"""Evidence-preserving conformance inventory for nimrod's public contracts."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from nimrod_simulator.errors import SimulatorError
from nimrod_simulator.model import JsonObject


CONFORMANCE_LEVELS: tuple[str, ...] = (
    "schema_only",
    "semantic_validator",
    "independent_harness_reference",
    "runtime_and_harness_reference",
)


def _level(has_semantic: bool, runtime_paths: Sequence[str], harness_paths: Sequence[str]) -> str:
    if runtime_paths and harness_paths:
        return "runtime_and_harness_reference"
    if harness_paths:
        return "independent_harness_reference"
    if has_semantic:
        return "semantic_validator"
    return "schema_only"


def build_contract_conformance(
    contract_pairs: Sequence[tuple[str, str]],
    semantic_contracts: frozenset[str],
    runtime_references: Mapping[str, Sequence[str]],
    harness_references: Mapping[str, Sequence[str]],
) -> JsonObject:
    """Build an honest static reference matrix without claiming runtime execution."""
    rows: list[JsonObject] = []
    for schema_name, example_name in contract_pairs:
        runtime_paths = sorted(set(runtime_references.get(schema_name, ())))
        harness_paths = sorted(set(harness_references.get(schema_name, ())))
        has_semantic = schema_name in semantic_contracts
        rows.append(
            {
                "schema": schema_name,
                "example": example_name,
                "draft_2020_12_validated": True,
                "negative_schema_mutation_validated": True,
                "semantic_validator_present": has_semantic,
                "runtime_reference_paths": runtime_paths,
                "independent_harness_reference_paths": harness_paths,
                "conformance_level": _level(has_semantic, runtime_paths, harness_paths),
                "live_runtime_evidence_present": False,
                "production_conformance_claimed": False,
            }
        )
    level_counts = {level: len([row for row in rows if row["conformance_level"] == level]) for level in CONFORMANCE_LEVELS}
    body: JsonObject = {
        "matrix_version": "0.1.0",
        "origin": "static_repository_analysis",
        "contract_count": len(rows),
        "rows": rows,
        "summary": {
            "schema_validated_count": len(rows),
            "negative_schema_mutation_validated_count": len(rows),
            "semantic_validator_count": len([row for row in rows if row["semantic_validator_present"] is True]),
            "runtime_reference_count": len([row for row in rows if row["runtime_reference_paths"]]),
            "independent_harness_reference_count": len(
                [row for row in rows if row["independent_harness_reference_paths"]]
            ),
            "conformance_level_counts": level_counts,
            "live_runtime_evidence_count": 0,
            "production_conformance_claim_count": 0,
        },
        "authority": {
            "can_authorize": False,
            "can_execute": False,
            "can_promote": False,
            "can_claim_production_readiness": False,
        },
    }
    validate_contract_conformance(body, len(contract_pairs))
    return body


def validate_contract_conformance(document: JsonObject, expected_count: int) -> None:
    if document.get("matrix_version") != "0.1.0" or document.get("origin") != "static_repository_analysis":
        raise SimulatorError("Contract conformance matrix identity is invalid.")
    rows = document.get("rows")
    if not isinstance(rows, list) or len(rows) != expected_count or document.get("contract_count") != expected_count:
        raise SimulatorError("Contract conformance matrix count differs from the canonical contract inventory.")
    schemas: list[str] = []
    for row in rows:
        if not isinstance(row, dict):
            raise SimulatorError("Contract conformance row must be an object.")
        schema = row.get("schema")
        if not isinstance(schema, str):
            raise SimulatorError("Contract conformance row lacks a schema identity.")
        schemas.append(schema)
        if row.get("draft_2020_12_validated") is not True or row.get("negative_schema_mutation_validated") is not True:
            raise SimulatorError(f"Contract '{schema}' lacks schema and negative-mutation evidence.")
        if row.get("conformance_level") not in CONFORMANCE_LEVELS:
            raise SimulatorError(f"Contract '{schema}' has an invalid conformance level.")
        if row.get("live_runtime_evidence_present") is not False or row.get("production_conformance_claimed") is not False:
            raise SimulatorError(f"Contract '{schema}' fabricated live or production conformance.")
    if len(set(schemas)) != expected_count:
        raise SimulatorError("Contract conformance matrix contains duplicate schema identities.")
    authority = document.get("authority")
    if not isinstance(authority, dict) or any(value is not False for value in authority.values()):
        raise SimulatorError("Contract conformance matrix widened authority.")
    summary = document.get("summary")
    if not isinstance(summary, dict):
        raise SimulatorError("Contract conformance matrix summary is missing.")
    if summary.get("schema_validated_count") != expected_count or summary.get("live_runtime_evidence_count") != 0:
        raise SimulatorError("Contract conformance matrix summary contradicts its bounded evidence.")
