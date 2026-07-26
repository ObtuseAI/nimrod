"""Publish the 97-contract static runtime-conformance gap matrix."""

from __future__ import annotations

import copy
import json
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import cast

from nimrod_cacis.contract_conformance import build_contract_conformance, validate_contract_conformance
from nimrod_simulator.errors import SimulatorError
from nimrod_simulator.model import JsonObject
from validate_contracts import CONTRACT_PAIRS, SEMANTIC_VALIDATORS


def _reference_index(paths: Sequence[Path], project_root: Path) -> dict[str, list[str]]:
    index: dict[str, list[str]] = {schema_name: [] for schema_name, _ in CONTRACT_PAIRS}
    for path in paths:
        text = path.read_text(encoding="utf-8")
        relative = path.relative_to(project_root).as_posix()
        for schema_name, example_name in CONTRACT_PAIRS:
            if schema_name in text or example_name in text:
                index[schema_name].append(relative)
    return index


def _expect_error(operation: Callable[[], object], label: str) -> None:
    try:
        operation()
    except SimulatorError:
        return
    raise RuntimeError(f"Expected SimulatorError for {label}.")


def validate_matrix(project_root: Path) -> JsonObject:
    runtime_paths = sorted((project_root / "src").rglob("*.py"))
    harness_paths = sorted(
        path
        for path in (project_root / "tools").glob("validate_*.py")
        if path.name not in {"validate_contracts.py", "validate_contract_conformance.py"}
    )
    document = build_contract_conformance(
        CONTRACT_PAIRS,
        frozenset(SEMANTIC_VALIDATORS),
        _reference_index(runtime_paths, project_root),
        _reference_index(harness_paths, project_root),
    )
    validate_contract_conformance(document, 97)
    adversarial_count = 0
    mutations: tuple[tuple[str, Callable[[JsonObject], None]], ...] = (
        ("contract removal", lambda value: cast(list[object], value["rows"]).pop()),
        ("count drift", lambda value: value.__setitem__("contract_count", 96)),
        ("duplicate schema", lambda value: cast(JsonObject, cast(list[object], value["rows"])[1]).__setitem__("schema", cast(JsonObject, cast(list[object], value["rows"])[0])["schema"])),
        ("schema proof removal", lambda value: cast(JsonObject, cast(list[object], value["rows"])[0]).__setitem__("draft_2020_12_validated", False)),
        ("live evidence fabrication", lambda value: cast(JsonObject, cast(list[object], value["rows"])[0]).__setitem__("live_runtime_evidence_present", True)),
        ("production claim fabrication", lambda value: cast(JsonObject, cast(list[object], value["rows"])[0]).__setitem__("production_conformance_claimed", True)),
        ("authority widening", lambda value: cast(JsonObject, value["authority"]).__setitem__("can_execute", True)),
        ("summary laundering", lambda value: cast(JsonObject, value["summary"]).__setitem__("live_runtime_evidence_count", 1)),
    )
    for label, mutate in mutations:
        candidate = copy.deepcopy(document)
        mutate(candidate)
        _expect_error(lambda candidate=candidate: validate_contract_conformance(candidate, 97), label)
        adversarial_count += 1
    summary = cast(JsonObject, document["summary"])
    return {
        "status": "CONTRACT_CONFORMANCE_MATRIX_STATIC_EVIDENCE_VALID_LIVE_RUNTIME_BLOCKED",
        "contract_count": document["contract_count"],
        "schema_validated_count": summary["schema_validated_count"],
        "semantic_validator_count": summary["semantic_validator_count"],
        "runtime_reference_count": summary["runtime_reference_count"],
        "independent_harness_reference_count": summary["independent_harness_reference_count"],
        "conformance_level_counts": summary["conformance_level_counts"],
        "negative_fail_closed_case_count": adversarial_count,
        "live_runtime_evidence_count": 0,
        "production_conformance_claim_count": 0,
        "execution_authorized": False,
        "execution_performed": False,
        "matrix": document,
    }


def main() -> None:
    project_root = Path(__file__).resolve().parents[1]
    result = validate_matrix(project_root)
    report_path = project_root / "reports" / "CONTRACT_CONFORMANCE_MATRIX.json"
    report_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({key: value for key, value in result.items() if key != "matrix"}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
