"""Validate CACIS W5 candidate-only genome evaluation replay."""

from __future__ import annotations

import copy
import json
from collections.abc import Callable
from pathlib import Path
from typing import cast

from nimrod_cacis.genome import build_genome_evaluation, validate_genome_evaluation
from nimrod_simulator.errors import GenomeEvaluationError
from nimrod_simulator.jsonio import read_json_object, sha256_digest
from nimrod_simulator.model import JsonObject


def source_digests(project_root: Path) -> tuple[tuple[str, str], ...]:
    immune = read_json_object(project_root / "reports" / "CACIS_IMMUNE_RUNTIME_VALIDATION.json")
    research = read_json_object(project_root / "reports" / "INTELLIGENCE_RESEARCH_VALIDATION.json")
    homeostasis = read_json_object(project_root / "reports" / "CACIS_HOMEOSTASIS_CHRONOS_VALIDATION.json")
    return (
        ("credential_theft_lifecycle", cast(str, immune["receipt_digest"])),
        ("suspicious_script_lifecycle", cast(str, immune["suspicious_script_receipt_digest"])),
        ("cire_settlement", cast(str, research["settlement_digest"])),
        ("homeostasis_receipt", cast(str, homeostasis["receipt_digest"])),
    )


def expect_error(operation: Callable[[], object], label: str) -> None:
    try:
        operation()
    except GenomeEvaluationError:
        return
    raise RuntimeError(f"Expected GenomeEvaluationError for {label}.")


def validate_genome(project_root: Path) -> JsonObject:
    sources = source_digests(project_root)
    generated = build_genome_evaluation(sources)
    if generated != build_genome_evaluation(tuple(sources)):
        raise RuntimeError("CACIS W5 genome evaluation is not deterministic.")
    adversarial_count = 0
    mutations: tuple[tuple[str, Callable[[JsonObject], None]], ...] = (
        ("authority widening", lambda value: cast(JsonObject, cast(JsonObject, value["genome"])["authority"]).__setitem__("can_execute", True)),
        ("memory stratum removal", lambda value: cast(list[object], cast(JsonObject, value["genome"])["memory_strata"]).pop()),
        ("raw evidence retention", lambda value: cast(JsonObject, cast(list[JsonObject], cast(JsonObject, value["genome"])["memory_strata"])[0]).__setitem__("raw_evidence_retained", True)),
        ("private answer exposure", lambda value: cast(list[JsonObject], cast(JsonObject, value["genome"])["evaluation_partitions"])[1].__setitem__("candidate_answer_visibility", True)),
        ("external origin laundering", lambda value: cast(list[JsonObject], cast(JsonObject, value["genome"])["evaluation_partitions"])[2].__setitem__("origin", "external")),
        ("reward defense removal", lambda value: cast(list[object], cast(JsonObject, value["genome"])["reward_hacking_checks"]).pop()),
        ("complexity failure suppression", lambda value: cast(list[JsonObject], cast(JsonObject, cast(JsonObject, value["genome"])["complexity_gate"])["metrics"])[0].__setitem__("observed", 33)),
        ("semantic replay removal", lambda value: cast(JsonObject, cast(JsonObject, value["genome"])["distillation"]).__setitem__("semantic_replay_preserved", False)),
        ("promotion fabrication", lambda value: cast(JsonObject, cast(JsonObject, value["genome"])["settlement"]).__setitem__("promotion_authorized", True)),
        ("external replication fabrication", lambda value: cast(JsonObject, cast(JsonObject, value["genome"])["settlement"]).__setitem__("external_replication_performed", True)),
    )
    for label, mutation in mutations:
        candidate = copy.deepcopy(generated)
        mutation(candidate)
        candidate["genome_digest"] = sha256_digest(cast(JsonObject, candidate["genome"]))
        expect_error(lambda candidate=candidate: validate_genome_evaluation(candidate, sources), label)
        adversarial_count += 1
    body = cast(JsonObject, generated["genome"])
    return {
        "status": "CACIS_GENOME_EVALUATION_W5_REPLAY_VALID_CANDIDATE_ONLY",
        "genome_digest": generated["genome_digest"],
        "memory_stratum_count": len(cast(list[object], body["memory_strata"])),
        "evaluation_partition_count": len(cast(list[object], body["evaluation_partitions"])),
        "reward_hacking_defense_count": len(cast(list[object], body["reward_hacking_checks"])),
        "complexity_metric_count": len(cast(list[object], cast(JsonObject, body["complexity_gate"])["metrics"])),
        "negative_fail_closed_case_count": adversarial_count,
        "distillation_replay_preserved": True,
        "candidate_status": "candidate_only",
        "external_replication_performed": False,
        "promotion_authorized": False,
        "execution_authorized": False,
        "execution_performed": False,
    }


def main() -> None:
    project_root = Path(__file__).resolve().parents[1]
    result = validate_genome(project_root)
    report_path = project_root / "reports" / "CACIS_GENOME_EVALUATION_VALIDATION.json"
    report_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
