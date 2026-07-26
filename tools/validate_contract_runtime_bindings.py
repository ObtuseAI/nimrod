"""Validate the six weakest contract-to-runtime bindings with independent semantics."""

from __future__ import annotations

import copy
import json
from collections.abc import Callable
from pathlib import Path
from typing import cast

from nimrod_simulator.errors import ProtectionProfileError, SimulatorError
from nimrod_simulator.evolution_foundry import validate_epistemic_posture
from nimrod_simulator.jsonio import read_json_object, validate_contract
from nimrod_simulator.model import JsonObject
from nimrod_simulator.protection_profile import validate_protection_profile


CONTRACTS: tuple[tuple[str, str], ...] = (
    ("action-and-evidence-envelope.schema.json", "action-envelope.example.json"),
    ("causal-coverage-verdict.schema.json", "causal-coverage-verdict.example.json"),
    ("epistemic-posture.schema.json", "epistemic-posture.example.json"),
    ("evolution-baseline.schema.json", "evolution-baseline.example.json"),
    ("protection-profile.schema.json", "protection-profile.example.json"),
    ("swarm-verdict.schema.json", "swarm-verdict.example.json"),
)


def _raise(message: str) -> None:
    raise SimulatorError(message)


def _validate_action(value: JsonObject) -> None:
    authorization = value.get("authorization")
    if (
        value.get("origin") != "simulated"
        or not isinstance(authorization, dict)
        or authorization.get("policy_decision") != "deny"
        or value.get("signatures") != []
        or "execution" in value
    ):
        _raise("Action envelope widened origin, authorization, or execution state.")


def _validate_causal(value: JsonObject) -> None:
    chain = value.get("causal_chain")
    if value.get("origin") != "simulated" or value.get("status") != "inconclusive_timeout" or not isinstance(chain, dict):
        _raise("Causal verdict laundered a planning fixture into a successful outcome.")
    if any(chain.get(field) is not None for field in ("attempt", "state_delta", "observation", "detection", "response", "recovery", "post_state")):
        _raise("Causal verdict fabricated an unobserved causal stage.")


def _validate_baseline(value: JsonObject) -> None:
    authority = value.get("authority")
    if (
        value.get("origin") != "simulated"
        or value.get("active") is not True
        or not isinstance(authority, dict)
        or authority != {"candidate_write_permitted": False, "can_execute": False}
    ):
        _raise("Evolution baseline widened candidate-write or execution authority.")


def _validate_swarm(value: JsonObject) -> None:
    authority = value.get("authority")
    contributions = value.get("contributions")
    if (
        value.get("origin") != "simulated"
        or value.get("status") != "proposal_ready"
        or not isinstance(authority, dict)
        or authority.get("execution_authorized") is not False
        or authority.get("maximum_outcome") != "typed_proposal"
        or not isinstance(contributions, list)
        or not any(isinstance(item, dict) and item.get("stance") == "abstain" for item in contributions)
    ):
        _raise("Swarm verdict removed proposal-only authority or required abstention.")


def _expect_error(operation: Callable[[], object], label: str) -> None:
    try:
        operation()
    except (SimulatorError, ProtectionProfileError):
        return
    raise RuntimeError(f"Expected fail-closed error for {label}.")


def validate_bindings(project_root: Path) -> JsonObject:
    specs_root = project_root / "specs"
    examples_root = specs_root / "examples"
    documents: dict[str, JsonObject] = {}
    for schema_name, example_name in CONTRACTS:
        document = read_json_object(examples_root / example_name)
        validate_contract(document, specs_root / schema_name, example_name)
        documents[schema_name] = document
    _validate_action(documents["action-and-evidence-envelope.schema.json"])
    _validate_causal(documents["causal-coverage-verdict.schema.json"])
    validate_epistemic_posture(documents["epistemic-posture.schema.json"])
    _validate_baseline(documents["evolution-baseline.schema.json"])
    validate_protection_profile(documents["protection-profile.schema.json"])
    _validate_swarm(documents["swarm-verdict.schema.json"])

    mutations: tuple[tuple[str, str, Callable[[JsonObject], None], Callable[[JsonObject], None]], ...] = (
        ("action execution", "action-and-evidence-envelope.schema.json", lambda value: value.__setitem__("execution", {"performed": True}), _validate_action),
        ("action authorization", "action-and-evidence-envelope.schema.json", lambda value: cast(JsonObject, value["authorization"]).__setitem__("policy_decision", "allow"), _validate_action),
        ("causal success", "causal-coverage-verdict.schema.json", lambda value: value.__setitem__("status", "pass"), _validate_causal),
        ("causal observation", "causal-coverage-verdict.schema.json", lambda value: cast(JsonObject, value["causal_chain"]).__setitem__("observation", {"id": "fabricated"}), _validate_causal),
        ("posture authority", "epistemic-posture.schema.json", lambda value: cast(JsonObject, value["authority"]).__setitem__("can_waive_hard_failures", True), validate_epistemic_posture),
        ("baseline write", "evolution-baseline.schema.json", lambda value: cast(JsonObject, value["authority"]).__setitem__("candidate_write_permitted", True), _validate_baseline),
        ("profile raw export", "protection-profile.schema.json", lambda value: cast(JsonObject, value["data_policy"]).__setitem__("raw_export_allowed", True), validate_protection_profile),
        ("profile no interlock", "protection-profile.schema.json", lambda value: value.__setitem__("safety_interlocks", []), validate_protection_profile),
        ("profile no oracle", "protection-profile.schema.json", lambda value: value.__setitem__("oracles", []), validate_protection_profile),
        ("profile no snapshot", "protection-profile.schema.json", lambda value: cast(JsonObject, value["recovery"]).__setitem__("snapshot_required", False), validate_protection_profile),
        ("swarm execution", "swarm-verdict.schema.json", lambda value: cast(JsonObject, value["authority"]).__setitem__("execution_authorized", True), _validate_swarm),
        ("swarm abstention removal", "swarm-verdict.schema.json", lambda value: [item.__setitem__("stance", "support") for item in cast(list[JsonObject], value["contributions"]) if item.get("stance") == "abstain"], _validate_swarm),
    )
    for label, schema_name, mutate, validator in mutations:
        candidate = copy.deepcopy(documents[schema_name])
        mutate(candidate)
        _expect_error(lambda candidate=candidate, validator=validator: validator(candidate), label)
    return {
        "status": "SIX_CONTRACT_RUNTIME_BINDINGS_VALID_PRODUCTION_EVIDENCE_BLOCKED",
        "contract_count": len(CONTRACTS),
        "semantic_binding_count": len(CONTRACTS),
        "negative_fail_closed_case_count": len(mutations),
        "live_runtime_evidence_present": False,
        "production_conformance_claimed": False,
        "execution_authorized": False,
        "execution_performed": False,
    }


def main() -> None:
    project_root = Path(__file__).resolve().parents[1]
    result = validate_bindings(project_root)
    report_path = project_root / "reports" / "CONTRACT_RUNTIME_BINDINGS_VALIDATION.json"
    report_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
