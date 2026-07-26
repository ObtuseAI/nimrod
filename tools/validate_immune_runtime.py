"""Validate the replay-only CACIS W2 immune-organism lifecycle."""

from __future__ import annotations

import copy
import json
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import cast

from nimrod_cacis.immune_runtime import (
    build_immune_organism_lifecycle_receipt,
    validate_immune_organism_lifecycle_receipt,
    validate_immune_organism_mission,
)
from nimrod_cacis.immune_runtime_cli import run_immune_replay
from nimrod_simulator.errors import ImmuneRuntimeError
from nimrod_simulator.jsonio import read_json_object, sha256_digest, validate_contract
from nimrod_simulator.model import JsonObject


Mutation = Callable[[JsonObject], None]


def expect_runtime_error(label: str, operation: Callable[[], object]) -> None:
    try:
        operation()
    except ImmuneRuntimeError:
        return
    raise RuntimeError(f"Expected ImmuneRuntimeError for {label}.")


def mission_object(value: JsonObject, field: str) -> JsonObject:
    return cast(JsonObject, value[field])


def mission_cells(value: JsonObject) -> list[JsonObject]:
    return cast(list[JsonObject], value["cells"])


def receipt_body(value: JsonObject) -> JsonObject:
    return cast(JsonObject, value["receipt"])


def receipt_events(value: JsonObject) -> list[JsonObject]:
    return cast(list[JsonObject], receipt_body(value)["events"])


def receipt_contributions(value: JsonObject) -> list[JsonObject]:
    return cast(list[JsonObject], receipt_body(value)["contributions"])


def build_mission_case(mission: JsonObject, world: JsonObject, mutation: Mutation) -> Callable[[], object]:
    def operation() -> object:
        candidate = copy.deepcopy(mission)
        mutation(candidate)
        validate_immune_organism_mission(candidate)
        return build_immune_organism_lifecycle_receipt(candidate, world)

    return operation


def build_receipt_case(document: JsonObject, mission: JsonObject, mutation: Mutation) -> Callable[[], object]:
    def operation() -> object:
        candidate = copy.deepcopy(document)
        original_digest = candidate["receipt_digest"]
        mutation(candidate)
        if candidate["receipt_digest"] == original_digest:
            candidate["receipt_digest"] = sha256_digest(receipt_body(candidate))
        validate_immune_organism_lifecycle_receipt(candidate, mission)
        return candidate

    return operation


def validate_cli(project_root: Path, mission_path: Path, world_path: Path, expected: JsonObject) -> bool:
    with tempfile.TemporaryDirectory(prefix="nimrod-cacis-immune-") as temporary:
        output_path = Path(temporary) / "lifecycle-receipt.json"
        result = run_immune_replay(project_root, mission_path, world_path, output_path)
        restored = read_json_object(output_path)
        if restored != expected:
            raise RuntimeError("CACIS W2 CLI output differs from the deterministic lifecycle receipt.")
        if result.get("lifecycle_state") != "disposed" or result.get("execution_performed") is not False:
            raise RuntimeError(f"CACIS W2 CLI summary widened lifecycle or execution state: result={result!r}.")
    return True


def validate_immune_runtime(project_root: Path) -> JsonObject:
    mission_path = project_root / "specs" / "examples" / "immune-organism-mission.example.json"
    world_path = project_root / "specs" / "examples" / "world-model-generation.example.json"
    expected_path = project_root / "specs" / "examples" / "immune-organism-lifecycle-receipt.example.json"
    mission = read_json_object(mission_path)
    world = read_json_object(world_path)
    expected = read_json_object(expected_path)
    validate_contract(
        mission,
        project_root / "specs" / "immune-organism-mission.schema.json",
        "CACIS W2 immune mission",
    )
    validate_immune_organism_mission(mission)
    generated = build_immune_organism_lifecycle_receipt(mission, world)
    validate_contract(
        generated,
        project_root / "specs" / "immune-organism-lifecycle-receipt.schema.json",
        "CACIS W2 lifecycle receipt",
    )
    validate_immune_organism_lifecycle_receipt(generated, mission)
    if generated != expected or generated != build_immune_organism_lifecycle_receipt(copy.deepcopy(mission), copy.deepcopy(world)):
        raise RuntimeError("CACIS W2 lifecycle replay is not deterministic or differs from its canonical example.")
    cli_verified = validate_cli(project_root, mission_path, world_path, expected)
    suspicious_mission_path = project_root / "tests" / "fixtures" / "cacis" / "immune-organism-mission-suspicious-script.json"
    suspicious_mission = read_json_object(suspicious_mission_path)
    validate_contract(
        suspicious_mission,
        project_root / "specs" / "immune-organism-mission.schema.json",
        "CACIS W2 suspicious-script immune mission",
    )
    suspicious_receipt = build_immune_organism_lifecycle_receipt(suspicious_mission, world)
    validate_contract(
        suspicious_receipt,
        project_root / "specs" / "immune-organism-lifecycle-receipt.schema.json",
        "CACIS W2 suspicious-script lifecycle receipt",
    )
    validate_immune_organism_lifecycle_receipt(suspicious_receipt, suspicious_mission)
    suspicious_body = receipt_body(suspicious_receipt)
    suspicious_roles = {str(item["role"]) for item in receipt_contributions(suspicious_receipt)}
    required_suspicious_roles = {
        "script_analysis",
        "memory_analysis",
        "behavior",
        "identity",
        "network",
        "containment",
        "recovery",
        "evidence",
        "historian",
    }
    if suspicious_roles != required_suspicious_roles:
        raise RuntimeError(f"CACIS W2 suspicious-script morphology is incomplete: roles={sorted(suspicious_roles)!r}.")
    if len([item for item in receipt_contributions(suspicious_receipt) if item["status"] == "abstained"]) != 2:
        raise RuntimeError("CACIS W2 suspicious-script morphology must preserve containment and recovery abstention.")

    mission_cases: tuple[tuple[str, Mutation], ...] = (
        ("mission execution authority", lambda value: mission_object(value, "authority").__setitem__("can_execute", True)),
        ("Governor authorization", lambda value: mission_object(value, "governor").__setitem__("can_authorize", True)),
        ("capability allowlist removal", lambda value: cast(list[str], mission_object(value, "capability_lease")["allowed_capabilities"]).pop()),
        ("capability denylist removal", lambda value: cast(list[str], mission_object(value, "capability_lease")["prohibited_capabilities"]).pop()),
        ("ambient credential widening", lambda value: mission_object(value, "capability_lease").__setitem__("ambient_credentials_allowed", True)),
        ("raw-command bridge widening", lambda value: mission_object(value, "capability_lease").__setitem__("raw_command_bridge_allowed", True)),
        ("cell execution authority", lambda value: mission_cells(value)[0].__setitem__("can_execute", True)),
        ("cell self verification", lambda value: mission_cells(value)[0].__setitem__("can_self_verify", True)),
        ("duplicate cell identity", lambda value: mission_cells(value)[1].__setitem__("cell_id", mission_cells(value)[0]["cell_id"])),
        ("duplicate cell role", lambda value: mission_cells(value)[1].__setitem__("role", mission_cells(value)[0]["role"])),
        ("missing Shadow", lambda value: mission_cells(value).pop()),
        ("Shadow identity substitution", lambda value: mission_object(value, "shadow_policy").__setitem__("shadow_cell_id", mission_cells(value)[0]["cell_id"])),
        ("Shadow control removal", lambda value: cast(list[str], mission_object(value, "shadow_policy")["allowed_controls"]).pop()),
        ("termination trigger removal", lambda value: cast(list[str], mission_object(value, "shadow_policy")["automatic_termination_triggers"]).pop()),
        ("resource expiry mismatch", lambda value: mission_object(value, "resource_lease").__setitem__("expires_at", "2026-07-15T06:09:00Z")),
        ("mission interval reversal", lambda value: value.__setitem__("expires_at", "2026-07-15T06:04:00Z")),
        ("model-call allocation", lambda value: mission_object(value, "resource_lease").__setitem__("model_calls", 1)),
        ("sandbox allocation", lambda value: mission_object(value, "resource_lease").__setitem__("sandbox_runs", 1)),
        ("live-origin laundering", lambda value: value.__setitem__("origin", "live")),
        ("outcome widening", lambda value: value.__setitem__("maximum_outcome", "verified_action")),
        ("generation substitution", lambda value: value.__setitem__("world_model_generation_digest", "sha256:" + "1" * 64)),
    )
    negative_count = 0
    for label, mutation in mission_cases:
        expect_runtime_error(label, build_mission_case(mission, world, mutation))
        negative_count += 1

    receipt_cases: tuple[tuple[str, Mutation], ...] = (
        ("receipt digest substitution", lambda value: value.__setitem__("receipt_digest", "sha256:" + "0" * 64)),
        ("mission binding substitution", lambda value: receipt_body(value).__setitem__("mission_digest", "sha256:" + "2" * 64)),
        ("generation binding substitution", lambda value: receipt_body(value).__setitem__("world_model_generation_digest", "sha256:" + "3" * 64)),
        ("receipt execution authority", lambda value: cast(JsonObject, receipt_body(value)["authority"]).__setitem__("can_execute", True)),
        ("security claim widening", lambda value: receipt_body(value).__setitem__("security_claim", "verified production defense")),
        ("terminal reason laundering", lambda value: receipt_body(value).__setitem__("terminal_reason", "mission_complete")),
        ("event sequence gap", lambda value: receipt_events(value)[1].__setitem__("sequence", 9)),
        ("event parent substitution", lambda value: receipt_events(value)[1].__setitem__("parent_event_digest", "sha256:" + "4" * 64)),
        ("event timestamp rollback", lambda value: receipt_events(value)[1].__setitem__("timestamp", receipt_events(value)[0]["timestamp"])),
        ("pause removal", lambda value: receipt_events(value)[2].__setitem__("event_type", "contribution_emitted")),
        ("abstention removal", lambda value: [item.__setitem__("status", "proposed") for item in receipt_contributions(value)]),
        ("unknown contribution cell", lambda value: receipt_contributions(value)[0].__setitem__("cell_id", "72000000-0000-4000-8000-000000009999")),
        ("contribution self verification", lambda value: receipt_contributions(value)[0].__setitem__("can_verify", True)),
        ("contribution generation substitution", lambda value: receipt_contributions(value)[0].__setitem__("parent_generation_digest", "sha256:" + "5" * 64)),
        ("duplicate contribution", lambda value: receipt_contributions(value)[1].__setitem__("contribution_id", receipt_contributions(value)[0]["contribution_id"])),
        ("CPU lease overrun", lambda value: cast(JsonObject, receipt_body(value)["resource_usage"]).__setitem__("cpu_millis", 501)),
        ("memory lease overrun", lambda value: cast(JsonObject, receipt_body(value)["resource_usage"]).__setitem__("peak_memory_mb", 65)),
        ("incomplete cell termination", lambda value: cast(JsonObject, receipt_body(value)["termination"]).__setitem__("all_cells_terminated", False)),
        ("scratch retention", lambda value: cast(JsonObject, receipt_body(value)["termination"]).__setitem__("scratch_state_destroyed", False)),
        ("credential issuance laundering", lambda value: cast(JsonObject, receipt_body(value)["termination"]).__setitem__("credentials_issued", True)),
        ("target contact laundering", lambda value: cast(JsonObject, receipt_body(value)["termination"]).__setitem__("target_contact_performed", True)),
        ("execution laundering", lambda value: cast(JsonObject, receipt_body(value)["termination"]).__setitem__("execution_performed", True)),
        ("raw context retention", lambda value: cast(JsonObject, receipt_body(value)["retained_knowledge"]).__setitem__("raw_context_retained", True)),
        ("knowledge authority retention", lambda value: cast(JsonObject, receipt_body(value)["retained_knowledge"]).__setitem__("authority_retained", True)),
        ("knowledge promotion", lambda value: cast(list[JsonObject], cast(JsonObject, receipt_body(value)["retained_knowledge"])["entries"])[0].__setitem__("status", "promoted")),
        ("knowledge source substitution", lambda value: cast(list[JsonObject], cast(JsonObject, receipt_body(value)["retained_knowledge"])["entries"])[0].__setitem__("source_contribution_id", "72000000-0000-4000-8000-000000009998")),
        ("self-verification laundering", lambda value: cast(JsonObject, receipt_body(value)["independent_verification"]).__setitem__("performed", True)),
        ("verifier identity fabrication", lambda value: cast(JsonObject, receipt_body(value)["independent_verification"]).__setitem__("verifier_identity", "organism:self")),
    )
    for label, mutation in receipt_cases:
        expect_runtime_error(label, build_receipt_case(generated, mission, mutation))
        negative_count += 1

    receipt = receipt_body(generated)
    termination = cast(JsonObject, receipt["termination"])
    retained = cast(JsonObject, receipt["retained_knowledge"])
    result: JsonObject = {
        "status": "CACIS_IMMUNE_RUNTIME_W2_REPLAY_VALID_PROPOSAL_ONLY",
        "origin": "replayed",
        "mission_digest": sha256_digest(mission),
        "receipt_digest": generated["receipt_digest"],
        "suspicious_script_receipt_digest": suspicious_receipt["receipt_digest"],
        "world_model_generation_digest": receipt["world_model_generation_digest"],
        "cell_count": len(mission_cells(mission)),
        "event_count": len(receipt_events(generated)),
        "contribution_count": len(receipt_contributions(generated)),
        "abstention_count": len([item for item in receipt_contributions(generated) if item["status"] == "abstained"]),
        "retained_knowledge_count": len(cast(list[object], retained["entries"])),
        "suspicious_script_cell_count": suspicious_body["cell_count"],
        "suspicious_script_contribution_count": len(receipt_contributions(suspicious_receipt)),
        "suspicious_script_abstention_count": 2,
        "suspicious_script_morphology_verified": True,
        "negative_fail_closed_case_count": negative_count,
        "deterministic_replay_verified": True,
        "cli_replay_verified": cli_verified,
        "shadow_pause_verified": True,
        "shadow_resume_verified": True,
        "shadow_termination_verified": receipt["terminal_reason"] == "shadow_terminated",
        "resource_lease_enforced": True,
        "capability_lease_enforced": True,
        "all_cells_terminated": termination["all_cells_terminated"],
        "scratch_state_destroyed": termination["scratch_state_destroyed"],
        "leases_revoked": termination["capability_lease_revoked"] and termination["resource_lease_revoked"],
        "independent_verification_performed": False,
        "live_sensing_performed": False,
        "execution_authorized": False,
        "execution_performed": False,
        "target_contact_performed": False,
        "production_truth_claimed": False,
    }
    return result


def main() -> None:
    project_root = Path(__file__).resolve().parents[1]
    result = validate_immune_runtime(project_root)
    report_path = project_root / "reports" / "CACIS_IMMUNE_RUNTIME_VALIDATION.json"
    report_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
