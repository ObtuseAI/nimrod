"""Audit locally achievable roadmap completion and preserve external blockers."""

from __future__ import annotations

import copy
import json
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import cast

from nimrod_simulator.errors import SimulatorError
from nimrod_simulator.jsonio import read_json_object, sha256_digest
from nimrod_simulator.model import JsonObject, JsonValue


LOCAL_GATES: tuple[tuple[str, str, Mapping[str, JsonValue]], ...] = (
    ("constitutional_roadmap", "CACIS_ROADMAP_VALIDATION.json", {"status": "CACIS_ROADMAP_CONTRACT_VALID_IMPLEMENTATION_GATED", "implementation_wave_count": 8, "authority_change": "none"}),
    ("contract_system", "CONTRACT_CONFORMANCE_MATRIX.json", {"contract_count": 97, "schema_validated_count": 97, "semantic_validator_count": 97, "independent_harness_reference_count": 97, "live_runtime_evidence_count": 0}),
    ("distribution", "DISTRIBUTION_VALIDATION.json", {"status": "DISTRIBUTION_WHEEL_CONTENT_VALID", "missing_package_count": 0, "missing_command_module_count": 0, "distribution_published": False}),
    ("world_model", "CACIS_WORLD_MODEL_VALIDATION.json", {"status": "CACIS_WORLD_MODEL_W1_REPLAY_VALID_NON_AUTHORIZING", "policy_input_ready": False, "execution_performed": False}),
    ("governed_world_intake", "CACIS_WORLD_INTAKE_GOVERNANCE_VALIDATION.json", {"status": "CACIS_WORLD_INTAKE_GOVERNANCE_REPLAY_VALID_LIVE_ADMISSION_BLOCKED", "dropped_event_count": 0, "live_sensor_admission_authorized": False}),
    ("immune_runtime", "CACIS_IMMUNE_RUNTIME_VALIDATION.json", {"status": "CACIS_IMMUNE_RUNTIME_W2_REPLAY_VALID_PROPOSAL_ONLY", "execution_authorized": False, "target_contact_performed": False}),
    ("intelligence_research", "INTELLIGENCE_RESEARCH_VALIDATION.json", {"status": "INTELLIGENCE_RESEARCH_W3_REPLAY_VALID_CANDIDATE_THEORY_ONLY", "generalization_allowed": False, "promotion_authorized": False}),
    ("homeostasis_chronos", "CACIS_HOMEOSTASIS_CHRONOS_VALIDATION.json", {"status": "CACIS_W4_HOMEOSTASIS_CHRONOS_REPLAY_VALID_SCHEDULE_PROPOSAL_ONLY", "execution_authorized": False}),
    ("genome_evaluation", "CACIS_GENOME_EVALUATION_VALIDATION.json", {"status": "CACIS_GENOME_EVALUATION_W5_REPLAY_VALID_CANDIDATE_ONLY", "promotion_authorized": False, "external_replication_performed": False}),
    ("autonomous_threshold_promotion", "AUTONOMOUS_PROMOTION_VALIDATION.json", {"status": "AUTONOMOUS_THRESHOLD_PROMOTION_REPLAY_VALID_SHADOW_AND_DEMOTION_ONLY", "autonomous_promotion_standard": True, "human_approval_required_for_eligible_tiers": False, "production_promotion_authorized": False}),
    ("arenas_observatory", "CACIS_ARENAS_OBSERVATORY_VALIDATION.json", {"status": "CACIS_ARENAS_OBSERVATORY_W6_REPLAY_VALID_DISPLAY_ONLY", "arena_count": 15, "evaluated_arena_count": 15, "live_range_connected": False}),
    ("continuous_defensive_observation", "EDGE_CONTINUOUS_OBSERVATION_VALIDATION.json", {"status": "EDGE_CONTINUOUS_DEFENSIVE_OBSERVATION_VALID_POLICY_AND_ACTION_BLOCKED", "policy_input_ready": False, "execution_performed": False}),
    ("control_board", "CONTROL_BOARD_VALIDATION.json", {"status": "CONTROL_BOARD_SIGNED_INGRESS_INTEGRATION_VALID", "execution_authorized": False, "live_execution_performed": False}),
    ("release_trust", "RELEASE_FOUNDATION_VALIDATION.json", {"status": "EDGE_UPDATE_AND_PLUGIN_TRUST_FOUNDATION_VALID_INSTALLATION_BLOCKED", "installation_authorized": False, "installation_performed": False}),
    ("verifier_identity_readiness", "VERIFIER_IDENTITY_READINESS_VALIDATION.json", {"status": "LIVE_IDENTITY_OBSERVED_DEDICATED_ACCOUNT_CUSTODY_AND_EGRESS_BLOCKED", "surface_count": 3, "production_eligible_count": 0}),
)

EXTERNAL_GATES: tuple[tuple[str, str, Mapping[str, JsonValue], str], ...] = (
    ("design_partner_validation", "DESIGN_PARTNER_KIT_VALIDATION.json", {"actual_participant_count": 0, "participant_contacted": False}, "Requires real external participants and consented evaluation."),
    ("production_custody", "WINDOWS_CUSTODY_READINESS_VALIDATION.json", {"production_custody_verified": False, "signing_operation_performed": False}, "Requires independently administered hardware-backed signing custody."),
    ("construction_zone", "CONSTRUCTION_ZONE_PROVISIONING_GATE_VALIDATION.json", {"provisioning_authorized": False, "provisioning_performed": False, "verified_control_count": 0}, "Requires owner-selected provider, accounts, credentials, budget, and independent attestations."),
    ("range_execution", "RANGE_EXECUTION_GATE_VALIDATION.json", {"range_connection_authorized": False, "live_execution_performed": False, "real_environment_attestation_count": 0}, "Requires an owner-controlled disposable range and nine real environment attestations."),
    ("range_completion", "RANGE_EVIDENCE_COMPLETION_VALIDATION.json", {"completion_authorized": False, "accepted_control_count": 0, "real_independent_verifier_count": 0}, "Requires real cleanup, recovery, independent post-state, and evidence acceptance."),
    ("production_release", "RELEASE_FOUNDATION_VALIDATION.json", {"installation_authorized": False, "installation_performed": False}, "Requires signed production custody and an owner-approved staged rollout."),
)


def _require_fields(document: JsonObject, expected: Mapping[str, JsonValue], label: str) -> None:
    mismatches = [f"{field}={document.get(field)!r}, expected={value!r}" for field, value in expected.items() if document.get(field) != value]
    if mismatches:
        raise SimulatorError(f"Completion audit gate '{label}' failed: {'; '.join(mismatches)}.")


def build_completion_audit(project_root: Path) -> JsonObject:
    reports_root = project_root / "reports"
    local_rows: list[JsonObject] = []
    for gate_id, report_name, expected in LOCAL_GATES:
        document = read_json_object(reports_root / report_name)
        _require_fields(document, expected, gate_id)
        local_rows.append({"gate_id": gate_id, "state": "complete_local_evidence", "report": report_name, "report_digest": sha256_digest(document)})
    external_rows: list[JsonObject] = []
    for gate_id, report_name, expected, requirement in EXTERNAL_GATES:
        document = read_json_object(reports_root / report_name)
        _require_fields(document, expected, gate_id)
        external_rows.append({"gate_id": gate_id, "state": "blocked_external_evidence_required", "report": report_name, "report_digest": sha256_digest(document), "requirement": requirement})
    audit: JsonObject = {
        "audit_version": "0.1.0",
        "status": "LOCAL_ROADMAP_COMPLETE_EXTERNAL_OPERATIONAL_GATES_BLOCKED",
        "local_gates": local_rows,
        "external_gates": external_rows,
        "summary": {
            "local_gate_count": len(local_rows),
            "local_gate_complete_count": len(local_rows),
            "external_gate_count": len(external_rows),
            "external_gate_blocked_count": len(external_rows),
            "deployable_product_claimed": False,
            "production_protection_claimed": False,
            "execution_authorized": False,
            "execution_performed": False,
        },
        "authority": {"can_authorize": False, "can_execute": False, "can_clear_external_gate": False, "can_claim_production": False},
    }
    validate_completion_audit(audit)
    return audit


def validate_completion_audit(audit: JsonObject) -> None:
    if audit.get("audit_version") != "0.1.0" or audit.get("status") != "LOCAL_ROADMAP_COMPLETE_EXTERNAL_OPERATIONAL_GATES_BLOCKED":
        raise SimulatorError("Completion audit identity or status is invalid.")
    local_rows = audit.get("local_gates")
    external_rows = audit.get("external_gates")
    if not isinstance(local_rows, list) or [row.get("gate_id") for row in local_rows if isinstance(row, dict)] != [gate[0] for gate in LOCAL_GATES]:
        raise SimulatorError("Completion audit local gates are incomplete or reordered.")
    if not isinstance(external_rows, list) or [row.get("gate_id") for row in external_rows if isinstance(row, dict)] != [gate[0] for gate in EXTERNAL_GATES]:
        raise SimulatorError("Completion audit external gates are incomplete or reordered.")
    if any(not isinstance(row, dict) or row.get("state") != "complete_local_evidence" for row in local_rows):
        raise SimulatorError("Completion audit downgraded or fabricated a local gate state.")
    if any(not isinstance(row, dict) or row.get("state") != "blocked_external_evidence_required" or not row.get("requirement") for row in external_rows):
        raise SimulatorError("Completion audit hid an external blocker.")
    summary = audit.get("summary")
    if not isinstance(summary, dict) or summary != {
        "local_gate_count": len(LOCAL_GATES),
        "local_gate_complete_count": len(LOCAL_GATES),
        "external_gate_count": len(EXTERNAL_GATES),
        "external_gate_blocked_count": len(EXTERNAL_GATES),
        "deployable_product_claimed": False,
        "production_protection_claimed": False,
        "execution_authorized": False,
        "execution_performed": False,
    }:
        raise SimulatorError("Completion audit summary contradicts its bounded evidence.")
    authority = audit.get("authority")
    if not isinstance(authority, dict) or any(value is not False for value in authority.values()):
        raise SimulatorError("Completion audit widened authority.")


def _expect_error(operation: Callable[[], object], label: str) -> None:
    try:
        operation()
    except SimulatorError:
        return
    raise RuntimeError(f"Expected SimulatorError for {label}.")


def validate_audit(project_root: Path) -> JsonObject:
    audit = build_completion_audit(project_root)
    mutations: tuple[tuple[str, Callable[[JsonObject], None]], ...] = (
        ("local gate removal", lambda value: cast(list[object], value["local_gates"]).pop()),
        ("external gate removal", lambda value: cast(list[object], value["external_gates"]).pop()),
        ("external blocker laundering", lambda value: cast(JsonObject, cast(list[object], value["external_gates"])[0]).__setitem__("state", "complete")),
        ("external requirement removal", lambda value: cast(JsonObject, cast(list[object], value["external_gates"])[0]).__setitem__("requirement", "")),
        ("deployable claim", lambda value: cast(JsonObject, value["summary"]).__setitem__("deployable_product_claimed", True)),
        ("protection claim", lambda value: cast(JsonObject, value["summary"]).__setitem__("production_protection_claimed", True)),
        ("execution claim", lambda value: cast(JsonObject, value["summary"]).__setitem__("execution_performed", True)),
        ("authority widening", lambda value: cast(JsonObject, value["authority"]).__setitem__("can_authorize", True)),
        ("status widening", lambda value: value.__setitem__("status", "PRODUCTION_COMPLETE")),
        ("local count inflation", lambda value: cast(JsonObject, value["summary"]).__setitem__("local_gate_complete_count", len(LOCAL_GATES) + 1)),
    )
    for label, mutate in mutations:
        candidate = copy.deepcopy(audit)
        mutate(candidate)
        _expect_error(lambda candidate=candidate: validate_completion_audit(candidate), label)
    summary = cast(JsonObject, audit["summary"])
    return {
        "status": audit["status"],
        "local_gate_count": summary["local_gate_count"],
        "local_gate_complete_count": summary["local_gate_complete_count"],
        "external_gate_count": summary["external_gate_count"],
        "external_gate_blocked_count": summary["external_gate_blocked_count"],
        "negative_fail_closed_case_count": len(mutations),
        "deployable_product_claimed": False,
        "production_protection_claimed": False,
        "execution_authorized": False,
        "execution_performed": False,
        "audit": audit,
    }


def main() -> None:
    project_root = Path(__file__).resolve().parents[1]
    result = validate_audit(project_root)
    report_path = project_root / "reports" / "COMPLETION_AUDIT.json"
    report_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({key: value for key, value in result.items() if key != "audit"}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
