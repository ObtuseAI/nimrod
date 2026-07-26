"""Validate the fail-closed Edge design-partner evidence plan."""

from __future__ import annotations

import copy
import json
from collections.abc import Callable
from pathlib import Path
from typing import TypeVar

from nimrod_edge.design_partner import validate_design_partner_plan
from nimrod_simulator.errors import DesignPartnerPlanError
from nimrod_simulator.jsonio import read_json_object, validate_contract
from nimrod_simulator.model import JsonObject


TError = TypeVar("TError", bound=Exception)


def expect_error(
    error_type: type[TError],
    operation: Callable[[], object],
    label: str,
) -> None:
    try:
        operation()
    except error_type:
        return
    raise RuntimeError(f"Expected {error_type.__name__} for {label}.")


def validate_design_partner_kit(project_root: Path) -> JsonObject:
    plan = read_json_object(
        project_root / "specs" / "examples" / "design-partner-evaluation-plan.example.json"
    )
    validate_contract(
        plan,
        project_root / "specs" / "design-partner-evaluation-plan.schema.json",
        "Edge design-partner evaluation plan",
    )
    validate_design_partner_plan(plan)
    adversarial_count = 0

    fabricated_participant = copy.deepcopy(plan)
    fabricated_participant["cohort"]["participants"] = ["participant:fake"]
    fabricated_participant["cohort"]["participant_count"] = 1
    expect_error(
        DesignPartnerPlanError,
        lambda: validate_design_partner_plan(fabricated_participant),
        "fabricated participant",
    )
    adversarial_count += 1
    fabricated_contact = copy.deepcopy(plan)
    fabricated_contact["activity"]["participant_contacted"] = True
    expect_error(
        DesignPartnerPlanError,
        lambda: validate_design_partner_plan(fabricated_contact),
        "fabricated participant contact",
    )
    adversarial_count += 1
    raw_collection = copy.deepcopy(plan)
    raw_collection["data_boundary"]["raw_endpoint_telemetry_collected"] = True
    expect_error(
        DesignPartnerPlanError,
        lambda: validate_design_partner_plan(raw_collection),
        "raw endpoint collection",
    )
    adversarial_count += 1
    missing_consent = copy.deepcopy(plan)
    missing_consent["data_boundary"]["explicit_consent_required"] = False
    expect_error(
        DesignPartnerPlanError,
        lambda: validate_design_partner_plan(missing_consent),
        "consent removal",
    )
    adversarial_count += 1
    missing_task = copy.deepcopy(plan)
    missing_task["tasks"].pop()
    expect_error(
        DesignPartnerPlanError,
        lambda: validate_design_partner_plan(missing_task),
        "evaluation task removal",
    )
    adversarial_count += 1
    false_exit = copy.deepcopy(plan)
    false_exit["exit_gate"]["satisfied"] = True
    expect_error(
        DesignPartnerPlanError,
        lambda: validate_design_partner_plan(false_exit),
        "false exit success",
    )
    adversarial_count += 1
    false_claim_authority = copy.deepcopy(plan)
    false_claim_authority["exit_gate"]["production_claims_authorized"] = True
    expect_error(
        DesignPartnerPlanError,
        lambda: validate_design_partner_plan(false_claim_authority),
        "false product claim authority",
    )
    adversarial_count += 1
    contact_authority = copy.deepcopy(plan)
    contact_authority["authority"]["can_contact_participants"] = True
    expect_error(
        DesignPartnerPlanError,
        lambda: validate_design_partner_plan(contact_authority),
        "contact authority widening",
    )
    adversarial_count += 1
    return {
        "status": "EDGE_DESIGN_PARTNER_EVIDENCE_PLAN_VALID_RECRUITMENT_NOT_STARTED",
        "origin": "simulated",
        "target_partner_count": plan["cohort"]["target_count"],
        "maximum_partner_count": plan["cohort"]["maximum_count"],
        "actual_participant_count": 0,
        "evaluation_task_count": len(plan["tasks"]),
        "privacy_control_count": len(plan["data_boundary"]),
        "negative_fail_closed_case_count": adversarial_count,
        "recruitment_started": False,
        "participant_contacted": False,
        "consent_collected": False,
        "software_installed": False,
        "endpoint_data_collected": False,
        "external_message_sent": False,
        "exit_gate_satisfied": False,
        "production_claims_authorized": False,
    }


def main() -> None:
    project_root = Path(__file__).resolve().parents[1]
    result = validate_design_partner_kit(project_root)
    report_path = project_root / "reports" / "DESIGN_PARTNER_KIT_VALIDATION.json"
    report_path.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
