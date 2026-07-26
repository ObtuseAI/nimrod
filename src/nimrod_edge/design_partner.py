"""Fail-closed design-partner evaluation plan validation."""

from __future__ import annotations

from nimrod_simulator.errors import DesignPartnerPlanError
from nimrod_simulator.model import JsonObject


PLAN_STATUS = "RECRUITMENT_NOT_STARTED"
PLAN_BLOCKERS = [
    "COUNSEL_PRIVACY_REVIEW_INCOMPLETE",
    "NAMED_PARTNERS_NOT_SELECTED",
    "PARTICIPANT_CONSENT_NOT_COLLECTED",
]
PLAN_AUTHORITY = {
    "can_contact_participants": False,
    "can_collect_endpoint_data": False,
    "can_install_software": False,
    "can_authorize_execution": False,
    "can_publish_claims": False,
}
REQUIRED_TASK_IDS = {
    "distinguish_live_from_replayed",
    "explain_replayed_event",
    "inspect_missing_evidence",
    "understand_action_boundary",
    "export_local_evidence",
}


def validate_design_partner_plan(plan: JsonObject) -> None:
    if plan.get("status") != PLAN_STATUS or plan.get("origin") != "simulated":
        raise DesignPartnerPlanError("Design-partner plan must remain a simulated recruitment-not-started plan.")
    if plan.get("authority") != PLAN_AUTHORITY:
        raise DesignPartnerPlanError("Design-partner plan exposes prohibited contact, collection, or publication authority.")
    if plan.get("blockers") != PLAN_BLOCKERS:
        raise DesignPartnerPlanError("Design-partner plan blockers are incomplete or reordered.")
    cohort = plan.get("cohort")
    data_boundary = plan.get("data_boundary")
    activity = plan.get("activity")
    exit_gate = plan.get("exit_gate")
    tasks = plan.get("tasks")
    if not all(isinstance(value, dict) for value in (cohort, data_boundary, activity, exit_gate)):
        raise DesignPartnerPlanError("Design-partner plan is missing cohort, data, activity, or exit-gate state.")
    if not isinstance(tasks, list) or not all(isinstance(task, dict) for task in tasks):
        raise DesignPartnerPlanError("Design-partner tasks must be an object list.")
    if cohort.get("participants") != [] or cohort.get("participant_count") != 0:
        raise DesignPartnerPlanError("Recruitment-not-started plan cannot fabricate participants.")
    if cohort.get("target_count") != 5 or cohort.get("maximum_count") != 8:
        raise DesignPartnerPlanError("Design-partner cohort must preserve the approved 5-to-8 target.")
    if {task.get("task_id") for task in tasks} != REQUIRED_TASK_IDS:
        raise DesignPartnerPlanError("Design-partner plan omits or widens the required evaluation tasks.")
    required_data_false = (
        "raw_endpoint_telemetry_collected",
        "external_telemetry_upload",
        "credential_collection",
        "background_surveillance",
        "screen_recording_enabled_by_default",
    )
    if any(data_boundary.get(field) is not False for field in required_data_false):
        raise DesignPartnerPlanError("Design-partner data boundary permits prohibited collection.")
    if data_boundary.get("explicit_consent_required") is not True:
        raise DesignPartnerPlanError("Design-partner evaluation requires explicit consent before any session.")
    if any(activity.get(field) is not False for field in activity):
        raise DesignPartnerPlanError("Design-partner plan fabricates recruitment, contact, installation, or collection activity.")
    if exit_gate.get("satisfied") is not False or exit_gate.get("production_claims_authorized") is not False:
        raise DesignPartnerPlanError("Design-partner plan cannot claim exit success or authorize product claims.")
