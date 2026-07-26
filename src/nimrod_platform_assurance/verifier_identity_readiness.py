"""Validation for live, read-only verifier identity readiness observations."""

from __future__ import annotations

from typing import cast

from nimrod_simulator.errors import VerifierIdentityReadinessError
from nimrod_simulator.model import JsonObject


SURFACE_IDS: tuple[str, ...] = (
    "world_model_intake_verifier",
    "constitutional_intelligence_research_verifier",
    "observatory_projection_verifier",
)
AUTHORITY: dict[str, bool] = {
    "can_authorize": False,
    "can_execute": False,
    "can_create_account": False,
    "can_modify_acl": False,
    "can_modify_firewall": False,
    "can_provision_custody": False,
}


def validate_verifier_identity_readiness(document: JsonObject) -> None:
    if document.get("readiness_version") != "0.1.0" or document.get("origin") != "live_read_only_probe":
        raise VerifierIdentityReadinessError("Verifier identity readiness identity or origin is invalid.")
    surfaces = document.get("surfaces")
    if not isinstance(surfaces, list) or [item.get("surface_id") for item in surfaces if isinstance(item, dict)] != list(SURFACE_IDS):
        raise VerifierIdentityReadinessError("Verifier identity readiness surfaces are incomplete or reordered.")
    process_ids: list[int] = []
    for surface in cast(list[JsonObject], surfaces):
        process_id = surface.get("worker_process_id")
        if isinstance(process_id, bool) or not isinstance(process_id, int) or process_id <= 0:
            raise VerifierIdentityReadinessError("Verifier identity readiness process identity is invalid.")
        process_ids.append(process_id)
        if surface.get("distinct_process_observed") is not True:
            raise VerifierIdentityReadinessError("Verifier identity readiness omitted a distinct process boundary.")
        if surface.get("credential_environment_allowlisted") is not True or surface.get("credential_value_accessed") is not False:
            raise VerifierIdentityReadinessError("Verifier identity probe inherited or accessed credential material.")
        if surface.get("active_network_probe_performed") is not False:
            raise VerifierIdentityReadinessError("Verifier identity probe performed an active network operation.")
        dedicated = surface.get("dedicated_os_account_verified")
        same_account = surface.get("worker_account_sid_digest") == surface.get("supervisor_account_sid_digest")
        if dedicated is not (not same_account):
            raise VerifierIdentityReadinessError("Verifier dedicated-account result contradicts observed SIDs.")
        access = surface.get("input_effective_access")
        if not isinstance(access, dict):
            raise VerifierIdentityReadinessError("Verifier identity probe lacks effective input ACL evidence.")
        read_only = access.get("read_allowed") is True and access.get("write_allowed") is False
        if surface.get("read_only_input_acl_verified") is not read_only:
            raise VerifierIdentityReadinessError("Verifier read-only ACL result contradicts effective access.")
        for unproven in (
            "network_egress_denied_verified",
            "production_signing_custody_verified",
            "separate_administrator_verified",
            "production_eligible",
        ):
            if surface.get(unproven) is not False:
                raise VerifierIdentityReadinessError(
                    f"Verifier identity probe fabricated unmeasured production control '{unproven}'."
                )
    if len(set(process_ids)) != len(SURFACE_IDS):
        raise VerifierIdentityReadinessError("Verifier identity probes reused one process identity.")
    summary = document.get("summary")
    if not isinstance(summary, dict):
        raise VerifierIdentityReadinessError("Verifier identity readiness summary is missing.")
    dedicated_count = len([surface for surface in cast(list[JsonObject], surfaces) if surface["dedicated_os_account_verified"] is True])
    read_only_count = len([surface for surface in cast(list[JsonObject], surfaces) if surface["read_only_input_acl_verified"] is True])
    if (
        summary.get("surface_count") != len(SURFACE_IDS)
        or summary.get("dedicated_os_account_verified_count") != dedicated_count
        or summary.get("read_only_input_acl_verified_count") != read_only_count
        or summary.get("production_eligible_count") != 0
        or summary.get("status") != "LIVE_IDENTITY_OBSERVED_DEDICATED_ACCOUNT_CUSTODY_AND_EGRESS_BLOCKED"
    ):
        raise VerifierIdentityReadinessError("Verifier identity readiness summary contradicts observations.")
    if document.get("authority") != AUTHORITY:
        raise VerifierIdentityReadinessError("Verifier identity readiness widened authority.")
