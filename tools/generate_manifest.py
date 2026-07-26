from __future__ import annotations

import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import cast

from validate_manifest import (
    MANIFEST_PATH,
    canonical_repository_bytes,
    list_project_files,
    read_git_attributes,
)


def build_file_entries(project_root: Path) -> list[dict[str, object]]:
    relative_paths = list_project_files(project_root)
    attributes = read_git_attributes(project_root, relative_paths)
    entries: list[dict[str, object]] = []
    normalization_required: list[str] = []
    for relative_path in relative_paths:
        raw_bytes = (project_root / relative_path).read_bytes()
        canonical_bytes = canonical_repository_bytes(
            raw_bytes,
            attributes[relative_path],
        )
        if raw_bytes != canonical_bytes:
            normalization_required.append(relative_path)
        entries.append(
            {
                "path": relative_path,
                "bytes": len(canonical_bytes),
                "sha256": hashlib.sha256(canonical_bytes).hexdigest().upper(),
            }
        )
    if normalization_required:
        raise ValueError(
            "Tracked text files require LF normalization before manifest generation: "
            f"paths={normalization_required!r}"
        )
    return entries


def update_manifest_metadata(
    manifest: dict[str, object],
    project_root: Path,
    entries: list[dict[str, object]],
) -> dict[str, object]:
    updated = dict(manifest)
    updated.pop("files", None)
    updated["manifest_version"] = "33.0"
    updated["generated_at"] = datetime.now().astimezone().isoformat()
    updated["project_path"] = "."
    updated["contract_schema_count"] = 97
    updated["contract_semantic_family_count"] = 92
    updated["cacis_vnext"] = (
        "W4_HOMEOSTASIS_CHRONOS_REPLAY_VALID_SCHEDULE_PROPOSAL_ONLY_"
        "EXTERNAL_SETTLEMENT_AND_EXECUTION_BLOCKED"
    )
    updated["cacis_roadmap_negative_case_count"] = 19
    updated["cacis_runtime_capability_implemented"] = True
    updated["cacis_execution_authorized"] = False
    updated["cacis_target_contact_performed"] = False
    updated["cacis_world_model"] = (
        "EIGHT_OBSERVATION_ONE_GENERATION_REPLAY_VALID_NON_AUTHORIZING"
    )
    updated["cacis_world_model_negative_case_count"] = 26
    updated["cacis_world_model_replay_implemented"] = True
    updated["cacis_world_model_live_sensing_performed"] = False
    updated["cacis_world_model_policy_input_ready"] = False
    updated["cacis_immune_runtime"] = "EIGHT_CELL_FIFTEEN_EVENT_SHADOW_TERMINATED_REPLAY_VALID_PROPOSAL_ONLY"
    updated["cacis_immune_runtime_negative_case_count"] = 49
    updated["cacis_immune_runtime_receipt_digest"] = "sha256:6e860d5e51a210ce0056266b3b95fc460c078785ef0db8c0ff8fb143c9838cc8"
    updated["cacis_immune_runtime_implemented"] = True
    updated["cacis_immune_runtime_live_sensing_performed"] = False
    updated["cacis_immune_runtime_independent_verification_performed"] = False
    updated["cacis_immune_runtime_execution_authorized"] = False
    updated["cacis_immune_runtime_execution_performed"] = False
    updated["cacis_immune_runtime_target_contact_performed"] = False
    updated["intelligence_research"] = (
        "FOUR_HYPOTHESIS_TWO_METHOD_TWO_CASE_SIX_CHALLENGE_REPLAY_VALID_"
        "CANDIDATE_THEORY_ONLY"
    )
    updated["intelligence_research_negative_case_count"] = 71
    updated["intelligence_research_mission_digest"] = "sha256:7af5c7cd14b45cff8c15795b827d677dfb9120deca8d476f4a1c24c24017c0e6"
    updated["intelligence_research_settlement_digest"] = "sha256:7ec6369f01c1aa975659c5e8ed3d44a31dea931deca03e383af56d6f89f629c9"
    updated["intelligence_research_hypothesis_cortex_implemented"] = True
    updated["intelligence_research_logical_read_only_verification_performed"] = True
    updated["intelligence_research_separate_process_verification_performed"] = False
    updated["intelligence_research_production_independence_verified"] = False
    updated["intelligence_research_held_out_evaluation_performed"] = False
    updated["intelligence_research_external_replication_performed"] = False
    updated["intelligence_research_generalization_allowed"] = False
    updated["intelligence_research_promotion_authorized"] = False
    updated["intelligence_research_execution_authorized"] = False
    updated["intelligence_research_execution_performed"] = False
    updated["intelligence_research_target_contact_performed"] = False
    updated["cacis_homeostasis_chronos"] = (
        "NINE_RESOURCE_THIRTEEN_SIGNAL_SEVEN_CLOCK_REPLAY_VALID_"
        "SCHEDULE_PROPOSAL_ONLY"
    )
    updated["cacis_homeostasis_chronos_negative_case_count"] = 60
    updated["cacis_homeostasis_chronos_mission_digest"] = "sha256:90bdd6c4203cf884886394735a519b5121f867542078b98602354a25ab281a81"
    updated["cacis_homeostasis_chronos_receipt_digest"] = "sha256:6771bb7dd2ace6cbe24e0932fdfa3f96780eef352f432915e825687d8e32b86a"
    updated["cacis_homeostasis_chronos_live_sensing_performed"] = False
    updated["cacis_homeostasis_chronos_independent_verification_performed"] = False
    updated["cacis_homeostasis_chronos_execution_authorized"] = False
    updated["cacis_homeostasis_chronos_execution_performed"] = False
    updated["cacis_homeostasis_chronos_target_contact_performed"] = False
    updated["edge_preview"] = (
        "REPLAYED_WINDOWS_PROCESS_EGRESS_BUDGET_ONE_PROPOSAL_"
        "INDEPENDENTLY_STRUCTURALLY_VERIFIED_POST_STATE_UNOBSERVED"
    )
    updated["edge_preview_origin"] = "replayed"
    updated["edge_preview_witness_entry_count"] = 4
    updated["edge_preview_fail_closed_case_count"] = 7
    updated["edge_preview_execution_authorized"] = False
    updated["edge_preview_execution_performed"] = False
    updated["edge_preview_target_state_changed"] = False
    updated["edge_preview_post_state_observed"] = False
    updated["edge_preview_recovery_verified"] = False
    updated["edge_live_observation"] = (
        "ONE_CALLER_SELECTED_WINDOWS_PROCESS_HASHED_IDENTITY_"
        "POLICY_AND_ACTION_BLOCKED"
    )
    updated["edge_live_observation_origin"] = "live"
    updated["edge_live_observation_supported_interface_count"] = 6
    updated["edge_live_observation_policy_input_ready"] = False
    updated["edge_live_observation_execution_authorized"] = False
    updated["edge_live_observation_execution_performed"] = False
    updated["release_foundation"] = (
        "TWO_ROLE_SIGNED_CANDIDATE_EXACT_PREDECESSOR_ARTIFACT_ROLLBACK_"
        "AND_PLUGIN_MANIFEST_VALID_INSTALLATION_BLOCKED"
    )
    updated["release_foundation_verified_signer_count"] = 2
    updated["release_foundation_plugin_code_executed"] = False
    updated["release_foundation_installation_authorized"] = False
    updated["release_foundation_installation_performed"] = False
    updated["design_partner_kit"] = (
        "FIVE_TO_EIGHT_PARTNER_PLAN_ZERO_PARTICIPANTS_RECRUITMENT_NOT_STARTED"
    )
    updated["design_partner_actual_participant_count"] = 0
    updated["design_partner_recruitment_started"] = False
    updated["design_partner_external_message_sent"] = False
    updated["github_default_branch_ruleset"] = (
        "ACTIVE_STRICT_CONSTITUTIONAL_VALIDATION_NO_BYPASS"
    )
    updated["github_secret_scanning"] = "ENABLED"
    updated["github_secret_scanning_push_protection"] = "ENABLED"
    updated["github_dependabot_security_updates"] = "ENABLED"
    updated["github_code_security"] = "DISABLED"
    updated["file_count"] = len(entries)
    updated["project_file_count"] = len(entries) + 1
    updated["files"] = entries
    return updated


def write_manifest(project_root: Path) -> dict[str, object]:
    manifest_path = project_root / MANIFEST_PATH
    loaded = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    if not isinstance(loaded, dict):
        raise TypeError(f"Foundation manifest must be an object: {manifest_path}")
    manifest = cast(dict[str, object], loaded)
    entries = build_file_entries(project_root)
    updated = update_manifest_metadata(manifest, project_root, entries)
    temporary_path = manifest_path.with_suffix(".json.tmp")
    temporary_path.write_text(
        json.dumps(updated, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    temporary_path.replace(manifest_path)
    return {
        "status": "FOUNDATION_MANIFEST_REGENERATED",
        "manifest_version": updated["manifest_version"],
        "file_count": updated["file_count"],
        "project_file_count": updated["project_file_count"],
    }


def main() -> None:
    project_root = Path(__file__).resolve().parents[1]
    result = write_manifest(project_root)
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
