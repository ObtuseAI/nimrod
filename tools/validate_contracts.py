from __future__ import annotations

import base64
import binascii
import copy
import hashlib
import json
from collections.abc import Callable, Mapping
from datetime import datetime
from pathlib import Path
from typing import cast

from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import SchemaError

from nimrod_cacis.immune_runtime import AUTHORITY as IMMUNE_AUTHORITY, validate_immune_organism_mission
from nimrod_cacis.homeostasis import AUTHORITY as HOMEOSTASIS_AUTHORITY, validate_homeostasis_chronos_mission
from nimrod_cacis.roadmap import validate_cacis_roadmap
from nimrod_cacis.world_model import validate_observation, validate_world_model_generation
from nimrod_edge.design_partner import validate_design_partner_plan
from nimrod_edge.live_observation import validate_live_process_observation
from nimrod_research.intelligence_lab import validate_intelligence_research_mission
from nimrod_release.verification import verify_plugin_manifest
from nimrod_simulator.errors import ProtectionProfileError, SimulatorError
from nimrod_simulator.migrations import migrate_causal_verdict_0_1_to_0_2
from nimrod_simulator.jsonio import sha256_digest
from nimrod_simulator.model import JsonObject
from nimrod_simulator.evolution_constitution import REQUIRED_AXIOMS, REQUIRED_CAPABILITY_RESPONSES, REQUIRED_HARD_FAILURES
from nimrod_simulator.evolution_foundry import CANDIDATE_AUTHORITY, EPISTEMIC_STANDARD_BY_MODE, REQUIRED_CHAMPION_FLOORS, REQUIRED_EVALUATOR_ROLES
from nimrod_simulator.range_recovery import range_cleanup_subject_digest
from nimrod_simulator.protection_profile import validate_protection_profile


Mutation = Callable[[JsonObject], JsonObject]

CONTRACT_PAIRS: tuple[tuple[str, str], ...] = (
    ("action-and-evidence-envelope.schema.json", "action-envelope.example.json"),
    ("authorization-lease.schema.json", "authorization-lease.example.json"),
    ("authorization-proof-bundle.schema.json", "authorization-proof-bundle.example.json"),
    ("authorization-trust-policy.schema.json", "authorization-trust-policy.example.json"),
    ("cacis-capability-roadmap.schema.json", "cacis-capability-roadmap.example.json"),
    ("causal-coverage-verdict.schema.json", "causal-coverage-verdict.example.json"),
    ("capability-threshold-report.schema.json", "capability-threshold-report.example.json"),
    ("cognitive-candidate-bundle.schema.json", "cognitive-candidate-bundle.example.json"),
    ("connector-manifest.schema.json", "connector-manifest.example.json"),
    ("construction-zone-isolation-attestation-plan.schema.json", "construction-zone-isolation-attestation-plan.example.json"),
    ("construction-zone-preflight-result.schema.json", "construction-zone-preflight-result.example.json"),
    ("construction-zone-provisioning-authorization.schema.json", "construction-zone-provisioning-authorization.example.json"),
    ("construction-zone-provisioning-gate-result.schema.json", "construction-zone-provisioning-gate-result.example.json"),
    ("control-board-ingress-receipt.schema.json", "control-board-ingress-receipt.example.json"),
    ("control-board-foundry-projection.schema.json", "control-board-foundry-projection.example.json"),
    ("control-board-snapshot.schema.json", "control-board-snapshot.example.json"),
    ("control-board-verifier-projection.schema.json", "control-board-verifier-projection.example.json"),
    ("disposable-range-preflight.schema.json", "disposable-range-preflight.example.json"),
    ("disposable-range-preflight-result.schema.json", "disposable-range-preflight-result.example.json"),
    ("design-partner-evaluation-plan.schema.json", "design-partner-evaluation-plan.example.json"),
    ("edge-live-process-observation.schema.json", "edge-live-process-observation.example.json"),
    ("edge-preview-result.schema.json", "edge-preview-result.example.json"),
    ("edge-preview-scenario.schema.json", "edge-preview-scenario.example.json"),
    ("edge-update-manifest.schema.json", "edge-update-manifest.example.json"),
    ("edge-update-verification-receipt.schema.json", "edge-update-verification-receipt.example.json"),
    ("evidence-receipt.schema.json", "evidence-receipt.example.json"),
    ("epistemic-posture.schema.json", "epistemic-posture.example.json"),
    ("evolution-baseline.schema.json", "evolution-baseline.example.json"),
    ("evolution-constitution.schema.json", "evolution-constitution.example.json"),
    ("evolution-assurance-receipt.schema.json", "evolution-assurance-receipt.example.json"),
    ("evolution-evaluation-vector.schema.json", "evolution-evaluation-vector.example.json"),
    ("evolution-transition-envelope.schema.json", "evolution-transition-envelope.example.json"),
    ("evolution-transition-receipt.schema.json", "evolution-transition-receipt.example.json"),
    ("evaluator-conformance-bundle.schema.json", "evaluator-conformance-bundle.example.json"),
    ("improvement-candidate.schema.json", "improvement-candidate.example.json"),
    ("homeostasis-chronos-mission.schema.json", "homeostasis-chronos-mission.example.json"),
    ("homeostasis-chronos-receipt.schema.json", "homeostasis-chronos-receipt.example.json"),
    ("intelligence-research-mission.schema.json", "intelligence-research-mission.example.json"),
    ("intelligence-research-settlement.schema.json", "intelligence-research-settlement.example.json"),
    ("immune-organism-lifecycle-receipt.schema.json", "immune-organism-lifecycle-receipt.example.json"),
    ("immune-organism-mission.schema.json", "immune-organism-mission.example.json"),
    ("isolated-construction-zone.schema.json", "isolated-construction-zone.example.json"),
    ("evaluator-observation-envelope.schema.json", "evaluator-observation-envelope.example.json"),
    ("evaluator-trust-policy.schema.json", "evaluator-trust-policy.example.json"),
    ("key-governance-state.schema.json", "key-governance-state.example.json"),
    ("key-governance-transition.schema.json", "key-governance-transition.example.json"),
    ("lineage-resource-ledger.schema.json", "lineage-resource-ledger.example.json"),
    ("os-isolation-attestation.schema.json", "os-isolation-attestation.example.json"),
    ("owner-scope-exclusion-registry.schema.json", "owner-scope-exclusion-registry.example.json"),
    ("plugin-capability-manifest.schema.json", "plugin-capability-manifest.example.json"),
    ("protection-profile.schema.json", "protection-profile.example.json"),
    ("public-corpus-intake-report.schema.json", "public-corpus-intake-report.example.json"),
    ("public-sacrificial-source-registry.schema.json", "public-sacrificial-source-registry.example.json"),
    ("public-source-staging-authorization.schema.json", "public-source-staging-authorization.example.json"),
    ("range-adapter-policy.schema.json", "range-adapter-policy.example.json"),
    ("range-adapter-policy-envelope.schema.json", "range-adapter-policy-envelope.example.json"),
    ("range-compilation-receipt.schema.json", "range-compilation-receipt.example.json"),
    ("range-collector-policy.schema.json", "range-collector-policy.example.json"),
    ("range-connector-capability-manifest.schema.json", "range-connector-capability-manifest.example.json"),
    ("range-corpus-manifest.schema.json", "range-corpus-manifest.example.json"),
    ("range-corpus-report.schema.json", "range-corpus-report.example.json"),
    ("range-environment-observation.schema.json", "range-environment-observation.example.json"),
    ("range-evidence-acceptance-report.schema.json", "range-evidence-acceptance-report.example.json"),
    ("range-evidence-admission-report.schema.json", "range-evidence-admission-report.example.json"),
    ("range-evidence-completion-authorization.schema.json", "range-evidence-completion-authorization.example.json"),
    ("range-evidence-completion-policy.schema.json", "range-evidence-completion-policy.example.json"),
    ("range-evidence-completion-receipt.schema.json", "range-evidence-completion-receipt.example.json"),
    ("range-kill-command.schema.json", "range-kill-command.example.json"),
    ("range-kill-state.schema.json", "range-kill-state.example.json"),
    ("range-lease-topology-scope.schema.json", "range-lease-topology-scope.example.json"),
    ("range-preexecution-evidence-packet.schema.json", "range-preexecution-evidence-packet.example.json"),
    ("range-recovery-evidence.schema.json", "range-recovery-evidence.example.json"),
    ("range-recovery-receipt.schema.json", "range-recovery-receipt.example.json"),
    ("range-source-import.schema.json", "range-source-import.example.json"),
    ("range-topology.schema.json", "range-topology.example.json"),
    ("range-topology-verdict.schema.json", "range-topology-verdict.example.json"),
    ("range-verifier-decision.schema.json", "range-verifier-decision.example.json"),
    ("range-verifier-policy.schema.json", "range-verifier-policy.example.json"),
    ("resource-meter-receipt.schema.json", "resource-meter-receipt.example.json"),
    ("sacrificial-replica-plan.schema.json", "sacrificial-replica-plan.example.json"),
    ("source-staging-gate-report.schema.json", "source-staging-gate-report.example.json"),
    ("source-quarantine-evidence-receipt.schema.json", "source-quarantine-evidence-receipt.example.json"),
    ("swarm-mission.schema.json", "swarm-mission.example.json"),
    ("swarm-verdict.schema.json", "swarm-verdict.example.json"),
    ("validation-campaign.schema.json", "validation-campaign.example.json"),
    ("verifier-consensus.schema.json", "verifier-consensus.example.json"),
    ("verifier-health.schema.json", "verifier-health.example.json"),
    ("verifier-observation.schema.json", "verifier-observation.example.json"),
    ("verifier-service-policy.schema.json", "verifier-service-policy.example.json"),
    ("witness-anchor-head.schema.json", "witness-anchor-head.example.json"),
    ("witness-anchor-policy.schema.json", "witness-anchor-policy.example.json"),
    ("witness-anchor-receipt.schema.json", "witness-anchor-receipt.example.json"),
    ("witness-checkpoint.schema.json", "witness-checkpoint.example.json"),
    ("windows-custody-readiness.schema.json", "windows-custody-readiness.example.json"),
    ("windows-isolation-measurement.schema.json", "windows-isolation-measurement.example.json"),
    ("world-model-generation.schema.json", "world-model-generation.example.json"),
    ("world-observation-envelope.schema.json", "world-observation-envelope.example.json"),
)


def read_object(path: Path) -> JsonObject:
    value: object = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise TypeError(f"Expected a JSON object at {path}; received {type(value).__name__}.")
    return cast(JsonObject, value)


def remove_required_field(value: JsonObject) -> JsonObject:
    mutated = copy.deepcopy(value)
    mutated.pop(next(iter(mutated)))
    return mutated


def invalid_authorization_target(value: JsonObject) -> JsonObject:
    mutated = copy.deepcopy(value)
    mutated["target_graph"] = []
    return mutated


def invalid_authorization_proof(value: JsonObject) -> JsonObject:
    mutated = copy.deepcopy(value)
    mutated["signatures"] = []
    return mutated


def invalid_trust_threshold(value: JsonObject) -> JsonObject:
    mutated = copy.deepcopy(value)
    mutated["threshold"] = 1
    return mutated


def invalid_verdict_status(value: JsonObject) -> JsonObject:
    mutated = copy.deepcopy(value)
    mutated["status"] = "pass"
    return mutated


def invalid_connector_operation(value: JsonObject) -> JsonObject:
    mutated = copy.deepcopy(value)
    mutated["lifecycle_operations"] = ["run"]
    return mutated


def invalid_control_board_verifier_authority(value: JsonObject) -> JsonObject:
    mutated = copy.deepcopy(value)
    authority = mutated.get("authority")
    if not isinstance(authority, dict):
        raise TypeError("control-board verifier projection authority must be an object")
    authority["can_execute"] = True
    return mutated


def invalid_control_board_snapshot_authority(value: JsonObject) -> JsonObject:
    mutated = copy.deepcopy(value)
    authority = mutated.get("authority")
    if not isinstance(authority, dict):
        raise TypeError("control-board snapshot authority must be an object")
    authority["can_authorize"] = True
    return mutated


def invalid_control_board_ingress_guard(value: JsonObject) -> JsonObject:
    mutated = copy.deepcopy(value)
    mutated["durable_replay_guard"] = False
    return mutated


def invalid_evidence_class(value: JsonObject) -> JsonObject:
    mutated = copy.deepcopy(value)
    mutated["classification"] = "E7"
    return mutated


def invalid_edge_scenario_authority(value: JsonObject) -> JsonObject:
    mutated = copy.deepcopy(value)
    cast(JsonObject, mutated["authority"])["can_execute"] = True
    return mutated


def invalid_edge_result_authority(value: JsonObject) -> JsonObject:
    mutated = copy.deepcopy(value)
    cast(JsonObject, mutated["authority"])["can_authorize"] = True
    return mutated


def invalid_edge_live_observation_authority(value: JsonObject) -> JsonObject:
    mutated = copy.deepcopy(value)
    cast(JsonObject, mutated["authority"])["can_execute"] = True
    return mutated


def invalid_plugin_network(value: JsonObject) -> JsonObject:
    mutated = copy.deepcopy(value)
    cast(JsonObject, mutated["network"])["allowed_destinations"] = ["telemetry.invalid:443"]
    return mutated


def invalid_update_rollout(value: JsonObject) -> JsonObject:
    mutated = copy.deepcopy(value)
    cast(JsonObject, mutated["rollout"])["installation_authorized"] = True
    return mutated


def invalid_update_receipt_authority(value: JsonObject) -> JsonObject:
    mutated = copy.deepcopy(value)
    mutated["installation_authorized"] = True
    return mutated


def invalid_design_partner_activity(value: JsonObject) -> JsonObject:
    mutated = copy.deepcopy(value)
    cast(JsonObject, mutated["activity"])["recruitment_started"] = True
    return mutated


def invalid_improvement_tier(value: JsonObject) -> JsonObject:
    mutated = copy.deepcopy(value)
    mutated["authority_tier"] = "E"
    return mutated


def invalid_profile_oracles(value: JsonObject) -> JsonObject:
    mutated = copy.deepcopy(value)
    mutated["oracles"] = []
    return mutated


def invalid_range_adapter_policy_authority(value: JsonObject) -> JsonObject:
    mutated = copy.deepcopy(value)
    authority = mutated.get("authority")
    if not isinstance(authority, dict):
        raise TypeError("range-adapter policy authority must be an object")
    authority["can_connect"] = True
    return mutated


def invalid_range_policy_envelope_authority(value: JsonObject) -> JsonObject:
    mutated = copy.deepcopy(value)
    authority = mutated.get("authority")
    if not isinstance(authority, dict):
        raise TypeError("range policy envelope authority must be an object")
    authority["can_execute"] = True
    return mutated


def invalid_range_corpus_manifest_authority(value: JsonObject) -> JsonObject:
    mutated = copy.deepcopy(value)
    authority = mutated.get("authority")
    if not isinstance(authority, dict):
        raise TypeError("range corpus manifest authority must be an object")
    authority["can_fetch"] = True
    return mutated


def invalid_range_corpus_report_activity(value: JsonObject) -> JsonObject:
    mutated = copy.deepcopy(value)
    mutated["compilation_performed"] = True
    return mutated


def invalid_range_preflight_authority(value: JsonObject) -> JsonObject:
    mutated = copy.deepcopy(value)
    authority = mutated.get("authority")
    if not isinstance(authority, dict):
        raise TypeError("range preflight authority must be an object")
    authority["can_connect"] = True
    return mutated


def invalid_range_preflight_result_authority(value: JsonObject) -> JsonObject:
    mutated = copy.deepcopy(value)
    mutated["range_connection_authorized"] = True
    return mutated


def invalid_range_topology_authority(value: JsonObject) -> JsonObject:
    mutated = copy.deepcopy(value)
    authority = mutated.get("authority")
    if not isinstance(authority, dict):
        raise TypeError("range topology authority must be an object")
    authority["can_provision"] = True
    return mutated


def invalid_range_topology_verdict_environment(value: JsonObject) -> JsonObject:
    mutated = copy.deepcopy(value)
    mutated["environment_verified"] = True
    return mutated


def invalid_range_kill_command_authority(value: JsonObject) -> JsonObject:
    mutated = copy.deepcopy(value)
    authority = mutated.get("authority")
    if not isinstance(authority, dict):
        raise TypeError("range kill command authority must be an object")
    authority["can_disengage"] = True
    return mutated


def invalid_range_kill_state_reset(value: JsonObject) -> JsonObject:
    mutated = copy.deepcopy(value)
    mutated["kill_remains_engaged"] = False
    return mutated


def invalid_range_recovery_evidence_authority(value: JsonObject) -> JsonObject:
    mutated = copy.deepcopy(value)
    authority = mutated.get("authority")
    if not isinstance(authority, dict):
        raise TypeError("range recovery evidence authority must be an object")
    authority["can_reset_kill"] = True
    return mutated


def invalid_range_recovery_receipt_authority(value: JsonObject) -> JsonObject:
    mutated = copy.deepcopy(value)
    mutated["range_reuse_authorized"] = True
    return mutated


def invalid_evolution_baseline_authority(value: JsonObject) -> JsonObject:
    mutated = copy.deepcopy(value)
    cast(JsonObject, mutated["authority"])["candidate_write_permitted"] = True
    return mutated


def invalid_evolution_constitution_authority(value: JsonObject) -> JsonObject:
    mutated = copy.deepcopy(value)
    cast(JsonObject, mutated["authority"])["can_modify_itself"] = True
    return mutated


def invalid_epistemic_posture_authority(value: JsonObject) -> JsonObject:
    mutated = copy.deepcopy(value)
    cast(JsonObject, mutated["authority"])["can_waive_hard_failures"] = True
    return mutated


def invalid_cognitive_candidate_authority(value: JsonObject) -> JsonObject:
    mutated = copy.deepcopy(value)
    cast(JsonObject, mutated["authority"])["can_execute"] = True
    return mutated


def invalid_capability_report_authority(value: JsonObject) -> JsonObject:
    mutated = copy.deepcopy(value)
    cast(JsonObject, mutated["authority"])["can_expand_authority"] = True
    return mutated


def invalid_evolution_evaluation_scalar(value: JsonObject) -> JsonObject:
    mutated = copy.deepcopy(value)
    mutated["aggregate_score_present"] = True
    return mutated


def invalid_evolution_transition_authority(value: JsonObject) -> JsonObject:
    mutated = copy.deepcopy(value)
    cast(JsonObject, mutated["authority"])["can_modify_active_baseline"] = True
    return mutated


def invalid_evolution_receipt_authority(value: JsonObject) -> JsonObject:
    mutated = copy.deepcopy(value)
    mutated["production_promotion_authorized"] = True
    return mutated


def invalid_range_compilation_forwarding(value: JsonObject) -> JsonObject:
    mutated = copy.deepcopy(value)
    mutated["raw_execution_material_forwarded"] = True
    return mutated


def invalid_range_import_retention(value: JsonObject) -> JsonObject:
    mutated = copy.deepcopy(value)
    mutated["raw_execution_material_retained"] = True
    return mutated


def invalid_key_governance_export(value: JsonObject) -> JsonObject:
    mutated = copy.deepcopy(value)
    keys = mutated.get("keys")
    if not isinstance(keys, list) or not keys or not isinstance(keys[0], dict):
        raise TypeError("key governance keys must contain an object")
    custody = keys[0].get("custody")
    if not isinstance(custody, dict):
        raise TypeError("key governance custody must be an object")
    custody["private_key_exportable"] = True
    return mutated


def invalid_key_transition_threshold(value: JsonObject) -> JsonObject:
    mutated = copy.deepcopy(value)
    signatures = mutated.get("signatures")
    if not isinstance(signatures, list) or not signatures:
        raise TypeError("key transition signatures must be a non-empty list")
    mutated["signatures"] = signatures[:1]
    return mutated


def invalid_witness_checkpoint_size(value: JsonObject) -> JsonObject:
    mutated = copy.deepcopy(value)
    mutated["tree_size"] = 0
    return mutated


def invalid_anchor_policy_witnesses(value: JsonObject) -> JsonObject:
    mutated = copy.deepcopy(value)
    mutated["allowed_witness_ids"] = []
    return mutated


def invalid_anchor_receipt_sequence(value: JsonObject) -> JsonObject:
    mutated = copy.deepcopy(value)
    mutated["sequence"] = 0
    return mutated


def invalid_anchor_head_sequence(value: JsonObject) -> JsonObject:
    mutated = copy.deepcopy(value)
    mutated["sequence"] = 0
    return mutated


def invalid_verifier_policy_capability(value: JsonObject) -> JsonObject:
    mutated = copy.deepcopy(value)
    mutated["allowed_capabilities"] = ["health.report", "witness.verify", "anchor.verify", "execute"]
    return mutated


def invalid_verifier_observation_status(value: JsonObject) -> JsonObject:
    mutated = copy.deepcopy(value)
    mutated["status"] = "success"
    return mutated


def invalid_verifier_consensus_state(value: JsonObject) -> JsonObject:
    mutated = copy.deepcopy(value)
    mutated["state"] = "pass"
    return mutated


def invalid_verifier_health_write(value: JsonObject) -> JsonObject:
    mutated = copy.deepcopy(value)
    mutated["filesystem_write_capability_exposed"] = True
    return mutated


def invalid_swarm_mission_authority(value: JsonObject) -> JsonObject:
    mutated = copy.deepcopy(value)
    mutated["proposal_only"] = False
    return mutated


def invalid_swarm_verdict_authority(value: JsonObject) -> JsonObject:
    mutated = copy.deepcopy(value)
    authority = mutated.get("authority")
    if not isinstance(authority, dict):
        raise TypeError("swarm verdict authority must be an object")
    authority["execution_authorized"] = True
    return mutated


def invalid_range_connector_capability_authority(value: JsonObject) -> JsonObject:
    mutated = copy.deepcopy(value)
    authority = mutated.get("authority")
    if not isinstance(authority, dict):
        raise TypeError("range connector capability authority must be an object")
    authority["can_connect"] = True
    return mutated


def invalid_range_scope_authority(value: JsonObject) -> JsonObject:
    mutated = copy.deepcopy(value)
    authority = mutated.get("authority")
    if not isinstance(authority, dict):
        raise TypeError("range lease topology scope authority must be an object")
    authority["can_execute"] = True
    return mutated


def invalid_range_preexecution_evidence_completion(value: JsonObject) -> JsonObject:
    mutated = copy.deepcopy(value)
    mutated["evidence_complete"] = True
    return mutated


def invalid_range_collector_policy_authority(value: JsonObject) -> JsonObject:
    mutated = copy.deepcopy(value)
    authority = mutated.get("authority")
    if not isinstance(authority, dict):
        raise TypeError("range collector policy authority must be an object")
    authority["can_open_network_connection"] = True
    return mutated


def invalid_range_environment_observation_activity(value: JsonObject) -> JsonObject:
    mutated = copy.deepcopy(value)
    activity = mutated.get("activity")
    if not isinstance(activity, dict):
        raise TypeError("range environment observation activity must be an object")
    activity["network_contact_performed"] = True
    return mutated


def invalid_range_evidence_admission_completion(value: JsonObject) -> JsonObject:
    mutated = copy.deepcopy(value)
    mutated["evidence_complete"] = True
    return mutated


def invalid_range_evidence_acceptance_completion(value: JsonObject) -> JsonObject:
    mutated = copy.deepcopy(value)
    mutated["evidence_complete"] = True
    return mutated


def invalid_range_evidence_completion_policy_authority(value: JsonObject) -> JsonObject:
    mutated = copy.deepcopy(value)
    authority = mutated.get("authority")
    if not isinstance(authority, dict):
        raise TypeError("range evidence completion policy authority must be an object")
    authority["can_mark_evidence_complete"] = True
    return mutated


def invalid_range_evidence_completion_authorization(value: JsonObject) -> JsonObject:
    mutated = copy.deepcopy(value)
    mutated["outcome"] = "authorize_completion"
    return mutated


def invalid_range_evidence_completion_receipt(value: JsonObject) -> JsonObject:
    mutated = copy.deepcopy(value)
    mutated["range_connection_authorized"] = True
    return mutated


def invalid_range_verifier_decision_accept(value: JsonObject) -> JsonObject:
    mutated = copy.deepcopy(value)
    mutated["decision"] = "accept"
    mutated["reason"] = "evidence_supports_control"
    return mutated


def invalid_range_verifier_policy_authority(value: JsonObject) -> JsonObject:
    mutated = copy.deepcopy(value)
    authority = mutated.get("authority")
    if not isinstance(authority, dict):
        raise TypeError("range verifier policy authority must be an object")
    authority["can_execute"] = True
    return mutated


def invalid_public_corpus_intake_target(value: JsonObject) -> JsonObject:
    mutated = copy.deepcopy(value)
    mutated["public_host_target_authorized"] = True
    return mutated


def invalid_public_source_registry_authority(value: JsonObject) -> JsonObject:
    mutated = copy.deepcopy(value)
    authority = mutated.get("authority")
    if not isinstance(authority, dict):
        raise TypeError("public source registry authority must be an object")
    authority["can_target_public_host"] = True
    return mutated


def invalid_sacrificial_replica_network(value: JsonObject) -> JsonObject:
    mutated = copy.deepcopy(value)
    network = mutated.get("network")
    if not isinstance(network, dict):
        raise TypeError("sacrificial replica network must be an object")
    network["internet_egress"] = True
    return mutated


def invalid_owner_scope_registry_completion(value: JsonObject) -> JsonObject:
    mutated = copy.deepcopy(value)
    mutated["registry_complete"] = True
    return mutated


def invalid_source_staging_authority(value: JsonObject) -> JsonObject:
    mutated = copy.deepcopy(value)
    authority = mutated.get("authority")
    if not isinstance(authority, dict):
        raise TypeError("source staging authority must be an object")
    authority["can_stage_source"] = True
    return mutated


def invalid_source_staging_report(value: JsonObject) -> JsonObject:
    mutated = copy.deepcopy(value)
    mutated["staging_authorized"] = True
    return mutated


def invalid_construction_zone_provisioning(value: JsonObject) -> JsonObject:
    mutated = copy.deepcopy(value)
    activity = mutated.get("activity")
    if not isinstance(activity, dict):
        raise TypeError("construction zone activity must be an object")
    activity["construction_zone_provisioned"] = True
    return mutated


def invalid_quarantine_evidence(value: JsonObject) -> JsonObject:
    mutated = copy.deepcopy(value)
    mutated["source_archive_count"] = 1
    return mutated


def invalid_construction_preflight(value: JsonObject) -> JsonObject:
    mutated = copy.deepcopy(value)
    mutated["construction_zone_provisioned"] = True
    return mutated


def invalid_construction_attestation_plan(value: JsonObject) -> JsonObject:
    mutated = copy.deepcopy(value)
    controls = mutated.get("controls")
    if not isinstance(controls, list) or not controls or not isinstance(controls[0], dict):
        raise TypeError("construction attestation controls must be a non-empty object list")
    controls[0]["collector_id"] = "collector:fake"
    return mutated


def invalid_construction_provisioning_authorization(value: JsonObject) -> JsonObject:
    mutated = copy.deepcopy(value)
    mutated["authorized_operations"] = ["CREATE_DISPOSABLE_WORKSPACE"]
    return mutated


def invalid_construction_provisioning_result(value: JsonObject) -> JsonObject:
    mutated = copy.deepcopy(value)
    mutated["provisioning_authorized"] = True
    return mutated


def invalid_campaign_steps(value: JsonObject) -> JsonObject:
    mutated = copy.deepcopy(value)
    mutated["steps"] = []
    return mutated


def invalid_cacis_authority(value: JsonObject) -> JsonObject:
    mutated = copy.deepcopy(value)
    authority = mutated.get("authority")
    if not isinstance(authority, dict):
        raise TypeError("CACIS roadmap authority must be an object")
    authority["can_execute"] = True
    return mutated


def invalid_world_observation_authority(value: JsonObject) -> JsonObject:
    mutated = copy.deepcopy(value)
    authority = mutated.get("authority")
    if not isinstance(authority, dict):
        raise TypeError("world observation authority must be an object")
    authority["can_claim_truth"] = True
    return mutated


def invalid_world_generation_authority(value: JsonObject) -> JsonObject:
    mutated = copy.deepcopy(value)
    generation = mutated.get("generation")
    if not isinstance(generation, dict) or not isinstance(generation.get("authority"), dict):
        raise TypeError("world generation authority must be an object")
    generation["authority"]["policy_input_ready"] = True
    return mutated


def invalid_immune_mission_authority(value: JsonObject) -> JsonObject:
    mutated = copy.deepcopy(value)
    authority = mutated.get("authority")
    if not isinstance(authority, dict):
        raise TypeError("immune mission authority must be an object")
    authority["can_execute"] = True
    return mutated


def invalid_immune_receipt_execution(value: JsonObject) -> JsonObject:
    mutated = copy.deepcopy(value)
    receipt = mutated.get("receipt")
    if not isinstance(receipt, dict) or not isinstance(receipt.get("termination"), dict):
        raise TypeError("immune lifecycle termination must be an object")
    receipt["termination"]["execution_performed"] = True
    return mutated


def invalid_intelligence_research_mission_authority(value: JsonObject) -> JsonObject:
    mutated = copy.deepcopy(value)
    authority = mutated.get("authority")
    if not isinstance(authority, dict):
        raise TypeError("intelligence research mission authority must be an object")
    authority["can_promote"] = True
    return mutated


def invalid_intelligence_research_settlement_promotion(value: JsonObject) -> JsonObject:
    mutated = copy.deepcopy(value)
    settlement = mutated.get("settlement")
    if not isinstance(settlement, dict) or not isinstance(settlement.get("candidate_theory"), dict):
        raise TypeError("intelligence research candidate theory must be an object")
    settlement["candidate_theory"]["promotion_authorized"] = True
    return mutated


def invalid_homeostasis_mission_authority(value: JsonObject) -> JsonObject:
    mutated = copy.deepcopy(value)
    authority = mutated.get("authority")
    if not isinstance(authority, dict):
        raise TypeError("homeostasis mission authority must be an object")
    authority["can_execute"] = True
    return mutated


def invalid_homeostasis_receipt_authority(value: JsonObject) -> JsonObject:
    mutated = copy.deepcopy(value)
    receipt = mutated.get("receipt")
    if not isinstance(receipt, dict) or not isinstance(receipt.get("authority"), dict):
        raise TypeError("homeostasis receipt authority must be an object")
    receipt["authority"]["can_promote"] = True
    return mutated


NEGATIVE_MUTATIONS: Mapping[str, Mutation] = {
    "action-and-evidence-envelope.schema.json": remove_required_field,
    "authorization-lease.schema.json": invalid_authorization_target,
    "authorization-proof-bundle.schema.json": invalid_authorization_proof,
    "authorization-trust-policy.schema.json": invalid_trust_threshold,
    "cacis-capability-roadmap.schema.json": invalid_cacis_authority,
    "causal-coverage-verdict.schema.json": invalid_verdict_status,
    "capability-threshold-report.schema.json": invalid_capability_report_authority,
    "cognitive-candidate-bundle.schema.json": invalid_cognitive_candidate_authority,
    "connector-manifest.schema.json": invalid_connector_operation,
    "construction-zone-isolation-attestation-plan.schema.json": invalid_construction_attestation_plan,
    "construction-zone-preflight-result.schema.json": invalid_construction_preflight,
    "construction-zone-provisioning-authorization.schema.json": invalid_construction_provisioning_authorization,
    "construction-zone-provisioning-gate-result.schema.json": invalid_construction_provisioning_result,
    "control-board-ingress-receipt.schema.json": invalid_control_board_ingress_guard,
    "control-board-foundry-projection.schema.json": remove_required_field,
    "control-board-snapshot.schema.json": invalid_control_board_snapshot_authority,
    "control-board-verifier-projection.schema.json": invalid_control_board_verifier_authority,
    "disposable-range-preflight.schema.json": invalid_range_preflight_authority,
    "disposable-range-preflight-result.schema.json": invalid_range_preflight_result_authority,
    "design-partner-evaluation-plan.schema.json": invalid_design_partner_activity,
    "edge-live-process-observation.schema.json": invalid_edge_live_observation_authority,
    "edge-preview-result.schema.json": invalid_edge_result_authority,
    "edge-preview-scenario.schema.json": invalid_edge_scenario_authority,
    "edge-update-manifest.schema.json": invalid_update_rollout,
    "edge-update-verification-receipt.schema.json": invalid_update_receipt_authority,
    "evidence-receipt.schema.json": invalid_evidence_class,
    "epistemic-posture.schema.json": invalid_epistemic_posture_authority,
    "evolution-baseline.schema.json": invalid_evolution_baseline_authority,
    "evolution-constitution.schema.json": invalid_evolution_constitution_authority,
    "evolution-assurance-receipt.schema.json": remove_required_field,
    "evolution-evaluation-vector.schema.json": invalid_evolution_evaluation_scalar,
    "evolution-transition-envelope.schema.json": invalid_evolution_transition_authority,
    "evolution-transition-receipt.schema.json": invalid_evolution_receipt_authority,
    "evaluator-conformance-bundle.schema.json": remove_required_field,
    "improvement-candidate.schema.json": invalid_improvement_tier,
    "homeostasis-chronos-mission.schema.json": invalid_homeostasis_mission_authority,
    "homeostasis-chronos-receipt.schema.json": invalid_homeostasis_receipt_authority,
    "intelligence-research-mission.schema.json": invalid_intelligence_research_mission_authority,
    "intelligence-research-settlement.schema.json": invalid_intelligence_research_settlement_promotion,
    "immune-organism-lifecycle-receipt.schema.json": invalid_immune_receipt_execution,
    "immune-organism-mission.schema.json": invalid_immune_mission_authority,
    "isolated-construction-zone.schema.json": invalid_construction_zone_provisioning,
    "evaluator-observation-envelope.schema.json": remove_required_field,
    "evaluator-trust-policy.schema.json": remove_required_field,
    "key-governance-state.schema.json": invalid_key_governance_export,
    "key-governance-transition.schema.json": invalid_key_transition_threshold,
    "lineage-resource-ledger.schema.json": remove_required_field,
    "os-isolation-attestation.schema.json": remove_required_field,
    "owner-scope-exclusion-registry.schema.json": invalid_owner_scope_registry_completion,
    "plugin-capability-manifest.schema.json": invalid_plugin_network,
    "protection-profile.schema.json": invalid_profile_oracles,
    "public-corpus-intake-report.schema.json": invalid_public_corpus_intake_target,
    "public-sacrificial-source-registry.schema.json": invalid_public_source_registry_authority,
    "public-source-staging-authorization.schema.json": invalid_source_staging_authority,
    "range-adapter-policy.schema.json": invalid_range_adapter_policy_authority,
    "range-adapter-policy-envelope.schema.json": invalid_range_policy_envelope_authority,
    "range-compilation-receipt.schema.json": invalid_range_compilation_forwarding,
    "range-collector-policy.schema.json": invalid_range_collector_policy_authority,
    "range-connector-capability-manifest.schema.json": invalid_range_connector_capability_authority,
    "range-corpus-manifest.schema.json": invalid_range_corpus_manifest_authority,
    "range-corpus-report.schema.json": invalid_range_corpus_report_activity,
    "range-environment-observation.schema.json": invalid_range_environment_observation_activity,
    "range-evidence-acceptance-report.schema.json": invalid_range_evidence_acceptance_completion,
    "range-evidence-admission-report.schema.json": invalid_range_evidence_admission_completion,
    "range-evidence-completion-authorization.schema.json": invalid_range_evidence_completion_authorization,
    "range-evidence-completion-policy.schema.json": invalid_range_evidence_completion_policy_authority,
    "range-evidence-completion-receipt.schema.json": invalid_range_evidence_completion_receipt,
    "range-kill-command.schema.json": invalid_range_kill_command_authority,
    "range-kill-state.schema.json": invalid_range_kill_state_reset,
    "range-lease-topology-scope.schema.json": invalid_range_scope_authority,
    "range-preexecution-evidence-packet.schema.json": invalid_range_preexecution_evidence_completion,
    "range-recovery-evidence.schema.json": invalid_range_recovery_evidence_authority,
    "range-recovery-receipt.schema.json": invalid_range_recovery_receipt_authority,
    "range-source-import.schema.json": invalid_range_import_retention,
    "range-topology.schema.json": invalid_range_topology_authority,
    "range-topology-verdict.schema.json": invalid_range_topology_verdict_environment,
    "range-verifier-decision.schema.json": invalid_range_verifier_decision_accept,
    "range-verifier-policy.schema.json": invalid_range_verifier_policy_authority,
    "resource-meter-receipt.schema.json": remove_required_field,
    "sacrificial-replica-plan.schema.json": invalid_sacrificial_replica_network,
    "source-staging-gate-report.schema.json": invalid_source_staging_report,
    "source-quarantine-evidence-receipt.schema.json": invalid_quarantine_evidence,
    "swarm-mission.schema.json": invalid_swarm_mission_authority,
    "swarm-verdict.schema.json": invalid_swarm_verdict_authority,
    "validation-campaign.schema.json": invalid_campaign_steps,
    "verifier-consensus.schema.json": invalid_verifier_consensus_state,
    "verifier-health.schema.json": invalid_verifier_health_write,
    "verifier-observation.schema.json": invalid_verifier_observation_status,
    "verifier-service-policy.schema.json": invalid_verifier_policy_capability,
    "witness-anchor-head.schema.json": invalid_anchor_head_sequence,
    "witness-anchor-policy.schema.json": invalid_anchor_policy_witnesses,
    "witness-anchor-receipt.schema.json": invalid_anchor_receipt_sequence,
    "witness-checkpoint.schema.json": invalid_witness_checkpoint_size,
    "windows-custody-readiness.schema.json": remove_required_field,
    "windows-isolation-measurement.schema.json": remove_required_field,
    "world-model-generation.schema.json": invalid_world_generation_authority,
    "world-observation-envelope.schema.json": invalid_world_observation_authority,
}


def parse_timestamp(value: object, field: str) -> datetime:
    if not isinstance(value, str):
        raise TypeError(f"{field} must be an ISO 8601 string.")
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def validate_authorization_semantics(value: JsonObject) -> tuple[str, ...]:
    issued = parse_timestamp(value.get("issued_at"), "issued_at")
    not_before = parse_timestamp(value.get("not_before"), "not_before")
    expires = parse_timestamp(value.get("expires_at"), "expires_at")
    errors: list[str] = []
    if issued > not_before:
        errors.append("issued_at must not be after not_before")
    if not_before >= expires:
        errors.append("not_before must be before expires_at")
    targets = value.get("target_graph")
    if isinstance(targets, list):
        production = any(isinstance(target, dict) and target.get("environment_class") == "production" for target in targets)
        if production and value.get("effect_ceiling") == "sacrificial_replica_only":
            errors.append("ordinary production cannot use the sacrificial-replica effect ceiling")
    return tuple(errors)


def validate_campaign_semantics(value: JsonObject) -> tuple[str, ...]:
    raw_steps = value.get("steps")
    if not isinstance(raw_steps, list):
        return ("steps must be a list",)
    steps = [step for step in raw_steps if isinstance(step, dict)]
    identifiers = [str(step.get("step_id") or "") for step in steps]
    sequences = [step.get("sequence") for step in steps]
    errors: list[str] = []
    if len(identifiers) != len(set(identifiers)):
        errors.append("campaign step IDs must be unique")
    if len(sequences) != len(set(sequences)):
        errors.append("campaign step sequence values must be unique")
    if sequences != sorted(sequences):
        errors.append("campaign steps must be ordered by sequence")
    return tuple(errors)


def validate_authorization_proof_semantics(value: JsonObject) -> tuple[str, ...]:
    raw_signatures = value.get("signatures")
    if not isinstance(raw_signatures, list):
        return ("signatures must be a list",)
    signer_ids = [
        str(signature.get("signer_id") or "")
        for signature in raw_signatures
        if isinstance(signature, dict)
    ]
    if len(signer_ids) != len(set(signer_ids)):
        return ("authorization proof signer IDs must be unique",)
    return ()


def validate_trust_policy_semantics(value: JsonObject) -> tuple[str, ...]:
    raw_signers = value.get("trusted_signers")
    if not isinstance(raw_signers, list):
        return ("trusted_signers must be a list",)
    signer_ids = [str(signer.get("signer_id") or "") for signer in raw_signers if isinstance(signer, dict)]
    roles = {str(signer.get("role") or "") for signer in raw_signers if isinstance(signer, dict)}
    required_roles = value.get("required_roles")
    threshold = value.get("threshold")
    errors: list[str] = []
    if len(signer_ids) != len(set(signer_ids)):
        errors.append("trusted signer IDs must be unique")
    if isinstance(threshold, int) and threshold > len(signer_ids):
        errors.append("trust threshold cannot exceed distinct trusted signers")
    if isinstance(required_roles, list):
        missing = sorted(str(role) for role in required_roles if str(role) not in roles)
        if missing:
            errors.append(f"required roles lack a trusted signer: {', '.join(missing)}")
    return tuple(errors)


def validate_key_governance_state_semantics(value: JsonObject) -> tuple[str, ...]:
    raw_keys = value.get("keys")
    if not isinstance(raw_keys, list):
        return ("keys must be a list",)
    keys = [key for key in raw_keys if isinstance(key, dict)]
    key_ids = [str(key.get("key_id") or "") for key in keys]
    public_keys = [str(key.get("public_key_base64") or "") for key in keys]
    active = [key for key in keys if key.get("status") == "active"]
    active_roles = {str(key.get("role") or "") for key in active}
    ceremony_count = value.get("ceremony_key_count")
    minimum_roles = value.get("minimum_distinct_roles")
    errors: list[str] = []
    if len(key_ids) != len(set(key_ids)):
        errors.append("key governance key IDs must be unique")
    if len(public_keys) != len(set(public_keys)):
        errors.append("key governance public keys must be unique")
    if isinstance(ceremony_count, int) and len(active) != ceremony_count:
        errors.append("key governance must have exactly the ceremony key count active")
    if isinstance(minimum_roles, int) and len(active_roles) < minimum_roles:
        errors.append("active key roles do not satisfy minimum diversity")
    for key in keys:
        custody = key.get("custody")
        if not isinstance(custody, dict):
            errors.append("every key requires custody metadata")
            continue
        if custody.get("private_key_exportable") is not False:
            errors.append("private key custody must be non-exportable")
        if custody.get("allowed_operations") != ["sign"]:
            errors.append("custody must allow only signing")
    return tuple(errors)


def validate_key_transition_semantics(value: JsonObject) -> tuple[str, ...]:
    from_epoch = value.get("from_epoch")
    to_epoch = value.get("to_epoch")
    signatures = value.get("signatures")
    errors: list[str] = []
    if isinstance(from_epoch, int) and isinstance(to_epoch, int) and to_epoch != from_epoch + 1:
        errors.append("key governance transition epochs must be consecutive")
    if isinstance(signatures, list):
        signer_ids = [str(signature.get("signer_id") or "") for signature in signatures if isinstance(signature, dict)]
        if len(signer_ids) != len(set(signer_ids)):
            errors.append("key governance transition signer IDs must be unique")
    return tuple(errors)


def validate_witness_checkpoint_semantics(value: JsonObject) -> tuple[str, ...]:
    signatures = value.get("signatures")
    if not isinstance(signatures, list):
        return ("checkpoint signatures must be a list",)
    signer_ids = [str(signature.get("signer_id") or "") for signature in signatures if isinstance(signature, dict)]
    if len(signer_ids) != len(set(signer_ids)):
        return ("checkpoint signer IDs must be unique",)
    return ()


def validate_anchor_policy_semantics(value: JsonObject) -> tuple[str, ...]:
    not_before = parse_timestamp(value.get("not_before"), "not_before")
    expires_at = parse_timestamp(value.get("expires_at"), "expires_at")
    if not_before >= expires_at:
        return ("anchor policy not_before must precede expires_at",)
    return ()


def validate_anchor_receipt_semantics(value: JsonObject) -> tuple[str, ...]:
    sequence = value.get("sequence")
    previous = value.get("previous_receipt_digest")
    if sequence == 1 and previous is not None:
        return ("first anchor receipt cannot have a previous receipt digest",)
    if isinstance(sequence, int) and sequence > 1 and previous is None:
        return ("later anchor receipts require a previous receipt digest",)
    return ()


def validate_anchor_head_semantics(value: JsonObject) -> tuple[str, ...]:
    if value.get("sequence") == 1 and value.get("tree_size") is None:
        return ("anchor head must bind a tree size",)
    return ()


def validate_verifier_policy_semantics(value: JsonObject) -> tuple[str, ...]:
    expected_account = value.get("expected_os_account_identifier")
    boundary_status = value.get("os_account_boundary_status")
    origin = value.get("origin")
    if origin == "live" and (expected_account is None or boundary_status != "verified"):
        return ("live verifier policy requires a verified expected OS account",)
    return ()


def validate_verifier_observation_semantics(value: JsonObject) -> tuple[str, ...]:
    if value.get("status") == "valid":
        errors: list[str] = []
        if value.get("subject_digest") is None:
            errors.append("valid verifier observation requires a subject digest")
        if value.get("process_id") is None:
            errors.append("valid verifier observation requires a process ID")
        if value.get("read_only_behavior_verified") is not True:
            errors.append("valid verifier observation requires read-only behavior verification")
        if value.get("credential_environment_variable_count") != 0:
            errors.append("valid verifier observation cannot expose credential environment variables")
        return tuple(errors)
    return ()


def validate_verifier_consensus_semantics(value: JsonObject) -> tuple[str, ...]:
    accepted = value.get("verification_accepted") is True
    state = value.get("state")
    if accepted != (state == "agreed_valid"):
        return ("verification can be accepted only for agreed_valid",)
    return ()


def validate_verifier_health_semantics(value: JsonObject) -> tuple[str, ...]:
    if value.get("production_ready") is True and value.get("os_account_boundary_verified") is not True:
        return ("production-ready verifier health requires OS account isolation",)
    return ()


def validate_control_board_verifier_semantics(value: JsonObject) -> tuple[str, ...]:
    authority = value.get("authority")
    boundary = value.get("boundary")
    if not isinstance(authority, dict) or not isinstance(boundary, dict):
        return ("control-board verifier authority and boundary must be objects",)
    production_ready = boundary.get("production_ready") is True
    accepted_rendering = authority.get("may_mark_verification_accepted") is True
    errors: list[str] = []
    if authority.get("can_authorize") is not False or authority.get("can_execute") is not False:
        errors.append("control-board verifier projection cannot authorize or execute")
    if production_ready != accepted_rendering:
        errors.append("accepted rendering must equal production boundary readiness")
    if production_ready and (value.get("operator_state") != "verified" or value.get("severity") != "verified"):
        errors.append("production-ready projection must render a verified operator state")
    if production_ready and (
        boundary.get("isolation_evidence_verified") is not True
        or boundary.get("live_os_enforcement_verified") is not True
        or boundary.get("dedicated_os_identity_verified") is not True
        or boundary.get("os_read_only_acl_verified") is not True
    ):
        errors.append("production-ready projection requires complete live OS-isolation evidence")
    digests = boundary.get("isolation_attestation_digests")
    if not isinstance(digests, list) or len(digests) != 2 or len(set(str(item) for item in digests)) != 2:
        errors.append("verifier projection must bind exactly two isolation attestation digests")
    if not production_ready and value.get("severity") != "blocked":
        errors.append("non-production verifier projection must remain blocked")
    return tuple(errors)


def validate_control_board_snapshot_semantics(value: JsonObject) -> tuple[str, ...]:
    issued_at = parse_timestamp(value.get("issued_at"), "issued_at")
    not_before = parse_timestamp(value.get("not_before"), "not_before")
    expires_at = parse_timestamp(value.get("expires_at"), "expires_at")
    signatures = value.get("signatures")
    authority = value.get("authority")
    errors: list[str] = []
    if issued_at > not_before or not_before >= expires_at:
        errors.append("snapshot requires issued_at <= not_before < expires_at")
    if isinstance(signatures, list):
        signer_ids = [
            str(signature.get("signer_id") or "")
            for signature in signatures
            if isinstance(signature, dict)
        ]
        if len(signer_ids) != len(set(signer_ids)):
            errors.append("snapshot signer IDs must be unique")
    if not isinstance(authority, dict) or authority.get("can_authorize") is not False or authority.get("can_execute") is not False:
        errors.append("snapshot transport cannot authorize or execute")
    return tuple(errors)


def validate_control_board_ingress_semantics(value: JsonObject) -> tuple[str, ...]:
    authority = value.get("authority")
    if not isinstance(authority, dict):
        return ("ingress authority must be an object",)
    if authority.get("can_authorize") is not False or authority.get("can_execute") is not False:
        return ("ingress receipt cannot authorize or execute",)
    return ()


def validate_range_import_semantics(value: JsonObject) -> tuple[str, ...]:
    findings = value.get("findings")
    authority = value.get("authority")
    errors: list[str] = []
    if value.get("quarantine_status") == "eligible_for_no_execution_mapping" and findings != []:
        errors.append("eligible range imports cannot contain findings")
    if value.get("raw_execution_material_retained") is not False:
        errors.append("range imports cannot retain raw execution material")
    if not isinstance(authority, dict) or any(
        authority.get(field) is not False for field in ("can_connect", "can_execute", "can_discover_targets")
    ):
        errors.append("range import authority must remain false")
    return tuple(errors)


def validate_range_policy_semantics(value: JsonObject) -> tuple[str, ...]:
    mappings = value.get("source_mappings")
    authority = value.get("authority")
    output = value.get("output_template")
    errors: list[str] = []
    if isinstance(mappings, list):
        identities = [
            (
                str(mapping.get("source_kind") or ""),
                str(mapping.get("source_object_id") or ""),
                str(mapping.get("source_artifact_digest") or ""),
            )
            for mapping in mappings
            if isinstance(mapping, dict)
        ]
        if len(identities) != len(set(identities)):
            errors.append("range policy source mappings must be unique")
    if not isinstance(authority, dict) or any(
        authority.get(field) is not False for field in ("can_connect", "can_execute", "can_discover_targets")
    ):
        errors.append("range policy authority must remain false")
    if not isinstance(output, dict) or output.get("connector_id") != "connector.simulated.atomic" or output.get("capability") != "range.test.simulate":
        errors.append("range policy output must remain no-execution only")
    return tuple(errors)


def validate_range_compilation_semantics(value: JsonObject) -> tuple[str, ...]:
    authority = value.get("authority")
    false_fields = (
        "raw_execution_material_forwarded",
        "source_tool_contacted",
        "target_discovery_performed",
        "live_execution_performed",
    )
    errors: list[str] = []
    if any(value.get(field) is not False for field in false_fields):
        errors.append("range compilation receipt must preserve no-execution fields")
    if not isinstance(authority, dict) or any(
        authority.get(field) is not False for field in ("can_connect", "can_execute", "can_discover_targets")
    ):
        errors.append("range compilation authority must remain false")
    return tuple(errors)


def validate_range_policy_envelope_semantics(value: JsonObject) -> tuple[str, ...]:
    issued = parse_timestamp(value.get("issued_at"), "issued_at")
    not_before = parse_timestamp(value.get("not_before"), "not_before")
    expires = parse_timestamp(value.get("expires_at"), "expires_at")
    signatures = value.get("signatures")
    authority = value.get("authority")
    errors: list[str] = []
    if issued > not_before or not_before >= expires:
        errors.append("range policy envelope requires issued_at <= not_before < expires_at")
    if isinstance(signatures, list):
        signer_ids = [str(item.get("signer_id") or "") for item in signatures if isinstance(item, dict)]
        if len(signer_ids) != len(set(signer_ids)):
            errors.append("range policy envelope signer IDs must be unique")
    if not isinstance(authority, dict) or any(authority.get(field) is not False for field in ("can_connect", "can_execute", "can_discover_targets")):
        errors.append("range policy envelope authority must remain false")
    return tuple(errors)


def validate_range_corpus_manifest_semantics(value: JsonObject) -> tuple[str, ...]:
    entries = value.get("entries")
    authority = value.get("authority")
    if not isinstance(entries, list):
        return ("range corpus entries must be a list",)
    objects = [entry for entry in entries if isinstance(entry, dict)]
    entry_ids = [str(entry.get("entry_id") or "") for entry in objects]
    paths = [str(entry.get("relative_path") or "") for entry in objects]
    errors: list[str] = []
    if len(entry_ids) != len(set(entry_ids)):
        errors.append("range corpus entry IDs must be unique")
    if len(paths) != len(set(paths)):
        errors.append("range corpus paths must be unique")
    if value.get("snapshot_digest") != sha256_digest(entries):
        errors.append("range corpus snapshot digest must bind its ordered entries")
    if authority != {"can_fetch": False, "can_compile": False, "can_execute": False}:
        errors.append("range corpus manifest authority must remain false")
    return tuple(errors)


def validate_range_corpus_report_semantics(value: JsonObject) -> tuple[str, ...]:
    items = value.get("items")
    authority = value.get("authority")
    if not isinstance(items, list):
        return ("range corpus report items must be a list",)
    declared = value.get("declared_entry_count")
    compatible = value.get("compatible_entry_count")
    blocked = value.get("blocked_entry_count")
    errors: list[str] = []
    if declared != len(items):
        errors.append("range corpus declared count must match items")
    if isinstance(compatible, int) and isinstance(blocked, int) and declared != compatible + blocked:
        errors.append("range corpus compatible and blocked counts must equal declared count")
    clean = blocked == 0 and value.get("missing_files") == [] and value.get("unexpected_files") == []
    if (value.get("status") == "compatible_no_execution") != clean:
        errors.append("range corpus compatibility status must match counts and file-set checks")
    if any(value.get(field) is not False for field in ("compilation_performed", "source_tool_contacted", "network_access_performed", "live_execution_performed")):
        errors.append("range corpus report activity fields must remain false")
    if authority != {"can_connect": False, "can_compile": False, "can_execute": False}:
        errors.append("range corpus report authority must remain false")
    return tuple(errors)


def validate_range_preflight_semantics(value: JsonObject) -> tuple[str, ...]:
    controls = value.get("controls")
    authority = value.get("authority")
    if not isinstance(controls, list):
        return ("range preflight controls must be a list",)
    required = {
        "CLEANUP_CONTRACT", "DEDICATED_CREDENTIALS", "DEFAULT_DENY_EGRESS",
        "DISPOSABLE_TARGET", "INDEPENDENT_VERIFIER", "OUT_OF_BAND_KILL",
        "RESTORABLE_SNAPSHOT", "TELEMETRY_SEPARATION", "TRUSTED_TIME",
    }
    objects = [control for control in controls if isinstance(control, dict)]
    identifiers = [str(control.get("control_id") or "") for control in objects]
    errors: list[str] = []
    if len(identifiers) != len(set(identifiers)) or set(identifiers) != required:
        errors.append("range preflight must contain each required control exactly once")
    if any(control.get("status") == "proven" and not control.get("evidence") for control in objects):
        errors.append("proven range preflight controls require evidence")
    if authority != {"can_connect": False, "can_execute": False}:
        errors.append("range preflight authority must remain false")
    return tuple(errors)


def validate_range_preflight_result_semantics(value: JsonObject) -> tuple[str, ...]:
    status = value.get("status")
    gate = value.get("connection_gate_satisfied")
    blocked = value.get("blocked_controls")
    authority = value.get("authority")
    errors: list[str] = []
    if not isinstance(blocked, list):
        errors.append("range preflight blocked_controls must be a list")
    elif (status == "ready_for_separately_authorized_range_connection") != (gate is True and not blocked):
        errors.append("range preflight result status must match the connection gate and blockers")
    if any(value.get(field) is not False for field in ("tool_installation_authorized", "range_connection_authorized", "execution_authorized")):
        errors.append("range preflight result cannot authorize installation, connection, or execution")
    if authority != {"can_connect": False, "can_execute": False}:
        errors.append("range preflight result authority must remain false")
    return tuple(errors)


def validate_range_topology_semantics(value: JsonObject) -> tuple[str, ...]:
    zones = value.get("zones")
    nodes = value.get("nodes")
    routes = value.get("routes")
    authority = value.get("authority")
    if not isinstance(zones, list) or not isinstance(nodes, list) or not isinstance(routes, list):
        return ("range topology zones, nodes, and routes must be lists",)
    zone_objects = [item for item in zones if isinstance(item, dict)]
    node_objects = [item for item in nodes if isinstance(item, dict)]
    route_objects = [item for item in routes if isinstance(item, dict)]
    errors: list[str] = []
    for objects, field, label in (
        (zone_objects, "zone_id", "zone"),
        (node_objects, "node_id", "node"),
        (route_objects, "route_id", "route"),
    ):
        identifiers = [str(item.get(field) or "") for item in objects]
        if len(identifiers) != len(set(identifiers)):
            errors.append(f"range topology {label} IDs must be unique")
    credential_scopes = [str(item.get("credential_scope") or "") for item in node_objects]
    if len(credential_scopes) != len(set(credential_scopes)):
        errors.append("range topology credential scopes must be unique")
    if authority != {"can_provision": False, "can_connect": False, "can_execute": False}:
        errors.append("range topology authority must remain false")
    return tuple(errors)


def validate_range_topology_verdict_semantics(value: JsonObject) -> tuple[str, ...]:
    authority = value.get("authority")
    errors: list[str] = []
    if value.get("environment_verified") is not False or value.get("provisioning_performed") is not False or value.get("network_contact_performed") is not False:
        errors.append("range topology verdict must remain declaration-only and unverified")
    if authority != {"can_provision": False, "can_connect": False, "can_execute": False}:
        errors.append("range topology verdict authority must remain false")
    return tuple(errors)


def validate_range_connector_capability_semantics(value: JsonObject) -> tuple[str, ...]:
    issued = parse_timestamp(value.get("issued_at"), "issued_at")
    not_before = parse_timestamp(value.get("not_before"), "not_before")
    expires = parse_timestamp(value.get("expires_at"), "expires_at")
    signatures = value.get("signatures")
    errors: list[str] = []
    if issued > not_before or not_before >= expires:
        errors.append("range connector capability requires issued_at <= not_before < expires_at")
    if value.get("capability_allowlist") != ["range.test.simulate"]:
        errors.append("range connector capability must expose only range.test.simulate")
    if value.get("operation_allowlist") != ["compile", "preflight", "verify"]:
        errors.append("range connector capability operations must remain non-executing")
    for field in ("network_destinations", "secret_references"):
        if value.get(field) != []:
            errors.append(f"range connector capability {field} must remain empty")
    for field in ("installation_required", "source_tool_contact_required", "target_discovery_performed"):
        if value.get(field) is not False:
            errors.append(f"range connector capability {field} must remain false")
    expected_authority = {
        "can_install": False,
        "can_provision": False,
        "can_connect": False,
        "can_execute": False,
        "can_discover_targets": False,
    }
    if value.get("authority") != expected_authority:
        errors.append("range connector capability authority must remain false")
    if isinstance(signatures, list):
        signer_ids = [str(item.get("signer_id") or "") for item in signatures if isinstance(item, dict)]
        if len(signer_ids) != len(set(signer_ids)):
            errors.append("range connector capability signer IDs must be unique")
    return tuple(errors)


def validate_range_collector_policy_semantics(value: JsonObject) -> tuple[str, ...]:
    collectors = value.get("collectors")
    environment = value.get("environment")
    errors: list[str] = []
    if not isinstance(collectors, list) or len(collectors) != 9:
        return ("range collector policy requires nine collectors",)
    objects = [item for item in collectors if isinstance(item, dict)]
    for field in ("collector_id", "logical_principal", "process_id", "public_key_base64", "allowed_control_id"):
        values = [str(item.get(field) or "") for item in objects]
        if len(values) != 9 or len(values) != len(set(values)):
            errors.append(f"range collector policy {field} values must be unique")
    if any(item.get("read_only") is not True for item in objects):
        errors.append("range collectors must remain read-only")
    if any(item.get("operation_allowlist") != ["digest", "emit_attestation", "observe"] for item in objects):
        errors.append("range collector operations must remain observe, digest, and emit_attestation")
    if any(item.get("network_destinations") != [] or item.get("secret_references") != [] for item in objects):
        errors.append("range collectors cannot declare destinations or secrets")
    if not isinstance(environment, dict) or environment.get("owner_named") is not False:
        errors.append("canonical range collector policy must preserve the missing owner-named environment")
    if value.get("blockers") != ["OWNER_NAMED_SACRIFICIAL_RANGE_MISSING"]:
        errors.append("range collector policy must preserve the owner-name blocker")
    if value.get("authority") != {
        "can_install": False,
        "can_provision": False,
        "can_change_policy": False,
        "can_access_credentials": False,
        "can_contact_source_tools": False,
        "can_open_network_connection": False,
        "can_execute": False,
    }:
        errors.append("range collector policy authority must remain false")
    return tuple(errors)


def validate_range_environment_observation_semantics(value: JsonObject) -> tuple[str, ...]:
    raw_evidence = value.get("raw_evidence")
    errors: list[str] = []
    if not isinstance(raw_evidence, dict):
        return ("range environment observation requires raw evidence",)
    payload_base64 = raw_evidence.get("payload_base64")
    if not isinstance(payload_base64, str):
        errors.append("range environment observation payload must be base64 text")
    else:
        try:
            payload = base64.b64decode(payload_base64, validate=True)
        except (binascii.Error, ValueError):
            errors.append("range environment observation payload must be canonical base64")
        else:
            if raw_evidence.get("byte_length") != len(payload):
                errors.append("range environment observation byte length must match retained payload")
            if raw_evidence.get("digest") != f"sha256:{hashlib.sha256(payload).hexdigest()}":
                errors.append("range environment observation digest must match retained payload")
    if raw_evidence.get("retention_mode") != "inline_content_addressed":
        errors.append("range environment observation must retain content-addressed raw evidence")
    if raw_evidence.get("contains_credentials") is not False or raw_evidence.get("contains_secrets") is not False:
        errors.append("range environment observation cannot contain credentials or secrets")
    if value.get("activity") != {
        "environment_contact_performed_by_nimrod": False,
        "policy_mutation_performed": False,
        "credential_access_performed": False,
        "tool_installation_performed": False,
        "source_tool_contact_performed": False,
        "network_contact_performed": False,
        "campaign_execution_performed": False,
    }:
        errors.append("range environment observation activity must remain false")
    if value.get("authority") != {
        "can_install": False,
        "can_provision": False,
        "can_change_policy": False,
        "can_access_credentials": False,
        "can_connect": False,
        "can_execute": False,
        "can_verify_attestation": False,
    }:
        errors.append("range environment observation authority must remain false")
    return tuple(errors)


def validate_range_evidence_admission_semantics(value: JsonObject) -> tuple[str, ...]:
    retained = value.get("retained_observations")
    attestations = value.get("emitted_attestations")
    errors: list[str] = []
    if not isinstance(retained, list) or len(retained) != 9:
        errors.append("range evidence admission must retain nine observations")
    if not isinstance(attestations, list) or len(attestations) != 9:
        errors.append("range evidence admission must emit nine attestations")
    else:
        if any(
            not isinstance(item, dict)
            or item.get("status") != "unproven"
            or item.get("verifier") is not None
            for item in attestations
        ):
            errors.append("range evidence admission cannot claim verified attestations")
    if any(value.get(field) != 9 for field in (
        "required_control_count",
        "signed_observation_count",
        "content_addressed_observation_count",
        "distinct_collector_count",
        "emitted_attestation_count",
    )):
        errors.append("range evidence admission counts must preserve all nine controls")
    if value.get("real_observation_count") != 0 or value.get("verified_attestation_count") != 0:
        errors.append("canonical range evidence admission cannot claim real or verified evidence")
    if value.get("owner_named_environment") is not False or value.get("evidence_complete") is not False:
        errors.append("canonical range evidence admission must preserve environment and evidence blockers")
    if value.get("activity") != {
        "infrastructure_provisioned": False,
        "host_or_network_policy_changed": False,
        "credentials_handled": False,
        "tools_installed": False,
        "source_tools_contacted": False,
        "network_contact_performed": False,
        "range_connected": False,
        "campaign_executed": False,
    }:
        errors.append("range evidence admission activity must remain false")
    if value.get("authority") != {
        "can_install": False,
        "can_provision": False,
        "can_change_policy": False,
        "can_access_credentials": False,
        "can_connect": False,
        "can_execute": False,
        "can_mark_evidence_complete": False,
        "can_verify_attestation": False,
    }:
        errors.append("range evidence admission authority must remain false")
    return tuple(errors)


def validate_range_verifier_policy_semantics(value: JsonObject) -> tuple[str, ...]:
    verifiers = value.get("verifiers")
    errors: list[str] = []
    if not isinstance(verifiers, list) or len(verifiers) != 3:
        return ("range verifier policy requires three verifier identities",)
    objects = [item for item in verifiers if isinstance(item, dict)]
    for field in ("verifier_id", "logical_principal", "process_id", "public_key_base64"):
        values = [str(item.get(field) or "") for item in objects]
        if len(values) != 3 or len(values) != len(set(values)):
            errors.append(f"range verifier policy {field} values must be unique")
    if any(item.get("read_only") is not True for item in objects):
        errors.append("range verifiers must remain read-only")
    if any(
        item.get("operation_allowlist") != ["emit_decision", "inspect_retained_observation"]
        for item in objects
    ):
        errors.append("range verifier operations must remain inspect and decide only")
    if any(
        item.get("identity_enforcement") != "fixture_logical_only"
        or item.get("independence_evidence_digest") is not None
        for item in objects
    ):
        errors.append("canonical range verifier identities must remain fixture-only and unproven")
    if any(
        item.get("collector_identity_shared") is not False
        or item.get("network_destinations") != []
        or item.get("secret_references") != []
        for item in objects
    ):
        errors.append("range verifiers cannot share collector identity, destinations, or secrets")
    if value.get("minimum_decisions_per_observation") != 2:
        errors.append("range verifier policy requires two decisions per observation")
    if value.get("allowed_decisions") != ["abstain", "accept", "reject", "timeout"]:
        errors.append("range verifier policy must preserve the full decision vocabulary")
    if value.get("blockers") != [
        "EVIDENCE_COMPLETION_AUTHORITY_MISSING",
        "REAL_INDEPENDENT_VERIFIER_ACCEPTANCE_MISSING",
    ]:
        errors.append("canonical range verifier policy must preserve fixture and completion blockers")
    if value.get("authority") != {
        "can_collect": False,
        "can_install": False,
        "can_provision": False,
        "can_change_policy": False,
        "can_access_credentials": False,
        "can_connect": False,
        "can_execute": False,
        "can_mark_evidence_complete": False,
        "can_authorize_action": False,
    }:
        errors.append("range verifier policy authority must remain false")
    return tuple(errors)


def validate_range_verifier_decision_semantics(value: JsonObject) -> tuple[str, ...]:
    errors: list[str] = []
    decision = value.get("decision")
    reasons = {
        "accept": "evidence_supports_control",
        "reject": "evidence_contradicts_control",
        "abstain": "insufficient_or_fixture_evidence",
        "timeout": "verification_deadline_exceeded",
    }
    if value.get("origin") == "simulated" and decision == "accept":
        errors.append("simulated evidence cannot receive an accepting decision")
    if reasons.get(str(decision)) != value.get("reason"):
        errors.append("range verifier decision reason must match the decision")
    if value.get("evidence_read_only") is not True:
        errors.append("range verifier decision must preserve read-only evidence")
    if value.get("activity") != {
        "environment_contact_performed_by_nimrod": False,
        "collection_performed": False,
        "policy_mutation_performed": False,
        "credential_access_performed": False,
        "tool_installation_performed": False,
        "network_contact_performed": False,
        "range_connection_performed": False,
        "campaign_execution_performed": False,
    }:
        errors.append("range verifier decision activity must remain false")
    if value.get("authority") != {
        "can_collect": False,
        "can_install": False,
        "can_provision": False,
        "can_change_policy": False,
        "can_access_credentials": False,
        "can_connect": False,
        "can_execute": False,
        "can_mark_evidence_complete": False,
        "can_authorize_action": False,
    }:
        errors.append("range verifier decision authority must remain false")
    verifier = value.get("verifier")
    signature = value.get("signature")
    if not isinstance(verifier, dict) or not isinstance(signature, dict):
        errors.append("range verifier decision identity and signature must be objects")
    elif verifier.get("verifier_id") != signature.get("signer_id"):
        errors.append("range verifier decision signer must equal verifier identity")
    return tuple(errors)


def validate_range_evidence_acceptance_semantics(value: JsonObject) -> tuple[str, ...]:
    retained = value.get("retained_decisions")
    controls = value.get("control_results")
    resolutions = value.get("resolution_counts")
    errors: list[str] = []
    if not isinstance(retained, list) or len(retained) != 18:
        errors.append("range evidence acceptance must retain eighteen decisions")
    if not isinstance(controls, list) or len(controls) != 9:
        errors.append("range evidence acceptance must preserve nine control results")
    if not isinstance(resolutions, dict):
        errors.append("range evidence acceptance resolution counts must be an object")
    else:
        counts = [resolutions.get(key) for key in ("accepted", "rejected", "abstained", "disagreement", "timeout")]
        if any(not isinstance(count, int) for count in counts) or sum(int(count) for count in counts if isinstance(count, int)) != 9:
            errors.append("range evidence acceptance resolutions must partition nine controls")
        if resolutions.get("accepted") != 0:
            errors.append("canonical fixture decisions cannot accept a control")
        if any(resolutions.get(key, 0) == 0 for key in ("rejected", "abstained", "disagreement", "timeout")):
            errors.append("canonical acceptance report must preserve every non-success resolution class")
    if value.get("accepted_control_count") != 0 or value.get("verified_attestation_count") != 0:
        errors.append("canonical acceptance report cannot claim accepted controls or verified attestations")
    if value.get("real_independent_verifier_count") != 0 or value.get("evidence_complete") is not False:
        errors.append("canonical acceptance report must preserve real-verifier and completion blockers")
    if value.get("activity") != {
        "environment_contact_performed": False,
        "collection_performed": False,
        "infrastructure_provisioned": False,
        "host_or_network_policy_changed": False,
        "credentials_handled": False,
        "tools_installed": False,
        "network_contact_performed": False,
        "range_connected": False,
        "campaign_executed": False,
    }:
        errors.append("range evidence acceptance activity must remain false")
    if value.get("authority") != {
        "can_collect": False,
        "can_install": False,
        "can_provision": False,
        "can_change_policy": False,
        "can_access_credentials": False,
        "can_connect": False,
        "can_execute": False,
        "can_mark_evidence_complete": False,
        "can_authorize_action": False,
    }:
        errors.append("range evidence acceptance authority must remain false")
    return tuple(errors)


def validate_range_evidence_completion_policy_semantics(value: JsonObject) -> tuple[str, ...]:
    errors: list[str] = []
    required_controls = value.get("required_controls")
    if not isinstance(required_controls, list) or len(required_controls) != 9 or len(set(required_controls)) != 9:
        errors.append("range evidence completion policy must require nine unique controls")
    if any(
        value.get(field) != expected
        for field, expected in (
            ("required_accepted_control_count", 9),
            ("required_verified_attestation_count", 9),
            ("required_real_independent_verifier_count", 2),
        )
    ):
        errors.append("range evidence completion policy cannot weaken completion thresholds")
    if value.get("network_destinations") != [] or value.get("secret_references") != []:
        errors.append("range evidence completion policy cannot declare destinations or secrets")
    if value.get("authority") != {
        "can_collect": False,
        "can_install": False,
        "can_provision": False,
        "can_change_policy": False,
        "can_access_credentials": False,
        "can_connect": False,
        "can_execute": False,
        "can_mark_evidence_complete": False,
        "can_authorize_action": False,
    }:
        errors.append("range evidence completion policy authority must remain false")
    return tuple(errors)


def validate_range_evidence_completion_authorization_semantics(value: JsonObject) -> tuple[str, ...]:
    authority = value.get("authority")
    errors: list[str] = []
    if value.get("origin") == "simulated" and value.get("outcome") != "deny_completion":
        errors.append("simulated evidence completion must remain denied")
    if not isinstance(authority, dict):
        errors.append("range evidence completion authorization authority must be an object")
    else:
        if any(authority.get(field) is not False for field in (
            "can_collect",
            "can_install",
            "can_provision",
            "can_change_policy",
            "can_access_credentials",
            "can_connect",
            "can_execute",
            "can_authorize_action",
        )):
            errors.append("range evidence completion authorization cannot widen operational authority")
        if authority.get("can_mark_evidence_complete") != (value.get("outcome") == "authorize_completion"):
            errors.append("completion authority must match the signed outcome")
    return tuple(errors)


def validate_range_evidence_completion_receipt_semantics(value: JsonObject) -> tuple[str, ...]:
    errors: list[str] = []
    if value.get("origin") == "simulated" and any(
        value.get(field) is not False
        for field in ("completion_prerequisites_satisfied", "completion_authorized", "evidence_complete")
    ):
        errors.append("canonical completion receipt cannot complete simulated evidence")
    if value.get("range_connection_authorized") is not False or value.get("execution_authorized") is not False:
        errors.append("evidence completion cannot authorize connection or execution")
    if value.get("activity") != {
        "environment_contact_performed": False,
        "collection_performed": False,
        "infrastructure_provisioned": False,
        "host_or_network_policy_changed": False,
        "credentials_handled": False,
        "tools_installed": False,
        "network_contact_performed": False,
        "range_connected": False,
        "campaign_executed": False,
    }:
        errors.append("range evidence completion activity must remain false")
    if value.get("authority") != {
        "can_collect": False,
        "can_install": False,
        "can_provision": False,
        "can_change_policy": False,
        "can_access_credentials": False,
        "can_connect": False,
        "can_execute": False,
        "can_mark_evidence_complete": False,
        "can_authorize_action": False,
    }:
        errors.append("range evidence completion receipt authority must remain false")
    return tuple(errors)


def validate_public_source_registry_semantics(value: JsonObject) -> tuple[str, ...]:
    owner_boundary = value.get("owner_boundary")
    sources = value.get("sources")
    errors: list[str] = []
    if not isinstance(owner_boundary, dict):
        errors.append("public source registry requires an owner boundary")
    else:
        excluded = {str(item).casefold() for item in owner_boundary.get("excluded_organizations", [])}
        if owner_boundary.get("registry_complete") is not False or owner_boundary.get("unknown_ownership_action") != "deny":
            errors.append("owner exclusions must remain incomplete and deny unknown ownership")
        if "obtuseai" not in excluded:
            errors.append("public source registry must exclude obtuseai")
    if not isinstance(sources, list) or len(sources) != 5:
        errors.append("public source registry requires five pinned sources")
    elif any(
        not isinstance(item, dict)
        or item.get("source_downloaded") is not False
        or item.get("public_target_authorized") is not False
        or item.get("authorized_network_targets") != []
        for item in sources
    ):
        errors.append("public sources must remain metadata-only and non-targetable")
    if value.get("authority") != {
        "can_download_source": False,
        "can_build_replica": False,
        "can_provision": False,
        "can_connect": False,
        "can_execute": False,
        "can_target_public_host": False,
        "can_authorize_action": False,
    }:
        errors.append("public source registry authority must remain false")
    return tuple(errors)


def validate_sacrificial_replica_plan_semantics(value: JsonObject) -> tuple[str, ...]:
    network = value.get("network")
    replicas = value.get("replicas")
    errors: list[str] = []
    if not isinstance(network, dict) or any(network.get(field) is not False for field in (
        "upstream_access",
        "internet_egress",
        "public_ingress",
        "github_access",
        "registry_access",
        "dns_external_resolution",
    )):
        errors.append("sacrificial replica network must remain offline and default-deny")
    if not isinstance(replicas, list) or len(replicas) != 5:
        errors.append("sacrificial replica plan requires five declarations")
    elif any(
        not isinstance(item, dict)
        or any(item.get(field) is not False for field in (
            "source_archive_present",
            "image_built",
            "replica_provisioned",
            "network_connected",
            "public_target_authorized",
            "execution_authorized",
        ))
        for item in replicas
    ):
        errors.append("sacrificial replicas cannot claim staging, build, connection, or execution")
    return tuple(errors)


def validate_public_corpus_intake_semantics(value: JsonObject) -> tuple[str, ...]:
    errors: list[str] = []
    if any(value.get(field) != expected for field, expected in (
        ("pinned_source_count", 5),
        ("metadata_reviewed_source_count", 5),
        ("source_archive_count", 0),
        ("replica_declared_count", 5),
        ("replica_ready_count", 0),
    )):
        errors.append("public corpus intake counts must preserve metadata-only state")
    if any(value.get(field) is not False for field in (
        "owner_exclusion_registry_complete",
        "public_host_target_authorized",
        "range_connection_authorized",
        "execution_authorized",
    )):
        errors.append("public corpus intake cannot claim owner completeness or operational authority")
    activity = value.get("activity")
    if not isinstance(activity, dict) or activity.get("github_metadata_network_read_performed") is not True:
        errors.append("public corpus intake must disclose live metadata research")
    elif any(activity.get(field) is not False for field in (
        "repository_content_downloaded",
        "source_archive_staged",
        "dependency_resolution_performed",
        "container_image_pulled",
        "replica_built",
        "infrastructure_provisioned",
        "public_host_contacted_for_testing",
        "campaign_executed",
    )):
        errors.append("public corpus intake cannot claim source, build, targeting, or execution activity")
    return tuple(errors)


def validate_owner_scope_registry_semantics(value: JsonObject) -> tuple[str, ...]:
    errors: list[str] = []
    if value.get("registry_complete") is not False or value.get("owner_attestation_present") is not False:
        errors.append("owner scope registry cannot claim completion or owner attestation")
    if value.get("unknown_ownership_action") != "deny":
        errors.append("owner scope registry must deny unknown ownership")
    if {str(item).casefold() for item in cast(list[object], value.get("excluded_organizations", []))} != {"obtuseai"}:
        errors.append("owner scope registry must preserve the known organization exclusion")
    if {str(item).casefold() for item in cast(list[object], value.get("excluded_repositories", []))} != {"obtuseai/nimrod"}:
        errors.append("owner scope registry must preserve the known repository exclusion")
    if value.get("ownership_proof_digests") != []:
        errors.append("owner scope registry cannot fabricate ownership proof")
    if value.get("authority") != {
        "can_complete_registry": False,
        "can_attest_ownership": False,
        "can_stage_source": False,
        "can_authorize_action": False,
    }:
        errors.append("owner scope registry authority must remain false")
    return tuple(errors)


def validate_source_staging_authorization_semantics(value: JsonObject) -> tuple[str, ...]:
    errors: list[str] = []
    if value.get("outcome") != "deny_staging" or value.get("status") != "signed_denial_owner_scope_incomplete":
        errors.append("source staging authorization must preserve the signed denial")
    if value.get("authorized_source_ids") != [] or value.get("authorized_content_digests") != []:
        errors.append("source staging denial cannot authorize sources or content")
    if value.get("construction_zone_id") is not None:
        errors.append("source staging denial cannot name an unproven construction zone")
    network = value.get("network")
    if not isinstance(network, dict) or any(
        network.get(field) is not False
        for field in ("internet_egress", "public_ingress", "github_access", "registry_access", "external_dns_resolution")
    ):
        errors.append("source staging network must remain offline")
    if value.get("authority") != {
        "can_download_source": False,
        "can_stage_source": False,
        "can_extract_source": False,
        "can_resolve_dependencies": False,
        "can_build_replica": False,
        "can_provision": False,
        "can_connect": False,
        "can_execute": False,
        "can_target_public_host": False,
        "can_authorize_action": False,
    }:
        errors.append("source staging authority must remain false")
    return tuple(errors)


def validate_source_staging_gate_semantics(value: JsonObject) -> tuple[str, ...]:
    errors: list[str] = []
    if any(
        value.get(field) != expected
        for field, expected in (
            ("requested_source_count", 5),
            ("authorized_source_count", 0),
            ("staged_source_count", 0),
            ("quarantine_requirement_count", 8),
            ("quarantine_completed_count", 0),
        )
    ):
        errors.append("source staging report counts must preserve the denied state")
    if any(
        value.get(field) is not False
        for field in (
            "owner_exclusion_registry_complete",
            "owner_attestation_present",
            "staging_authorized",
            "build_authorized",
            "range_connection_authorized",
            "execution_authorized",
        )
    ):
        errors.append("source staging report cannot claim owner or operational authority")
    activity = value.get("activity")
    if not isinstance(activity, dict) or any(item is not False for item in activity.values()):
        errors.append("source staging report activity must remain false")
    authority = value.get("authority")
    if not isinstance(authority, dict) or any(item is not False for item in authority.values()):
        errors.append("source staging report authority must remain false")
    return tuple(errors)


def validate_construction_zone_semantics(value: JsonObject) -> tuple[str, ...]:
    errors: list[str] = []
    controls = value.get("controls")
    if not isinstance(controls, list) or len(controls) != 10:
        errors.append("construction zone requires ten declared controls")
    elif any(
        not isinstance(control, dict)
        or control.get("status") != "unproven"
        or control.get("evidence") != []
        for control in controls
    ):
        errors.append("construction zone controls cannot claim evidence")
    network = value.get("network")
    if not isinstance(network, dict) or network.get("policy_applied") is not False:
        errors.append("construction zone cannot claim network enforcement")
    activity = value.get("activity")
    if not isinstance(activity, dict) or any(item is not False for item in activity.values()):
        errors.append("construction zone activity must remain false")
    authority = value.get("authority")
    if not isinstance(authority, dict) or any(item is not False for item in authority.values()):
        errors.append("construction zone authority must remain false")
    return tuple(errors)


def validate_quarantine_receipt_semantics(value: JsonObject) -> tuple[str, ...]:
    errors: list[str] = []
    if value.get("source_archive_count") != 0 or value.get("source_archive_digests") != []:
        errors.append("quarantine receipt cannot claim unstaged archives")
    results = value.get("results")
    if not isinstance(results, list) or len(results) != 8:
        errors.append("quarantine receipt requires eight results")
    elif any(
        not isinstance(result, dict)
        or result.get("status") != "missing"
        or result.get("performed") is not False
        or result.get("evidence_digest") is not None
        or result.get("evidence") != []
        for result in results
    ):
        errors.append("quarantine results cannot fabricate evidence")
    activity = value.get("activity")
    if not isinstance(activity, dict) or any(item is not False for item in activity.values()):
        errors.append("quarantine receipt activity must remain false")
    return tuple(errors)


def validate_construction_preflight_semantics(value: JsonObject) -> tuple[str, ...]:
    errors: list[str] = []
    if any(
        value.get(field) != expected
        for field, expected in (
            ("zone_control_count", 10),
            ("verified_zone_control_count", 0),
            ("quarantine_requirement_count", 8),
            ("verified_quarantine_requirement_count", 0),
            ("source_archive_count", 0),
        )
    ):
        errors.append("construction preflight counts must preserve missing evidence")
    if any(
        value.get(field) is not False
        for field in (
            "construction_zone_provisioned",
            "quarantine_evidence_complete",
            "staging_authorized",
            "build_authorized",
            "range_connection_authorized",
            "execution_authorized",
        )
    ):
        errors.append("construction preflight cannot claim readiness or operational authority")
    activity = value.get("activity")
    authority = value.get("authority")
    if not isinstance(activity, dict) or any(item is not False for item in activity.values()):
        errors.append("construction preflight activity must remain false")
    if not isinstance(authority, dict) or any(item is not False for item in authority.values()):
        errors.append("construction preflight authority must remain false")
    return tuple(errors)


def validate_construction_attestation_plan_semantics(value: JsonObject) -> tuple[str, ...]:
    errors: list[str] = []
    controls = value.get("controls")
    if not isinstance(controls, list) or len(controls) != 10:
        errors.append("construction attestation plan requires ten controls")
    elif any(
        not isinstance(control, dict)
        or control.get("status") != "unassigned"
        or control.get("evidence") != []
        or any(
            control.get(field) is not None
            for field in (
                "collector_id",
                "collector_principal",
                "collector_process_id",
                "verifier_id",
                "verifier_principal",
                "verifier_process_id",
            )
        )
        for control in controls
    ):
        errors.append("construction attestation plan cannot fabricate observers or evidence")
    activity = value.get("activity")
    authority = value.get("authority")
    if not isinstance(activity, dict) or any(item is not False for item in activity.values()):
        errors.append("construction attestation plan activity must remain false")
    if not isinstance(authority, dict) or any(item is not False for item in authority.values()):
        errors.append("construction attestation plan authority must remain false")
    return tuple(errors)


def validate_construction_provisioning_authorization_semantics(value: JsonObject) -> tuple[str, ...]:
    errors: list[str] = []
    if value.get("outcome") != "deny_provisioning":
        errors.append("construction provisioning authorization must preserve denial")
    if value.get("authorized_operations") != []:
        errors.append("construction provisioning denial cannot authorize operations")
    if value.get("operator_approval_reference") is not None or value.get("provider_id") is not None:
        errors.append("construction provisioning denial cannot fabricate approval or provider selection")
    if value.get("credential_references") != []:
        errors.append("construction provisioning denial cannot carry credentials")
    authority = value.get("authority")
    if not isinstance(authority, dict) or any(item is not False for item in authority.values()):
        errors.append("construction provisioning authorization authority must remain false")
    return tuple(errors)


def validate_construction_provisioning_result_semantics(value: JsonObject) -> tuple[str, ...]:
    errors: list[str] = []
    if any(
        value.get(field) != expected
        for field, expected in (
            ("required_control_count", 10),
            ("assigned_collector_count", 0),
            ("assigned_verifier_count", 0),
            ("verified_control_count", 0),
        )
    ):
        errors.append("construction provisioning result counts must preserve missing observers and evidence")
    if any(
        value.get(field) is not False
        for field in (
            "attestation_plan_complete",
            "operator_approval_present",
            "provider_selected",
            "provisioning_authorized",
            "provisioning_performed",
            "staging_authorized",
            "build_authorized",
            "range_connection_authorized",
            "execution_authorized",
        )
    ):
        errors.append("construction provisioning result cannot claim readiness or operational authority")
    activity = value.get("activity")
    authority = value.get("authority")
    if not isinstance(activity, dict) or any(item is not False for item in activity.values()):
        errors.append("construction provisioning result activity must remain false")
    if not isinstance(authority, dict) or any(item is not False for item in authority.values()):
        errors.append("construction provisioning result authority must remain false")
    return tuple(errors)


def validate_range_scope_semantics(value: JsonObject) -> tuple[str, ...]:
    target_bindings = value.get("target_bindings")
    errors: list[str] = []
    if not isinstance(target_bindings, list) or len(target_bindings) != 1:
        errors.append("range scope must contain exactly one target binding")
    elif isinstance(target_bindings[0], dict):
        target = target_bindings[0]
        if target.get("environment_class") != "range" or target.get("resource_type") != "windows_device":
            errors.append("range scope target must remain a Windows range device")
    if value.get("cryptographic_authorization_verified") is not True:
        errors.append("range scope requires cryptographically verified authorization")
    if value.get("topology_environment_verified") is not False:
        errors.append("range scope cannot claim a verified environment")
    if value.get("capability_intersection") != ["range.test.simulate"]:
        errors.append("range scope capability intersection must remain simulation-only")
    for field in (
        "provisioning_performed",
        "installation_performed",
        "network_contact_performed",
        "range_connection_authorized",
        "execution_authorized",
    ):
        if value.get(field) is not False:
            errors.append(f"range scope {field} must remain false")
    expected_authority = {
        "can_install": False,
        "can_provision": False,
        "can_connect": False,
        "can_execute": False,
    }
    if value.get("authority") != expected_authority:
        errors.append("range scope authority must remain false")
    return tuple(errors)


def validate_range_preexecution_packet_semantics(value: JsonObject) -> tuple[str, ...]:
    required = {
        "CLEANUP_CONTRACT",
        "DEDICATED_CREDENTIALS",
        "DEFAULT_DENY_EGRESS",
        "DISPOSABLE_TARGET",
        "INDEPENDENT_VERIFIER",
        "OUT_OF_BAND_KILL",
        "RESTORABLE_SNAPSHOT",
        "TELEMETRY_SEPARATION",
        "TRUSTED_TIME",
    }
    attestations = value.get("environment_attestations")
    errors: list[str] = []
    if not isinstance(attestations, list):
        errors.append("range preexecution attestations must be a list")
    else:
        objects = [item for item in attestations if isinstance(item, dict)]
        identifiers = [str(item.get("control_id") or "") for item in objects]
        if len(identifiers) != len(set(identifiers)) or set(identifiers) != required:
            errors.append("range preexecution packet must contain every required attestation exactly once")
        if any(
            item.get("origin") != "simulated"
            or item.get("status") != "unproven"
            or item.get("evidence") != []
            or item.get("verifier") is not None
            for item in objects
        ):
            errors.append("simulated preexecution attestations must remain unproven and unverifiable")
    if set(str(item) for item in value.get("required_attestation_controls", [])) != required:
        errors.append("range preexecution required controls must match the exact set")
    if set(str(item) for item in value.get("missing_real_attestations", [])) != required:
        errors.append("range preexecution packet must report every real attestation as missing")
    if value.get("real_environment_attestation_count") != 0 or value.get("distinct_verified_verifier_count") != 0:
        errors.append("range preexecution packet cannot claim real or independently verified evidence")
    if value.get("evidence_complete") is not False:
        errors.append("range preexecution evidence must remain incomplete")
    for field in (
        "provisioning_performed",
        "installation_performed",
        "source_tool_contacted",
        "network_contact_performed",
        "range_connection_authorized",
        "execution_authorized",
    ):
        if value.get(field) is not False:
            errors.append(f"range preexecution packet {field} must remain false")
    expected_authority = {
        "can_install": False,
        "can_provision": False,
        "can_connect": False,
        "can_execute": False,
        "can_mark_evidence_complete": False,
    }
    if value.get("authority") != expected_authority:
        errors.append("range preexecution packet authority must remain false")
    return tuple(errors)


def validate_range_kill_command_semantics(value: JsonObject) -> tuple[str, ...]:
    issued = parse_timestamp(value.get("issued_at"), "issued_at")
    not_before = parse_timestamp(value.get("not_before"), "not_before")
    expires = parse_timestamp(value.get("expires_at"), "expires_at")
    signatures = value.get("signatures")
    authority = value.get("authority")
    errors: list[str] = []
    if issued > not_before or not_before >= expires:
        errors.append("range kill command requires issued_at <= not_before < expires_at")
    if value.get("sequence") != value.get("generation"):
        errors.append("range kill command sequence must equal topology generation")
    if isinstance(signatures, list):
        signer_ids = [str(item.get("signer_id") or "") for item in signatures if isinstance(item, dict)]
        if len(signer_ids) != len(set(signer_ids)):
            errors.append("range kill command signer IDs must be unique")
    if authority != {"can_disengage": False, "can_connect": False, "can_execute": False}:
        errors.append("range kill command authority must remain false")
    return tuple(errors)


def validate_range_kill_state_semantics(value: JsonObject) -> tuple[str, ...]:
    authority = value.get("authority")
    signers = value.get("verified_signer_ids")
    roles = value.get("verified_roles")
    errors: list[str] = []
    if value.get("sequence") != value.get("generation"):
        errors.append("range kill state sequence must equal topology generation")
    if value.get("kill_remains_engaged") is not True or value.get("cleanup_required") is not True:
        errors.append("range kill state must remain engaged and cleanup-required")
    if isinstance(signers, list) and len(signers) != len(set(str(item) for item in signers)):
        errors.append("range kill verified signer IDs must be unique")
    if isinstance(roles, list) and len(roles) != len(set(str(item) for item in roles)):
        errors.append("range kill verified roles must be unique")
    if authority != {"can_disengage": False, "can_connect": False, "can_execute": False}:
        errors.append("range kill state authority must remain false")
    return tuple(errors)


def validate_range_recovery_evidence_semantics(value: JsonObject) -> tuple[str, ...]:
    obligations = value.get("cleanup_obligations")
    observations = value.get("verifier_observations")
    authority = value.get("authority")
    if not isinstance(obligations, list) or not isinstance(observations, list):
        return ("range recovery obligations and verifier observations must be lists",)
    required = {"AGENT_ABSENCE", "CREDENTIAL_DISPOSITION", "ROUTE_CLOSURE", "TARGET_RESTORED", "TELEMETRY_FINALIZED", "TOOL_ARTIFACT_REMOVAL"}
    obligation_objects = [item for item in obligations if isinstance(item, dict)]
    identifiers = [str(item.get("obligation_id") or "") for item in obligation_objects]
    observation_objects = [item for item in observations if isinstance(item, dict)]
    errors: list[str] = []
    if len(identifiers) != len(set(identifiers)) or set(identifiers) != required:
        errors.append("range recovery must contain each cleanup obligation exactly once")
    if any(item.get("status") == "verified" and not item.get("evidence") for item in obligation_objects):
        errors.append("verified cleanup obligations require evidence")
    for field in ("verifier_id", "logical_principal", "process_id"):
        values = [str(item.get(field) or "") for item in observation_objects]
        if len(values) != len(set(values)):
            errors.append(f"range recovery verifier {field} values must be unique")
    if value.get("cleanup_subject_digest") != range_cleanup_subject_digest(value):
        errors.append("range recovery cleanup subject digest must bind the evidence subject")
    if authority != {"can_reset_kill": False, "can_reuse_range": False, "can_execute": False}:
        errors.append("range recovery evidence authority must remain false")
    return tuple(errors)


def validate_range_recovery_receipt_semantics(value: JsonObject) -> tuple[str, ...]:
    authority = value.get("authority")
    blockers = value.get("blockers")
    errors: list[str] = []
    if not isinstance(blockers, list):
        errors.append("range recovery receipt blockers must be a list")
    else:
        verified = value.get("cleanup_verified") is True and not blockers
        if (value.get("status") == "verified_contract_only") != verified:
            errors.append("range recovery receipt status must match cleanup verification and blockers")
    if value.get("kill_remains_engaged") is not True:
        errors.append("range recovery receipt cannot reset kill state")
    if any(value.get(field) is not False for field in ("range_reuse_authorized", "range_connection_authorized", "execution_authorized")):
        errors.append("range recovery receipt cannot authorize reuse, connection, or execution")
    if authority != {"can_reset_kill": False, "can_reuse_range": False, "can_execute": False}:
        errors.append("range recovery receipt authority must remain false")
    return tuple(errors)


def validate_evolution_baseline_semantics(value: JsonObject) -> tuple[str, ...]:
    if value.get("active") is not True or value.get("authority") != {"candidate_write_permitted": False, "can_execute": False}:
        return ("evolution baseline must be active, immutable to candidates, and non-executing",)
    return ()


def validate_evolution_constitution_semantics(value: JsonObject) -> tuple[str, ...]:
    axioms = value.get("axioms")
    hard_failures = value.get("hard_failures")
    triggers = value.get("capability_triggers")
    authority = value.get("authority")
    errors: list[str] = []
    if not isinstance(axioms, list) or len(axioms) != len(set(str(item) for item in axioms)) or set(str(item) for item in axioms) != REQUIRED_AXIOMS:
        errors.append("Evolution Constitution must contain every required axiom exactly once")
    if not isinstance(hard_failures, list) or set(str(item) for item in hard_failures) != REQUIRED_HARD_FAILURES:
        errors.append("Evolution Constitution hard failures must match the immutable set")
    if isinstance(triggers, list):
        mapping = {str(item.get("trigger_id")): str(item.get("response")) for item in triggers if isinstance(item, dict)}
        if mapping != REQUIRED_CAPABILITY_RESPONSES:
            errors.append("Evolution Constitution capability responses are incomplete or weakened")
    required_authority = {"can_modify_itself": False, "can_select_evaluators": False, "can_select_signers": False, "can_expand_authority": False, "can_execute": False}
    if authority != required_authority:
        errors.append("Evolution Constitution authority must remain false")
    return tuple(errors)


def validate_epistemic_posture_semantics(value: JsonObject) -> tuple[str, ...]:
    mode = str(value.get("mode") or "")
    claim_type = str(value.get("claim_type") or "")
    errors: list[str] = []
    if value.get("evidence_standard") != EPISTEMIC_STANDARD_BY_MODE.get(mode):
        errors.append("epistemic mode and evidence standard must match")
    if value.get("counterfactual") != (claim_type == "counterfactual"):
        errors.append("only counterfactual claims may set counterfactual true")
    if value.get("authority") != {"can_relabel_evidence": False, "can_waive_hard_failures": False}:
        errors.append("epistemic posture authority must remain false")
    return tuple(errors)


def validate_cognitive_candidate_semantics(value: JsonObject) -> tuple[str, ...]:
    errors: list[str] = []
    if value.get("authority") != CANDIDATE_AUTHORITY:
        errors.append("cognitive candidate authority must remain false")
    if value.get("proposed_delta_retained") is not False or value.get("active_baseline_modified") is not False or value.get("candidate_executed") is not False:
        errors.append("cognitive candidate must not retain delta material, modify baseline, or execute")
    if value.get("status") != "quarantined":
        errors.append("compiled cognitive candidate must begin quarantined")
    return tuple(errors)


def validate_capability_report_semantics(value: JsonObject) -> tuple[str, ...]:
    assessments = value.get("assessments")
    errors: list[str] = []
    if isinstance(assessments, list):
        identifiers = [str(item.get("trigger_id") or "") for item in assessments if isinstance(item, dict)]
        if len(identifiers) != len(set(identifiers)) or set(identifiers) != set(REQUIRED_CAPABILITY_RESPONSES):
            errors.append("capability report must contain every trigger exactly once")
    if (value.get("status") == "clear") != (value.get("required_safeguard_level") == "baseline" and value.get("blockers") == []):
        errors.append("capability report clear status must match baseline safeguards and no blockers")
    if value.get("paused") != (value.get("required_safeguard_level") == "pause"):
        errors.append("capability report pause flag must match safeguard level")
    if value.get("authority") != {"can_expand_safeguards": False, "can_expand_authority": False, "can_execute": False}:
        errors.append("capability report authority must remain false")
    return tuple(errors)


def validate_evolution_evaluation_semantics(value: JsonObject) -> tuple[str, ...]:
    observations = value.get("evaluator_observations")
    gates = value.get("hard_gate_results")
    floors = value.get("champion_floor_results")
    metrics = value.get("metrics")
    errors: list[str] = []
    if isinstance(observations, list):
        roles = {str(item.get("role") or "") for item in observations if isinstance(item, dict)}
        if roles != REQUIRED_EVALUATOR_ROLES:
            errors.append("evaluation must contain every independent evaluator role")
    if isinstance(gates, list):
        identifiers = {str(item.get("gate_id") or "") for item in gates if isinstance(item, dict)}
        if identifiers != REQUIRED_HARD_FAILURES:
            errors.append("evaluation hard gates must match the constitution")
    if isinstance(floors, list):
        identifiers = {str(item.get("floor_id") or "") for item in floors if isinstance(item, dict)}
        if identifiers != REQUIRED_CHAMPION_FLOORS:
            errors.append("evaluation champion floors must be complete")
    if value.get("aggregate_score_present") is not False or (isinstance(metrics, list) and any(isinstance(metric, dict) and any("score" in key.casefold() for key in metric) for metric in metrics)):
        errors.append("evaluation cannot contain aggregate scores")
    eligible = value.get("status") == "eligible_for_shadow"
    if eligible != (value.get("blockers") == []):
        errors.append("evaluation eligibility must match an empty blocker set")
    return tuple(errors)


def validate_evolution_transition_semantics(value: JsonObject) -> tuple[str, ...]:
    action = value.get("action")
    destination = value.get("destination")
    sequence = value.get("sequence")
    previous = value.get("previous_receipt_digest")
    errors: list[str] = []
    expected = {"register_shadow": ("shadow", 1, True), "demote": ("quarantine", 2, False), "rollback": ("rolled_back", 2, False)}
    if action in expected:
        expected_destination, expected_sequence, previous_null = expected[str(action)]
        if destination != expected_destination or sequence != expected_sequence or ((previous is None) != previous_null):
            errors.append("evolution transition action, destination, sequence, and predecessor are inconsistent")
    if value.get("authority") != {"can_modify_active_baseline": False, "can_execute_candidate": False, "can_promote_to_production": False, "can_expand_authority": False}:
        errors.append("evolution transition authority must remain false")
    return tuple(errors)


def validate_evolution_receipt_semantics(value: JsonObject) -> tuple[str, ...]:
    expected_status = {"register_shadow": "shadow_candidate_registered", "demote": "candidate_demoted", "rollback": "candidate_rolled_back"}
    errors: list[str] = []
    if expected_status.get(str(value.get("action"))) != value.get("status"):
        errors.append("evolution receipt action and status are inconsistent")
    if any(value.get(field) is not False for field in ("active_baseline_modified", "candidate_executed", "production_promotion_authorized")):
        errors.append("evolution receipt cannot modify baseline, execute, or authorize production")
    if value.get("authority") != {"can_modify_active_baseline": False, "can_execute_candidate": False, "can_promote_to_production": False}:
        errors.append("evolution receipt authority must remain false")
    return tuple(errors)


def validate_swarm_mission_semantics(value: JsonObject) -> tuple[str, ...]:
    raw_cells = value.get("cells")
    raw_work = value.get("work_items")
    if not isinstance(raw_cells, list) or not isinstance(raw_work, list):
        return ("cells and work_items must be lists",)
    cells = [cell for cell in raw_cells if isinstance(cell, dict)]
    work_items = [work for work in raw_work if isinstance(work, dict)]
    agent_ids = [str(cell.get("agent_id") or "") for cell in cells]
    roles = [str(cell.get("role") or "") for cell in cells]
    work_ids = [str(work.get("work_id") or "") for work in work_items]
    errors: list[str] = []
    if len(agent_ids) != len(set(agent_ids)):
        errors.append("swarm agent IDs must be unique")
    if len(roles) != len(set(roles)):
        errors.append("swarm roles must be unique")
    if len(work_ids) != len(set(work_ids)):
        errors.append("swarm work IDs must be unique")
    unknown_agents = sorted(
        str(work.get("assigned_agent_id") or "")
        for work in work_items
        if str(work.get("assigned_agent_id") or "") not in set(agent_ids)
    )
    if unknown_agents:
        errors.append(f"work items reference unknown agents: {', '.join(unknown_agents)}")
    return tuple(errors)


def validate_swarm_verdict_semantics(value: JsonObject) -> tuple[str, ...]:
    raw_contributions = value.get("contributions")
    quorum = value.get("quorum")
    authority = value.get("authority")
    if not isinstance(raw_contributions, list) or not isinstance(quorum, dict) or not isinstance(authority, dict):
        return ("contributions, quorum, and authority must have valid container types",)
    roles = {
        str(contribution.get("role") or "")
        for contribution in raw_contributions
        if isinstance(contribution, dict)
    }
    errors: list[str] = []
    if quorum.get("observed_distinct_roles") != len(roles):
        errors.append("swarm quorum observed role count must match contributions")
    if authority.get("execution_authorized") is not False:
        errors.append("swarm verdict cannot authorize execution")
    return tuple(errors)


def validate_improvement_semantics(value: JsonObject) -> tuple[str, ...]:
    tier = str(value.get("authority_tier") or "")
    policy = value.get("promotion_policy")
    if not isinstance(policy, dict):
        return ("promotion_policy must be an object",)
    destination = str(policy.get("maximum_destination") or "")
    human_required = policy.get("human_threshold_required") is True
    errors: list[str] = []
    if tier == "B" and destination not in {"quarantine", "evaluation", "shadow", "canary"}:
        errors.append("tier B candidates cannot autonomously exceed canary")
    if tier == "C" and (destination == "production" or not human_required):
        errors.append("tier C candidates require threshold humans and cannot directly target production")
    if tier == "D" and (destination not in {"quarantine", "evaluation"} or not human_required):
        errors.append("tier D candidates cannot autonomously promote")
    return tuple(errors)


def validate_os_isolation_semantics(value: JsonObject) -> tuple[str, ...]:
    controls = value.get("controls")
    authority = value.get("authority")
    if not isinstance(controls, list) or not isinstance(authority, dict):
        return ("OS isolation controls and authority must have valid container types",)
    control_objects = [item for item in controls if isinstance(item, dict)]
    control_ids = [str(item.get("control_id") or "") for item in control_objects]
    required = {
        "CREDENTIAL_ISOLATION",
        "DEDICATED_OS_ACCOUNT",
        "DISTINCT_PROCESS",
        "EXECUTABLE_IDENTITY",
        "NETWORK_EGRESS_DENIED",
        "READ_ONLY_INPUT_ACL",
        "SEPARATE_OUTPUT_ACL",
    }
    blockers = sorted(
        str(item.get("control_id")) for item in control_objects if item.get("status") != "verified"
    )
    violated = any(item.get("status") == "violated" for item in control_objects)
    expected_status = "verified" if not blockers else ("violated" if violated else "boundary_unproven")
    errors: list[str] = []
    if len(control_ids) != len(set(control_ids)) or set(control_ids) != required:
        errors.append("OS isolation controls must match the constitutional set exactly")
    if value.get("blockers") != blockers or value.get("status") != expected_status:
        errors.append("OS isolation status and blockers must derive from control evidence")
    expected_authority = {
        "can_authorize": False,
        "can_execute": False,
        "can_modify_acl": False,
        "can_grant_credentials": False,
    }
    if authority != expected_authority:
        errors.append("OS isolation attestation cannot authorize, execute, modify ACLs, or grant credentials")
    return tuple(errors)


def validate_evaluator_policy_semantics(value: JsonObject) -> tuple[str, ...]:
    evaluators = value.get("evaluators")
    authority = value.get("authority")
    if not isinstance(evaluators, list):
        return ("evaluator policy evaluators must be a list",)
    evaluator_objects = [item for item in evaluators if isinstance(item, dict)]
    expected_roles = {"public_regression", "sealed_holdout", "adversarial", "rights_and_recovery"}
    errors: list[str] = []
    for field in (
        "evaluator_id",
        "logical_principal",
        "role",
        "public_key_base64",
        "expected_os_account_identifier",
        "expected_os_account_sid",
    ):
        values = [str(item.get(field) or "") for item in evaluator_objects]
        if len(values) != len(set(values)):
            errors.append(f"evaluator policy {field} values must be unique")
    if {str(item.get("role") or "") for item in evaluator_objects} != expected_roles:
        errors.append("evaluator policy must bind all four constitutional roles")
    if authority != {
        "can_select_itself": False,
        "can_modify_constitution": False,
        "can_grant_credentials": False,
        "can_execute": False,
    }:
        errors.append("evaluator policy authority must remain false")
    return tuple(errors)


def validate_evaluator_observation_envelope_semantics(value: JsonObject) -> tuple[str, ...]:
    errors: list[str] = []
    if value.get("status") == "pass" and value.get("evidence") == []:
        errors.append("passing evaluator observations require evidence")
    if value.get("authority") != {
        "can_promote": False,
        "can_execute": False,
        "can_modify_evaluators": False,
        "can_allocate_resources": False,
    }:
        errors.append("evaluator observation authority must remain false")
    signature = value.get("signature")
    if isinstance(signature, dict) and signature.get("signer_id") != value.get("evaluator_id"):
        errors.append("evaluator observation signer must equal evaluator identity")
    return tuple(errors)


def validate_lineage_resource_ledger_semantics(value: JsonObject) -> tuple[str, ...]:
    entries = value.get("entries")
    blockers = value.get("blockers")
    if not isinstance(entries, list) or not isinstance(blockers, list):
        return ("resource ledger entries and blockers must be lists",)
    entry_objects = [item for item in entries if isinstance(item, dict)]
    errors: list[str] = []
    if [item.get("sequence") for item in entry_objects] != list(range(1, len(entry_objects) + 1)):
        errors.append("resource ledger sequence must be contiguous")
    if entry_objects and entry_objects[0].get("parent_candidate_digest") is not None:
        errors.append("resource ledger first entry must be the root")
    if (value.get("status") == "within_constitution") != (blockers == []):
        errors.append("resource ledger status must match its blockers")
    if value.get("authority") != {
        "can_allocate": False,
        "can_purchase_compute": False,
        "can_extend_lease": False,
        "can_execute": False,
    }:
        errors.append("resource ledger authority must remain false")
    return tuple(errors)


def validate_evolution_assurance_semantics(value: JsonObject) -> tuple[str, ...]:
    evaluators = value.get("evaluator_verifications")
    if not isinstance(evaluators, list):
        return ("evolution assurance evaluator verifications must be a list",)
    roles = {str(item.get("role") or "") for item in evaluators if isinstance(item, dict)}
    errors: list[str] = []
    if roles != {"public_regression", "sealed_holdout", "adversarial", "rights_and_recovery"}:
        errors.append("evolution assurance must preserve four evaluator roles")
    if value.get("live_os_enforcement_verified") is True and value.get("contract_boundary_verified") is not True:
        errors.append("live OS enforcement cannot be true without the contract boundary")
    if value.get("production_promotion_authorized") is not False:
        errors.append("evolution assurance cannot authorize production promotion")
    if value.get("authority") != {
        "can_promote": False,
        "can_execute": False,
        "can_modify_evaluators": False,
        "can_expand_resources": False,
    }:
        errors.append("evolution assurance authority must remain false")
    return tuple(errors)


def validate_control_board_foundry_semantics(value: JsonObject) -> tuple[str, ...]:
    boundary = value.get("boundary")
    if not isinstance(boundary, dict):
        return ("Foundry projection boundary must be an object",)
    shadow_eligible = boundary.get("shadow_eligible") is True
    errors: list[str] = []
    if shadow_eligible != str(value.get("operator_state") or "").startswith("shadow_eligible"):
        errors.append("Foundry operator state must match shadow eligibility")
    if boundary.get("production_ready") is not False:
        errors.append("Foundry projection cannot claim production readiness")
    if value.get("authority") != {
        "can_promote": False,
        "can_execute": False,
        "can_modify_evaluators": False,
        "can_expand_resources": False,
    }:
        errors.append("Foundry projection authority must remain false")
    return tuple(errors)


def validate_evaluator_conformance_bundle_semantics(value: JsonObject) -> tuple[str, ...]:
    attestations = value.get("isolation_attestations")
    envelopes = value.get("evaluator_envelopes")
    errors: list[str] = []
    if not isinstance(attestations, list) or len(attestations) != 4:
        errors.append("evaluator conformance bundle requires four isolation attestations")
    if not isinstance(envelopes, list) or len(envelopes) != 4:
        errors.append("evaluator conformance bundle requires four evaluator envelopes")
    if value.get("authority") != {"can_authorize": False, "can_execute": False, "can_promote": False}:
        errors.append("evaluator conformance bundle authority must remain false")
    return tuple(errors)


def validate_resource_meter_receipt_semantics(value: JsonObject) -> tuple[str, ...]:
    durability = value.get("durability")
    job = value.get("job")
    blockers = value.get("blockers")
    errors: list[str] = []
    if not isinstance(durability, dict):
        return ("resource meter durability must be an object",)
    if not isinstance(job, dict):
        return ("resource meter Job Object evidence must be an object",)
    if value.get("meter_version") != "0.2.0":
        errors.append("resource meter must use the race-closed version")
    if any(
        job.get(field) is not True
        for field in ("job_object_assigned", "created_suspended", "assigned_before_first_resume", "assignment_race_closed")
    ):
        errors.append("resource meter must prove suspended assignment before first resume")
    if durability.get("power_loss_durability_verified") is not False:
        errors.append("resource meter cannot claim power-loss durability")
    if durability.get("physical_power_loss_test_performed") is not False:
        errors.append("resource meter cannot claim a physical power-loss test")
    if durability.get("file_data_flush_verified") is not True or durability.get("write_through_publish_verified") is not True:
        errors.append("resource meter must preserve file flush and write-through publication evidence")
    if durability.get("crash_recovered") is True and durability.get("injected_process_crash_recovery_verified") is not True:
        errors.append("resource meter crash recovery must preserve its injected-crash evidence")
    if blockers != ["PHYSICAL_POWER_LOSS_TEST_UNPROVEN"]:
        errors.append("resource meter must preserve the physical-power-loss blocker after race closure")
    if value.get("network_access_performed") is not False or value.get("candidate_executed") is not False:
        errors.append("resource meter cannot claim network or candidate execution")
    if value.get("production_promotion_authorized") is not False:
        errors.append("resource meter cannot authorize production promotion")
    if value.get("authority") != {
        "can_allocate": False,
        "can_extend_lease": False,
        "can_execute_candidate": False,
        "can_promote": False,
    }:
        errors.append("resource meter authority must remain false")
    return tuple(errors)


def validate_windows_isolation_measurement_semantics(value: JsonObject) -> tuple[str, ...]:
    controls = value.get("controls")
    blockers = value.get("blockers")
    environment = value.get("environment")
    filesystem = value.get("filesystem")
    network = value.get("network")
    errors: list[str] = []
    if not isinstance(controls, list):
        return ("Windows isolation controls must be a list",)
    expected_controls = {
        "CREDENTIAL_ISOLATION",
        "DEDICATED_OS_ACCOUNT",
        "DISTINCT_PROCESS",
        "EXECUTABLE_IDENTITY",
        "NETWORK_EGRESS_DENIED",
        "READ_ONLY_INPUT_ACL",
        "SEPARATE_OUTPUT_ACL",
    }
    actual_controls = {str(control.get("control_id") or "") for control in controls if isinstance(control, dict)}
    derived_blockers = sorted(
        str(control.get("control_id") or "")
        for control in controls
        if isinstance(control, dict) and control.get("status") != "verified"
    )
    if actual_controls != expected_controls:
        errors.append("Windows isolation measurement must preserve the exact seven-control set")
    if blockers != derived_blockers:
        errors.append("Windows isolation measurement blockers must derive from control state")
    if not isinstance(environment, dict) or environment.get("credential_value_accessed") is not False:
        errors.append("Windows isolation measurement cannot access credential values")
    if not isinstance(filesystem, dict) or filesystem.get("acl_modified") is not False:
        errors.append("Windows isolation measurement cannot modify ACLs")
    elif filesystem.get("effective_rights_computed") is not True:
        errors.append("Windows isolation measurement must compute DACL effective rights")
    if not isinstance(network, dict) or network.get("active_probe_performed") is not False:
        errors.append("Windows isolation measurement cannot perform an active network probe")
    elif network.get("target_inspection_method") != "powershell_netsecurity_read_only":
        errors.append("Windows isolation measurement must inspect target-specific firewall policy")
    elif network.get("firewall_modified") is not False:
        errors.append("Windows isolation measurement cannot modify firewall policy")
    if value.get("authority") != {
        "can_authorize": False,
        "can_execute": False,
        "can_modify_acl": False,
        "can_modify_firewall": False,
        "can_read_credential_values": False,
    }:
        errors.append("Windows isolation measurement authority must remain false")
    return tuple(errors)


def validate_windows_custody_readiness_semantics(value: JsonObject) -> tuple[str, ...]:
    cng = value.get("cng")
    tpm = value.get("tpm")
    key_material = value.get("key_material")
    blockers = value.get("blockers")
    errors: list[str] = []
    if not isinstance(cng, dict) or not isinstance(tpm, dict) or not isinstance(key_material, dict):
        return ("Windows custody readiness requires CNG, TPM, and key-material evidence",)
    provider_digests = cng.get("provider_name_digests")
    if not isinstance(provider_digests, list) or cng.get("provider_count") != len(provider_digests):
        errors.append("Windows custody provider count must match its digests")
    expected_blockers = {
        "HARDWARE_KEY_REFERENCE_MISSING",
        "PROVIDER_ATTESTATION_MISSING",
        "INDEPENDENT_CUSTODY_OPERATOR_MISSING",
    }
    if tpm.get("query_succeeded") is not True:
        expected_blockers.add("TPM_MANAGEMENT_STATE_UNAVAILABLE")
    if cng.get("platform_crypto_provider_present") is not True:
        expected_blockers.add("PLATFORM_CRYPTO_PROVIDER_MISSING")
    if not isinstance(blockers, list) or set(blockers) != expected_blockers:
        errors.append("Windows custody blockers must derive from provider and TPM readiness")
    if any(value is not False for value in key_material.values()):
        errors.append("Windows custody readiness cannot claim key, signing, attestation, or private-material activity")
    if value.get("status") != "blocked" or value.get("production_custody_verified") is not False:
        errors.append("Windows custody readiness must remain production-blocked")
    if value.get("authority") != {
        "can_create_key": False,
        "can_delete_key": False,
        "can_sign": False,
        "can_export_private_key": False,
        "can_authorize_production": False,
    }:
        errors.append("Windows custody readiness authority must remain false")
    return tuple(errors)


def validate_edge_preview_scenario_semantics(value: JsonObject) -> tuple[str, ...]:
    observation = value.get("observation")
    policy = value.get("policy")
    authority = value.get("authority")
    if not isinstance(observation, dict) or not isinstance(policy, dict):
        return ("Edge preview scenario observation and policy must be objects",)
    rule = policy.get("rule")
    if not isinstance(rule, dict):
        return ("Edge preview policy rule must be an object",)
    errors: list[str] = []
    if set(cast(list[str], observation.get("facts", []))) != set(cast(list[str], rule.get("match_all_facts", []))):
        errors.append("Edge preview policy facts must exactly match the replay facts")
    if policy.get("autonomy_budget") != 1 or rule.get("outcome") != "challenge":
        errors.append("Edge preview must remain Budget 1 with a challenge outcome")
    if authority != {
        "can_replay": True,
        "can_propose": True,
        "can_authorize": False,
        "can_execute": False,
        "can_change_policy": False,
    }:
        errors.append("Edge preview scenario authority is widened or incomplete")
    return tuple(errors)


def validate_edge_preview_result_semantics(value: JsonObject) -> tuple[str, ...]:
    verification = value.get("independent_verification")
    references = value.get("references")
    authority = value.get("authority")
    if not isinstance(verification, dict) or not isinstance(references, dict):
        return ("Edge preview result verification and references must be objects",)
    verification_reference = references.get("verification")
    errors: list[str] = []
    if not isinstance(verification_reference, dict) or verification_reference.get("digest") != sha256_digest(cast(JsonObject, verification)):
        errors.append("Edge preview verification reference must bind the independent result")
    if value.get("scenario_digest") != verification.get("scenario_digest"):
        errors.append("Edge preview result and verifier must bind the same scenario")
    if any(
        verification.get(field) is not False
        for field in ("verified_outcome", "execution_authorized", "execution_performed", "target_state_changed", "recovery_verified")
    ):
        errors.append("Edge structural verification cannot claim endpoint outcome, execution, state change, or recovery")
    if authority != {
        "can_authorize": False,
        "can_execute": False,
        "target_state_changed": False,
        "recovery_verified": False,
    }:
        errors.append("Edge preview result authority is widened or incomplete")
    return tuple(errors)


def validate_edge_live_observation_semantics(value: JsonObject) -> tuple[str, ...]:
    try:
        validate_live_process_observation(value)
    except SimulatorError as error:
        return (str(error),)
    return ()


def validate_plugin_manifest_semantics(value: JsonObject) -> tuple[str, ...]:
    try:
        verify_plugin_manifest(value)
    except SimulatorError as error:
        return (str(error),)
    return ()


def validate_update_manifest_semantics(value: JsonObject) -> tuple[str, ...]:
    previous_release = value.get("previous_release")
    rollback = value.get("rollback")
    rollout = value.get("rollout")
    authority = value.get("authority")
    if not all(isinstance(item, dict) for item in (previous_release, rollback, rollout, authority)):
        return ("Edge update manifest is missing predecessor, rollback, rollout, or authority state",)
    errors: list[str] = []
    if rollback.get("target_release_manifest_digest") != previous_release.get("manifest_digest"):
        errors.append("Edge update rollback target must equal the trusted predecessor digest")
    if rollout != {"percentage": 0, "cohort": [], "installation_authorized": False}:
        errors.append("Edge candidate rollout must remain zero and installation-blocked")
    if authority != {
        "can_install": False,
        "can_promote": False,
        "can_change_rollout": False,
        "can_change_policy": False,
    }:
        errors.append("Edge update manifest authority is widened or incomplete")
    return tuple(errors)


def validate_update_receipt_semantics(value: JsonObject) -> tuple[str, ...]:
    authority = value.get("authority")
    errors: list[str] = []
    if any(
        value.get(field) is not False
        for field in (
            "plugin_code_executed",
            "installation_authorized",
            "installation_performed",
            "rollback_performed",
            "network_access_performed",
        )
    ):
        errors.append("Edge update verification cannot claim execution, installation, rollback, or network activity")
    if authority != {
        "can_install": False,
        "can_promote": False,
        "can_execute_plugin": False,
        "can_change_trust": False,
    }:
        errors.append("Edge update receipt authority is widened or incomplete")
    return tuple(errors)


def validate_design_partner_plan_semantics(value: JsonObject) -> tuple[str, ...]:
    try:
        validate_design_partner_plan(value)
    except SimulatorError as error:
        return (str(error),)
    return ()


def validate_cacis_roadmap_semantics(value: JsonObject) -> tuple[str, ...]:
    try:
        validate_cacis_roadmap(value)
    except SimulatorError as error:
        return (str(error),)
    return ()


def validate_world_observation_semantics(value: JsonObject) -> tuple[str, ...]:
    try:
        validate_observation(value)
    except SimulatorError as error:
        return (str(error),)
    return ()


def validate_world_generation_semantics(value: JsonObject) -> tuple[str, ...]:
    try:
        validate_world_model_generation(value)
    except SimulatorError as error:
        return (str(error),)
    return ()


def validate_immune_mission_semantics(value: JsonObject) -> tuple[str, ...]:
    try:
        validate_immune_organism_mission(value)
    except SimulatorError as error:
        return (str(error),)
    return ()


def validate_immune_receipt_semantics(value: JsonObject) -> tuple[str, ...]:
    receipt = value.get("receipt")
    if not isinstance(receipt, dict):
        return ("immune lifecycle receipt body must be an object",)
    errors: list[str] = []
    if value.get("receipt_digest") != sha256_digest(cast(JsonObject, receipt)):
        errors.append("immune lifecycle receipt digest does not match canonical content")
    if receipt.get("authority") != IMMUNE_AUTHORITY:
        errors.append("immune lifecycle receipt authority is widened or incomplete")
    termination = receipt.get("termination")
    if not isinstance(termination, dict) or any(
        termination.get(field) is not False
        for field in ("credentials_issued", "target_contact_performed", "execution_performed")
    ):
        errors.append("immune lifecycle receipt claims credentials, target contact, or execution")
    verification = receipt.get("independent_verification")
    if not isinstance(verification, dict) or verification != {
        "required": True,
        "performed": False,
        "status": "pending_external_verification",
        "verifier_identity": None,
    }:
        errors.append("immune lifecycle receipt launders self-verification")
    return tuple(errors)


def validate_intelligence_research_mission_semantics(value: JsonObject) -> tuple[str, ...]:
    try:
        validate_intelligence_research_mission(value)
    except SimulatorError as error:
        return (str(error),)
    return ()


def validate_homeostasis_mission_semantics(value: JsonObject) -> tuple[str, ...]:
    try:
        validate_homeostasis_chronos_mission(value)
    except SimulatorError as error:
        return (str(error),)
    return ()


def validate_homeostasis_receipt_semantics(value: JsonObject) -> tuple[str, ...]:
    body = value.get("receipt")
    if not isinstance(body, dict):
        return ("homeostasis receipt body must be an object",)
    errors: list[str] = []
    unsigned: JsonObject = {"receipt_version": value.get("receipt_version"), "receipt": body}
    if value.get("receipt_digest") != sha256_digest(unsigned):
        errors.append("homeostasis receipt digest does not match canonical content")
    authority = body.get("authority")
    if authority != HOMEOSTASIS_AUTHORITY:
        errors.append("homeostasis receipt authority is widened")
    decisions = body.get("allocation_decisions")
    if not isinstance(decisions, list) or any(
        isinstance(item, dict) and item.get("clock_state") == "expired" and item.get("action") != "abstained"
        for item in decisions
    ):
        errors.append("homeostasis receipt launders expired evidence into scheduled work")
    ledger = body.get("resource_ledger")
    if not isinstance(ledger, dict):
        errors.append("homeostasis receipt resource ledger is missing")
    else:
        for entry in ledger.values():
            if not isinstance(entry, dict) or entry.get("allocated", 1) > entry.get("capacity", 0) or entry.get("remaining") != entry.get("capacity", 0) - entry.get("allocated", 0):
                errors.append("homeostasis receipt resource ledger is oversubscribed or inconsistent")
                break
    return tuple(errors)


def validate_intelligence_research_settlement_semantics(value: JsonObject) -> tuple[str, ...]:
    settlement = value.get("settlement")
    if not isinstance(settlement, dict):
        return ("intelligence research settlement body must be an object",)
    errors: list[str] = []
    if value.get("settlement_digest") != sha256_digest(cast(JsonObject, settlement)):
        errors.append("intelligence research settlement digest does not match canonical content")
    theory = settlement.get("candidate_theory")
    if not isinstance(theory, dict) or any(
        theory.get(field) is not False
        for field in ("generalization_allowed", "promotion_authorized", "authority_retained")
    ):
        errors.append("intelligence research theory exceeds its candidate-only ceiling")
    verification = settlement.get("independent_verification")
    if (
        not isinstance(verification, dict)
        or verification.get("separate_process") is not True
        or verification.get("production_independence_verified") is not False
    ):
        errors.append("intelligence research verifier launders production independence")
    authority = settlement.get("authority")
    if not isinstance(authority, dict) or any(authority.get(field) is not False for field in authority):
        errors.append("intelligence research settlement authority is widened")
    return tuple(errors)


def validate_action_envelope_semantics(value: JsonObject) -> tuple[str, ...]:
    errors: list[str] = []
    authorization = value.get("authorization")
    verification = value.get("verification")
    if not isinstance(authorization, dict):
        return ("action envelope authorization is missing",)
    decision = authorization.get("policy_decision")
    approvals = authorization.get("approvals")
    if decision == "deny" and approvals != []:
        errors.append("denied action envelope cannot retain approvals")
    if value.get("origin") == "simulated" and decision != "deny":
        errors.append("simulated action envelope cannot authorize execution")
    if value.get("signatures") != [] and decision != "allow":
        errors.append("non-allowed action envelope cannot retain signatures")
    if not isinstance(verification, dict) or not verification.get("independent_verifiers"):
        errors.append("action envelope requires an independent verifier")
    execution_contract = value.get("execution_contract")
    if not isinstance(execution_contract, dict):
        errors.append("action envelope execution contract is missing")
    else:
        try:
            if parse_timestamp(execution_contract.get("expires_at"), "execution_contract.expires_at") <= parse_timestamp(value.get("timestamp"), "timestamp"):
                errors.append("action envelope expiration must follow its timestamp")
        except ValueError as error:
            errors.append(str(error))
    return tuple(errors)


def validate_causal_coverage_semantics(value: JsonObject) -> tuple[str, ...]:
    errors: list[str] = []
    chain = value.get("causal_chain")
    if not isinstance(chain, dict):
        return ("causal verdict chain is missing",)
    downstream = ("attempt", "state_delta", "observation", "detection", "response", "recovery", "post_state")
    status = value.get("status")
    if status == "pass" and any(chain.get(field) is None for field in downstream):
        errors.append("passing causal verdict requires a complete causal chain")
    if status == "inconclusive_timeout" and any(chain.get(field) is not None for field in downstream):
        errors.append("timeout causal verdict cannot fabricate downstream causal stages")
    if value.get("origin") == "simulated" and status == "pass":
        errors.append("simulated causal verdict cannot claim live coverage pass")
    if not value.get("uncertainties") or not value.get("residual_risks"):
        errors.append("causal verdict must preserve uncertainty and residual risk")
    return tuple(errors)


def validate_connector_manifest_semantics(value: JsonObject) -> tuple[str, ...]:
    errors: list[str] = []
    operations = value.get("lifecycle_operations")
    if not isinstance(operations, list):
        return ("connector lifecycle operations are missing",)
    operation_set = set(operations)
    if "execute" in operation_set and not {"preflight", "abort", "cleanup", "verify"}.issubset(operation_set):
        errors.append("executable connector lacks preflight, abort, cleanup, or verify lifecycle")
    if "execute" in operation_set and (not value.get("permissions") or not value.get("side_effects")):
        errors.append("executable connector lacks explicit permission or side-effect declaration")
    license_review = value.get("license_review")
    if not isinstance(license_review, dict):
        errors.append("connector license review is missing")
    elif license_review.get("status") != "approved" and value.get("signature") is not None:
        errors.append("unapproved connector cannot retain a release signature")
    if license_review == {"status": "pending", "license": "planning-example", "redistribution_allowed": False}:
        if value.get("secret_references") != []:
            errors.append("planning connector cannot retain secret references")
        if any(not isinstance(destination, str) or not destination.startswith("range:") for destination in value.get("network_destinations", [])):
            errors.append("planning connector destination must remain range-bound")
    return tuple(errors)


def validate_evidence_receipt_semantics(value: JsonObject) -> tuple[str, ...]:
    errors: list[str] = []
    try:
        observation = parse_timestamp(value.get("observation_time"), "observation_time")
        collection = parse_timestamp(value.get("collection_time"), "collection_time")
        validity = value.get("validity_interval")
        if not isinstance(validity, dict):
            return ("evidence validity interval is missing",)
        start = parse_timestamp(validity.get("start"), "validity_interval.start")
        if collection < observation or observation < start:
            errors.append("evidence temporal ordering is invalid")
        end_value = validity.get("end")
        if end_value is not None and parse_timestamp(end_value, "validity_interval.end") < collection:
            errors.append("evidence validity ends before collection")
    except ValueError as error:
        errors.append(str(error))
    if value.get("evidence_id") != value.get("content_digest"):
        errors.append("evidence identity must bind its content digest")
    if value.get("origin") == "simulated":
        if value.get("classification") != "E0" or value.get("signatures") != []:
            errors.append("simulated evidence cannot claim elevated classification or signatures")
        if value.get("device_or_workload_attestation") is not None:
            errors.append("simulated evidence cannot claim device or workload attestation")
    retention = value.get("retention_policy")
    if not isinstance(retention, dict) or not retention.get("purpose"):
        errors.append("evidence receipt lacks a purpose-bound retention policy")
    return tuple(errors)


def validate_protection_profile_semantics(value: JsonObject) -> tuple[str, ...]:
    try:
        validate_protection_profile(value)
    except ProtectionProfileError as error:
        return (str(error),)
    return ()


SEMANTIC_VALIDATORS: Mapping[str, Callable[[JsonObject], tuple[str, ...]]] = {
    "action-and-evidence-envelope.schema.json": validate_action_envelope_semantics,
    "authorization-lease.schema.json": validate_authorization_semantics,
    "authorization-proof-bundle.schema.json": validate_authorization_proof_semantics,
    "authorization-trust-policy.schema.json": validate_trust_policy_semantics,
    "cacis-capability-roadmap.schema.json": validate_cacis_roadmap_semantics,
    "causal-coverage-verdict.schema.json": validate_causal_coverage_semantics,
    "connector-manifest.schema.json": validate_connector_manifest_semantics,
    "control-board-ingress-receipt.schema.json": validate_control_board_ingress_semantics,
    "control-board-foundry-projection.schema.json": validate_control_board_foundry_semantics,
    "control-board-snapshot.schema.json": validate_control_board_snapshot_semantics,
    "control-board-verifier-projection.schema.json": validate_control_board_verifier_semantics,
    "construction-zone-isolation-attestation-plan.schema.json": validate_construction_attestation_plan_semantics,
    "construction-zone-preflight-result.schema.json": validate_construction_preflight_semantics,
    "construction-zone-provisioning-authorization.schema.json": validate_construction_provisioning_authorization_semantics,
    "construction-zone-provisioning-gate-result.schema.json": validate_construction_provisioning_result_semantics,
    "capability-threshold-report.schema.json": validate_capability_report_semantics,
    "cognitive-candidate-bundle.schema.json": validate_cognitive_candidate_semantics,
    "disposable-range-preflight.schema.json": validate_range_preflight_semantics,
    "disposable-range-preflight-result.schema.json": validate_range_preflight_result_semantics,
    "design-partner-evaluation-plan.schema.json": validate_design_partner_plan_semantics,
    "edge-live-process-observation.schema.json": validate_edge_live_observation_semantics,
    "edge-preview-result.schema.json": validate_edge_preview_result_semantics,
    "edge-preview-scenario.schema.json": validate_edge_preview_scenario_semantics,
    "edge-update-manifest.schema.json": validate_update_manifest_semantics,
    "edge-update-verification-receipt.schema.json": validate_update_receipt_semantics,
    "evidence-receipt.schema.json": validate_evidence_receipt_semantics,
    "improvement-candidate.schema.json": validate_improvement_semantics,
    "homeostasis-chronos-mission.schema.json": validate_homeostasis_mission_semantics,
    "homeostasis-chronos-receipt.schema.json": validate_homeostasis_receipt_semantics,
    "intelligence-research-mission.schema.json": validate_intelligence_research_mission_semantics,
    "intelligence-research-settlement.schema.json": validate_intelligence_research_settlement_semantics,
    "immune-organism-lifecycle-receipt.schema.json": validate_immune_receipt_semantics,
    "immune-organism-mission.schema.json": validate_immune_mission_semantics,
    "epistemic-posture.schema.json": validate_epistemic_posture_semantics,
    "isolated-construction-zone.schema.json": validate_construction_zone_semantics,
    "evolution-baseline.schema.json": validate_evolution_baseline_semantics,
    "evolution-constitution.schema.json": validate_evolution_constitution_semantics,
    "evolution-assurance-receipt.schema.json": validate_evolution_assurance_semantics,
    "evolution-evaluation-vector.schema.json": validate_evolution_evaluation_semantics,
    "evolution-transition-envelope.schema.json": validate_evolution_transition_semantics,
    "evolution-transition-receipt.schema.json": validate_evolution_receipt_semantics,
    "evaluator-conformance-bundle.schema.json": validate_evaluator_conformance_bundle_semantics,
    "evaluator-observation-envelope.schema.json": validate_evaluator_observation_envelope_semantics,
    "evaluator-trust-policy.schema.json": validate_evaluator_policy_semantics,
    "key-governance-state.schema.json": validate_key_governance_state_semantics,
    "key-governance-transition.schema.json": validate_key_transition_semantics,
    "lineage-resource-ledger.schema.json": validate_lineage_resource_ledger_semantics,
    "os-isolation-attestation.schema.json": validate_os_isolation_semantics,
    "owner-scope-exclusion-registry.schema.json": validate_owner_scope_registry_semantics,
    "plugin-capability-manifest.schema.json": validate_plugin_manifest_semantics,
    "protection-profile.schema.json": validate_protection_profile_semantics,
    "public-corpus-intake-report.schema.json": validate_public_corpus_intake_semantics,
    "public-sacrificial-source-registry.schema.json": validate_public_source_registry_semantics,
    "public-source-staging-authorization.schema.json": validate_source_staging_authorization_semantics,
    "range-adapter-policy.schema.json": validate_range_policy_semantics,
    "range-adapter-policy-envelope.schema.json": validate_range_policy_envelope_semantics,
    "range-compilation-receipt.schema.json": validate_range_compilation_semantics,
    "range-collector-policy.schema.json": validate_range_collector_policy_semantics,
    "range-connector-capability-manifest.schema.json": validate_range_connector_capability_semantics,
    "range-corpus-manifest.schema.json": validate_range_corpus_manifest_semantics,
    "range-corpus-report.schema.json": validate_range_corpus_report_semantics,
    "range-environment-observation.schema.json": validate_range_environment_observation_semantics,
    "range-evidence-acceptance-report.schema.json": validate_range_evidence_acceptance_semantics,
    "range-evidence-admission-report.schema.json": validate_range_evidence_admission_semantics,
    "range-evidence-completion-authorization.schema.json": validate_range_evidence_completion_authorization_semantics,
    "range-evidence-completion-policy.schema.json": validate_range_evidence_completion_policy_semantics,
    "range-evidence-completion-receipt.schema.json": validate_range_evidence_completion_receipt_semantics,
    "range-kill-command.schema.json": validate_range_kill_command_semantics,
    "range-kill-state.schema.json": validate_range_kill_state_semantics,
    "range-lease-topology-scope.schema.json": validate_range_scope_semantics,
    "range-preexecution-evidence-packet.schema.json": validate_range_preexecution_packet_semantics,
    "range-recovery-evidence.schema.json": validate_range_recovery_evidence_semantics,
    "range-recovery-receipt.schema.json": validate_range_recovery_receipt_semantics,
    "range-source-import.schema.json": validate_range_import_semantics,
    "range-topology.schema.json": validate_range_topology_semantics,
    "range-topology-verdict.schema.json": validate_range_topology_verdict_semantics,
    "range-verifier-decision.schema.json": validate_range_verifier_decision_semantics,
    "range-verifier-policy.schema.json": validate_range_verifier_policy_semantics,
    "resource-meter-receipt.schema.json": validate_resource_meter_receipt_semantics,
    "sacrificial-replica-plan.schema.json": validate_sacrificial_replica_plan_semantics,
    "source-quarantine-evidence-receipt.schema.json": validate_quarantine_receipt_semantics,
    "source-staging-gate-report.schema.json": validate_source_staging_gate_semantics,
    "swarm-mission.schema.json": validate_swarm_mission_semantics,
    "swarm-verdict.schema.json": validate_swarm_verdict_semantics,
    "validation-campaign.schema.json": validate_campaign_semantics,
    "verifier-consensus.schema.json": validate_verifier_consensus_semantics,
    "verifier-health.schema.json": validate_verifier_health_semantics,
    "verifier-observation.schema.json": validate_verifier_observation_semantics,
    "verifier-service-policy.schema.json": validate_verifier_policy_semantics,
    "witness-anchor-head.schema.json": validate_anchor_head_semantics,
    "witness-anchor-policy.schema.json": validate_anchor_policy_semantics,
    "witness-anchor-receipt.schema.json": validate_anchor_receipt_semantics,
    "witness-checkpoint.schema.json": validate_witness_checkpoint_semantics,
    "windows-custody-readiness.schema.json": validate_windows_custody_readiness_semantics,
    "windows-isolation-measurement.schema.json": validate_windows_isolation_measurement_semantics,
    "world-model-generation.schema.json": validate_world_generation_semantics,
    "world-observation-envelope.schema.json": validate_world_observation_semantics,
}


def validate_contracts(project_root: Path) -> JsonObject:
    schema_root = project_root / "specs"
    example_root = schema_root / "examples"
    format_checker = FormatChecker()
    positive_count = 0
    negative_count = 0
    semantic_count = 0
    migration_count = 0
    for schema_name, example_name in CONTRACT_PAIRS:
        schema = read_object(schema_root / schema_name)
        example = read_object(example_root / example_name)
        try:
            Draft202012Validator.check_schema(schema)
        except SchemaError as error:
            raise ValueError(f"Invalid Draft 2020-12 schema {schema_name}: {error.message}") from error
        validator = Draft202012Validator(schema, format_checker=format_checker)
        positive_errors = sorted(validator.iter_errors(example), key=lambda error: tuple(error.path))
        if positive_errors:
            messages = "; ".join(error.message for error in positive_errors)
            raise ValueError(f"Positive example {example_name} failed {schema_name}: {messages}")
        positive_count += 1
        negative = NEGATIVE_MUTATIONS[schema_name](example)
        if not tuple(validator.iter_errors(negative)):
            raise ValueError(f"Negative mutation unexpectedly passed {schema_name}.")
        negative_count += 1
        semantic_validator = SEMANTIC_VALIDATORS.get(schema_name)
        if semantic_validator is not None:
            semantic_errors = semantic_validator(example)
            if semantic_errors:
                raise ValueError(f"Semantic validation failed for {example_name}: {'; '.join(semantic_errors)}")
            semantic_count += 1
    current_verdict = read_object(example_root / "causal-coverage-verdict.example.json")
    legacy_verdict = copy.deepcopy(current_verdict)
    legacy_verdict["verdict_version"] = "0.1.0"
    legacy_verdict.pop("origin")
    migrated_verdict = migrate_causal_verdict_0_1_to_0_2(legacy_verdict, "simulated")
    verdict_schema = read_object(schema_root / "causal-coverage-verdict.schema.json")
    migrated_errors = tuple(
        Draft202012Validator(verdict_schema, format_checker=format_checker).iter_errors(migrated_verdict)
    )
    if migrated_errors:
        messages = "; ".join(error.message for error in migrated_errors)
        raise ValueError(f"Causal verdict v0.1 to v0.2 migration failed: {messages}")
    migration_count += 1
    return {
        "status": "CONTRACTS_VALID",
        "draft": "2020-12",
        "schema_count": len(CONTRACT_PAIRS),
        "positive_example_count": positive_count,
        "negative_mutation_count": negative_count,
        "semantic_contract_count": semantic_count,
        "migration_count": migration_count,
    }


def main() -> None:
    project_root = Path(__file__).resolve().parent.parent
    result = validate_contracts(project_root)
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
