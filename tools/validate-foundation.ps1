[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

[string]$projectRoot = Split-Path -Parent $PSScriptRoot
[string[]]$requiredFiles = @(
    'README.md',
    'AGENTS.md',
    'SECURITY.md',
    'CONTRIBUTING.md',
    'LICENSE-DECISION.md',
    '.gitignore',
    'pyproject.toml',
    'docs/source/nimrod_source_brief.md',
    'docs/source/cacis_vnext_owner_brief.md',
    'docs/DOCTRINE.md',
    'docs/MASTER_PLAN.md',
    'docs/VNEXT_CACIS_MASTER_PLAN.md',
    'docs/CACIS_WORLD_MODEL.md',
    'docs/CACIS_IMMUNE_RUNTIME.md',
    'docs/CONSTITUTIONAL_INTELLIGENCE_RESEARCH_ENGINE.md',
    'docs/CACIS_HOMEOSTASIS_CHRONOS.md',
    'docs/CACIS_GENOME_EVALUATION.md',
    'docs/CACIS_ARENAS_OBSERVATORY.md',
    'docs/CRUCIBLE.md',
    'docs/AI_ASSURANCE.md',
    'docs/SWARM_CONTROL_BOARD.md',
    'docs/SUPERVISED_VERIFIER.md',
    'docs/TRUST_ROOT_AND_WITNESS_ANCHOR.md',
    'docs/PRODUCT_REQUIREMENTS.md',
    'docs/CONTRACT_RUNTIME_CONFORMANCE.md',
    'docs/VERIFIER_IDENTITY_READINESS.md',
    'docs/COMPLETION_EVIDENCE.md',
    'docs/REFERENCE_ARCHITECTURE.md',
    'docs/RANGE_ADAPTER.md',
    'docs/RANGE_READINESS.md',
    'docs/RANGE_LIFECYCLE.md',
    'docs/RANGE_EXECUTION_GATE.md',
    'docs/RANGE_EVIDENCE_ADMISSION.md',
    'docs/RANGE_EVIDENCE_ACCEPTANCE.md',
    'docs/RANGE_EVIDENCE_COMPLETION.md',
    'docs/PUBLIC_SACRIFICIAL_CORPUS.md',
    'docs/SOURCE_STAGING_GATE.md',
    'docs/CONSTRUCTION_ZONE_PREFLIGHT.md',
    'docs/CONSTRUCTION_ZONE_PROVISIONING_GATE.md',
    'docs/EVOLUTION_FOUNDRY.md',
    'docs/AUTONOMOUS_THRESHOLD_PROMOTION.md',
    'docs/THREAT_MODEL.md',
    'docs/SECURITY_PRIVACY_COMPLIANCE.md',
    'docs/PUBLIC_LAUNCH.md',
    'docs/PHASE_0_BACKLOG.md',
    'docs/DECISION_REGISTER.md',
    'docs/decisions/ADR-068-doctrine-v0.1-owner-approval.md',
    'docs/decisions/ADR-069-cacis-vnext-target-architecture.md',
    'docs/decisions/ADR-070-cacis-world-model-immutable-generations.md',
    'docs/decisions/ADR-071-cacis-ephemeral-organism-leases-and-teardown.md',
    'docs/decisions/ADR-072-constitutional-intelligence-research-engine.md',
    'docs/decisions/ADR-073-bounded-homeostasis-and-domain-clocks.md',
    'docs/decisions/ADR-074-replay-safe-world-model-intake-succession.md',
    'docs/decisions/ADR-075-threshold-source-governance-and-bounded-intake.md',
    'docs/decisions/ADR-076-live-verifier-identity-readiness-without-provisioning.md',
    'docs/decisions/ADR-077-autonomous-threshold-promotion-standard.md',
    'docs/hardening/cacis-vnext/context.md',
    'docs/hardening/cacis-vnext/hardening.json',
    'docs/hardening/cacis-vnext/hardening.md',
    'docs/hardening/cacis-vnext/proposals/constitutional-immune-plane.md',
    'docs/hardening/cacis-vnext/diagrams/constitutional-immune-plane-before.mmd',
    'docs/hardening/cacis-vnext/diagrams/constitutional-immune-plane-current-extension-after.mmd',
    'docs/hardening/cacis-vnext/diagrams/constitutional-immune-plane-federated-after.mmd',
    'docs/hardening/cacis-vnext/diagrams/constitutional-immune-plane-service-mesh-after.mmd',
    'docs/hardening/cacis-vnext/implementation/federated-constitutional-immune-plane.md',
    'docs/EDGE_LIVE_OBSERVATION.md',
    'docs/EDGE_CONTINUOUS_OBSERVATION.md',
    'docs/RELEASE_AND_PLUGIN_TRUST.md',
    'docs/DESIGN_PARTNER_EVIDENCE_KIT.md',
    'reports/SIMULATOR_VALIDATION.json',
    'reports/AUTHORIZATION_STATE_VALIDATION.json',
    'reports/KEY_GOVERNANCE_VALIDATION.json',
    'reports/WITNESS_ANCHOR_VALIDATION.json',
    'reports/SUPERVISED_VERIFIER_VALIDATION.json',
    'reports/SWARM_VALIDATION.json',
    'reports/CONTROL_BOARD_VALIDATION.json',
    'reports/CONTROL_BOARD_INGRESS_VALIDATION.json',
    'reports/RANGE_ADAPTER_VALIDATION.json',
    'reports/RANGE_READINESS_VALIDATION.json',
    'reports/RANGE_LIFECYCLE_VALIDATION.json',
    'reports/RANGE_EXECUTION_GATE_VALIDATION.json',
    'reports/RANGE_EVIDENCE_ADMISSION_VALIDATION.json',
    'reports/RANGE_EVIDENCE_ACCEPTANCE_VALIDATION.json',
    'reports/RANGE_EVIDENCE_COMPLETION_VALIDATION.json',
    'reports/PUBLIC_SACRIFICIAL_CORPUS_VALIDATION.json',
    'reports/SOURCE_STAGING_GATE_VALIDATION.json',
    'reports/CONSTRUCTION_ZONE_PREFLIGHT_VALIDATION.json',
    'reports/CONSTRUCTION_ZONE_PROVISIONING_GATE_VALIDATION.json',
    'reports/EVOLUTION_FOUNDRY_VALIDATION.json',
    'reports/EVOLUTION_ASSURANCE_VALIDATION.json',
    'reports/AUTONOMOUS_PROMOTION_VALIDATION.json',
    'reports/DISTRIBUTION_VALIDATION.json',
    'reports/EVALUATOR_CONFORMANCE_VALIDATION.json',
    'reports/RESOURCE_METER_VALIDATION.json',
    'reports/WINDOWS_CUSTODY_READINESS_VALIDATION.json',
    'reports/WINDOWS_ISOLATION_VALIDATION.json',
    'reports/EDGE_PREVIEW_VALIDATION.json',
    'reports/GITHUB_GOVERNANCE_VALIDATION.json',
    'reports/EDGE_LIVE_OBSERVATION_VALIDATION.json',
    'reports/EDGE_CONTINUOUS_OBSERVATION_VALIDATION.json',
    'reports/RELEASE_FOUNDATION_VALIDATION.json',
    'reports/DESIGN_PARTNER_KIT_VALIDATION.json',
    'reports/CACIS_ROADMAP_VALIDATION.json',
    'reports/CACIS_WORLD_MODEL_VALIDATION.json',
    'reports/CACIS_WORLD_INTAKE_VALIDATION.json',
    'reports/CACIS_WORLD_INTAKE_GOVERNANCE_VALIDATION.json',
    'reports/CACIS_IMMUNE_RUNTIME_VALIDATION.json',
    'reports/INTELLIGENCE_RESEARCH_VALIDATION.json',
    'reports/CACIS_HOMEOSTASIS_CHRONOS_VALIDATION.json',
    'reports/CACIS_GENOME_EVALUATION_VALIDATION.json',
    'reports/CACIS_ARENAS_OBSERVATORY_VALIDATION.json',
    'reports/CONTRACT_CONFORMANCE_MATRIX.json',
    'reports/CONTRACT_RUNTIME_BINDINGS_VALIDATION.json',
    'reports/VERIFIER_IDENTITY_READINESS_VALIDATION.json',
    'reports/COMPLETION_AUDIT.json',
    'reports/SESSION_REPORT_2026-07-12_CONTROL_BOARD_VERIFIER.md',
    'reports/SESSION_REPORT_2026-07-12_SIGNED_BOARD_INGRESS.md',
    'reports/SESSION_REPORT_2026-07-12_RANGE_ADAPTER_WAVE.md',
    'reports/SESSION_REPORT_2026-07-12_RANGE_READINESS_WAVE.md',
    'reports/SESSION_REPORT_2026-07-12_RANGE_LIFECYCLE_WAVE.md',
    'reports/SESSION_REPORT_2026-07-12_EVOLUTION_FOUNDRY_WAVE.md',
    'reports/SESSION_REPORT_2026-07-12_EVOLUTION_ASSURANCE_WAVE.md',
    'reports/SESSION_REPORT_2026-07-13_PLATFORM_ASSURANCE_WAVE.md',
    'reports/SESSION_REPORT_2026-07-13_DEPLOYMENT_ASSURANCE_WAVE.md',
    'reports/SESSION_REPORT_2026-07-13_RANGE_EXECUTION_GATE_WAVE.md',
    'reports/SESSION_REPORT_2026-07-13_RANGE_EVIDENCE_ADMISSION_WAVE.md',
    'reports/SESSION_REPORT_2026-07-13_RANGE_EVIDENCE_ACCEPTANCE_WAVE.md',
    'reports/SESSION_REPORT_2026-07-13_RANGE_EVIDENCE_COMPLETION_WAVE.md',
    'reports/SESSION_REPORT_2026-07-13_PUBLIC_SACRIFICIAL_CORPUS_WAVE.md',
    'reports/SESSION_REPORT_2026-07-13_SOURCE_STAGING_GATE_WAVE.md',
    'reports/SESSION_REPORT_2026-07-13_CONSTRUCTION_ZONE_PREFLIGHT_WAVE.md',
    'reports/SESSION_REPORT_2026-07-13_CONSTRUCTION_ZONE_PROVISIONING_GATE_WAVE.md',
    'reports/SESSION_REPORT_2026-07-15_EDGE_FOUNDATION_WAVE.md',
    'reports/SESSION_REPORT_2026-07-15_EDGE_PRODUCTIZATION_WAVE.md',
    'reports/SESSION_REPORT_2026-07-15_CACIS_VNEXT_INTEGRATION_WAVE.md',
    'reports/SESSION_REPORT_2026-07-15_CACIS_WORLD_MODEL_WAVE.md',
    'reports/SESSION_REPORT_2026-07-15_CACIS_IMMUNE_RUNTIME_WAVE.md',
    'reports/SESSION_REPORT_2026-07-15_INTELLIGENCE_RESEARCH_W3_WAVE.md',
    'reports/SESSION_REPORT_2026-07-16_CACIS_HOMEOSTASIS_CHRONOS_W4_WAVE.md',
    'reports/SESSION_REPORT_2026-07-16_TAKEOVER_W5_W6_WAVE.md',
    'reports/SESSION_REPORT_2026-07-16_WORLD_INTAKE_SUCCESSION_WAVE.md',
    'reports/SESSION_REPORT_2026-07-16_WORLD_INTAKE_GOVERNANCE_CONFORMANCE_WAVE.md',
    'reports/SESSION_REPORT_2026-07-16_FULL_ARENA_CONTRACT_IDENTITY_WAVE.md',
    'reports/SESSION_REPORT_2026-07-16_AUTONOMOUS_THRESHOLD_PROMOTION_WAVE.md',
    'reports/SESSION_REPORT_2026-07-16_COMPLETION_REVIEW_AND_DISTRIBUTION_WAVE.md',
    'specs/action-and-evidence-envelope.schema.json',
    'specs/cacis-capability-roadmap.schema.json',
    'specs/world-model-generation.schema.json',
    'specs/world-observation-envelope.schema.json',
    'specs/immune-organism-lifecycle-receipt.schema.json',
    'specs/immune-organism-mission.schema.json',
    'specs/intelligence-research-mission.schema.json',
    'specs/intelligence-research-settlement.schema.json',
    'specs/homeostasis-chronos-mission.schema.json',
    'specs/homeostasis-chronos-receipt.schema.json',
    'specs/evolution-baseline.schema.json',
    'specs/evolution-constitution.schema.json',
    'specs/epistemic-posture.schema.json',
    'specs/cognitive-candidate-bundle.schema.json',
    'specs/capability-threshold-report.schema.json',
    'specs/evolution-evaluation-vector.schema.json',
    'specs/evolution-transition-envelope.schema.json',
    'specs/evolution-transition-receipt.schema.json',
    'specs/authorization-lease.schema.json',
    'specs/authorization-proof-bundle.schema.json',
    'specs/authorization-trust-policy.schema.json',
    'specs/causal-coverage-verdict.schema.json',
    'specs/connector-manifest.schema.json',
    'specs/control-board-verifier-projection.schema.json',
    'specs/control-board-foundry-projection.schema.json',
    'specs/control-board-snapshot.schema.json',
    'specs/control-board-ingress-receipt.schema.json',
    'specs/evidence-receipt.schema.json',
    'specs/evaluator-observation-envelope.schema.json',
    'specs/evaluator-trust-policy.schema.json',
    'specs/evolution-assurance-receipt.schema.json',
    'specs/evaluator-conformance-bundle.schema.json',
    'specs/improvement-candidate.schema.json',
    'specs/lineage-resource-ledger.schema.json',
    'specs/os-isolation-attestation.schema.json',
    'specs/resource-meter-receipt.schema.json',
    'specs/windows-custody-readiness.schema.json',
    'specs/windows-isolation-measurement.schema.json',
    'specs/key-governance-state.schema.json',
    'specs/key-governance-transition.schema.json',
    'specs/protection-profile.schema.json',
    'specs/range-adapter-policy.schema.json',
    'specs/range-adapter-policy-envelope.schema.json',
    'specs/range-compilation-receipt.schema.json',
    'specs/range-collector-policy.schema.json',
    'specs/range-connector-capability-manifest.schema.json',
    'specs/range-corpus-manifest.schema.json',
    'specs/range-corpus-report.schema.json',
    'specs/range-environment-observation.schema.json',
    'specs/range-evidence-admission-report.schema.json',
    'specs/range-verifier-policy.schema.json',
    'specs/range-verifier-decision.schema.json',
    'specs/range-evidence-acceptance-report.schema.json',
    'specs/range-evidence-completion-authorization.schema.json',
    'specs/range-evidence-completion-policy.schema.json',
    'specs/range-evidence-completion-receipt.schema.json',
    'specs/public-corpus-intake-report.schema.json',
    'specs/public-sacrificial-source-registry.schema.json',
    'specs/sacrificial-replica-plan.schema.json',
    'specs/owner-scope-exclusion-registry.schema.json',
    'specs/public-source-staging-authorization.schema.json',
    'specs/source-staging-gate-report.schema.json',
    'specs/isolated-construction-zone.schema.json',
    'specs/source-quarantine-evidence-receipt.schema.json',
    'specs/construction-zone-preflight-result.schema.json',
    'specs/construction-zone-isolation-attestation-plan.schema.json',
    'specs/construction-zone-provisioning-authorization.schema.json',
    'specs/construction-zone-provisioning-gate-result.schema.json',
    'specs/range-kill-command.schema.json',
    'specs/range-kill-state.schema.json',
    'specs/range-lease-topology-scope.schema.json',
    'specs/range-preexecution-evidence-packet.schema.json',
    'specs/range-recovery-evidence.schema.json',
    'specs/range-recovery-receipt.schema.json',
    'specs/range-source-import.schema.json',
    'specs/range-topology.schema.json',
    'specs/range-topology-verdict.schema.json',
    'specs/disposable-range-preflight.schema.json',
    'specs/disposable-range-preflight-result.schema.json',
    'specs/swarm-mission.schema.json',
    'specs/swarm-verdict.schema.json',
    'specs/validation-campaign.schema.json',
    'specs/verifier-consensus.schema.json',
    'specs/verifier-health.schema.json',
    'specs/verifier-observation.schema.json',
    'specs/verifier-service-policy.schema.json',
    'specs/witness-anchor-head.schema.json',
    'specs/witness-anchor-policy.schema.json',
    'specs/witness-anchor-receipt.schema.json',
    'specs/witness-checkpoint.schema.json',
    'specs/examples/action-envelope.example.json',
    'specs/examples/cacis-capability-roadmap.example.json',
    'specs/examples/world-model-generation.example.json',
    'specs/examples/world-observation-envelope.example.json',
    'specs/examples/immune-organism-lifecycle-receipt.example.json',
    'specs/examples/immune-organism-mission.example.json',
    'specs/examples/intelligence-research-mission.example.json',
    'specs/examples/intelligence-research-settlement.example.json',
    'specs/examples/homeostasis-chronos-mission.example.json',
    'specs/examples/homeostasis-chronos-receipt.example.json',
    'specs/examples/evolution-baseline.example.json',
    'specs/examples/evolution-constitution.example.json',
    'specs/examples/epistemic-posture.example.json',
    'specs/examples/cognitive-candidate-bundle.example.json',
    'specs/examples/capability-threshold-report.example.json',
    'specs/examples/evolution-evaluation-vector.example.json',
    'specs/examples/evolution-transition-envelope.example.json',
    'specs/examples/evolution-transition-receipt.example.json',
    'specs/examples/authorization-lease.example.json',
    'specs/examples/authorization-proof-bundle.example.json',
    'specs/examples/authorization-trust-policy.example.json',
    'specs/examples/causal-coverage-verdict.example.json',
    'specs/examples/connector-manifest.example.json',
    'specs/examples/control-board-verifier-projection.example.json',
    'specs/examples/control-board-foundry-projection.example.json',
    'specs/examples/control-board-snapshot.example.json',
    'specs/examples/control-board-ingress-receipt.example.json',
    'specs/examples/evidence-receipt.example.json',
    'specs/examples/evaluator-observation-envelope.example.json',
    'specs/examples/evaluator-trust-policy.example.json',
    'specs/examples/evolution-assurance-receipt.example.json',
    'specs/examples/evaluator-conformance-bundle.example.json',
    'specs/examples/improvement-candidate.example.json',
    'specs/examples/lineage-resource-ledger.example.json',
    'specs/examples/os-isolation-attestation.example.json',
    'specs/examples/resource-meter-receipt.example.json',
    'specs/examples/windows-custody-readiness.example.json',
    'specs/examples/windows-isolation-measurement.example.json',
    'specs/examples/key-governance-state.example.json',
    'specs/examples/key-governance-transition.example.json',
    'specs/examples/protection-profile.example.json',
    'specs/examples/range-adapter-policy.example.json',
    'specs/examples/range-adapter-policy-envelope.example.json',
    'specs/examples/range-compilation-receipt.example.json',
    'specs/examples/range-collector-policy.example.json',
    'specs/examples/range-connector-capability-manifest.example.json',
    'specs/examples/range-corpus-manifest.example.json',
    'specs/examples/range-corpus-report.example.json',
    'specs/examples/range-environment-observation.example.json',
    'specs/examples/range-evidence-admission-report.example.json',
    'specs/examples/range-verifier-policy.example.json',
    'specs/examples/range-verifier-decision.example.json',
    'specs/examples/range-evidence-acceptance-report.example.json',
    'specs/examples/range-evidence-completion-authorization.example.json',
    'specs/examples/range-evidence-completion-policy.example.json',
    'specs/examples/range-evidence-completion-receipt.example.json',
    'specs/examples/public-corpus-intake-report.example.json',
    'specs/examples/public-sacrificial-source-registry.example.json',
    'specs/examples/sacrificial-replica-plan.example.json',
    'specs/examples/owner-scope-exclusion-registry.example.json',
    'specs/examples/public-source-staging-authorization.example.json',
    'specs/examples/source-staging-gate-report.example.json',
    'specs/examples/isolated-construction-zone.example.json',
    'specs/examples/source-quarantine-evidence-receipt.example.json',
    'specs/examples/construction-zone-preflight-result.example.json',
    'specs/examples/construction-zone-isolation-attestation-plan.example.json',
    'specs/examples/construction-zone-provisioning-authorization.example.json',
    'specs/examples/construction-zone-provisioning-gate-result.example.json',
    'specs/examples/range-kill-command.example.json',
    'specs/examples/range-kill-state.example.json',
    'specs/examples/range-lease-topology-scope.example.json',
    'specs/examples/range-preexecution-evidence-packet.example.json',
    'specs/examples/range-recovery-evidence.example.json',
    'specs/examples/range-recovery-receipt.example.json',
    'specs/examples/range-source-import.example.json',
    'specs/examples/range-topology.example.json',
    'specs/examples/range-topology-verdict.example.json',
    'specs/examples/disposable-range-preflight.example.json',
    'specs/examples/disposable-range-preflight-result.example.json',
    'specs/examples/swarm-mission.example.json',
    'specs/examples/swarm-verdict.example.json',
    'specs/examples/validation-campaign.example.json',
    'specs/examples/verifier-consensus.example.json',
    'specs/examples/verifier-health.example.json',
    'specs/examples/verifier-observation.example.json',
    'specs/examples/verifier-service-policy.example.json',
    'specs/examples/witness-anchor-head.example.json',
    'specs/examples/witness-anchor-policy.example.json',
    'specs/examples/witness-anchor-receipt.example.json',
    'specs/examples/witness-checkpoint.example.json',
    'src/nimrod_simulator/anchor_verifier_cli.py',
    'src/nimrod_cacis/__init__.py',
    'src/nimrod_cacis/roadmap.py',
    'src/nimrod_cacis/world_model.py',
    'src/nimrod_cacis/world_model_cli.py',
    'src/nimrod_cacis/world_intake.py',
    'src/nimrod_cacis/world_intake_cli.py',
    'src/nimrod_cacis/world_intake_process.py',
    'src/nimrod_cacis/world_intake_verifier.py',
    'src/nimrod_cacis/world_intake_verifier_cli.py',
    'src/nimrod_cacis/world_intake_governance.py',
    'src/nimrod_cacis/world_intake_governance_process.py',
    'src/nimrod_cacis/world_intake_governance_verifier_cli.py',
    'src/nimrod_cacis/immune_runtime.py',
    'src/nimrod_cacis/immune_runtime_cli.py',
    'src/nimrod_cacis/homeostasis.py',
    'src/nimrod_cacis/homeostasis_cli.py',
    'src/nimrod_cacis/genome.py',
    'src/nimrod_cacis/arenas.py',
    'src/nimrod_cacis/contract_conformance.py',
    'src/nimrod_research/__init__.py',
    'src/nimrod_research/intelligence_lab.py',
    'src/nimrod_research/verifier.py',
    'src/nimrod_research/verifier_cli.py',
    'src/nimrod_research/process_verification.py',
    'src/nimrod_research/cli.py',
    'src/nimrod_simulator/__init__.py',
    'src/nimrod_simulator/authorization.py',
    'src/nimrod_simulator/authorization_crypto.py',
    'src/nimrod_simulator/cli.py',
    'src/nimrod_simulator/compiler.py',
    'src/nimrod_simulator/control_board.py',
    'src/nimrod_simulator/control_board_foundry.py',
    'src/nimrod_simulator/control_board_ingress.py',
    'src/nimrod_simulator/errors.py',
    'src/nimrod_simulator/autonomous_promotion.py',
    'src/nimrod_simulator/protection_profile.py',
    'src/nimrod_simulator/evolution_constitution.py',
    'src/nimrod_simulator/evolution_foundry.py',
    'src/nimrod_simulator/evaluator_observation.py',
    'src/nimrod_simulator/isolation_boundary.py',
    'src/nimrod_simulator/resource_ledger.py',
    'src/nimrod_platform_assurance/__init__.py',
    'src/nimrod_platform_assurance/resource_meter.py',
    'src/nimrod_platform_assurance/windows_custody_readiness.py',
    'src/nimrod_platform_assurance/windows_isolation_collector.py',
    'src/nimrod_platform_assurance/verifier_identity_readiness.py',
    'src/nimrod_simulator/evolution_transition.py',
    'src/nimrod_simulator/jsonio.py',
    'src/nimrod_simulator/key_governance.py',
    'src/nimrod_simulator/model.py',
    'src/nimrod_simulator/range_adapter.py',
    'src/nimrod_simulator/range_policy.py',
    'src/nimrod_simulator/range_corpus.py',
    'src/nimrod_simulator/range_preflight.py',
    'src/nimrod_simulator/range_execution_gate.py',
    'src/nimrod_simulator/range_evidence_admission.py',
    'src/nimrod_simulator/range_evidence_acceptance.py',
    'src/nimrod_simulator/range_evidence_completion.py',
    'src/nimrod_simulator/public_sacrificial_corpus.py',
    'src/nimrod_simulator/source_staging_gate.py',
    'src/nimrod_simulator/construction_zone_preflight.py',
    'src/nimrod_simulator/construction_zone_provisioning_gate.py',
    'src/nimrod_simulator/range_topology.py',
    'src/nimrod_simulator/range_kill.py',
    'src/nimrod_simulator/range_recovery.py',
    'src/nimrod_simulator/threshold_signing.py',
    'src/nimrod_simulator/migrations.py',
    'src/nimrod_simulator/runtime.py',
    'src/nimrod_simulator/state_journal.py',
    'src/nimrod_simulator/swarm.py',
    'src/nimrod_simulator/swarm_cli.py',
    'src/nimrod_simulator/verifier_cli.py',
    'src/nimrod_simulator/verifier_service.py',
    'src/nimrod_simulator/verifier_service_cli.py',
    'src/nimrod_simulator/witness.py',
    'src/nimrod_simulator/witness_checkpoint.py',
    'tests/fixtures/simulator/control-state.valid.json',
    'tests/fixtures/range_adapter/atomic.valid.yaml',
    'tests/fixtures/range_adapter/caldera.valid.yml',
    'tests/fixtures/cacis/world-model-replay-credential-theft.json',
    'tests/fixtures/cacis/immune-organism-mission-suspicious-script.json',
    'tests/fixtures/cacis/arena-replay-scenarios.json',
    'tools/authorization_state_worker.py',
    'tools/evolution_foundry_worker.py',
    'tools/evolution_evaluator_worker.py',
    'tools/evolution_promoter_worker.py',
    'tools/autonomous_promotion_worker.py',
    'tools/validate_evolution_foundry.py',
    'tools/validate_evolution_assurance.py',
    'tools/validate_autonomous_promotion.py',
    'tools/validate_distribution.py',
    'tools/validate_evaluator_conformance.py',
    'tools/validate_resource_meter.py',
    'tools/validate_windows_custody_readiness.py',
    'tools/validate_windows_isolation.py',
    'tools/validate_cacis_roadmap.py',
    'tools/validate_world_model.py',
    'tools/validate_world_intake.py',
    'tools/validate_world_intake_governance.py',
    'tools/validate_immune_runtime.py',
    'tools/validate_intelligence_research.py',
    'tools/validate_homeostasis_chronos.py',
    'tools/validate_genome_evaluation.py',
    'tools/validate_arenas_observatory.py',
    'tools/validate_contract_conformance.py',
    'tools/validate_contract_runtime_bindings.py',
    'tools/validate_verifier_identity_readiness.py',
    'tools/validate_completion_audit.py',
    'tools/verifier_identity_probe_worker.py',
    'tools/validate_authorization_state.py',
    'tools/validate_key_governance.py',
    'tools/validate_supervised_verifier.py',
    'tools/validate_witness_anchor.py',
    'tools/verifier_stall_worker.py',
    'tools/verifier_unavailable_worker.py',
    'tools/validate_contracts.py',
    'tools/validate_manifest.py',
    'tools/validate_simulator.py',
    'tools/validate_swarm.py',
    'tools/validate_control_board.py',
    'tools/validate_control_board_ingress.py',
    'tools/validate_range_adapter.py',
    'tools/validate_range_readiness.py',
    'tools/validate_range_lifecycle.py',
    'tools/validate_range_execution_gate.py',
    'tools/validate_range_evidence_admission.py',
    'tools/validate_range_evidence_acceptance.py',
    'tools/validate_range_evidence_completion.py',
    'tools/validate_public_sacrificial_corpus.py',
    'tools/validate_source_staging_gate.py',
    'tools/validate_construction_zone_preflight.py',
    'tools/validate_construction_zone_provisioning_gate.py',
    'tools/range_kill_worker.py',
    'tools/resource_meter_worker.py',
    'tools/resource_meter_abrupt_crash_driver.py',
    'tools/resource_meter_recovery_driver.py',
    'tools/windows_isolation_target_worker.py',
    'conformance/typescript-evaluator/package.json',
    'conformance/typescript-evaluator/package-lock.json',
    'conformance/typescript-evaluator/tsconfig.json',
    'conformance/typescript-evaluator/src/index.ts',
    'ui/index.html',
    'ui/styles.css',
    'ui/app.js',
    'ui/demo-state.json',
    'specs/edge-preview-scenario.schema.json',
    'specs/edge-preview-result.schema.json',
    'specs/examples/edge-preview-scenario.example.json',
    'specs/examples/edge-preview-result.example.json',
    'src/nimrod_edge/__init__.py',
    'src/nimrod_edge/model.py',
    'src/nimrod_edge/runtime.py',
    'src/nimrod_edge/verifier.py',
    'src/nimrod_edge/verifier_cli.py',
    'src/nimrod_edge/cli.py',
    'src/nimrod_edge/live_observation.py',
    'src/nimrod_edge/live_cli.py',
    'src/nimrod_edge/continuous_observation.py',
    'src/nimrod_edge/continuous_cli.py',
    'src/nimrod_edge/design_partner.py',
    'src/nimrod_release/__init__.py',
    'src/nimrod_release/verification.py',
    'tools/generate_manifest.py',
    'tools/validate_edge_preview.py',
    'tools/validate_edge_live_observation.py',
    'tools/validate_edge_continuous_observation.py',
    'tools/validate_release_foundation.py',
    'tools/validate_design_partner_kit.py',
    'specs/edge-live-process-observation.schema.json',
    'specs/plugin-capability-manifest.schema.json',
    'specs/edge-update-manifest.schema.json',
    'specs/edge-update-verification-receipt.schema.json',
    'specs/design-partner-evaluation-plan.schema.json',
    'specs/examples/edge-live-process-observation.example.json',
    'specs/examples/plugin-capability-manifest.example.json',
    'specs/examples/edge-update-manifest.example.json',
    'specs/examples/edge-update-verification-receipt.example.json',
    'specs/examples/design-partner-evaluation-plan.example.json'
)

[System.Collections.Generic.List[string]]$missingFiles = [System.Collections.Generic.List[string]]::new()
foreach ($relativePath in $requiredFiles) {
    [string]$absolutePath = Join-Path $projectRoot $relativePath
    if (-not (Test-Path -LiteralPath $absolutePath -PathType Leaf)) {
        $missingFiles.Add($relativePath)
    }
}

if ($missingFiles.Count -gt 0) {
    throw [System.IO.FileNotFoundException]::new("nimrod foundation is missing required files: $($missingFiles -join ', ')")
}

[string[]]$jsonFiles = @(
    'specs/action-and-evidence-envelope.schema.json',
    'specs/evolution-baseline.schema.json',
    'specs/evolution-constitution.schema.json',
    'specs/epistemic-posture.schema.json',
    'specs/cognitive-candidate-bundle.schema.json',
    'specs/capability-threshold-report.schema.json',
    'specs/evolution-evaluation-vector.schema.json',
    'specs/evolution-transition-envelope.schema.json',
    'specs/evolution-transition-receipt.schema.json',
    'specs/authorization-lease.schema.json',
    'specs/authorization-proof-bundle.schema.json',
    'specs/authorization-trust-policy.schema.json',
    'specs/causal-coverage-verdict.schema.json',
    'specs/connector-manifest.schema.json',
    'specs/control-board-verifier-projection.schema.json',
    'specs/control-board-foundry-projection.schema.json',
    'specs/control-board-snapshot.schema.json',
    'specs/control-board-ingress-receipt.schema.json',
    'specs/evidence-receipt.schema.json',
    'specs/evaluator-observation-envelope.schema.json',
    'specs/evaluator-trust-policy.schema.json',
    'specs/evolution-assurance-receipt.schema.json',
    'specs/evaluator-conformance-bundle.schema.json',
    'specs/improvement-candidate.schema.json',
    'specs/lineage-resource-ledger.schema.json',
    'specs/os-isolation-attestation.schema.json',
    'specs/resource-meter-receipt.schema.json',
    'specs/windows-custody-readiness.schema.json',
    'specs/windows-isolation-measurement.schema.json',
    'specs/key-governance-state.schema.json',
    'specs/key-governance-transition.schema.json',
    'specs/protection-profile.schema.json',
    'specs/range-adapter-policy.schema.json',
    'specs/range-adapter-policy-envelope.schema.json',
    'specs/range-compilation-receipt.schema.json',
    'specs/range-collector-policy.schema.json',
    'specs/range-connector-capability-manifest.schema.json',
    'specs/range-corpus-manifest.schema.json',
    'specs/range-corpus-report.schema.json',
    'specs/range-environment-observation.schema.json',
    'specs/range-evidence-admission-report.schema.json',
    'specs/range-verifier-policy.schema.json',
    'specs/range-verifier-decision.schema.json',
    'specs/range-evidence-acceptance-report.schema.json',
    'specs/range-evidence-completion-authorization.schema.json',
    'specs/range-evidence-completion-policy.schema.json',
    'specs/range-evidence-completion-receipt.schema.json',
    'specs/public-corpus-intake-report.schema.json',
    'specs/public-sacrificial-source-registry.schema.json',
    'specs/sacrificial-replica-plan.schema.json',
    'specs/owner-scope-exclusion-registry.schema.json',
    'specs/public-source-staging-authorization.schema.json',
    'specs/source-staging-gate-report.schema.json',
    'specs/isolated-construction-zone.schema.json',
    'specs/source-quarantine-evidence-receipt.schema.json',
    'specs/construction-zone-preflight-result.schema.json',
    'specs/construction-zone-isolation-attestation-plan.schema.json',
    'specs/construction-zone-provisioning-authorization.schema.json',
    'specs/construction-zone-provisioning-gate-result.schema.json',
    'specs/range-kill-command.schema.json',
    'specs/range-kill-state.schema.json',
    'specs/range-lease-topology-scope.schema.json',
    'specs/range-preexecution-evidence-packet.schema.json',
    'specs/range-recovery-evidence.schema.json',
    'specs/range-recovery-receipt.schema.json',
    'specs/range-source-import.schema.json',
    'specs/range-topology.schema.json',
    'specs/range-topology-verdict.schema.json',
    'specs/disposable-range-preflight.schema.json',
    'specs/disposable-range-preflight-result.schema.json',
    'specs/swarm-mission.schema.json',
    'specs/swarm-verdict.schema.json',
    'specs/validation-campaign.schema.json',
    'specs/verifier-consensus.schema.json',
    'specs/verifier-health.schema.json',
    'specs/verifier-observation.schema.json',
    'specs/verifier-service-policy.schema.json',
    'specs/witness-anchor-head.schema.json',
    'specs/witness-anchor-policy.schema.json',
    'specs/witness-anchor-receipt.schema.json',
    'specs/witness-checkpoint.schema.json',
    'specs/examples/action-envelope.example.json',
    'specs/examples/evolution-baseline.example.json',
    'specs/examples/evolution-constitution.example.json',
    'specs/examples/epistemic-posture.example.json',
    'specs/examples/cognitive-candidate-bundle.example.json',
    'specs/examples/capability-threshold-report.example.json',
    'specs/examples/evolution-evaluation-vector.example.json',
    'specs/examples/evolution-transition-envelope.example.json',
    'specs/examples/evolution-transition-receipt.example.json',
    'specs/examples/authorization-lease.example.json',
    'specs/examples/authorization-proof-bundle.example.json',
    'specs/examples/authorization-trust-policy.example.json',
    'specs/examples/causal-coverage-verdict.example.json',
    'specs/examples/connector-manifest.example.json',
    'specs/examples/control-board-verifier-projection.example.json',
    'specs/examples/control-board-foundry-projection.example.json',
    'specs/examples/control-board-snapshot.example.json',
    'specs/examples/control-board-ingress-receipt.example.json',
    'specs/examples/evidence-receipt.example.json',
    'specs/examples/evaluator-observation-envelope.example.json',
    'specs/examples/evaluator-trust-policy.example.json',
    'specs/examples/evolution-assurance-receipt.example.json',
    'specs/examples/evaluator-conformance-bundle.example.json',
    'specs/examples/improvement-candidate.example.json',
    'specs/examples/lineage-resource-ledger.example.json',
    'specs/examples/os-isolation-attestation.example.json',
    'specs/examples/resource-meter-receipt.example.json',
    'specs/examples/windows-custody-readiness.example.json',
    'specs/examples/windows-isolation-measurement.example.json',
    'specs/examples/key-governance-state.example.json',
    'specs/examples/key-governance-transition.example.json',
    'specs/examples/protection-profile.example.json',
    'specs/examples/range-adapter-policy.example.json',
    'specs/examples/range-adapter-policy-envelope.example.json',
    'specs/examples/range-compilation-receipt.example.json',
    'specs/examples/range-collector-policy.example.json',
    'specs/examples/range-connector-capability-manifest.example.json',
    'specs/examples/range-corpus-manifest.example.json',
    'specs/examples/range-corpus-report.example.json',
    'specs/examples/range-environment-observation.example.json',
    'specs/examples/range-evidence-admission-report.example.json',
    'specs/examples/range-verifier-policy.example.json',
    'specs/examples/range-verifier-decision.example.json',
    'specs/examples/range-evidence-acceptance-report.example.json',
    'specs/examples/range-evidence-completion-authorization.example.json',
    'specs/examples/range-evidence-completion-policy.example.json',
    'specs/examples/range-evidence-completion-receipt.example.json',
    'specs/examples/public-corpus-intake-report.example.json',
    'specs/examples/public-sacrificial-source-registry.example.json',
    'specs/examples/sacrificial-replica-plan.example.json',
    'specs/examples/owner-scope-exclusion-registry.example.json',
    'specs/examples/public-source-staging-authorization.example.json',
    'specs/examples/source-staging-gate-report.example.json',
    'specs/examples/isolated-construction-zone.example.json',
    'specs/examples/source-quarantine-evidence-receipt.example.json',
    'specs/examples/construction-zone-preflight-result.example.json',
    'specs/examples/construction-zone-isolation-attestation-plan.example.json',
    'specs/examples/construction-zone-provisioning-authorization.example.json',
    'specs/examples/construction-zone-provisioning-gate-result.example.json',
    'specs/examples/range-kill-command.example.json',
    'specs/examples/range-kill-state.example.json',
    'specs/examples/range-lease-topology-scope.example.json',
    'specs/examples/range-preexecution-evidence-packet.example.json',
    'specs/examples/range-recovery-evidence.example.json',
    'specs/examples/range-recovery-receipt.example.json',
    'specs/examples/range-source-import.example.json',
    'specs/examples/range-topology.example.json',
    'specs/examples/range-topology-verdict.example.json',
    'specs/examples/disposable-range-preflight.example.json',
    'specs/examples/disposable-range-preflight-result.example.json',
    'specs/examples/swarm-mission.example.json',
    'specs/examples/swarm-verdict.example.json',
    'specs/examples/validation-campaign.example.json',
    'specs/examples/verifier-consensus.example.json',
    'specs/examples/verifier-health.example.json',
    'specs/examples/verifier-observation.example.json',
    'specs/examples/verifier-service-policy.example.json',
    'specs/examples/witness-anchor-head.example.json',
    'specs/examples/witness-anchor-policy.example.json',
    'specs/examples/witness-anchor-receipt.example.json',
    'specs/examples/witness-checkpoint.example.json',
    'specs/edge-preview-scenario.schema.json',
    'specs/edge-preview-result.schema.json',
    'specs/examples/edge-preview-scenario.example.json',
    'specs/examples/edge-preview-result.example.json',
    'specs/edge-live-process-observation.schema.json',
    'specs/plugin-capability-manifest.schema.json',
    'specs/edge-update-manifest.schema.json',
    'specs/edge-update-verification-receipt.schema.json',
    'specs/design-partner-evaluation-plan.schema.json',
    'specs/examples/edge-live-process-observation.example.json',
    'specs/examples/plugin-capability-manifest.example.json',
    'specs/examples/edge-update-manifest.example.json',
    'specs/examples/edge-update-verification-receipt.example.json',
    'specs/examples/design-partner-evaluation-plan.example.json',
    'specs/cacis-capability-roadmap.schema.json',
    'specs/world-model-generation.schema.json',
    'specs/world-observation-envelope.schema.json',
    'specs/immune-organism-lifecycle-receipt.schema.json',
    'specs/immune-organism-mission.schema.json',
    'specs/examples/cacis-capability-roadmap.example.json',
    'specs/examples/world-model-generation.example.json',
    'specs/examples/world-observation-envelope.example.json',
    'specs/examples/immune-organism-lifecycle-receipt.example.json',
    'specs/examples/immune-organism-mission.example.json',
    'specs/intelligence-research-mission.schema.json',
    'specs/intelligence-research-settlement.schema.json',
    'specs/examples/intelligence-research-mission.example.json',
    'specs/examples/intelligence-research-settlement.example.json',
    'specs/homeostasis-chronos-mission.schema.json',
    'specs/homeostasis-chronos-receipt.schema.json',
    'specs/examples/homeostasis-chronos-mission.example.json',
    'specs/examples/homeostasis-chronos-receipt.example.json',
    'docs/hardening/cacis-vnext/hardening.json',
    'reports/CACIS_ROADMAP_VALIDATION.json',
    'reports/CACIS_WORLD_MODEL_VALIDATION.json',
    'reports/CACIS_WORLD_INTAKE_VALIDATION.json',
    'reports/CACIS_WORLD_INTAKE_GOVERNANCE_VALIDATION.json',
    'reports/CACIS_IMMUNE_RUNTIME_VALIDATION.json',
    'reports/INTELLIGENCE_RESEARCH_VALIDATION.json',
    'reports/CACIS_HOMEOSTASIS_CHRONOS_VALIDATION.json',
    'reports/CONTRACT_CONFORMANCE_MATRIX.json',
    'reports/CONTRACT_RUNTIME_BINDINGS_VALIDATION.json',
    'reports/VERIFIER_IDENTITY_READINESS_VALIDATION.json',
    'reports/COMPLETION_AUDIT.json',
    'reports/SIMULATOR_VALIDATION.json',
    'reports/AUTHORIZATION_STATE_VALIDATION.json',
    'reports/KEY_GOVERNANCE_VALIDATION.json',
    'reports/WITNESS_ANCHOR_VALIDATION.json',
    'reports/SUPERVISED_VERIFIER_VALIDATION.json',
    'reports/SWARM_VALIDATION.json',
    'reports/CONTROL_BOARD_VALIDATION.json',
    'reports/CONTROL_BOARD_INGRESS_VALIDATION.json',
    'reports/RANGE_ADAPTER_VALIDATION.json',
    'reports/RANGE_READINESS_VALIDATION.json',
    'reports/RANGE_LIFECYCLE_VALIDATION.json',
    'reports/RANGE_EXECUTION_GATE_VALIDATION.json',
    'reports/RANGE_EVIDENCE_ADMISSION_VALIDATION.json',
    'reports/RANGE_EVIDENCE_ACCEPTANCE_VALIDATION.json',
    'reports/RANGE_EVIDENCE_COMPLETION_VALIDATION.json',
    'reports/PUBLIC_SACRIFICIAL_CORPUS_VALIDATION.json',
    'reports/SOURCE_STAGING_GATE_VALIDATION.json',
    'reports/CONSTRUCTION_ZONE_PREFLIGHT_VALIDATION.json',
    'reports/CONSTRUCTION_ZONE_PROVISIONING_GATE_VALIDATION.json',
    'reports/EVOLUTION_FOUNDRY_VALIDATION.json',
    'reports/EVOLUTION_ASSURANCE_VALIDATION.json',
    'reports/EVALUATOR_CONFORMANCE_VALIDATION.json',
    'reports/RESOURCE_METER_VALIDATION.json',
    'reports/WINDOWS_CUSTODY_READINESS_VALIDATION.json',
    'reports/WINDOWS_ISOLATION_VALIDATION.json',
    'reports/EDGE_LIVE_OBSERVATION_VALIDATION.json',
    'reports/EDGE_CONTINUOUS_OBSERVATION_VALIDATION.json',
    'reports/EDGE_PREVIEW_VALIDATION.json',
    'reports/GITHUB_GOVERNANCE_VALIDATION.json',
    'reports/RELEASE_FOUNDATION_VALIDATION.json',
    'reports/DESIGN_PARTNER_KIT_VALIDATION.json',
    'reports/CACIS_GENOME_EVALUATION_VALIDATION.json',
    'reports/CACIS_ARENAS_OBSERVATORY_VALIDATION.json',
    'ui/demo-state.json',
    'tests/fixtures/simulator/control-state.valid.json',
    'tests/fixtures/cacis/world-model-replay-credential-theft.json',
    'tests/fixtures/cacis/immune-organism-mission-suspicious-script.json'
)

foreach ($relativePath in $jsonFiles) {
    [string]$absolutePath = Join-Path $projectRoot $relativePath
    try {
        $null = Get-Content -LiteralPath $absolutePath -Raw -Encoding utf8 | ConvertFrom-Json
    }
    catch {
        throw [System.IO.InvalidDataException]::new("Invalid JSON in schema '$relativePath': $($_.Exception.Message)", $_.Exception)
    }
}

[string]$actionExamplePath = Join-Path $projectRoot 'specs/examples/action-envelope.example.json'
[object]$actionExample = Get-Content -LiteralPath $actionExamplePath -Raw -Encoding utf8 | ConvertFrom-Json
[string[]]$requiredActionFields = @(
    'envelope_version',
    'event_id',
    'mission_id',
    'timestamp',
    'origin',
    'actor',
    'intent',
    'context',
    'risk',
    'execution_contract',
    'recovery',
    'verification',
    'authorization',
    'signatures'
)
foreach ($requiredField in $requiredActionFields) {
    if ($requiredField -notin $actionExample.PSObject.Properties.Name) {
        throw [System.IO.InvalidDataException]::new("Action envelope example is missing required field '$requiredField'.")
    }
}

[string]$evidenceExamplePath = Join-Path $projectRoot 'specs/examples/evidence-receipt.example.json'
[object]$evidenceExample = Get-Content -LiteralPath $evidenceExamplePath -Raw -Encoding utf8 | ConvertFrom-Json
[string[]]$requiredEvidenceFields = @(
    'receipt_version',
    'evidence_id',
    'incident_id',
    'origin',
    'observation_time',
    'collection_time',
    'validity_interval',
    'source_identity',
    'content_digest',
    'classification',
    'retention_policy',
    'signatures'
)
foreach ($requiredField in $requiredEvidenceFields) {
    if ($requiredField -notin $evidenceExample.PSObject.Properties.Name) {
        throw [System.IO.InvalidDataException]::new("Evidence receipt example is missing required field '$requiredField'.")
    }
}

[object[]]$additionalContractChecks = @(
    [pscustomobject]@{
        Path = 'specs/examples/protection-profile.example.json'
        Fields = @('profile_version','profile_id','subject','environment_class','sensors','prohibited_effects','recovery','oracles','known_limitations')
    },
    [pscustomobject]@{
        Path = 'specs/examples/connector-manifest.example.json'
        Fields = @('manifest_version','connector_id','connector_version','role','lifecycle_operations','permissions','abort_contract','cleanup_contract','license_review')
    },
    [pscustomobject]@{
        Path = 'specs/examples/authorization-lease.example.json'
        Fields = @('lease_version','lease_id','customer_id','authority_proof','target_graph','effect_ceiling','prohibited_actions','budgets','kill_switch','signatures')
    },
    [pscustomobject]@{
        Path = 'specs/examples/authorization-proof-bundle.example.json'
        Fields = @('bundle_version','bundle_id','origin','lease_id','lease_digest','trust_policy_digest','signed_at','signatures')
    },
    [pscustomobject]@{
        Path = 'specs/examples/authorization-trust-policy.example.json'
        Fields = @('policy_version','policy_id','origin','trust_source','threshold','required_roles','trusted_signers')
    },
    [pscustomobject]@{
        Path = 'specs/examples/validation-campaign.example.json'
        Fields = @('campaign_version','campaign_id','authorization_lease_id','objective','steps','negative_controls','expected_evidence','cleanup_plan','success_contract','failure_contract')
    },
    [pscustomobject]@{
        Path = 'specs/examples/causal-coverage-verdict.example.json'
        Fields = @('verdict_version','verdict_id','origin','campaign_id','step_id','target_id','status','causal_chain','assurance_vector','uncertainties','residual_risks')
    },
    [pscustomobject]@{
        Path = 'specs/examples/improvement-candidate.example.json'
        Fields = @('candidate_version','candidate_id','candidate_class','authority_tier','source_evidence','lens','mutation_family','evaluation_plan','sealed_evaluation','champion_floor','rollback','promotion_policy','demotion_triggers','status')
    },
    [pscustomobject]@{
        Path = 'specs/examples/swarm-mission.example.json'
        Fields = @('mission_version','mission_id','origin','authorization_lease_id','proposal_only','cells','separation_rules','work_items')
    },
    [pscustomobject]@{
        Path = 'specs/examples/swarm-verdict.example.json'
        Fields = @('verdict_version','verdict_id','origin','mission_id','status','contributions','quorum','authority','dissent')
    },
    [pscustomobject]@{
        Path = 'specs/examples/key-governance-state.example.json'
        Fields = @('state_version','governance_id','origin','epoch','previous_state_digest','threshold','ceremony_key_count','minimum_distinct_roles','keys')
    },
    [pscustomobject]@{
        Path = 'specs/examples/key-governance-transition.example.json'
        Fields = @('transition_version','transition_id','origin','governance_id','from_epoch','to_epoch','kind','previous_state_digest','next_state_digest','affected_key_ids','signatures')
    },
    [pscustomobject]@{
        Path = 'specs/examples/witness-checkpoint.example.json'
        Fields = @('checkpoint_version','checkpoint_id','origin','witness_id','tree_size','merkle_root_sha256','journal_prefix_digest','previous_checkpoint_digest','governance_state_digest','signatures')
    },
    [pscustomobject]@{
        Path = 'specs/examples/witness-anchor-policy.example.json'
        Fields = @('policy_version','policy_id','origin','anchor_store_id','not_before','expires_at','minimum_head_sequence','allowed_witness_ids','anchor_key')
    },
    [pscustomobject]@{
        Path = 'specs/examples/witness-anchor-receipt.example.json'
        Fields = @('receipt_version','receipt_id','origin','anchor_store_id','anchor_policy_digest','sequence','checkpoint_digest','previous_receipt_digest','anchor_key_id','signature_base64')
    },
    [pscustomobject]@{
        Path = 'specs/examples/witness-anchor-head.example.json'
        Fields = @('head_version','head_id','origin','anchor_store_id','anchor_policy_digest','sequence','latest_receipt_digest','latest_checkpoint_digest','tree_size','anchor_key_id','signature_base64')
    },
    [pscustomobject]@{
        Path = 'specs/examples/verifier-service-policy.example.json'
        Fields = @('policy_version','policy_id','origin','service_id','logical_principal','process_boundary_required','read_only_inputs_required','production_distinct_os_account_required','allowed_capabilities','prohibited_capabilities','environment_allowlist','request_timeout_ms')
    },
    [pscustomobject]@{
        Path = 'specs/examples/verifier-health.example.json'
        Fields = @('health_version','request_id','origin','service_id','logical_principal','process_id','status','read_only_inputs_required','filesystem_write_capability_exposed','os_account_boundary_verified','production_ready')
    },
    [pscustomobject]@{
        Path = 'specs/examples/verifier-observation.example.json'
        Fields = @('observation_version','observation_id','origin','service_id','logical_principal','process_id','observed_at','status','subject_digest','read_only_behavior_verified','os_account_boundary_verified','details')
    },
    [pscustomobject]@{
        Path = 'specs/examples/verifier-consensus.example.json'
        Fields = @('consensus_version','consensus_id','origin','observed_at','primary_observation_digest','secondary_observation_digest','state','verification_accepted','reason')
    },
    [pscustomobject]@{
        Path = 'specs/examples/control-board-snapshot.example.json'
        Fields = @('snapshot_version','snapshot_id','snapshot_kind','origin','issuer_service_id','audience','sequence','issued_at','not_before','expires_at','previous_snapshot_digest','projection_digest','governance_state_digest','authority','signatures')
    },
    [pscustomobject]@{
        Path = 'specs/examples/control-board-ingress-receipt.example.json'
        Fields = @('ingress_version','origin','status','issuer_service_id','audience','sequence','snapshot_id','snapshot_digest','projection_digest','accepted_at','freshness_seconds','verified_signer_ids','verified_roles','durable_replay_guard','stale_state_guard','authority')
    },
    [pscustomobject]@{
        Path = 'specs/examples/range-source-import.example.json'
        Fields = @('import_version','import_id','origin','source_kind','source_artifact_digest','source_object_id','technique_id','platforms','executors','raw_execution_fields_present','raw_execution_material_retained','command_digest','cleanup_digest','dynamic_input_or_payload_reference_count','findings','quarantine_status','authority')
    },
    [pscustomobject]@{
        Path = 'specs/examples/range-adapter-policy.example.json'
        Fields = @('policy_version','policy_id','origin','stage','source_mappings','output_template','authority')
    },
    [pscustomobject]@{
        Path = 'specs/examples/range-compilation-receipt.example.json'
        Fields = @('compilation_version','origin','status','source_kind','source_object_id','source_artifact_digest','import_receipt_digest','mapping_policy_digest','campaign_id','campaign_digest','connector_id','capability','raw_execution_material_forwarded','source_tool_contacted','target_discovery_performed','live_execution_performed','authority')
    },
    [pscustomobject]@{
        Path = 'specs/examples/range-connector-capability-manifest.example.json'
        Fields = @('manifest_version','manifest_id','origin','connector_id','connector_version','source_manifest_digest','governance_state_digest','issued_at','not_before','expires_at','capability_allowlist','operation_allowlist','supported_environment_classes','network_destinations','secret_references','installation_required','source_tool_contact_required','target_discovery_performed','artifact_digest_required','status','blockers','authority','signatures')
    },
    [pscustomobject]@{
        Path = 'specs/examples/range-lease-topology-scope.example.json'
        Fields = @('scope_version','scope_id','origin','status','compiled_at','lease_id','lease_digest','authorization_proof_bundle_digest','trust_policy_digest','cryptographic_authorization_verified','verified_authorization_signer_ids','verified_authorization_roles','topology_id','topology_digest','topology_generation','topology_environment_verified','connector_id','connector_manifest_digest','capability_intersection','target_bindings','kill_switch_binding','budgets','blockers','provisioning_performed','installation_performed','network_contact_performed','range_connection_authorized','execution_authorized','authority')
    },
    [pscustomobject]@{
        Path = 'specs/examples/range-preexecution-evidence-packet.example.json'
        Fields = @('packet_version','packet_id','origin','status','assembled_at','scope_id','scope_digest','connector_manifest_digest','topology_verdict_digest','preflight_result_digest','required_attestation_controls','environment_attestations','missing_real_attestations','real_environment_attestation_count','distinct_verified_verifier_count','evidence_complete','blockers','provisioning_performed','installation_performed','source_tool_contacted','network_contact_performed','range_connection_authorized','execution_authorized','authority')
    },
    [pscustomobject]@{
        Path = 'specs/examples/range-verifier-policy.example.json'
        Fields = @('policy_version','policy_id','origin','status','governance_state_digest','admission_report_id','admission_report_digest','scope_digest','environment_id','issued_at','not_before','expires_at','minimum_decisions_per_observation','allowed_decisions','verifiers','blockers','authority','signatures')
    },
    [pscustomobject]@{
        Path = 'specs/examples/range-verifier-decision.example.json'
        Fields = @('decision_version','decision_id','origin','status','policy_id','policy_digest','admission_report_id','admission_report_digest','environment_id','scope_digest','observation_id','observation_digest','raw_evidence_digest','control_id','verifier','decision','reason','decided_at','evidence_read_only','activity','authority','signature')
    },
    [pscustomobject]@{
        Path = 'specs/examples/range-evidence-acceptance-report.example.json'
        Fields = @('report_version','report_id','origin','status','assembled_at','policy_id','policy_digest','admission_report_id','admission_report_digest','scope_digest','environment_id','environment_name','owner_named_environment','required_control_count','verified_decision_count','distinct_signed_verifier_count','real_independent_verifier_count','retained_decisions','control_results','resolution_counts','accepted_control_count','verified_attestation_count','evidence_complete','blockers','activity','authority')
    },
    [pscustomobject]@{
        Path = 'specs/examples/range-evidence-completion-policy.example.json'
        Fields = @('policy_version','policy_id','origin','status','governance_state_digest','acceptance_report_id','acceptance_report_digest','scope_digest','environment_id','issued_at','not_before','expires_at','required_controls','required_accepted_control_count','required_verified_attestation_count','required_real_independent_verifier_count','required_acceptance_status','allowed_outcomes','network_destinations','secret_references','blockers','authority','signatures')
    },
    [pscustomobject]@{
        Path = 'specs/examples/range-evidence-completion-authorization.example.json'
        Fields = @('authorization_version','authorization_id','origin','status','policy_id','policy_digest','acceptance_report_id','acceptance_report_digest','scope_digest','environment_id','issued_at','not_before','expires_at','outcome','reason','authority','signatures')
    },
    [pscustomobject]@{
        Path = 'specs/examples/range-evidence-completion-receipt.example.json'
        Fields = @('receipt_version','receipt_id','origin','status','completed_at','policy_id','policy_digest','authorization_id','authorization_digest','acceptance_report_id','acceptance_report_digest','scope_digest','environment_id','environment_name','owner_named_environment','required_control_count','accepted_control_count','verified_attestation_count','real_independent_verifier_count','completion_prerequisites_satisfied','completion_authorized','evidence_complete','range_connection_authorized','execution_authorized','verified_authorization_signer_ids','verified_authorization_roles','blockers','activity','authority')
    },
    [pscustomobject]@{
        Path = 'specs/examples/public-sacrificial-source-registry.example.json'
        Fields = @('registry_version','registry_id','origin','status','observed_at','owner_boundary','sources','forbidden_target_classes','blockers','authority')
    },
    [pscustomobject]@{
        Path = 'specs/examples/sacrificial-replica-plan.example.json'
        Fields = @('plan_version','plan_id','origin','status','registry_id','registry_digest','network','replicas','forbidden_targets','authority')
    },
    [pscustomobject]@{
        Path = 'specs/examples/public-corpus-intake-report.example.json'
        Fields = @('report_version','report_id','origin','status','assessed_at','registry_id','registry_digest','plan_id','plan_digest','pinned_source_count','metadata_reviewed_source_count','source_archive_count','replica_declared_count','replica_ready_count','owner_exclusion_registry_complete','public_host_target_authorized','range_connection_authorized','execution_authorized','blockers','activity','authority')
    },
    [pscustomobject]@{
        Path = 'specs/examples/owner-scope-exclusion-registry.example.json'
        Fields = @('registry_version','registry_id','origin','status','recorded_at','registry_complete','owner_attestation_present','unknown_ownership_action','excluded_organizations','excluded_repositories','ownership_proof_digests','blockers','authority')
    },
    [pscustomobject]@{
        Path = 'specs/examples/public-source-staging-authorization.example.json'
        Fields = @('authorization_version','authorization_id','origin','status','governance_state_digest','owner_registry_id','owner_registry_digest','public_registry_id','public_registry_digest','replica_plan_id','replica_plan_digest','issued_at','not_before','expires_at','outcome','requested_source_ids','authorized_source_ids','authorized_content_digests','construction_zone_id','quarantine_requirements','network','blockers','authority','signatures')
    },
    [pscustomobject]@{
        Path = 'specs/examples/source-staging-gate-report.example.json'
        Fields = @('report_version','report_id','origin','status','assessed_at','authorization_id','authorization_digest','verified_signer_ids','verified_roles','requested_source_count','authorized_source_count','staged_source_count','quarantine_requirement_count','quarantine_completed_count','owner_exclusion_registry_complete','owner_attestation_present','staging_authorized','build_authorized','range_connection_authorized','execution_authorized','blockers','activity','authority')
    },
    [pscustomobject]@{
        Path = 'specs/examples/isolated-construction-zone.example.json'
        Fields = @('zone_version','zone_id','origin','status','declared_at','staging_authorization_id','staging_authorization_digest','environment_class','generation','controls','network','storage','activity','authority')
    },
    [pscustomobject]@{
        Path = 'specs/examples/source-quarantine-evidence-receipt.example.json'
        Fields = @('receipt_version','receipt_id','origin','status','recorded_at','zone_id','zone_digest','staging_authorization_id','staging_authorization_digest','requested_source_ids','source_archive_count','source_archive_digests','results','activity','authority')
    },
    [pscustomobject]@{
        Path = 'specs/examples/construction-zone-preflight-result.example.json'
        Fields = @('result_version','result_id','origin','status','assessed_at','zone_id','zone_digest','receipt_id','receipt_digest','staging_authorization_id','staging_authorization_digest','zone_control_count','verified_zone_control_count','quarantine_requirement_count','verified_quarantine_requirement_count','source_archive_count','construction_zone_provisioned','quarantine_evidence_complete','staging_authorized','build_authorized','range_connection_authorized','execution_authorized','blockers','activity','authority')
    },
    [pscustomobject]@{
        Path = 'specs/examples/construction-zone-isolation-attestation-plan.example.json'
        Fields = @('plan_version','plan_id','origin','status','declared_at','zone_id','zone_digest','preflight_result_id','preflight_result_digest','evidence_origin_requirement','minimum_distinct_principals_per_control','minimum_distinct_processes_per_control','controls','blockers','activity','authority')
    },
    [pscustomobject]@{
        Path = 'specs/examples/construction-zone-provisioning-authorization.example.json'
        Fields = @('authorization_version','authorization_id','origin','status','governance_state_digest','zone_id','zone_digest','preflight_result_id','preflight_result_digest','attestation_plan_id','attestation_plan_digest','issued_at','not_before','expires_at','outcome','requested_operations','authorized_operations','operator_approval_reference','provider_id','credential_references','blockers','authority','signatures')
    },
    [pscustomobject]@{
        Path = 'specs/examples/construction-zone-provisioning-gate-result.example.json'
        Fields = @('result_version','result_id','origin','status','assessed_at','zone_id','zone_digest','preflight_result_id','preflight_result_digest','attestation_plan_id','attestation_plan_digest','authorization_id','authorization_digest','verified_signer_ids','verified_roles','required_control_count','assigned_collector_count','assigned_verifier_count','verified_control_count','attestation_plan_complete','operator_approval_present','provider_selected','provisioning_authorized','provisioning_performed','staging_authorized','build_authorized','range_connection_authorized','execution_authorized','blockers','activity','authority')
    },
    [pscustomobject]@{
        Path = 'specs/examples/range-adapter-policy-envelope.example.json'
        Fields = @('envelope_version','envelope_id','origin','policy_id','policy_digest','governance_state_digest','issued_at','not_before','expires_at','authority','signatures')
    },
    [pscustomobject]@{
        Path = 'specs/examples/range-corpus-manifest.example.json'
        Fields = @('manifest_version','manifest_id','origin','snapshot_label','snapshot_digest','entries','authority')
    },
    [pscustomobject]@{
        Path = 'specs/examples/range-corpus-report.example.json'
        Fields = @('report_version','report_id','origin','scanned_at','status','manifest_digest','policy_envelope_digest','policy_digest','declared_entry_count','compatible_entry_count','blocked_entry_count','missing_files','unexpected_files','items','compilation_performed','source_tool_contacted','network_access_performed','live_execution_performed','authority')
    },
    [pscustomobject]@{
        Path = 'specs/examples/disposable-range-preflight.example.json'
        Fields = @('preflight_version','preflight_id','origin','range_id','environment_class','captured_at','policy_envelope_digest','corpus_report_digest','controls','authority')
    },
    [pscustomobject]@{
        Path = 'specs/examples/disposable-range-preflight-result.example.json'
        Fields = @('result_version','origin','status','preflight_id','range_id','policy_envelope_digest','corpus_report_digest','connection_gate_satisfied','blocked_controls','tool_installation_authorized','range_connection_authorized','execution_authorized','authority')
    },
    [pscustomobject]@{
        Path = 'specs/examples/range-topology.example.json'
        Fields = @('topology_version','topology_id','origin','environment_class','generation','zones','nodes','routes','controls','authority')
    },
    [pscustomobject]@{
        Path = 'specs/examples/range-topology-verdict.example.json'
        Fields = @('verdict_version','origin','topology_id','topology_digest','generation','status','zone_count','node_count','route_count','default_deny_declared','internet_egress_declared','out_of_band_kill_declared','environment_verified','provisioning_performed','network_contact_performed','authority')
    },
    [pscustomobject]@{
        Path = 'specs/examples/range-kill-command.example.json'
        Fields = @('command_version','command_id','origin','topology_id','topology_digest','generation','sequence','command','reason_code','governance_state_digest','issued_at','not_before','expires_at','authority','signatures')
    },
    [pscustomobject]@{
        Path = 'specs/examples/range-kill-state.example.json'
        Fields = @('state_version','origin','topology_id','topology_digest','generation','sequence','state','engaged_at','command_id','command_digest','governance_state_digest','verified_signer_ids','verified_roles','previous_state_digest','cleanup_required','kill_remains_engaged','authority')
    },
    [pscustomobject]@{
        Path = 'specs/examples/range-recovery-evidence.example.json'
        Fields = @('evidence_version','evidence_id','origin','captured_at','topology_digest','kill_state_digest','baseline_snapshot_digest','observed_post_cleanup_snapshot_digest','cleanup_obligations','cleanup_subject_digest','verifier_observations','authority')
    },
    [pscustomobject]@{
        Path = 'specs/examples/range-recovery-receipt.example.json'
        Fields = @('receipt_version','origin','status','evidence_id','evidence_digest','topology_digest','kill_state_digest','cleanup_subject_digest','snapshot_restored','cleanup_verified','cleanup_obligation_count','verified_verifier_count','blockers','kill_remains_engaged','range_reuse_authorized','range_connection_authorized','execution_authorized','authority')
    },
    [pscustomobject]@{
        Path = 'specs/examples/evolution-baseline.example.json'
        Fields = @('baseline_version','baseline_id','origin','generation','active','artifact_digest','authority')
    },
    [pscustomobject]@{
        Path = 'specs/examples/evolution-constitution.example.json'
        Fields = @('constitution_version','constitution_id','origin','governance_state_digest','issued_at','not_before','expires_at','axioms','hard_failures','capability_triggers','tier_policies','resource_ceilings','authority','signatures')
    },
    [pscustomobject]@{
        Path = 'specs/examples/epistemic-posture.example.json'
        Fields = @('posture_version','posture_id','origin','mode','claim_type','evidence_standard','counterfactual','context_boundaries','authority')
    },
    [pscustomobject]@{
        Path = 'specs/examples/cognitive-candidate-bundle.example.json'
        Fields = @('bundle_version','candidate_id','origin','compiled_at','source_candidate_digest','active_baseline_digest','constitution_digest','candidate_class','authority_tier','lens','mutation_family','epistemic_posture','source_evidence','contradicting_evidence','proposed_delta_digest','proposed_delta_retained','prediction','uncertainty','resource_lease','rollback_digest','status','active_baseline_modified','candidate_executed','authority')
    },
    [pscustomobject]@{
        Path = 'specs/examples/capability-threshold-report.example.json'
        Fields = @('report_version','report_id','origin','candidate_digest','constitution_digest','assessed_at','assessments','required_safeguard_level','paused','status','blockers','authority')
    },
    [pscustomobject]@{
        Path = 'specs/examples/evolution-evaluation-vector.example.json'
        Fields = @('evaluation_version','evaluation_id','origin','candidate_digest','active_baseline_digest','constitution_digest','capability_report_digest','evaluated_at','evaluator_observations','hard_gate_results','champion_floor_results','metrics','aggregate_score_present','status','blockers','candidate_executed','active_baseline_modified','authority')
    },
    [pscustomobject]@{
        Path = 'specs/examples/evolution-transition-envelope.example.json'
        Fields = @('envelope_version','envelope_id','origin','candidate_digest','evaluation_digest','capability_report_digest','constitution_digest','active_baseline_digest','action','destination','sequence','previous_receipt_digest','issued_at','not_before','expires_at','authority','signatures')
    },
    [pscustomobject]@{
        Path = 'specs/examples/evolution-transition-receipt.example.json'
        Fields = @('receipt_version','receipt_id','origin','candidate_id','candidate_digest','active_baseline_digest','constitution_digest','action','sequence','previous_receipt_digest','envelope_digest','recorded_at','status','destination','verified_signer_ids','verified_roles','active_baseline_modified','candidate_executed','production_promotion_authorized','authority')
    },
    [pscustomobject]@{
        Path = 'specs/examples/os-isolation-attestation.example.json'
        Fields = @('attestation_version','attestation_id','origin','component_kind','component_id','logical_principal','governance_state_digest','captured_at','issued_at','not_before','expires_at','process','collector','controls','status','blockers','authority','signatures')
    },
    [pscustomobject]@{
        Path = 'specs/examples/evaluator-trust-policy.example.json'
        Fields = @('policy_version','policy_id','origin','constitution_digest','governance_state_digest','issued_at','not_before','expires_at','evaluators','authority','signatures')
    },
    [pscustomobject]@{
        Path = 'specs/examples/evaluator-observation-envelope.example.json'
        Fields = @('envelope_version','envelope_id','origin','evaluator_policy_digest','evaluator_id','logical_principal','process_id','os_account_identifier','os_account_sid','role','subject_digest','constitution_digest','capability_report_digest','evaluation_input_digest','resource_ledger_digest','isolation_attestation_digest','observed_at','expires_at','status','evidence','authority','signature')
    },
    [pscustomobject]@{
        Path = 'specs/examples/lineage-resource-ledger.example.json'
        Fields = @('ledger_version','ledger_id','lineage_id','origin','constitution_digest','governance_state_digest','root_candidate_digest','generated_at','not_before','expires_at','entries','head_entry_digest','totals','status','blockers','authority','signatures')
    },
    [pscustomobject]@{
        Path = 'specs/examples/evolution-assurance-receipt.example.json'
        Fields = @('assurance_version','origin','candidate_digest','constitution_digest','evaluator_policy_digest','evaluation_input_digest','resource_ledger_digest','evaluator_verifications','resource_ledger_verification','contract_boundary_verified','live_os_enforcement_verified','shadow_evaluation_eligible','production_promotion_authorized','authority')
    },
    [pscustomobject]@{
        Path = 'specs/examples/control-board-foundry-projection.example.json'
        Fields = @('projection_version','origin','captured_at','candidate_digest','evaluation_digest','assurance_digest','operator_state','severity','summary','evaluator_mesh','resource_lineage','boundary','authority')
    },
    [pscustomobject]@{
        Path = 'specs/examples/evaluator-conformance-bundle.example.json'
        Fields = @('bundle_version','origin','verification_time','maximum_lifetime_seconds','constitution','governance_state','evaluator_policy','isolation_attestations','resource_ledger','evaluator_envelopes','expected_bindings','authority')
    },
    [pscustomobject]@{
        Path = 'specs/examples/resource-meter-receipt.example.json'
        Fields = @('meter_version','meter_id','origin','candidate_digest','resource_lease_digest','prepared_at','completed_at','recorded_at','worker','job','usage','durability','status','blockers','network_access_performed','candidate_executed','production_promotion_authorized','authority')
    },
    [pscustomobject]@{
        Path = 'specs/examples/windows-custody-readiness.example.json'
        Fields = @('custody_version','measurement_id','origin','collected_at','platform','cng','tpm','key_material','status','blockers','production_custody_verified','authority')
    },
    [pscustomobject]@{
        Path = 'specs/examples/windows-isolation-measurement.example.json'
        Fields = @('measurement_version','measurement_id','origin','collected_at','platform','target','collector','environment','filesystem','network','controls','status','blockers','authority')
    },
    [pscustomobject]@{
        Path = 'specs/examples/edge-preview-scenario.example.json'
        Fields = @('scenario_version','scenario_id','origin','observed_at','source','device','observation','policy','authority')
    },
    [pscustomobject]@{
        Path = 'specs/examples/edge-preview-result.example.json'
        Fields = @('result_version','run_id','scenario_id','scenario_digest','origin','evaluated_at','status','matched_rule_id','risk','explanation','uncertainties','security_claim','independent_verification','witness','references','authority')
    },
    [pscustomobject]@{
        Path = 'specs/examples/edge-live-process-observation.example.json'
        Fields = @('observation_version','observation_id','origin','status','collected_at','platform','scope','process','collector','policy_input','blockers','authority')
    },
    [pscustomobject]@{
        Path = 'specs/examples/plugin-capability-manifest.example.json'
        Fields = @('manifest_version','plugin_id','plugin_version','origin','artifact_digest','runtime','capabilities','filesystem','network','lifecycle','authority')
    },
    [pscustomobject]@{
        Path = 'specs/examples/edge-update-manifest.example.json'
        Fields = @('manifest_version','release_id','origin','product','channel','version','release_sequence','issued_at','expires_at','governance_state_digest','artifact','previous_release','plugins','rollback','rollout','authority','signatures')
    },
    [pscustomobject]@{
        Path = 'specs/examples/edge-update-verification-receipt.example.json'
        Fields = @('receipt_version','origin','status','verified_at','manifest_digest','artifact_digest','governance_state_digest','verified_signer_ids','verified_roles','anti_rollback_verified','previous_release_bound','artifact_verified','provenance_present','sbom_present','rollback_contract_verified','plugin_manifests_verified','plugin_code_executed','installation_authorized','installation_performed','rollback_performed','network_access_performed','blockers','authority')
    },
    [pscustomobject]@{
        Path = 'specs/examples/design-partner-evaluation-plan.example.json'
        Fields = @('plan_version','plan_id','origin','status','created_at','product_surface','cohort','tasks','measures','data_boundary','activity','exit_gate','blockers','authority')
    }
)

foreach ($contractCheck in $additionalContractChecks) {
    [string]$contractPath = Join-Path $projectRoot ([string]$contractCheck.Path)
    [object]$contractValue = Get-Content -LiteralPath $contractPath -Raw -Encoding utf8 | ConvertFrom-Json
    foreach ($requiredField in @($contractCheck.Fields)) {
        if ([string]$requiredField -notin $contractValue.PSObject.Properties.Name) {
            throw [System.IO.InvalidDataException]::new("Contract example '$($contractCheck.Path)' is missing required field '$requiredField'.")
        }
    }
}

[string]$projectLeaf = Split-Path -Leaf $projectRoot
if (-not [System.String]::Equals($projectLeaf, 'nimrod', [System.StringComparison]::Ordinal)) {
    throw [System.IO.InvalidDataException]::new("Project directory must use the lowercase brand 'nimrod'; received '$projectLeaf'.")
}

[string[]]$brandFiles = @(Get-ChildItem -LiteralPath $projectRoot -Recurse -File | Where-Object {
    $_.FullName -notlike "$projectRoot\.venv\*" -and
    $_.FullName -notlike "$projectRoot\conformance\typescript-evaluator\node_modules\*" -and
    $_.FullName -notlike "$projectRoot\conformance\typescript-evaluator\dist\*" -and
    $_.Extension -in @('.md','.json','.ps1','.py','.toml','.html','.css','.js','.yaml','.yml')
} | Select-Object -ExpandProperty FullName)
[string]$uppercaseBrand = -join ([char[]](78,73,77,82,79,68))
foreach ($brandFile in $brandFiles) {
    [string]$brandText = Get-Content -LiteralPath $brandFile -Raw -Encoding utf8
    if ($brandText.IndexOf($uppercaseBrand, [System.StringComparison]::Ordinal) -ge 0) {
        throw [System.IO.InvalidDataException]::new("Uppercase brand token found in '$brandFile'. Use lowercase 'nimrod'.")
    }
}

[string]$readmePath = Join-Path $projectRoot 'README.md'
[string]$readme = Get-Content -LiteralPath $readmePath -Raw -Encoding utf8
if ($readme.IndexOf('CONSTRUCTION_ZONE_PROVISIONING_SIGNED_DENIAL_INDEPENDENT_ATTESTATION_BLOCKED', [System.StringComparison]::Ordinal) -lt 0) {
    throw [System.IO.InvalidDataException]::new('README.md does not contain the required construction-zone provisioning status and production blockers.')
}

[string]$launchPath = Join-Path $projectRoot 'docs/PUBLIC_LAUNCH.md'
[string]$launchPlan = Get-Content -LiteralPath $launchPath -Raw -Encoding utf8
[string[]]$requiredBlockers = @(
    'BLOCKED_OWNER_AND_COUNSEL_DECISIONS',
    'BLOCKED_ACTUAL_PRODUCT_AND_COUNSEL_REVIEW',
    'IN_PROGRESS_UNPRIVILEGED_SIMULATOR_ONLY',
    'IN_PROGRESS_CONSTRUCTION_ZONE_PROVISIONING_SIGNED_DENIAL_OPERATOR_PROVIDER_INDEPENDENT_ATTESTATION_STAGING_BUILD_CONNECTION_AND_EXECUTION_BLOCKED',
    'IN_PROGRESS_DEPLOYMENT_ASSURANCE_RACE_CLOSED_EFFECTIVE_ACCESS_OBSERVED_CUSTODY_AND_PHYSICAL_POWER_LOSS_BLOCKED_NO_MODEL_EXECUTION_OR_PRODUCTION_EVIDENCE'
)

foreach ($requiredBlocker in $requiredBlockers) {
    if ($launchPlan.IndexOf($requiredBlocker, [System.StringComparison]::Ordinal) -lt 0) {
        throw [System.IO.InvalidDataException]::new("Public launch plan is missing required honest blocker '$requiredBlocker'.")
    }
}

[string[]]$requiredOwnerDecisions = @(
    'TRADEMARK_CLEARANCE_PAUSED_BY_OWNER',
    'PUBLIC_SOURCE_PREVIEW_SOURCE_AVAILABLE'
)

foreach ($requiredOwnerDecision in $requiredOwnerDecisions) {
    if ($launchPlan.IndexOf($requiredOwnerDecision, [System.StringComparison]::Ordinal) -lt 0) {
        throw [System.IO.InvalidDataException]::new("Public launch plan is missing required owner decision '$requiredOwnerDecision'.")
    }
}

[string]$licenseDecisionPath = Join-Path $projectRoot 'LICENSE-DECISION.md'
[string]$licenseDecision = Get-Content -LiteralPath $licenseDecisionPath -Raw -Encoding utf8
if ($licenseDecision.IndexOf('PUBLIC_SOURCE_PREVIEW_SOURCE_AVAILABLE', [System.StringComparison]::Ordinal) -lt 0) {
    throw [System.IO.InvalidDataException]::new('LICENSE-DECISION.md does not enforce the public source-preview repository posture.')
}

if ($licenseDecision.IndexOf('`ObtuseAI`', [System.StringComparison]::Ordinal) -lt 0) {
    throw [System.IO.InvalidDataException]::new('LICENSE-DECISION.md does not identify the required ObtuseAI GitHub organization.')
}

[string]$sourceBriefPath = Join-Path $projectRoot 'docs/source/nimrod_source_brief.md'
[string]$sourceBriefHash = (Get-FileHash -LiteralPath $sourceBriefPath -Algorithm SHA256).Hash
[string]$expectedSourceBriefHash = '1B25A1DE6E8305B2899B9FD52ED182D4BB6C4FD9097B68A09E2FC10C3E31CDB9'
if ($sourceBriefHash -ne $expectedSourceBriefHash) {
    throw [System.IO.InvalidDataException]::new("Source brief hash mismatch. Expected '$expectedSourceBriefHash', received '$sourceBriefHash'.")
}

[string]$cacisSourceBriefPath = Join-Path $projectRoot 'docs/source/cacis_vnext_owner_brief.md'
[string]$cacisSourceBriefHash = (Get-FileHash -LiteralPath $cacisSourceBriefPath -Algorithm SHA256).Hash
[string]$expectedCacisSourceBriefHash = 'F94689422F5B14AF6B3C902EC9174369F5F958186927503E9CD88E87674B1AB7'
if ($cacisSourceBriefHash -ne $expectedCacisSourceBriefHash) {
    throw [System.IO.InvalidDataException]::new("CACIS source brief hash mismatch. Expected '$expectedCacisSourceBriefHash', received '$cacisSourceBriefHash'.")
}

[ordered]@{
    status = 'FOUNDATION_CONSTRUCTION_ZONE_PROVISIONING_SIGNED_DENIAL_INDEPENDENT_ATTESTATION_BLOCKED'
    required_file_count = $requiredFiles.Count
    parsed_json_count = $jsonFiles.Count
    parsed_schema_count = 97
    parsed_example_count = 97
    draft_2020_12_harness = 'tools/validate_contracts.py'
    foundation_manifest_harness = 'tools/validate_manifest.py'
    edge_preview_harness = 'tools/validate_edge_preview.py'
    edge_live_observation_harness = 'tools/validate_edge_live_observation.py'
    edge_continuous_observation_harness = 'tools/validate_edge_continuous_observation.py'
    release_foundation_harness = 'tools/validate_release_foundation.py'
    design_partner_kit_harness = 'tools/validate_design_partner_kit.py'
    cacis_roadmap_harness = 'tools/validate_cacis_roadmap.py'
    cacis_world_model_harness = 'tools/validate_world_model.py'
    cacis_world_intake_harness = 'tools/validate_world_intake.py'
    cacis_world_intake_governance_harness = 'tools/validate_world_intake_governance.py'
    cacis_immune_runtime_harness = 'tools/validate_immune_runtime.py'
    intelligence_research_harness = 'tools/validate_intelligence_research.py'
    homeostasis_chronos_harness = 'tools/validate_homeostasis_chronos.py'
    genome_evaluation_harness = 'tools/validate_genome_evaluation.py'
    arenas_observatory_harness = 'tools/validate_arenas_observatory.py'
    contract_conformance_harness = 'tools/validate_contract_conformance.py'
    contract_runtime_bindings_harness = 'tools/validate_contract_runtime_bindings.py'
    verifier_identity_readiness_harness = 'tools/validate_verifier_identity_readiness.py'
    completion_audit_harness = 'tools/validate_completion_audit.py'
    simulator_harness = 'tools/validate_simulator.py'
    authorization_state_harness = 'tools/validate_authorization_state.py'
    key_governance_harness = 'tools/validate_key_governance.py'
    witness_anchor_harness = 'tools/validate_witness_anchor.py'
    supervised_verifier_harness = 'tools/validate_supervised_verifier.py'
    swarm_harness = 'tools/validate_swarm.py'
    control_board_harness = 'tools/validate_control_board.py'
    control_board_ingress_harness = 'tools/validate_control_board_ingress.py'
    range_adapter_harness = 'tools/validate_range_adapter.py'
    range_readiness_harness = 'tools/validate_range_readiness.py'
    range_lifecycle_harness = 'tools/validate_range_lifecycle.py'
    range_execution_gate_harness = 'tools/validate_range_execution_gate.py'
    range_evidence_admission_harness = 'tools/validate_range_evidence_admission.py'
    range_evidence_acceptance_harness = 'tools/validate_range_evidence_acceptance.py'
    range_evidence_completion_harness = 'tools/validate_range_evidence_completion.py'
    public_sacrificial_corpus_harness = 'tools/validate_public_sacrificial_corpus.py'
    source_staging_gate_harness = 'tools/validate_source_staging_gate.py'
    construction_zone_preflight_harness = 'tools/validate_construction_zone_preflight.py'
    construction_zone_provisioning_gate_harness = 'tools/validate_construction_zone_provisioning_gate.py'
    evolution_foundry_harness = 'tools/validate_evolution_foundry.py'
    evolution_assurance_harness = 'tools/validate_evolution_assurance.py'
    autonomous_promotion_harness = 'tools/validate_autonomous_promotion.py'
    distribution_harness = 'tools/validate_distribution.py'
    evaluator_conformance_harness = 'tools/validate_evaluator_conformance.py'
    windows_isolation_harness = 'tools/validate_windows_isolation.py'
    resource_meter_harness = 'tools/validate_resource_meter.py'
    windows_custody_readiness_harness = 'tools/validate_windows_custody_readiness.py'
    simulator_execution_mode = 'no_execution'
    cryptographic_authorization = 'ed25519_threshold_verified'
    authorization_state = 'process_crash_recovery_and_32_process_exactly_once_validated'
    key_governance = 'ed25519_2_of_3_rotation_revocation_loss_compromise_validated'
    witness_anchor = 'threshold_merkle_checkpoint_external_receipt_independent_pin_validated'
    supervised_verifier = 'separate_process_read_only_timeout_outage_disagreement_validated'
    verifier_os_account_isolation = 'SIGNED_ATTESTATION_CONTRACT_VALID_LIVE_DEDICATED_ACCOUNT_AND_ACL_UNPROVEN'
    control_board_verifier_projection = 'six_states_and_seven_adversarial_cases_validated'
    control_board_signed_ingress = 'two_of_three_freshness_crash_replay_rollback_and_tamper_validated'
    range_adapter = 'atomic_and_caldera_fixture_normalization_exact_digest_mapping_and_no_execution_compilation_validated'
    range_readiness = 'two_of_three_signed_policy_exact_local_corpus_and_nine_control_preflight_validated_connection_blocked'
    range_lifecycle = 'declaration_only_topology_irreversible_signed_kill_and_dual_verifier_cleanup_validated_environment_connection_blocked'
    range_execution_gate = 'threshold_signed_non_provisioning_connector_exact_lease_topology_scope_and_nine_real_attestation_gate_validated_connection_and_execution_blocked'
    range_evidence_admission = 'threshold_signed_collector_policy_nine_unique_signed_content_addressed_fixtures_attestation_only_owner_range_and_independent_verification_blocked'
    range_evidence_acceptance = 'separately_governed_three_verifier_policy_eighteen_signed_fixture_decisions_five_outcomes_zero_acceptance_completion_connection_or_execution'
    range_evidence_completion = 'separate_two_of_three_policy_and_authorization_signed_denial_real_completion_contract_valid_connection_and_execution_blocked'
    public_sacrificial_corpus = 'five_pinned_metadata_only_sources_owner_registry_incomplete_offline_replicas_unbuilt_public_targets_connection_and_execution_blocked'
    source_staging_gate = 'two_of_three_signed_denial_five_requested_zero_staged_eight_quarantine_controls_pending_owner_scope_build_connection_and_execution_blocked'
    construction_zone_preflight = 'ten_isolation_controls_unproven_eight_quarantine_results_missing_zero_archives_provisioning_staging_build_connection_and_execution_blocked'
    construction_zone_provisioning_gate = 'two_of_three_signed_denial_ten_controls_zero_collectors_zero_verifiers_zero_verified_controls_operator_provider_credentials_and_infrastructure_blocked'
    evolution_foundry = 'signed_constitution_candidate_only_cas_lexicographic_evaluation_and_shadow_transition_validated_production_blocked'
    evolution_assurance = 'four_signed_evaluators_seven_control_isolation_attestations_and_lineage_resource_ledger_valid_live_os_and_production_blocked'
    evaluator_conformance = 'independent_typescript_canonical_json_ed25519_and_assurance_semantics_validated'
    windows_isolation = 'live_read_only_signed_measurement_two_of_seven_controls_verified_five_blockers_production_blocked'
    windows_resource_meter = 'live_job_object_suspended_assignment_lineage_binding_and_abrupt_process_crash_recovery_validated_physical_power_loss_blocked'
    windows_custody_readiness = 'live_read_only_cng_provider_and_tpm_management_observation_hardware_key_attestation_and_independent_custody_blocked'
    edge_preview = 'replayed_windows_process_egress_budget_one_proposal_independently_structurally_verified_post_state_unobserved'
    edge_live_observation = 'one_caller_selected_windows_process_hashed_identity_policy_and_action_blocked'
    release_foundation = 'two_role_signed_candidate_exact_predecessor_artifact_rollback_and_plugin_manifest_valid_installation_blocked'
    design_partner_kit = 'five_to_eight_partner_plan_zero_participants_recruitment_not_started'
    cacis_vnext = 'w6_arenas_observatory_replay_valid_candidate_and_display_only_external_settlement_and_execution_blocked'
    cacis_roadmap_negative_case_count = 21
    cacis_world_model = 'eight_observation_first_generation_plus_three_generation_two_cursor_succession_replay_valid_non_authorizing'
    cacis_world_model_negative_case_count = 26
    cacis_world_model_live_sensing_performed = $false
    cacis_world_model_policy_input_ready = $false
    cacis_world_intake_negative_case_count = 16
    cacis_world_intake_separate_process_causal_verification_performed = $true
    cacis_world_intake_live_sensor_admission_performed = $false
    cacis_world_intake_governance = 'two_role_threshold_signed_replay_policy_health_and_decision_no_drop_backpressure_and_retention_projection_valid_live_admission_blocked'
    cacis_world_intake_governance_negative_case_count = 19
    cacis_world_intake_governance_policy_verified_signer_count = 2
    cacis_world_intake_governance_policy_verified_role_count = 2
    cacis_world_intake_governance_accepted_event_count = 2
    cacis_world_intake_governance_deferred_event_count = 3
    cacis_world_intake_governance_dropped_event_count = 0
    cacis_world_intake_governance_production_verifier_independence_verified = $false
    cacis_world_intake_governance_live_sensor_admission_authorized = $false
    cacis_immune_runtime = 'credential_eight_cell_and_suspicious_script_ten_cell_shadow_terminated_replay_valid_proposal_only'
    cacis_immune_runtime_negative_case_count = 49
    cacis_immune_runtime_independent_verification_performed = $false
    cacis_immune_runtime_execution_authorized = $false
    cacis_immune_runtime_target_contact_performed = $false
    intelligence_research = 'four_hypothesis_two_method_two_case_six_challenge_replay_valid_candidate_theory_only'
    intelligence_research_negative_case_count = 71
    intelligence_research_logical_read_only_verification_performed = $true
    intelligence_research_separate_process_verification_performed = $true
    intelligence_research_production_independence_verified = $false
    intelligence_research_generalization_allowed = $false
    intelligence_research_promotion_authorized = $false
    intelligence_research_execution_authorized = $false
    intelligence_research_target_contact_performed = $false
    cacis_homeostasis_chronos = 'nine_resource_thirteen_signal_seven_clock_replay_valid_schedule_proposal_only'
    cacis_homeostasis_chronos_negative_case_count = 60
    cacis_homeostasis_chronos_receipt_digest = 'sha256:615e552494c6c37d61069b4ce95f219b63e1bce8d7728cd34f44bfc88668e4b6'
    cacis_homeostasis_chronos_live_sensing_performed = $false
    cacis_homeostasis_chronos_independent_verification_performed = $false
    cacis_homeostasis_chronos_execution_authorized = $false
    cacis_homeostasis_chronos_target_contact_performed = $false
    cacis_genome_evaluation = 'nine_memory_three_partition_nine_reward_defense_seven_complexity_metric_candidate_only_replay_valid'
    cacis_genome_external_replication_performed = $false
    cacis_genome_promotion_authorized = $false
    autonomous_threshold_promotion = 'tier_a_b_four_evaluator_two_role_threshold_shadow_promotion_regression_demotion_exactly_once_replay_valid'
    autonomous_promotion_threshold_signer_count = 2
    autonomous_promotion_threshold_role_count = 2
    autonomous_promotion_independent_evaluator_count = 4
    autonomous_promotion_human_approval_required = $false
    autonomous_promotion_production_authorized = $false
    distribution = 'wheel_contains_all_six_source_packages_and_fourteen_command_modules'
    distribution_source_package_count = 6
    distribution_command_module_count = 14
    distribution_published = $false
    cacis_arenas_observatory = 'fifteen_explicit_synthetic_replay_scenarios_fourteen_dimensions_two_role_threshold_signed_display_only_live_blocked'
    cacis_arenas_observatory_live_range_connected = $false
    contract_conformance = 'ninety_seven_contract_static_schema_semantic_runtime_reference_and_independent_harness_gap_matrix_live_runtime_blocked'
    contract_conformance_contract_count = 97
    contract_conformance_semantic_validator_count = 97
    contract_conformance_independent_harness_reference_count = 97
    contract_conformance_runtime_reference_count = 30
    contract_conformance_live_runtime_evidence_count = 0
    contract_runtime_bindings = 'six_previously_weak_contracts_twelve_fail_closed_semantic_cases_valid_live_and_production_evidence_blocked'
    verifier_identity_readiness = 'three_live_read_only_distinct_processes_zero_dedicated_accounts_zero_read_only_acls_zero_production_custody_production_blocked'
    verifier_identity_readiness_surface_count = 3
    verifier_identity_readiness_production_eligible_count = 0
    completion_audit = 'fifteen_local_gates_complete_six_external_operational_gates_blocked_no_deployable_or_production_claim'
    completion_audit_local_gate_count = 15
    completion_audit_external_gate_count = 6
    swarm_maximum_outcome = 'typed_proposal'
    lowercase_brand_enforced = $true
    source_brief_sha256 = $sourceBriefHash
    cacis_source_brief_sha256 = $cacisSourceBriefHash
    launch_readiness = 'BLOCKED_NO_DEPLOYABLE_PRODUCT'
    owner_decisions = @(
        'trademark_clearance_paused_indefinitely',
        'public_source_preview_under_obtuseai',
        'authorized_offensive_testing_required',
        'doctrine_v0_1_owner_approved'
    )
    unresolved_decisions = @(
        'external_product_identity',
        'commercial_customer_distribution_terms',
        'edge_and_crucible_design_partners',
        'stage_0_budget_and_accountable_leads',
        'legal_export_and_offensive_testing_applicability'
    )
} | ConvertTo-Json -Depth 10
