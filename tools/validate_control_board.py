from __future__ import annotations

import copy
import json
import re
from collections.abc import Callable
from html.parser import HTMLParser
from pathlib import Path
from typing import cast

from nimrod_cacis.immune_runtime import validate_immune_organism_lifecycle_receipt
from nimrod_cacis.homeostasis import validate_homeostasis_chronos_receipt
from nimrod_research.intelligence_lab import validate_intelligence_research_settlement
from nimrod_cacis.world_model import validate_world_model_generation
from nimrod_simulator.control_board import project_verifier_control_board
from nimrod_simulator.errors import ControlBoardProjectionError
from nimrod_simulator.isolation_boundary import ISOLATION_AUTHORITY, REQUIRED_ISOLATION_CONTROLS, sign_isolation_attestation
from nimrod_simulator.jsonio import read_json_object, sha256_digest, validate_contract
from nimrod_simulator.key_governance import EphemeralEd25519SigningConnector
from nimrod_simulator.model import JsonObject
from nimrod_simulator.verifier_service import reconcile_observations
from validate_evolution_assurance import governance_connectors, governance_state, reference


CAPTURED_AT = "2026-07-13T04:31:02Z"
MAXIMUM_ATTESTATION_LIFETIME_SECONDS = 1200


class ControlBoardHtmlParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.ids: set[str] = set()
        self.local_scripts: list[str] = []
        self.local_styles: list[str] = []
        self.external_references: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {key: value for key, value in attrs}
        element_id = attributes.get("id")
        if element_id is not None:
            self.ids.add(element_id)
        for attribute_name in ("src", "href"):
            reference = attributes.get(attribute_name)
            if reference is None or reference.startswith("#"):
                continue
            if reference.startswith(("http://", "https://", "//")):
                self.external_references.append(reference)
            elif tag == "script" and attribute_name == "src":
                self.local_scripts.append(reference)
            elif (
                tag == "link"
                and attribute_name == "href"
                and "stylesheet" in (attributes.get("rel") or "").split()
            ):
                self.local_styles.append(reference)


def read_object(path: Path) -> JsonObject:
    parsed: object = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(parsed, dict):
        raise TypeError(f"Expected a JSON object at '{path}'.")
    return cast(JsonObject, parsed)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def expect_projection_error(operation: str, callback: Callable[[], JsonObject]) -> None:
    try:
        callback()
    except ControlBoardProjectionError:
        return
    raise AssertionError(f"Projection adversarial case '{operation}' unexpectedly succeeded.")


def verifier_evidence(project_root: Path) -> tuple[list[JsonObject], list[JsonObject]]:
    example_root = project_root / "specs" / "examples"
    primary_health = read_json_object(example_root / "verifier-health.example.json")
    secondary_health = copy.deepcopy(primary_health)
    secondary_health["request_id"] = "health-2"
    secondary_health["service_id"] = "verifier:anchor-secondary"
    secondary_health["logical_principal"] = "service:nimrod-independent-verifier-secondary"
    secondary_health["process_id"] = 12346
    primary_observation = read_json_object(example_root / "verifier-observation.example.json")
    secondary_observation = copy.deepcopy(primary_observation)
    secondary_observation["observation_id"] = "aaaaaaaa-bbbb-4ccc-8ddd-ffffffffffff"
    secondary_observation["service_id"] = "verifier:anchor-secondary"
    secondary_observation["logical_principal"] = "service:nimrod-independent-verifier-secondary"
    secondary_observation["process_id"] = 12346
    return [primary_health, secondary_health], [primary_observation, secondary_observation]


def with_observation_state(observation: JsonObject, status: str) -> JsonObject:
    result = copy.deepcopy(observation)
    result["status"] = status
    if status in {"timeout", "unavailable"}:
        result["subject_digest"] = None
        result["read_only_behavior_verified"] = False
        result["details"] = {
            "error_type": "TimeoutExpired" if status == "timeout" else "VerifierServiceError",
            "message": "Validation fixture non-success state.",
        }
    elif status == "invalid":
        result["details"] = {
            "error_type": "AnchorIntegrityError",
            "message": "Validation fixture rejected the evidence subject.",
        }
    return result


def verifier_isolation_attestations(
    observations: list[JsonObject],
    governance: JsonObject,
    signers: list[EphemeralEd25519SigningConnector],
    collector_kind: str,
    read_only_verified: bool,
) -> list[JsonObject]:
    result: list[JsonObject] = []
    for index, observation in enumerate(observations):
        controls = []
        blockers: list[str] = []
        for control_id in sorted(REQUIRED_ISOLATION_CONTROLS):
            status = "verified"
            if control_id == "READ_ONLY_INPUT_ACL" and not read_only_verified:
                status = "unproven"
                blockers.append(control_id)
            controls.append(
                {
                    "control_id": control_id,
                    "status": status,
                    "evidence": [reference(f"verifier:{observation['service_id']}:{control_id}")]
                    if status == "verified"
                    else [],
                }
            )
        unsigned: JsonObject = {
            "attestation_version": "0.1.0",
            "attestation_id": f"{index + 1:08d}-3333-4333-8333-{index + 1:012d}",
            "origin": governance["origin"],
            "component_kind": "verifier",
            "component_id": observation["service_id"],
            "logical_principal": observation["logical_principal"],
            "governance_state_digest": sha256_digest(governance),
            "captured_at": "2026-07-13T04:30:00Z",
            "issued_at": "2026-07-13T04:30:01Z",
            "not_before": "2026-07-13T04:30:00Z",
            "expires_at": "2026-07-13T04:36:00Z",
            "process": {
                "process_id": observation["process_id"],
                "os_account_identifier": observation["os_account_identifier"],
                "os_account_sid": f"S-1-5-21-{9101 + index}",
                "executable_digest": sha256_digest({"verifier_binary": observation["service_id"]}),
            },
            "collector": {
                "collector_id": f"collector:{collector_kind}",
                "kind": collector_kind,
                "raw_evidence_digest": sha256_digest({"raw_isolation": observation["service_id"]}),
            },
            "controls": controls,
            "status": "verified" if not blockers else "boundary_unproven",
            "blockers": blockers,
            "authority": ISOLATION_AUTHORITY,
        }
        result.append(sign_isolation_attestation(unsigned, signers[:2]))
    return result


def build_projection(
    health_reports: list[JsonObject],
    observations: list[JsonObject],
    isolation_attestations: list[JsonObject],
    governance: JsonObject,
) -> JsonObject:
    consensus = reconcile_observations(observations[0], observations[1], "2026-07-12T23:00:01Z")
    return project_verifier_control_board(
        health_reports,
        observations,
        consensus,
        isolation_attestations,
        governance,
        CAPTURED_AT,
        MAXIMUM_ATTESTATION_LIFETIME_SECONDS,
    )


def validate_projection_state_matrix(project_root: Path) -> tuple[int, int]:
    health_reports, observations = verifier_evidence(project_root)
    signers = governance_connectors()
    governance = governance_state(signers, "simulated")
    simulated_isolation = verifier_isolation_attestations(observations, governance, signers, "fixture", True)
    boundary_projection = build_projection(health_reports, observations, simulated_isolation, governance)
    require(
        boundary_projection.get("operator_state") == "boundary_unproven",
        "Unisolated valid agreement must remain boundary_unproven.",
    )
    require(
        boundary_projection.get("authority") == {
            "can_authorize": False,
            "can_execute": False,
            "may_mark_verification_accepted": False,
        },
        "Boundary-unproven projection exposed authority.",
    )

    live_governance = governance_state(signers, "live")
    isolated_health = copy.deepcopy(health_reports)
    isolated_observations = copy.deepcopy(observations)
    account_identifiers = ("nimrod-verifier-primary", "nimrod-verifier-secondary")
    for index, health in enumerate(isolated_health):
        health["origin"] = "live"
        health["os_account_identifier"] = account_identifiers[index]
        health["os_account_boundary_verified"] = True
        health["production_ready"] = True
    for index, observation in enumerate(isolated_observations):
        observation["origin"] = "live"
        observation["os_account_identifier"] = account_identifiers[index]
        observation["os_account_boundary_verified"] = True
    live_isolation = verifier_isolation_attestations(
        isolated_observations,
        live_governance,
        signers,
        "windows_access_check",
        True,
    )
    verified_projection = build_projection(isolated_health, isolated_observations, live_isolation, live_governance)
    require(verified_projection.get("operator_state") == "verified", "Complete isolation did not project verified.")
    verified_authority = verified_projection.get("authority")
    require(isinstance(verified_authority, dict), "Verified projection authority is missing.")
    require(
        verified_authority.get("may_mark_verification_accepted") is True,
        "Complete verified boundary did not permit accepted rendering.",
    )
    require(
        verified_authority.get("can_authorize") is False and verified_authority.get("can_execute") is False,
        "Even a verified projection must not authorize or execute.",
    )

    invalid_observations = [with_observation_state(value, "invalid") for value in observations]
    disagreement_observations = [observations[0], with_observation_state(observations[1], "invalid")]
    timeout_observations = [observations[0], with_observation_state(observations[1], "timeout")]
    unavailable_observations = [observations[0], with_observation_state(observations[1], "unavailable")]
    cases = (
        (invalid_observations, "invalid"),
        (disagreement_observations, "disagreement"),
        (timeout_observations, "timeout"),
        (unavailable_observations, "unavailable"),
    )
    for case_observations, expected_state in cases:
        case_isolation = verifier_isolation_attestations(case_observations, governance, signers, "fixture", True)
        projection = build_projection(health_reports, case_observations, case_isolation, governance)
        require(
            projection.get("operator_state") == expected_state,
            f"Consensus state did not project literal operator state '{expected_state}'.",
        )
        authority = projection.get("authority")
        require(isinstance(authority, dict), f"Projection '{expected_state}' authority is missing.")
        require(
            authority.get("may_mark_verification_accepted") is False,
            f"Projection '{expected_state}' incorrectly permits accepted rendering.",
        )

    negative_count = 0
    consensus = reconcile_observations(observations[0], observations[1], "2026-07-12T23:00:01Z")
    digest_tamper = copy.deepcopy(consensus)
    digest_tamper["primary_observation_digest"] = "sha256:" + "0" * 64
    expect_projection_error(
        "consensus digest substitution",
        lambda: project_verifier_control_board(
            health_reports, observations, digest_tamper, simulated_isolation, governance, CAPTURED_AT, MAXIMUM_ATTESTATION_LIFETIME_SECONDS
        ),
    )
    negative_count += 1
    duplicate_process = copy.deepcopy(observations)
    duplicate_process[1]["process_id"] = duplicate_process[0]["process_id"]
    expect_projection_error(
        "same-process dual identity",
        lambda: project_verifier_control_board(
            health_reports, duplicate_process, consensus, simulated_isolation, governance, CAPTURED_AT, MAXIMUM_ATTESTATION_LIFETIME_SECONDS
        ),
    )
    negative_count += 1
    duplicate_principal = copy.deepcopy(observations)
    duplicate_principal[1]["logical_principal"] = duplicate_principal[0]["logical_principal"]
    expect_projection_error(
        "duplicate logical principal",
        lambda: project_verifier_control_board(
            health_reports, duplicate_principal, consensus, simulated_isolation, governance, CAPTURED_AT, MAXIMUM_ATTESTATION_LIFETIME_SECONDS
        ),
    )
    negative_count += 1
    unknown_health = copy.deepcopy(health_reports)
    unknown_health[1]["service_id"] = "verifier:unknown"
    expect_projection_error(
        "unbound health identity",
        lambda: build_projection(unknown_health, observations, simulated_isolation, governance),
    )
    negative_count += 1
    accepted_mismatch = copy.deepcopy(consensus)
    accepted_mismatch["verification_accepted"] = True
    expect_projection_error(
        "accepted non-success consensus",
        lambda: project_verifier_control_board(
            health_reports, observations, accepted_mismatch, simulated_isolation, governance, CAPTURED_AT, MAXIMUM_ATTESTATION_LIFETIME_SECONDS
        ),
    )
    negative_count += 1
    incomplete_health_projection = build_projection(health_reports[:1], observations, simulated_isolation, governance)
    incomplete_boundary = incomplete_health_projection.get("boundary")
    require(isinstance(incomplete_boundary, dict), "Incomplete-health projection boundary is missing.")
    require(
        incomplete_boundary.get("production_ready") is False
        and "VERIFIER_HEALTH_INCOMPLETE" in cast(list[object], incomplete_boundary.get("missing_controls")),
        "Missing verifier health was not preserved as a fail-closed blocker.",
    )
    negative_count += 1
    acl_unproven = verifier_isolation_attestations(
        isolated_observations,
        live_governance,
        signers,
        "windows_access_check",
        False,
    )
    acl_blocked = build_projection(isolated_health, isolated_observations, acl_unproven, live_governance)
    require(
        acl_blocked.get("operator_state") == "boundary_unproven",
        "Missing read-only ACL evidence was laundered into verified state.",
    )
    negative_count += 1
    return 6, negative_count


def validate_control_board(project_root: Path) -> JsonObject:
    ui_root = project_root / "ui"
    html_path = ui_root / "index.html"
    css_path = ui_root / "styles.css"
    script_path = ui_root / "app.js"
    state_path = ui_root / "demo-state.json"
    world_model_path = project_root / "specs" / "examples" / "world-model-generation.example.json"
    world_intake_path = project_root / "reports" / "CACIS_WORLD_INTAKE_VALIDATION.json"
    world_intake_governance_path = (
        project_root / "reports" / "CACIS_WORLD_INTAKE_GOVERNANCE_VALIDATION.json"
    )
    immune_mission_path = project_root / "specs" / "examples" / "immune-organism-mission.example.json"
    immune_receipt_path = project_root / "specs" / "examples" / "immune-organism-lifecycle-receipt.example.json"
    research_mission_path = project_root / "specs" / "examples" / "intelligence-research-mission.example.json"
    research_settlement_path = project_root / "specs" / "examples" / "intelligence-research-settlement.example.json"
    homeostasis_mission_path = project_root / "specs" / "examples" / "homeostasis-chronos-mission.example.json"
    homeostasis_receipt_path = project_root / "specs" / "examples" / "homeostasis-chronos-receipt.example.json"
    contract_conformance_path = project_root / "reports" / "CONTRACT_CONFORMANCE_MATRIX.json"
    verifier_identity_readiness_path = (
        project_root / "reports" / "VERIFIER_IDENTITY_READINESS_VALIDATION.json"
    )
    autonomous_promotion_path = project_root / "reports" / "AUTONOMOUS_PROMOTION_VALIDATION.json"
    completion_audit_path = project_root / "reports" / "COMPLETION_AUDIT.json"
    html = html_path.read_text(encoding="utf-8")
    css = css_path.read_text(encoding="utf-8")
    script = script_path.read_text(encoding="utf-8")
    state = read_object(state_path)
    world_model = read_object(world_model_path)
    world_intake = read_object(world_intake_path)
    world_intake_governance = read_object(world_intake_governance_path)
    immune_mission = read_object(immune_mission_path)
    immune_receipt = read_object(immune_receipt_path)
    research_mission = read_object(research_mission_path)
    research_settlement = read_object(research_settlement_path)
    homeostasis_mission = read_object(homeostasis_mission_path)
    homeostasis_receipt = read_object(homeostasis_receipt_path)
    contract_conformance = read_object(contract_conformance_path)
    verifier_identity_readiness = read_object(verifier_identity_readiness_path)
    autonomous_promotion = read_object(autonomous_promotion_path)
    completion_audit = read_object(completion_audit_path)
    validate_world_model_generation(world_model)
    require(
        world_intake.get("status") == "CACIS_WORLD_INTAKE_SUCCESSION_REPLAY_VALID_POLICY_AND_ACTION_BLOCKED"
        and world_intake.get("separate_process_causal_verification_performed") is True
        and world_intake.get("live_sensor_admission_performed") is False
        and world_intake.get("policy_input_ready") is False,
        "Control board World Model intake evidence is missing or authority-bearing.",
    )
    require(
        world_intake_governance.get("status")
        == "CACIS_WORLD_INTAKE_GOVERNANCE_REPLAY_VALID_LIVE_ADMISSION_BLOCKED"
        and world_intake_governance.get("separate_process_verification_performed") is True
        and world_intake_governance.get("production_verifier_independence_verified") is False
        and world_intake_governance.get("live_sensor_admission_authorized") is False
        and world_intake_governance.get("policy_input_ready") is False,
        "Control board World Model governance evidence is missing or authority-bearing.",
    )
    validate_immune_organism_lifecycle_receipt(immune_receipt, immune_mission)
    validate_intelligence_research_settlement(research_settlement, research_mission)
    validate_homeostasis_chronos_receipt(homeostasis_mission, homeostasis_receipt)
    require(
        contract_conformance.get("status")
        == "CONTRACT_CONFORMANCE_MATRIX_STATIC_EVIDENCE_VALID_LIVE_RUNTIME_BLOCKED"
        and contract_conformance.get("contract_count") == 97
        and contract_conformance.get("live_runtime_evidence_count") == 0
        and contract_conformance.get("production_conformance_claim_count") == 0,
        "Control board contract conformance evidence is missing or overclaims live proof.",
    )
    require(
        verifier_identity_readiness.get("status")
        == "LIVE_IDENTITY_OBSERVED_DEDICATED_ACCOUNT_CUSTODY_AND_EGRESS_BLOCKED"
        and verifier_identity_readiness.get("surface_count") == 3
        and verifier_identity_readiness.get("distinct_process_observed_count") == 3
        and verifier_identity_readiness.get("dedicated_os_account_verified_count") == 0
        and verifier_identity_readiness.get("read_only_input_acl_verified_count") == 0
        and verifier_identity_readiness.get("production_signing_custody_verified_count") == 0
        and verifier_identity_readiness.get("production_eligible_count") == 0,
        "Control board verifier identity readiness evidence is missing or launders production isolation.",
    )
    require(
        autonomous_promotion.get("status")
        == "AUTONOMOUS_THRESHOLD_PROMOTION_REPLAY_VALID_SHADOW_AND_DEMOTION_ONLY"
        and autonomous_promotion.get("autonomous_promotion_standard") is True
        and autonomous_promotion.get("eligible_tiers") == ["A", "B"]
        and autonomous_promotion.get("human_approval_required_for_eligible_tiers") is False
        and autonomous_promotion.get("threshold_signer_count") == 2
        and autonomous_promotion.get("threshold_role_count") == 2
        and autonomous_promotion.get("independent_evaluator_count") == 4
        and autonomous_promotion.get("shadow_promotion_count") == 1
        and autonomous_promotion.get("automatic_regression_demotion_count") == 1
        and autonomous_promotion.get("production_promotion_authorized") is False
        and autonomous_promotion.get("active_baseline_modified") is False
        and autonomous_promotion.get("candidate_executed") is False,
        "Control board autonomous-promotion evidence is missing or widens authority.",
    )
    require(
        completion_audit.get("status") == "LOCAL_ROADMAP_COMPLETE_EXTERNAL_OPERATIONAL_GATES_BLOCKED"
        and completion_audit.get("local_gate_count") == 15
        and completion_audit.get("local_gate_complete_count") == 15
        and completion_audit.get("external_gate_count") == 6
        and completion_audit.get("external_gate_blocked_count") == 6
        and completion_audit.get("deployable_product_claimed") is False
        and completion_audit.get("production_protection_claimed") is False,
        "Control board completion audit is missing or launders external blockers.",
    )
    parser = ControlBoardHtmlParser()
    parser.feed(html)

    required_ids = {
        "workspace",
        "cell-stack",
        "causal-map",
        "truth-braid",
        "dissent-list",
        "ledger",
        "swarm-matrix",
        "proof-console",
        "lease-facts",
        "kill-switch",
        "compile-proposal",
        "status-message",
        "verifier-pill",
        "ingress-pill",
        "board-ingress",
        "verifier-consensus",
        "verifier-health",
        "verifier-observations",
        "verifier-boundary",
        "verifier-dissent",
        "verifier-gate-facts",
        "range-gate-summary",
        "range-gate-stages",
        "range-gate-attestations",
        "range-gate-authority",
        "foundry-summary",
        "platform-assurance",
        "world-model-state",
        "world-generation",
        "world-observations",
        "world-generations",
        "world-cursors",
        "world-gaps",
        "world-intake-verifier",
        "world-source-governance",
        "world-backpressure",
        "world-retention",
        "world-source-health",
        "contract-count",
        "contract-semantic",
        "contract-runtime-refs",
        "contract-harness-refs",
        "contract-live-evidence",
        "verifier-identity-surfaces",
        "verifier-dedicated-accounts",
        "verifier-readonly-acls",
        "verifier-production-custody",
        "promotion-state",
        "promotion-tiers",
        "promotion-threshold",
        "promotion-evaluators",
        "promotion-human",
        "promotion-demotion",
        "promotion-production",
        "completion-local-gates",
        "completion-external-gates",
        "completion-product-state",
        "cacis-world-grid",
        "organism-state",
        "organism-ceiling",
        "organism-cells",
        "organism-events",
        "organism-contributions",
        "organism-abstentions",
        "organism-retained",
        "organism-verification",
        "cacis-organism-events",
        "research-state",
        "research-ceiling",
        "research-question",
        "research-hypotheses",
        "research-cases",
        "research-results",
        "research-challenges",
        "research-coverage",
        "research-verifier",
        "research-theory",
        "research-hypothesis-grid",
        "homeostasis-state",
        "homeostasis-ceiling",
        "homeostasis-breaches",
        "homeostasis-pressure",
        "homeostasis-confidence",
        "homeostasis-backlog",
        "homeostasis-scheduled",
        "homeostasis-deferred",
        "homeostasis-abstained",
        "homeostasis-signal-grid",
        "chronos-decision-grid",
        "observatory-mode",
        "genome-state",
        "genome-strata",
        "genome-partitions",
        "genome-reward-defenses",
        "genome-complexity",
        "arena-count",
        "arena-evaluated",
        "arena-blocked",
        "arena-dimensions",
        "observatory-signers",
        "foundry-evaluators",
        "foundry-boundary",
        "foundry-resource-ledger",
        "footer-verifier-state",
        "footer-ingress-state",
    }
    missing_ids = sorted(required_ids - parser.ids)
    require(not missing_ids, f"Control board is missing required element IDs: {', '.join(missing_ids)}")
    require(parser.local_scripts == ["app.js"], f"Unexpected local scripts: {parser.local_scripts}")
    require(parser.local_styles == ["styles.css"], f"Unexpected local styles: {parser.local_styles}")
    require(not parser.external_references, f"Control board loads external resources: {parser.external_references}")
    require("@media (prefers-reduced-motion: reduce)" in css, "Reduced-motion support is missing.")
    require(css.count("@media") >= 3, "Responsive control-board breakpoints are incomplete.")
    require(":focus-visible" in css and ".skip-link" in css, "Keyboard focus affordances are incomplete.")

    prohibited_script_tokens = (
        "eval(",
        "new Function",
        "WebSocket",
        "EventSource",
        "XMLHttpRequest",
        "http://",
        "https://",
        "document.cookie",
        "localStorage",
        "sessionStorage",
    )
    for token in prohibited_script_tokens:
        require(token not in script, f"Control-board script contains prohibited token '{token}'.")
    require(
        'const stateUrl = "demo-state.json";' in script
        and 'const edgeStateUrl = "../specs/examples/edge-preview-result.example.json";'
        in script
        and 'const worldModelStateUrl = "../specs/examples/world-model-generation.example.json";'
        in script
        and 'const worldIntakeStateUrl = "../reports/CACIS_WORLD_INTAKE_VALIDATION.json";'
        in script
        and 'const worldIntakeGovernanceStateUrl = "../reports/CACIS_WORLD_INTAKE_GOVERNANCE_VALIDATION.json";'
        in script
        and 'const immuneRuntimeStateUrl = "../specs/examples/immune-organism-lifecycle-receipt.example.json";'
        in script,
        "Control board must declare all explicit local evidence sources.",
    )
    require(
        'const intelligenceResearchStateUrl = "../specs/examples/intelligence-research-settlement.example.json";'
        in script,
        "Control board must declare the intelligence research settlement source.",
    )
    require(
        'const homeostasisChronosStateUrl = "../specs/examples/homeostasis-chronos-receipt.example.json";'
        in script,
        "Control board must declare the W4 Homeostasis and Chronos receipt source.",
    )
    require(
        'const genomeEvaluationStateUrl = "../reports/CACIS_GENOME_EVALUATION_VALIDATION.json";'
        in script
        and 'const arenasObservatoryStateUrl = "../reports/CACIS_ARENAS_OBSERVATORY_VALIDATION.json";'
        in script,
        "Control board must declare the W5 genome and W6 arena evidence sources.",
    )
    require(
        'const contractConformanceStateUrl = "../reports/CONTRACT_CONFORMANCE_MATRIX.json";'
        in script,
        "Control board must declare the contract conformance evidence source.",
    )
    require(
        'const verifierIdentityReadinessStateUrl = "../reports/VERIFIER_IDENTITY_READINESS_VALIDATION.json";'
        in script,
        "Control board must declare the verifier identity readiness evidence source.",
    )
    require(
        'const autonomousPromotionStateUrl = "../reports/AUTONOMOUS_PROMOTION_VALIDATION.json";'
        in script,
        "Control board must declare the autonomous-promotion evidence source.",
    )
    require(
        'const completionAuditStateUrl = "../reports/COMPLETION_AUDIT.json";' in script,
        "Control board must declare the completion audit evidence source.",
    )
    require(
        re.search(r'fetch\(url, \{cache: "no-store"\}\)', script) is not None
        and "Promise.all([loadJson(stateUrl), loadJson(edgeStateUrl), loadJson(worldModelStateUrl), loadJson(worldIntakeStateUrl), loadJson(worldIntakeGovernanceStateUrl), loadJson(immuneRuntimeStateUrl), loadJson(intelligenceResearchStateUrl), loadJson(homeostasisChronosStateUrl), loadJson(genomeEvaluationStateUrl), loadJson(arenasObservatoryStateUrl), loadJson(contractConformanceStateUrl), loadJson(verifierIdentityReadinessStateUrl), loadJson(autonomousPromotionStateUrl), loadJson(completionAuditStateUrl)])"
        in script,
        "Control board must load all explicit local evidence states.",
    )
    for required_renderer in (
        "renderBoardIngress",
        "renderVerifierConsensus",
        "renderVerifierHealth",
        "renderVerifierBoundary",
        "renderVerifierObservations",
        "renderVerifierDissent",
        "renderVerifierGate",
        "renderRangeGate",
        "renderFoundrySummary",
        "renderFoundryEvaluators",
        "renderFoundryResources",
        "renderFoundryBoundary",
        "renderPlatformAssurance",
        "renderWorldModel",
        "renderImmuneRuntime",
        "renderIntelligenceResearch",
        "renderHomeostasisChronos",
        "renderGenomeAndArenas",
        "renderContractConformance",
        "renderVerifierIdentityReadiness",
        "renderAutonomousPromotion",
        "renderCompletionAudit",
        "renderFoundry",
    ):
        require(required_renderer in script, f"Control-board script lacks '{required_renderer}'.")

    require(state.get("origin") == "simulated", "Control-board demo origin is not simulated.")
    mission = state.get("mission")
    proof = state.get("proof")
    cells = state.get("cells")
    verifier = state.get("verifier")
    foundry = state.get("foundry")
    platform_assurance = state.get("platform_assurance")
    range_execution_gate = state.get("range_execution_gate")
    ingress = state.get("ingress")
    require(isinstance(mission, dict), "Control-board mission state is missing.")
    require(isinstance(proof, dict), "Control-board proof state is missing.")
    require(isinstance(cells, list), "Control-board cells state is missing.")
    require(isinstance(verifier, dict), "Control-board verifier projection is missing.")
    require(isinstance(foundry, dict), "Control-board Foundry projection is missing.")
    require(isinstance(platform_assurance, dict), "Control-board platform-assurance state is missing.")
    require(isinstance(range_execution_gate, dict), "Control-board range execution-gate state is missing.")
    require(isinstance(ingress, dict), "Control-board signed-ingress receipt is missing.")
    require(mission.get("execution_authorized") is False, "Demo mission incorrectly authorizes execution.")
    require(proof.get("execution_authorized") is False, "Demo proof incorrectly authorizes execution.")
    require(proof.get("live_execution_performed") is False, "Demo proof incorrectly claims live execution.")
    require(proof.get("cryptographic_authorization_verified") is True, "Demo proof lacks authorization state.")
    require(len(cells) == 7, f"Control-board demo must contain seven roles; received {len(cells)}.")
    roles = {str(cell.get("role")) for cell in cells if isinstance(cell, dict)}
    require(len(roles) == 7, "Control-board demo role diversity contains duplicates.")

    range_gate_report = read_object(project_root / "reports" / "RANGE_EXECUTION_GATE_VALIDATION.json")
    for field in (
        "origin",
        "connector_manifest_status",
        "connector_verified_signer_count",
        "connector_operation_count",
        "connector_capability_count",
        "scope_status",
        "scope_target_binding_count",
        "cryptographic_authorization_verified",
        "topology_environment_verified",
        "preexecution_packet_status",
        "required_real_attestation_count",
        "missing_real_attestation_count",
        "real_environment_attestation_count",
        "evidence_complete",
    ):
        require(
            range_execution_gate.get(field) == range_gate_report.get(field),
            f"Range execution-gate field '{field}' differs from its validation report.",
        )
    require(
        range_execution_gate.get("execution_gate_status") == range_gate_report.get("status"),
        "Range execution-gate UI hides its underlying gate status.",
    )
    admission_report = read_object(project_root / "reports" / "RANGE_EVIDENCE_ADMISSION_VALIDATION.json")
    evidence_admission = range_execution_gate.get("evidence_admission")
    require(isinstance(evidence_admission, dict), "Range evidence-admission UI state is missing.")
    require(
        evidence_admission.get("status") == admission_report.get("status"),
        "Range evidence-admission state differs from its report.",
    )
    for field in (
        "collector_policy_status",
        "collector_policy_signer_count",
        "signed_observation_count",
        "content_addressed_observation_count",
        "distinct_collector_count",
        "owner_named_environment",
        "real_observation_count",
        "emitted_attestation_count",
        "verified_attestation_count",
        "independent_verifier_count",
        "fixture_independent_document_api",
        "evidence_complete",
        "blockers",
    ):
        require(
            evidence_admission.get(field) == admission_report.get(field),
            f"Range evidence-admission field '{field}' differs from its validation report.",
        )
    require(
        evidence_admission.get("activity") == admission_report.get("activity"),
        "Range evidence-admission activity differs from its validation report.",
    )
    require(
        evidence_admission.get("authority") == admission_report.get("authority"),
        "Range evidence-admission authority differs from its validation report.",
    )
    acceptance_report = read_object(project_root / "reports" / "RANGE_EVIDENCE_ACCEPTANCE_VALIDATION.json")
    evidence_acceptance = range_execution_gate.get("evidence_acceptance")
    require(isinstance(evidence_acceptance, dict), "Range evidence-acceptance UI state is missing.")
    require(
        evidence_acceptance.get("status") == acceptance_report.get("status"),
        "Range evidence-acceptance state differs from its report.",
    )
    for field in (
        "verifier_policy_status",
        "verifier_policy_signer_count",
        "configured_verifier_count",
        "required_control_count",
        "verified_decision_count",
        "distinct_signed_verifier_count",
        "real_independent_verifier_count",
        "resolution_counts",
        "accepted_control_count",
        "verified_attestation_count",
        "evidence_complete",
        "blockers",
    ):
        require(
            evidence_acceptance.get(field) == acceptance_report.get(field),
            f"Range evidence-acceptance field '{field}' differs from its validation report.",
        )
    require(
        evidence_acceptance.get("activity") == acceptance_report.get("activity"),
        "Range evidence-acceptance activity differs from its validation report.",
    )
    require(
        evidence_acceptance.get("authority") == acceptance_report.get("authority"),
        "Range evidence-acceptance authority differs from its validation report.",
    )
    completion_report = read_object(project_root / "reports" / "RANGE_EVIDENCE_COMPLETION_VALIDATION.json")
    evidence_completion = range_execution_gate.get("evidence_completion")
    require(isinstance(evidence_completion, dict), "Range evidence-completion UI state is missing.")
    require(
        evidence_completion.get("status") == completion_report.get("status"),
        "Range evidence-completion state differs from its report.",
    )
    for field in (
        "completion_policy_status",
        "completion_policy_signer_count",
        "completion_authorization_status",
        "completion_authorization_signer_count",
        "completion_prerequisites_satisfied",
        "completion_authorized",
        "accepted_control_count",
        "verified_attestation_count",
        "real_independent_verifier_count",
        "evidence_complete",
        "range_connection_authorized",
        "execution_authorized",
        "blockers",
    ):
        require(
            evidence_completion.get(field) == completion_report.get(field),
            f"Range evidence-completion field '{field}' differs from its validation report.",
        )
    require(
        evidence_completion.get("activity") == completion_report.get("activity"),
        "Range evidence-completion activity differs from its validation report.",
    )
    require(
        evidence_completion.get("authority") == completion_report.get("authority"),
        "Range evidence-completion authority differs from its validation report.",
    )
    corpus_report = read_object(project_root / "reports" / "PUBLIC_SACRIFICIAL_CORPUS_VALIDATION.json")
    public_corpus = range_execution_gate.get("public_sacrificial_corpus")
    require(isinstance(public_corpus, dict), "Public sacrificial-corpus UI state is missing.")
    require(
        public_corpus.get("status") == corpus_report.get("status"),
        "Public sacrificial-corpus state differs from its report.",
    )
    for field in (
        "origin",
        "pinned_source_count",
        "metadata_reviewed_source_count",
        "source_archive_count",
        "replica_declared_count",
        "replica_ready_count",
        "owner_exclusion_registry_complete",
        "unknown_ownership_action",
        "excluded_organizations",
        "public_host_target_authorized",
        "range_connection_authorized",
        "execution_authorized",
        "forbidden_target_class_count",
        "adversarial_case_count",
        "blockers",
    ):
        require(
            public_corpus.get(field) == corpus_report.get(field),
            f"Public sacrificial-corpus field '{field}' differs from its validation report.",
        )
    require(public_corpus.get("activity") == corpus_report.get("activity"), "Public corpus activity differs from its report.")
    require(public_corpus.get("authority") == corpus_report.get("authority"), "Public corpus authority differs from its report.")
    staging_report = read_object(project_root / "reports" / "SOURCE_STAGING_GATE_VALIDATION.json")
    source_staging = range_execution_gate.get("source_staging_gate")
    require(isinstance(source_staging, dict), "Source-staging gate UI state is missing.")
    require(
        source_staging.get("status") == staging_report.get("status"),
        "Source-staging gate state differs from its validation report.",
    )
    for field in (
        "origin",
        "verified_signer_count",
        "verified_role_count",
        "requested_source_count",
        "authorized_source_count",
        "staged_source_count",
        "quarantine_requirement_count",
        "quarantine_completed_count",
        "owner_exclusion_registry_complete",
        "owner_attestation_present",
        "staging_authorized",
        "build_authorized",
        "range_connection_authorized",
        "execution_authorized",
        "adversarial_case_count",
        "blockers",
    ):
        require(
            source_staging.get(field) == staging_report.get(field),
            f"Source-staging gate field '{field}' differs from its validation report.",
        )
    require(source_staging.get("activity") == staging_report.get("activity"), "Source-staging activity differs from its report.")
    require(source_staging.get("authority") == staging_report.get("authority"), "Source-staging authority differs from its report.")
    construction_report = read_object(project_root / "reports" / "CONSTRUCTION_ZONE_PREFLIGHT_VALIDATION.json")
    construction_preflight = range_execution_gate.get("construction_zone_preflight")
    require(isinstance(construction_preflight, dict), "Construction-zone preflight UI state is missing.")
    require(
        construction_preflight.get("status") == construction_report.get("status"),
        "Construction-zone preflight state differs from its validation report.",
    )
    for field in (
        "origin",
        "zone_control_count",
        "verified_zone_control_count",
        "quarantine_requirement_count",
        "verified_quarantine_requirement_count",
        "source_archive_count",
        "construction_zone_provisioned",
        "quarantine_evidence_complete",
        "staging_authorized",
        "build_authorized",
        "range_connection_authorized",
        "execution_authorized",
        "adversarial_case_count",
        "blockers",
    ):
        require(
            construction_preflight.get(field) == construction_report.get(field),
            f"Construction-zone preflight field '{field}' differs from its validation report.",
        )
    require(
        construction_preflight.get("activity") == construction_report.get("activity"),
        "Construction-zone preflight activity differs from its report.",
    )
    require(
        construction_preflight.get("authority") == construction_report.get("authority"),
        "Construction-zone preflight authority differs from its report.",
    )
    provisioning_report = read_object(
        project_root / "reports" / "CONSTRUCTION_ZONE_PROVISIONING_GATE_VALIDATION.json"
    )
    provisioning_gate = range_execution_gate.get("construction_zone_provisioning_gate")
    require(isinstance(provisioning_gate, dict), "Construction-zone provisioning-gate UI state is missing.")
    require(
        range_execution_gate.get("status") == provisioning_report.get("status")
        and provisioning_gate.get("status") == provisioning_report.get("status"),
        "Range gate terminal state differs from the construction-zone provisioning report.",
    )
    for field in (
        "origin",
        "verified_signer_count",
        "verified_role_count",
        "required_control_count",
        "assigned_collector_count",
        "assigned_verifier_count",
        "verified_control_count",
        "attestation_plan_complete",
        "operator_approval_present",
        "provider_selected",
        "provisioning_authorized",
        "provisioning_performed",
        "staging_authorized",
        "build_authorized",
        "range_connection_authorized",
        "execution_authorized",
        "adversarial_case_count",
        "blockers",
    ):
        require(
            provisioning_gate.get(field) == provisioning_report.get(field),
            f"Construction-zone provisioning field '{field}' differs from its validation report.",
        )
    require(
        provisioning_gate.get("activity") == provisioning_report.get("activity"),
        "Construction-zone provisioning activity differs from its report.",
    )
    require(
        provisioning_gate.get("authority") == provisioning_report.get("authority"),
        "Construction-zone provisioning authority differs from its report.",
    )
    packet_example = read_json_object(
        project_root / "specs" / "examples" / "range-preexecution-evidence-packet.example.json"
    )
    require(
        range_execution_gate.get("required_attestation_controls")
        == packet_example.get("required_attestation_controls"),
        "Range execution-gate UI hides or reorders required real attestations.",
    )
    range_activity = range_execution_gate.get("activity")
    range_authority = range_execution_gate.get("authority")
    require(isinstance(range_activity, dict), "Range execution-gate activity state is missing.")
    require(isinstance(range_authority, dict), "Range execution-gate authority state is missing.")
    require(
        all(value is False for value in range_activity.values()),
        "Range execution-gate UI claims prohibited activity.",
    )
    require(
        all(value is False for value in range_authority.values()),
        "Range execution-gate UI exposes authority.",
    )

    projection_example = read_json_object(
        project_root / "specs" / "examples" / "control-board-verifier-projection.example.json"
    )
    require(verifier == projection_example, "UI verifier projection differs from the canonical contract example.")
    validate_contract(
        projection_example,
        project_root / "specs" / "control-board-verifier-projection.schema.json",
        "control-board verifier projection",
    )
    require(verifier.get("operator_state") == "boundary_unproven", "Demo verifier state hides the OS boundary.")
    verifier_authority = verifier.get("authority")
    require(isinstance(verifier_authority, dict), "Demo verifier authority is missing.")
    require(
        verifier_authority.get("can_authorize") is False
        and verifier_authority.get("can_execute") is False
        and verifier_authority.get("may_mark_verification_accepted") is False,
        "Demo verifier projection exposes authority or accepted rendering.",
    )
    foundry_example = read_json_object(
        project_root / "specs" / "examples" / "control-board-foundry-projection.example.json"
    )
    require(foundry == foundry_example, "UI Foundry projection differs from the canonical contract example.")
    validate_contract(
        foundry_example,
        project_root / "specs" / "control-board-foundry-projection.schema.json",
        "control-board Foundry projection",
    )
    foundry_boundary = foundry.get("boundary")
    foundry_authority = foundry.get("authority")
    require(isinstance(foundry_boundary, dict), "Demo Foundry boundary is missing.")
    require(isinstance(foundry_authority, dict), "Demo Foundry authority is missing.")
    require(
        foundry_boundary.get("shadow_eligible") is True
        and foundry_boundary.get("live_os_enforcement_verified") is False
        and foundry_boundary.get("production_ready") is False,
        "Demo Foundry projection launders simulated isolation into production readiness.",
    )
    require(
        all(value is False for value in foundry_authority.values()),
        "Demo Foundry projection exposes authority.",
    )
    isolation_state = platform_assurance.get("windows_isolation")
    evaluator_state = platform_assurance.get("independent_evaluator")
    meter_state = platform_assurance.get("resource_meter")
    custody_state = platform_assurance.get("custody_readiness")
    require(isinstance(isolation_state, dict), "Platform-assurance isolation state is missing.")
    require(isinstance(evaluator_state, dict), "Platform-assurance evaluator state is missing.")
    require(isinstance(meter_state, dict), "Platform-assurance resource-meter state is missing.")
    require(isinstance(custody_state, dict), "Platform-assurance custody-readiness state is missing.")
    isolation_report = read_object(project_root / "reports" / "WINDOWS_ISOLATION_VALIDATION.json")
    evaluator_report = read_object(project_root / "reports" / "EVALUATOR_CONFORMANCE_VALIDATION.json")
    meter_report = read_object(project_root / "reports" / "RESOURCE_METER_VALIDATION.json")
    custody_report = read_object(project_root / "reports" / "WINDOWS_CUSTODY_READINESS_VALIDATION.json")
    for field in (
        "origin",
        "status",
        "verified_control_count",
        "control_count",
        "blockers",
        "signed_attestation_verified",
        "boundary_verified",
        "effective_acl_rights_computed",
        "target_specific_firewall_inspection",
        "all_traffic_target_block_rule_count",
    ):
        require(
            isolation_state.get(field) == isolation_report.get(field),
            f"Platform-assurance isolation field '{field}' differs from its validation report.",
        )
    for field in (
        "origin",
        "status",
        "implementation_language",
        "runtime_cryptography",
        "adversarial_case_count",
        "shared_python_verification_logic",
    ):
        require(
            evaluator_state.get(field) == evaluator_report.get(field),
            f"Platform-assurance evaluator field '{field}' differs from its validation report.",
        )
    for field in (
        "origin",
        "status",
        "job_object_assigned",
        "kill_on_close_configured",
        "lineage_ledger_within_constitution",
        "injected_process_crash_recovery_verified",
        "created_suspended",
        "assigned_before_first_resume",
        "assignment_race_closed",
        "abrupt_process_crash_recovery_verified",
        "write_through_publish_verified",
        "physical_power_loss_test_performed",
        "power_loss_durability_verified",
    ):
        require(
            meter_state.get(field) == meter_report.get(field),
            f"Platform-assurance resource-meter field '{field}' differs from its validation report.",
        )
    for field in (
        "origin",
        "status",
        "provider_count",
        "platform_crypto_provider_present",
        "tpm_management_query_succeeded",
        "blockers",
        "key_created",
        "signing_operation_performed",
        "private_key_material_accessed",
        "production_custody_verified",
    ):
        require(
            custody_state.get(field) == custody_report.get(field),
            f"Platform-assurance custody field '{field}' differs from its validation report.",
        )
    require(
        platform_assurance.get("status") == "boundary_incomplete"
        and platform_assurance.get("production_ready") is False
        and isolation_state.get("boundary_verified") is False
        and meter_state.get("assignment_race_closed") is True
        and meter_state.get("power_loss_durability_verified") is False
        and custody_state.get("production_custody_verified") is False,
        "Platform-assurance state hides an incomplete production boundary.",
    )
    validate_contract(
        ingress,
        project_root / "specs" / "control-board-ingress-receipt.schema.json",
        "control-board ingress receipt",
    )
    require(
        ingress.get("projection_digest") == sha256_digest(verifier),
        "Demo ingress receipt does not bind the rendered verifier projection.",
    )
    ingress_authority = ingress.get("authority")
    require(isinstance(ingress_authority, dict), "Demo ingress authority is missing.")
    require(
        ingress_authority.get("can_authorize") is False
        and ingress_authority.get("can_execute") is False,
        "Demo ingress receipt exposes authority.",
    )
    require(
        ingress.get("status") == "accepted"
        and ingress.get("durable_replay_guard") is True
        and ingress.get("stale_state_guard") is True,
        "Demo ingress receipt lacks signed freshness and replay guards.",
    )
    world_generation = cast(JsonObject, world_model["generation"])
    world_authority = cast(JsonObject, world_generation["authority"])
    require(
        world_authority.get("can_authorize") is False
        and world_authority.get("can_execute") is False
        and world_authority.get("can_change_policy") is False
        and world_authority.get("can_contact_targets") is False
        and world_authority.get("policy_input_ready") is False
        and world_authority.get("production_truth_claimed") is False,
        "World Model projection exposes operational authority.",
    )
    immune_body = cast(JsonObject, immune_receipt["receipt"])
    immune_termination = cast(JsonObject, immune_body["termination"])
    require(
        immune_body.get("terminal_reason") == "shadow_terminated"
        and immune_termination.get("lifecycle_state") == "disposed"
        and immune_termination.get("all_cells_terminated") is True
        and immune_termination.get("execution_performed") is False
        and immune_termination.get("target_contact_performed") is False,
        "Immune Runtime projection hides incomplete teardown or operational activity.",
    )
    research_body = cast(JsonObject, research_settlement["settlement"])
    research_theory = cast(JsonObject, research_body["candidate_theory"])
    research_verification = cast(JsonObject, research_body["independent_verification"])
    research_metacognition = cast(JsonObject, research_body["metacognition"])
    require(
        research_theory.get("status") == "candidate_only"
        and research_theory.get("generalization_allowed") is False
        and research_theory.get("promotion_authorized") is False
        and research_verification.get("scope") == "structural_replay_only"
        and research_verification.get("production_independence_verified") is False
        and research_metacognition.get("knowledge_state") == "partially_known"
        and research_metacognition.get("should_abstain_from_generalization") is True,
        "Intelligence Research projection launders replay evidence into generalization, promotion, or production independence.",
    )
    homeostasis_body = cast(JsonObject, homeostasis_receipt["receipt"])
    homeostasis_state = cast(JsonObject, homeostasis_body["homeostasis"])
    homeostasis_authority = cast(JsonObject, homeostasis_body["authority"])
    require(
        homeostasis_state.get("state") == "degraded_bounded"
        and homeostasis_state.get("breach_count") == 10
        and homeostasis_state.get("confidence_inflation") == 0.72
        and homeostasis_state.get("verification_backlog") == 0.8
        and homeostasis_state.get("scheduled_count") == 3
        and homeostasis_state.get("deferred_count") == 1
        and homeostasis_state.get("abstained_count") == 2
        and all(value is False for value in homeostasis_authority.values()),
        "Homeostasis projection launders pressure, backlog, confidence inflation, backpressure, expiry, or authority.",
    )
    state_count, negative_count = validate_projection_state_matrix(project_root)

    return {
        "status": "CONTROL_BOARD_SIGNED_INGRESS_INTEGRATION_VALID",
        "origin": "simulated",
        "html_required_id_count": len(required_ids),
        "external_resource_count": len(parser.external_references),
        "swarm_role_count": len(roles),
        "verifier_consensus_state_count": state_count,
        "verifier_projection_negative_case_count": negative_count,
        "verifier_service_count": len(cast(list[object], verifier.get("service_health"))),
        "verifier_dissent_count": len(cast(list[object], verifier.get("dissent"))),
        "verifier_operator_state": verifier.get("operator_state"),
        "verifier_verification_accepted": False,
        "verifier_os_identity_verified": False,
        "verifier_read_only_acl_verified": False,
        "foundry_evaluator_count": len(cast(list[object], foundry.get("evaluator_mesh"))),
        "foundry_operator_state": foundry.get("operator_state"),
        "foundry_resource_ledger_within_constitution": True,
        "foundry_live_os_enforcement_verified": False,
        "foundry_production_ready": False,
        "platform_assurance_status": platform_assurance.get("status"),
        "platform_assurance_live_isolation_verified_controls": isolation_state.get("verified_control_count"),
        "platform_assurance_independent_evaluator": evaluator_state.get("implementation_language"),
        "platform_assurance_job_object_metering_verified": meter_state.get("job_object_assigned"),
        "platform_assurance_assignment_race_closed": meter_state.get("assignment_race_closed"),
        "platform_assurance_custody_readiness_status": custody_state.get("status"),
        "platform_assurance_production_ready": False,
        "world_model_generation_digest": world_model.get("generation_digest"),
        "world_model_observation_count": len(cast(list[object], world_generation["observation_digests"])),
        "world_model_domain_count": len(cast(list[object], world_generation["domains"])),
        "world_model_execution_authorized": False,
        "world_model_policy_input_ready": False,
        "world_model_production_truth_claimed": False,
        "world_intake_generation_count": world_intake.get("world_generation_count"),
        "world_intake_cursor_transition_count": world_intake.get("cursor_transition_count"),
        "world_intake_gap_source_count": world_intake.get("gap_source_count"),
        "world_intake_separate_process_verified": world_intake.get(
            "separate_process_causal_verification_performed"
        ),
        "world_intake_live_sensor_admission_performed": False,
        "world_intake_governance_policy_signer_count": world_intake_governance.get(
            "source_policy_verified_signer_count"
        ),
        "world_intake_governance_policy_role_count": world_intake_governance.get(
            "source_policy_verified_role_count"
        ),
        "world_intake_governance_accepted_event_count": world_intake_governance.get(
            "accepted_event_count"
        ),
        "world_intake_governance_deferred_event_count": world_intake_governance.get(
            "deferred_event_count"
        ),
        "world_intake_governance_dropped_event_count": world_intake_governance.get(
            "dropped_event_count"
        ),
        "world_intake_governance_fresh_source_count": world_intake_governance.get(
            "fresh_source_count"
        ),
        "world_intake_governance_gap_source_count": world_intake_governance.get(
            "source_gap_count"
        ),
        "world_intake_governance_live_sensor_admission_authorized": False,
        "contract_conformance_contract_count": contract_conformance.get("contract_count"),
        "contract_conformance_semantic_validator_count": contract_conformance.get(
            "semantic_validator_count"
        ),
        "contract_conformance_runtime_reference_count": contract_conformance.get(
            "runtime_reference_count"
        ),
        "contract_conformance_harness_reference_count": contract_conformance.get(
            "independent_harness_reference_count"
        ),
        "contract_conformance_live_runtime_evidence_count": 0,
        "verifier_identity_readiness_surface_count": verifier_identity_readiness.get("surface_count"),
        "verifier_identity_readiness_distinct_process_count": verifier_identity_readiness.get(
            "distinct_process_observed_count"
        ),
        "verifier_identity_readiness_dedicated_account_count": 0,
        "verifier_identity_readiness_read_only_acl_count": 0,
        "verifier_identity_readiness_production_custody_count": 0,
        "verifier_identity_readiness_production_eligible_count": 0,
        "autonomous_promotion_standard": autonomous_promotion.get("autonomous_promotion_standard"),
        "autonomous_promotion_eligible_tiers": autonomous_promotion.get("eligible_tiers"),
        "autonomous_promotion_threshold_signer_count": autonomous_promotion.get("threshold_signer_count"),
        "autonomous_promotion_threshold_role_count": autonomous_promotion.get("threshold_role_count"),
        "autonomous_promotion_independent_evaluator_count": autonomous_promotion.get(
            "independent_evaluator_count"
        ),
        "autonomous_promotion_human_approval_required": False,
        "autonomous_promotion_shadow_count": autonomous_promotion.get("shadow_promotion_count"),
        "autonomous_promotion_regression_demotion_count": autonomous_promotion.get(
            "automatic_regression_demotion_count"
        ),
        "autonomous_promotion_production_authorized": False,
        "completion_audit_local_gate_count": completion_audit.get("local_gate_count"),
        "completion_audit_local_gate_complete_count": completion_audit.get("local_gate_complete_count"),
        "completion_audit_external_gate_count": completion_audit.get("external_gate_count"),
        "completion_audit_external_gate_blocked_count": completion_audit.get("external_gate_blocked_count"),
        "completion_audit_deployable_product_claimed": False,
        "immune_runtime_receipt_digest": immune_receipt.get("receipt_digest"),
        "immune_runtime_cell_count": immune_body.get("cell_count"),
        "immune_runtime_event_count": len(cast(list[object], immune_body["events"])),
        "immune_runtime_contribution_count": len(cast(list[object], immune_body["contributions"])),
        "immune_runtime_lifecycle_state": immune_termination.get("lifecycle_state"),
        "immune_runtime_execution_authorized": False,
        "immune_runtime_execution_performed": False,
        "immune_runtime_target_contact_performed": False,
        "intelligence_research_settlement_digest": research_settlement.get("settlement_digest"),
        "intelligence_research_hypothesis_count": len(cast(list[object], research_body["hypotheses"])),
        "intelligence_research_method_result_count": len(cast(list[object], research_body["method_results"])),
        "intelligence_research_challenge_count": len(cast(list[object], research_body["challenge_log"])),
        "intelligence_research_candidate_theory_status": research_theory.get("status"),
        "intelligence_research_generalization_allowed": False,
        "intelligence_research_production_independence_verified": False,
        "intelligence_research_promotion_authorized": False,
        "homeostasis_chronos_receipt_digest": homeostasis_receipt.get("receipt_digest"),
        "homeostasis_chronos_signal_count": len(cast(list[object], homeostasis_body["signal_assessments"])),
        "homeostasis_chronos_breach_count": homeostasis_state.get("breach_count"),
        "homeostasis_chronos_scheduled_count": homeostasis_state.get("scheduled_count"),
        "homeostasis_chronos_deferred_count": homeostasis_state.get("deferred_count"),
        "homeostasis_chronos_abstained_count": homeostasis_state.get("abstained_count"),
        "homeostasis_chronos_execution_authorized": False,
        "range_execution_gate_status": range_execution_gate.get("execution_gate_status"),
        "range_execution_gate_missing_real_attestation_count": range_execution_gate.get("missing_real_attestation_count"),
        "range_execution_gate_evidence_complete": False,
        "range_execution_gate_connection_authorized": False,
        "range_evidence_admission_status": evidence_admission.get("status"),
        "range_evidence_admission_signed_observation_count": evidence_admission.get("signed_observation_count"),
        "range_evidence_admission_distinct_collector_count": evidence_admission.get("distinct_collector_count"),
        "range_evidence_admission_verified_attestation_count": evidence_admission.get("verified_attestation_count"),
        "range_evidence_admission_owner_named_environment": evidence_admission.get("owner_named_environment"),
        "range_evidence_acceptance_status": evidence_acceptance.get("status"),
        "range_evidence_acceptance_signed_decision_count": evidence_acceptance.get("verified_decision_count"),
        "range_evidence_acceptance_real_independent_verifier_count": evidence_acceptance.get("real_independent_verifier_count"),
        "range_evidence_acceptance_resolution_counts": evidence_acceptance.get("resolution_counts"),
        "range_evidence_acceptance_accepted_control_count": evidence_acceptance.get("accepted_control_count"),
        "range_evidence_completion_status": evidence_completion.get("status"),
        "range_evidence_completion_policy_signer_count": evidence_completion.get("completion_policy_signer_count"),
        "range_evidence_completion_authorization_signer_count": evidence_completion.get("completion_authorization_signer_count"),
        "range_evidence_completion_authorized": evidence_completion.get("completion_authorized"),
        "range_evidence_completion_evidence_complete": evidence_completion.get("evidence_complete"),
        "public_sacrificial_corpus_status": public_corpus.get("status"),
        "public_sacrificial_corpus_pinned_source_count": public_corpus.get("pinned_source_count"),
        "public_sacrificial_corpus_replica_ready_count": public_corpus.get("replica_ready_count"),
        "public_sacrificial_corpus_owner_registry_complete": public_corpus.get("owner_exclusion_registry_complete"),
        "public_sacrificial_corpus_public_target_authorized": public_corpus.get("public_host_target_authorized"),
        "source_staging_gate_status": source_staging.get("status"),
        "source_staging_gate_verified_signer_count": source_staging.get("verified_signer_count"),
        "source_staging_gate_staged_source_count": source_staging.get("staged_source_count"),
        "source_staging_gate_quarantine_completed_count": source_staging.get("quarantine_completed_count"),
        "source_staging_gate_staging_authorized": source_staging.get("staging_authorized"),
        "construction_zone_preflight_status": construction_preflight.get("status"),
        "construction_zone_control_count": construction_preflight.get("zone_control_count"),
        "construction_zone_verified_control_count": construction_preflight.get("verified_zone_control_count"),
        "construction_zone_quarantine_requirement_count": construction_preflight.get("quarantine_requirement_count"),
        "construction_zone_verified_quarantine_requirement_count": construction_preflight.get(
            "verified_quarantine_requirement_count"
        ),
        "construction_zone_provisioned": construction_preflight.get("construction_zone_provisioned"),
        "construction_zone_provisioning_gate_status": provisioning_gate.get("status"),
        "construction_zone_provisioning_signer_count": provisioning_gate.get("verified_signer_count"),
        "construction_zone_assigned_collector_count": provisioning_gate.get("assigned_collector_count"),
        "construction_zone_assigned_verifier_count": provisioning_gate.get("assigned_verifier_count"),
        "construction_zone_provisioning_verified_control_count": provisioning_gate.get("verified_control_count"),
        "construction_zone_operator_approval_present": provisioning_gate.get("operator_approval_present"),
        "construction_zone_provider_selected": provisioning_gate.get("provider_selected"),
        "construction_zone_provisioning_authorized": provisioning_gate.get("provisioning_authorized"),
        "construction_zone_provisioning_performed": provisioning_gate.get("provisioning_performed"),
        "signed_ingress_status": ingress.get("status"),
        "signed_ingress_sequence": ingress.get("sequence"),
        "signed_ingress_projection_bound": True,
        "signed_ingress_replay_guard": True,
        "signed_ingress_stale_state_guard": True,
        "execution_authorized": False,
        "live_execution_performed": False,
        "responsive_breakpoint_count": css.count("@media"),
        "keyboard_accessibility_checks": 2,
    }


def main() -> None:
    project_root = Path(__file__).resolve().parent.parent
    result = validate_control_board(project_root)
    report_path = project_root / "reports" / "CONTROL_BOARD_VALIDATION.json"
    report_path.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n"
    )
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
