"use strict";

const stateUrl = "demo-state.json";
const edgeStateUrl = "../specs/examples/edge-preview-result.example.json";
const worldModelStateUrl = "../specs/examples/world-model-generation.example.json";
const worldIntakeStateUrl = "../reports/CACIS_WORLD_INTAKE_VALIDATION.json";
const worldIntakeGovernanceStateUrl = "../reports/CACIS_WORLD_INTAKE_GOVERNANCE_VALIDATION.json";
const immuneRuntimeStateUrl = "../specs/examples/immune-organism-lifecycle-receipt.example.json";
const intelligenceResearchStateUrl = "../specs/examples/intelligence-research-settlement.example.json";
const homeostasisChronosStateUrl = "../specs/examples/homeostasis-chronos-receipt.example.json";
const genomeEvaluationStateUrl = "../reports/CACIS_GENOME_EVALUATION_VALIDATION.json";
const arenasObservatoryStateUrl = "../reports/CACIS_ARENAS_OBSERVATORY_VALIDATION.json";
const contractConformanceStateUrl = "../reports/CONTRACT_CONFORMANCE_MATRIX.json";
const verifierIdentityReadinessStateUrl = "../reports/VERIFIER_IDENTITY_READINESS_VALIDATION.json";
const autonomousPromotionStateUrl = "../reports/AUTONOMOUS_PROMOTION_VALIDATION.json";
const completionAuditStateUrl = "../reports/COMPLETION_AUDIT.json";

function escapeHtml(value) {
  const element = document.createElement("span");
  element.textContent = String(value);
  return element.innerHTML;
}

function setText(id, value) {
  const element = document.getElementById(id);
  if (element === null) {
    throw new Error(`Missing required UI element #${id}.`);
  }
  element.textContent = String(value);
}

function renderCells(cells) {
  const root = document.getElementById("cell-stack");
  if (root === null) {
    throw new Error("Missing swarm cell stack.");
  }
  root.innerHTML = cells.map((cell) => `
    <article class="cell-card" data-search="${escapeHtml(`${cell.role} ${cell.stance} ${cell.lens}`.toLowerCase())}" style="--cell-color:${escapeHtml(cell.color)}">
      <span class="cell-signal" aria-hidden="true"></span>
      <div>
        <strong class="cell-role">${escapeHtml(cell.role)}</strong>
        <span class="cell-lens">${escapeHtml(cell.lens)}</span>
      </div>
      <span class="cell-stance">${escapeHtml(cell.stance)}</span>
    </article>
  `).join("");
}

function renderCausalMap(nodes) {
  const root = document.getElementById("causal-map");
  if (root === null) {
    throw new Error("Missing causal map.");
  }
  root.innerHTML = nodes.map((node) => `
    <article class="causal-node${node.gap ? " gap" : ""}" style="--node-color:${escapeHtml(node.color)}">
      <span class="node-index">${escapeHtml(node.index)}</span>
      <h3>${escapeHtml(node.name)}</h3>
      <p>${escapeHtml(node.detail)}</p>
      <span class="node-state">${escapeHtml(node.state)}</span>
    </article>
  `).join("");
}

function renderTruthBraid(rows) {
  const root = document.getElementById("truth-braid");
  if (root === null) {
    throw new Error("Missing truth braid.");
  }
  root.innerHTML = rows.map((row) => {
    const fill = row.maximum === 0 ? 0 : Math.round((row.value / row.maximum) * 100);
    return `
      <div class="braid-row">
        <span>${escapeHtml(row.label)}</span>
        <div class="braid-track"><div class="braid-fill" style="--fill:${fill}%;--braid-color:${escapeHtml(row.color)}"></div></div>
        <span class="braid-value">${escapeHtml(`${row.value}/${row.maximum}`)}</span>
      </div>
    `;
  }).join("");
}

function renderDissent(items) {
  const root = document.getElementById("dissent-list");
  if (root === null) {
    throw new Error("Missing dissent list.");
  }
  root.innerHTML = items.map((item) => `
    <article class="dissent-item">
      <strong>${escapeHtml(item.role)}</strong>
      <p>${escapeHtml(item.claim)}</p>
    </article>
  `).join("");
  setText("dissent-count", items.length);
}

function renderLedger(items) {
  const root = document.getElementById("ledger");
  if (root === null) {
    throw new Error("Missing truth ledger.");
  }
  root.innerHTML = items.map((item) => `
    <div class="ledger-row">
      <span>${escapeHtml(item.time)}</span>
      <span class="ledger-class-${escapeHtml(item.class)}">${escapeHtml(item.class)}</span>
      <span>${escapeHtml(item.claim)}</span>
      <span>${escapeHtml(`${item.source} / ${item.freshness}`)}</span>
    </div>
  `).join("");
}

function renderSwarmMatrix(cells) {
  const root = document.getElementById("swarm-matrix");
  if (root === null) {
    throw new Error("Missing swarm matrix.");
  }
  root.innerHTML = cells.map((cell) => `
    <article class="matrix-cell" style="--cell-color:${escapeHtml(cell.color)}">
      <h3>${escapeHtml(cell.role)} // ${escapeHtml(cell.stance)}</h3>
      <p>${escapeHtml(cell.lens)}</p>
      <span class="matrix-rule">proposal only</span>
      <span class="matrix-rule">no self-authorization</span>
    </article>
  `).join("");
}

function renderWorldModel(worldModelDocument, worldIntakeState, worldIntakeGovernanceState) {
  const root = document.getElementById("cacis-world-grid");
  if (root === null) {
    throw new Error("Missing CACIS world-model grid.");
  }
  const generation = worldModelDocument.generation;
  const descriptions = {
    identity: "Trust, privilege, delegation, secrets, lateral potential",
    endpoint: "Processes, services, memory, persistence, integrity",
    network: "Flows, routes, DNS, TLS, segmentation, attribution",
    cloud: "IAM, compute, storage, containers, secrets, supply chain",
    threat: "Competing benign, malicious, novel, and deceptive hypotheses",
    recovery: "Containment, restore integrity, residual risk, confidence",
  };
  root.innerHTML = generation.domains.map((domain, index) => `
    <article class="world-state-${escapeHtml(domain.knowledge_state)}">
      <span>${escapeHtml(String(index + 1).padStart(2, "0"))}</span>
      <h3>${escapeHtml(domain.domain)}</h3>
      <p>${escapeHtml(descriptions[domain.domain] ?? "Typed derived state")}</p>
      <strong>${escapeHtml(domain.knowledge_state)} // ${escapeHtml(domain.facts.length)} facts // ${escapeHtml(domain.missing_requirements.length)} missing</strong>
    </article>
  `).join("");
  setText("world-model-state", "W1 succession replay // display only");
  setText("world-generation", String(worldModelDocument.generation_digest).slice(0, 19) + "…");
  setText("world-observations", generation.replay.observation_count);
  setText("world-generations", worldIntakeState.world_generation_count);
  setText("world-cursors", worldIntakeState.cursor_transition_count);
  setText("world-gaps", `${worldIntakeState.gap_source_count} sources // ${worldIntakeState.missing_record_count} records`);
  setText("world-intake-verifier", worldIntakeState.separate_process_causal_verification_performed ? "separate process // replay causal" : "not verified");
  setText("world-source-governance", `${worldIntakeGovernanceState.source_policy_verified_signer_count} signers // ${worldIntakeGovernanceState.source_policy_verified_role_count} roles`);
  setText("world-backpressure", `${worldIntakeGovernanceState.accepted_event_count} accepted // ${worldIntakeGovernanceState.deferred_event_count} deferred // ${worldIntakeGovernanceState.dropped_event_count} dropped`);
  setText("world-retention", `raw ${worldIntakeGovernanceState.raw_event_payload_retention_seconds}s // ${worldIntakeGovernanceState.retention_within_limits ? "within limits" : "blocked"}`);
  setText("world-source-health", `${worldIntakeGovernanceState.fresh_source_count} fresh // ${worldIntakeGovernanceState.source_gap_count} gap`);
}

function renderImmuneRuntime(immuneRuntimeDocument) {
  const receipt = immuneRuntimeDocument.receipt;
  const termination = receipt.termination;
  const retained = receipt.retained_knowledge.entries;
  const abstentions = receipt.contributions.filter((item) => item.status === "abstained");
  const eventRoot = document.getElementById("cacis-organism-events");
  if (eventRoot === null) {
    throw new Error("Missing CACIS organism lifecycle events.");
  }
  const visibleEvents = receipt.events.filter((event) => ["spawned", "shadow_paused", "shadow_resumed", "abstained", "terminated", "leases_revoked", "disposed"].includes(event.event_type));
  eventRoot.innerHTML = visibleEvents.map((event) => `<span>${escapeHtml(event.event_type.replaceAll("_", " "))}</span>`).join("");
  setText("organism-state", `${termination.lifecycle_state} // replay only`);
  setText("organism-ceiling", `${receipt.terminal_reason.replaceAll("_", " ")} // proposal only`);
  setText("organism-cells", receipt.cell_count);
  setText("organism-events", receipt.events.length);
  setText("organism-contributions", receipt.contributions.length);
  setText("organism-abstentions", abstentions.length);
  setText("organism-retained", `${retained.length} candidate only`);
  setText("organism-verification", receipt.independent_verification.status.replaceAll("_", " "));
}

function renderIntelligenceResearch(researchDocument) {
  const settlement = researchDocument.settlement;
  const aggregate = settlement.aggregate_comparison;
  const metacognition = settlement.metacognition;
  const verifier = settlement.independent_verification;
  const theory = settlement.candidate_theory;
  const root = document.getElementById("research-hypothesis-grid");
  if (root === null) {
    throw new Error("Missing intelligence research hypothesis grid.");
  }
  root.innerHTML = settlement.hypotheses.map((hypothesis) => `
    <article class="research-hypothesis-card">
      <strong>${escapeHtml(hypothesis.kind)}</strong>
      <p>${escapeHtml(hypothesis.status.replaceAll("_", " "))}</p>
      <span>${escapeHtml(`${hypothesis.counter_evidence_ids.length} counter-evidence links`)}</span>
    </article>
  `).join("");
  setText("research-question", settlement.research_question);
  setText("research-state", metacognition.knowledge_state.replaceAll("_", " "));
  setText("research-ceiling", "candidate theory // no promotion");
  setText("research-hypotheses", settlement.hypotheses.length);
  setText("research-cases", new Set(settlement.method_results.map((result) => result.case_id)).size);
  setText("research-results", settlement.method_results.length);
  setText("research-challenges", settlement.challenge_log.length);
  setText("research-coverage", Number(aggregate.mean_required_operation_coverage_delta).toFixed(6));
  setText("research-verifier", verifier.production_independence_verified ? "production independent" : "logical replay only");
  setText("research-theory", theory.status.replaceAll("_", " "));
}

function renderHomeostasisChronos(homeostasisDocument) {
  const receipt = homeostasisDocument.receipt;
  const health = receipt.homeostasis;
  const signalRoot = document.getElementById("homeostasis-signal-grid");
  const decisionRoot = document.getElementById("chronos-decision-grid");
  if (signalRoot === null || decisionRoot === null) {
    throw new Error("Missing Homeostasis or Chronos projection grid.");
  }
  signalRoot.innerHTML = receipt.signal_assessments.map((signal) => `
    <article class="homeostasis-signal signal-${escapeHtml(signal.state)}">
      <strong>${escapeHtml(signal.signal.replaceAll("_", " "))}</strong>
      <span>${escapeHtml(`${signal.state} // ${Number(signal.observed).toFixed(2)} / ${Number(signal.threshold).toFixed(2)}`)}</span>
    </article>
  `).join("");
  decisionRoot.innerHTML = receipt.allocation_decisions.map((decision) => `
    <article class="chronos-decision decision-${escapeHtml(decision.action)}">
      <strong>${escapeHtml(decision.work_kind.replaceAll("_", " "))}</strong>
      <span>${escapeHtml(`${decision.action} // ${decision.clock_state} // ${Number(decision.priority_score).toFixed(3)}`)}</span>
      <span>${escapeHtml(decision.reason.replaceAll("_", " "))}</span>
    </article>
  `).join("");
  setText("homeostasis-ceiling", "replay schedule // no authorization");
  setText("homeostasis-state", health.state.replaceAll("_", " "));
  setText("homeostasis-breaches", `${health.breach_count} / ${receipt.signal_assessments.length}`);
  setText("homeostasis-pressure", Number(health.pressure_index).toFixed(2));
  setText("homeostasis-confidence", Number(health.confidence_inflation).toFixed(2));
  setText("homeostasis-backlog", Number(health.verification_backlog).toFixed(2));
  setText("homeostasis-scheduled", health.scheduled_count);
  setText("homeostasis-deferred", health.deferred_count);
  setText("homeostasis-abstained", health.abstained_count);
}

function renderGenomeAndArenas(genomeState, arenaState) {
  setText("genome-state", genomeState.candidate_status.replaceAll("_", " "));
  setText("genome-strata", genomeState.memory_stratum_count);
  setText("genome-partitions", genomeState.evaluation_partition_count);
  setText("genome-reward-defenses", genomeState.reward_hacking_defense_count);
  setText("genome-complexity", genomeState.complexity_metric_count);
  setText("arena-count", arenaState.arena_count);
  setText("arena-evaluated", arenaState.evaluated_arena_count);
  setText("arena-blocked", arenaState.blocked_live_gate_count);
  setText("arena-dimensions", arenaState.benchmark_dimension_count);
  setText("observatory-signers", `${arenaState.verified_signer_count} / ${arenaState.verified_role_count} roles`);
  setText("observatory-mode", arenaState.display_only ? "threshold signed // display only" : "invalid authority state");
}

function renderContractConformance(conformanceState) {
  setText("contract-count", conformanceState.contract_count);
  setText("contract-semantic", conformanceState.semantic_validator_count);
  setText("contract-runtime-refs", conformanceState.runtime_reference_count);
  setText("contract-harness-refs", conformanceState.independent_harness_reference_count);
  setText("contract-live-evidence", `${conformanceState.live_runtime_evidence_count} // blocked`);
}

function renderVerifierIdentityReadiness(readinessState) {
  setText("verifier-identity-surfaces", `${readinessState.distinct_process_observed_count} / ${readinessState.surface_count} distinct processes`);
  setText("verifier-dedicated-accounts", `${readinessState.dedicated_os_account_verified_count} / ${readinessState.surface_count} verified`);
  setText("verifier-readonly-acls", `${readinessState.read_only_input_acl_verified_count} / ${readinessState.surface_count} verified`);
  setText("verifier-production-custody", `${readinessState.production_signing_custody_verified_count} / ${readinessState.surface_count} verified`);
}

function renderAutonomousPromotion(promotionState) {
  setText("promotion-state", promotionState.autonomous_promotion_standard ? "autonomous threshold // shadow only" : "blocked");
  setText("promotion-tiers", promotionState.eligible_tiers.join(" / "));
  setText("promotion-threshold", `${promotionState.threshold_signer_count} signers // ${promotionState.threshold_role_count} roles`);
  setText("promotion-evaluators", `${promotionState.independent_evaluator_count} independent`);
  setText("promotion-human", promotionState.human_approval_required_for_eligible_tiers ? "required" : "not required // A/B");
  setText("promotion-demotion", `${promotionState.automatic_regression_demotion_count} regression proof`);
  setText("promotion-production", promotionState.production_promotion_authorized ? "authorized" : "blocked");
}

function renderCompletionAudit(auditState) {
  setText("completion-local-gates", `${auditState.local_gate_complete_count} / ${auditState.local_gate_count} complete`);
  setText("completion-external-gates", `${auditState.external_gate_blocked_count} / ${auditState.external_gate_count} blocked`);
  setText("completion-product-state", auditState.deployable_product_claimed ? "deployable" : "foundation only // not deployable");
}

function renderVerifierConsensus(verifier) {
  const root = document.getElementById("verifier-consensus");
  const pill = document.getElementById("verifier-pill");
  const footer = document.getElementById("footer-verifier-state");
  if (root === null || pill === null || footer === null) {
    throw new Error("Missing verifier consensus surfaces.");
  }
  const verified = verifier.boundary.production_ready === true;
  root.classList.toggle("verified", verified);
  root.classList.toggle("blocked", !verified);
  root.innerHTML = `
    <div>
      <p class="eyebrow">consensus state</p>
      <strong>${escapeHtml(verifier.consensus.state)}</strong>
      <p>${escapeHtml(verifier.summary)}</p>
    </div>
    <dl>
      <div><dt>accepted</dt><dd>${escapeHtml(verifier.consensus.verification_accepted)}</dd></div>
      <div><dt>operator state</dt><dd>${escapeHtml(verifier.operator_state)}</dd></div>
      <div><dt>observed</dt><dd>${escapeHtml(verifier.consensus.observed_at)}</dd></div>
    </dl>
  `;
  pill.textContent = verified ? "verifier // accepted" : `verifier // ${verifier.operator_state}`;
  pill.classList.toggle("state-verifier-verified", verified);
  pill.classList.toggle("state-verifier-blocked", !verified);
  footer.textContent = verifier.operator_state;
  footer.classList.toggle("denied", !verified);
  footer.classList.toggle("verified-text", verified);
}

function renderBoardIngress(ingress) {
  const root = document.getElementById("board-ingress");
  const pill = document.getElementById("ingress-pill");
  const footer = document.getElementById("footer-ingress-state");
  if (root === null || pill === null || footer === null) {
    throw new Error("Missing signed board-ingress surfaces.");
  }
  const accepted = ingress.status === "accepted"
    && ingress.durable_replay_guard === true
    && ingress.stale_state_guard === true;
  root.classList.toggle("accepted", accepted);
  root.classList.toggle("blocked", !accepted);
  root.innerHTML = `
    <div class="ingress-heading">
      <div>
        <p class="eyebrow">signed supervisor snapshot</p>
        <strong>${escapeHtml(ingress.status)} // sequence ${escapeHtml(ingress.sequence)}</strong>
      </div>
      <span>${escapeHtml(ingress.origin)} evidence</span>
    </div>
    <dl class="ingress-facts">
      <div><dt>issuer</dt><dd>${escapeHtml(ingress.issuer_service_id)}</dd></div>
      <div><dt>audience</dt><dd>${escapeHtml(ingress.audience)}</dd></div>
      <div><dt>freshness</dt><dd>${escapeHtml(ingress.freshness_seconds)}s</dd></div>
      <div><dt>threshold</dt><dd>${escapeHtml(ingress.verified_signer_ids.length)} signers / ${escapeHtml(ingress.verified_roles.length)} roles</dd></div>
      <div><dt>replay guard</dt><dd>${escapeHtml(ingress.durable_replay_guard)}</dd></div>
      <div><dt>stale guard</dt><dd>${escapeHtml(ingress.stale_state_guard)}</dd></div>
    </dl>
    <code title="${escapeHtml(ingress.snapshot_digest)}">${escapeHtml(ingress.snapshot_digest)}</code>
  `;
  pill.textContent = accepted ? "transport // signed + fresh" : "transport // blocked";
  pill.classList.toggle("state-ingress", accepted);
  pill.classList.toggle("state-verifier-blocked", !accepted);
  footer.textContent = accepted ? "signed + fresh" : "blocked";
  footer.classList.toggle("verified-text", accepted);
  footer.classList.toggle("denied", !accepted);
}

function renderVerifierHealth(health) {
  const root = document.getElementById("verifier-health");
  if (root === null) {
    throw new Error("Missing verifier health surface.");
  }
  root.innerHTML = health.map((service) => `
    <article class="verifier-service-card${service.production_ready ? " verified" : " blocked"}">
      <div class="verifier-service-heading">
        <strong>${escapeHtml(service.service_id)}</strong>
        <span>${escapeHtml(service.status)}</span>
      </div>
      <dl>
        <div><dt>principal</dt><dd title="${escapeHtml(service.logical_principal)}">${escapeHtml(service.logical_principal)}</dd></div>
        <div><dt>process</dt><dd>${escapeHtml(service.process_id)}</dd></div>
        <div><dt>OS account</dt><dd title="${escapeHtml(service.os_account_identifier)}">${escapeHtml(service.os_account_identifier)}</dd></div>
        <div><dt>identity boundary</dt><dd>${escapeHtml(service.os_account_boundary_verified)}</dd></div>
      </dl>
    </article>
  `).join("");
}

function renderVerifierBoundary(boundary) {
  const root = document.getElementById("verifier-boundary");
  if (root === null) {
    throw new Error("Missing verifier boundary surface.");
  }
  const controls = [
    ["health complete", boundary.health_complete],
    ["dedicated OS identity", boundary.dedicated_os_identity_verified],
    ["read-only ACL", boundary.os_read_only_acl_verified],
    ["production ready", boundary.production_ready]
  ];
  root.innerHTML = controls.map(([label, value]) => `
    <div class="boundary-row">
      <span>${escapeHtml(label)}</span>
      <strong class="${value ? "verified-text" : "denied"}">${escapeHtml(value)}</strong>
    </div>
  `).join("");
}

function renderVerifierObservations(observations) {
  const root = document.getElementById("verifier-observations");
  if (root === null) {
    throw new Error("Missing verifier observation surface.");
  }
  root.innerHTML = observations.map((observation) => `
    <article class="verifier-observation status-${escapeHtml(observation.status)}">
      <span>${escapeHtml(observation.service_id)}</span>
      <strong>${escapeHtml(observation.status)}</strong>
      <code title="${escapeHtml(observation.subject_digest)}">${escapeHtml(observation.subject_digest)}</code>
      <span>${escapeHtml(observation.observed_at)}</span>
      <p>${escapeHtml(observation.detail)}</p>
    </article>
  `).join("");
}

function renderVerifierDissent(items) {
  const root = document.getElementById("verifier-dissent");
  if (root === null) {
    throw new Error("Missing verifier dissent surface.");
  }
  root.innerHTML = items.map((item) => `
    <article class="verifier-blocker">
      <strong>${escapeHtml(item.code)}</strong>
      <span>${escapeHtml(item.source)}</span>
      <p>${escapeHtml(item.message)}</p>
    </article>
  `).join("");
  setText("verifier-dissent-count", items.length);
}

function renderVerifierGate(verifier, ingress) {
  const root = document.getElementById("verifier-gate-facts");
  const seal = document.getElementById("verifier-gate-state");
  if (root === null || seal === null) {
    throw new Error("Missing verifier authority gate.");
  }
  const ingressAccepted = ingress.status === "accepted"
    && ingress.durable_replay_guard === true
    && ingress.stale_state_guard === true;
  const accepted = verifier.authority.may_mark_verification_accepted === true && ingressAccepted;
  const facts = [
    ["signed ingress", ingress.status === "accepted"],
    ["replay guard", ingress.durable_replay_guard],
    ["stale guard", ingress.stale_state_guard],
    ["consensus", verifier.consensus.state],
    ["health", verifier.boundary.health_complete],
    ["OS identity", verifier.boundary.dedicated_os_identity_verified],
    ["read-only ACL", verifier.boundary.os_read_only_acl_verified],
    ["mark accepted", accepted],
    ["authorize", verifier.authority.can_authorize],
    ["execute", verifier.authority.can_execute]
  ];
  root.innerHTML = facts.map(([label, value]) => `
    <div><dt>${escapeHtml(label)}</dt><dd class="${value === true ? "verified-text" : "denied"}">${escapeHtml(value)}</dd></div>
  `).join("");
  seal.textContent = accepted ? "accepted" : "blocked";
  seal.classList.toggle("verified-seal", accepted);
  seal.classList.toggle("blocked-seal", !accepted);
}

function renderVerifier(verifier, ingress) {
  renderBoardIngress(ingress);
  renderVerifierConsensus(verifier);
  renderVerifierHealth(verifier.service_health);
  renderVerifierBoundary(verifier.boundary);
  renderVerifierObservations(verifier.observations);
  renderVerifierDissent(verifier.dissent);
  renderVerifierGate(verifier, ingress);
}

function renderRangeGate(rangeGate) {
  const summary = document.getElementById("range-gate-summary");
  const stages = document.getElementById("range-gate-stages");
  const attestations = document.getElementById("range-gate-attestations");
  const authority = document.getElementById("range-gate-authority");
  if (summary === null || stages === null || attestations === null || authority === null) {
    throw new Error("Missing range execution-gate surfaces.");
  }
  summary.innerHTML = `
    <div>
      <p class="eyebrow">terminal state</p>
      <strong title="${escapeHtml(rangeGate.status)}">provisioning denied // zero attestors assigned // zero controls verified</strong>
      <p>Two governance roles signed the provisioning denial. No provider or operator approval exists, and every isolation control still requires separate live collectors and verifiers.</p>
    </div>
    <dl>
      <div><dt>origin</dt><dd>${escapeHtml(rangeGate.origin)}</dd></div>
      <div><dt>target bindings</dt><dd>${escapeHtml(rangeGate.scope_target_binding_count)}</dd></div>
      <div><dt>sources requested</dt><dd>${escapeHtml(rangeGate.source_staging_gate.requested_source_count)}</dd></div>
      <div><dt>sources staged</dt><dd class="denied">${escapeHtml(rangeGate.source_staging_gate.staged_source_count)}</dd></div>
    </dl>
  `;
  const stageRows = [
    ["01", "connector", rangeGate.connector_manifest_status, `${rangeGate.connector_verified_signer_count} threshold signers / ${rangeGate.connector_operation_count} non-executing operations`],
    ["02", "scope compiler", rangeGate.scope_status, `${rangeGate.scope_target_binding_count} exact target / authorization ${rangeGate.cryptographic_authorization_verified}`],
    ["03", "evidence admission", rangeGate.evidence_admission.collector_policy_status, `${rangeGate.evidence_admission.distinct_collector_count} signed collectors / ${rangeGate.evidence_admission.content_addressed_observation_count} retained fixtures`],
    ["04", "independent acceptance", rangeGate.evidence_acceptance.verifier_policy_status, `${rangeGate.evidence_acceptance.verified_decision_count} signed decisions / ${rangeGate.evidence_acceptance.real_independent_verifier_count} real independent verifiers`],
    ["05", "evidence completion", rangeGate.evidence_completion.completion_authorization_status, `${rangeGate.evidence_completion.completion_authorization_signer_count} threshold signers / completion ${rangeGate.evidence_completion.evidence_complete}`],
    ["06", "public source corpus", rangeGate.public_sacrificial_corpus.status, `${rangeGate.public_sacrificial_corpus.pinned_source_count} pinned / ${rangeGate.public_sacrificial_corpus.replica_ready_count} replicas ready / unknown ownership ${rangeGate.public_sacrificial_corpus.unknown_ownership_action}`],
    ["07", "source staging gate", rangeGate.source_staging_gate.status, `${rangeGate.source_staging_gate.verified_signer_count} signers / ${rangeGate.source_staging_gate.staged_source_count} staged / ${rangeGate.source_staging_gate.quarantine_completed_count} of ${rangeGate.source_staging_gate.quarantine_requirement_count} quarantine controls complete`],
    ["08", "construction zone preflight", rangeGate.construction_zone_preflight.status, `${rangeGate.construction_zone_preflight.verified_zone_control_count} of ${rangeGate.construction_zone_preflight.zone_control_count} isolation controls verified / ${rangeGate.construction_zone_preflight.verified_quarantine_requirement_count} of ${rangeGate.construction_zone_preflight.quarantine_requirement_count} quarantine requirements evidenced`],
    ["09", "provisioning authorization", rangeGate.construction_zone_provisioning_gate.status, `${rangeGate.construction_zone_provisioning_gate.verified_signer_count} signers / ${rangeGate.construction_zone_provisioning_gate.assigned_collector_count} collectors / ${rangeGate.construction_zone_provisioning_gate.assigned_verifier_count} verifiers assigned`]
  ];
  stages.innerHTML = stageRows.map(([index, label, status, detail]) => `
    <article class="range-gate-stage">
      <span>${escapeHtml(index)}</span>
      <h3>${escapeHtml(label)}</h3>
      <strong>${escapeHtml(status)}</strong>
      <p>${escapeHtml(detail)}</p>
    </article>
  `).join("");
  attestations.innerHTML = rangeGate.required_attestation_controls.map((control) => `
    <div class="range-attestation">
      <span>${escapeHtml(control)}</span>
      <strong>not accepted / completion denied</strong>
    </div>
  `).join("");
  authority.innerHTML = Object.entries({
    ...rangeGate.activity,
    ...rangeGate.authority,
    ...rangeGate.evidence_admission.activity,
    ...rangeGate.evidence_admission.authority,
    ...rangeGate.evidence_acceptance.activity,
    ...rangeGate.evidence_acceptance.authority,
    ...rangeGate.evidence_completion.activity,
    ...rangeGate.evidence_completion.authority,
    ...rangeGate.public_sacrificial_corpus.activity,
    ...rangeGate.public_sacrificial_corpus.authority,
    ...rangeGate.source_staging_gate.activity,
    ...rangeGate.source_staging_gate.authority,
    ...rangeGate.construction_zone_preflight.activity,
    ...rangeGate.construction_zone_preflight.authority,
    ...rangeGate.construction_zone_provisioning_gate.activity,
    ...rangeGate.construction_zone_provisioning_gate.authority
  }).map(([label, value]) => `
    <div class="boundary-row">
      <span>${escapeHtml(label.replaceAll("_", " "))}</span>
      <strong class="denied">${escapeHtml(value)}</strong>
    </div>
  `).join("");
}

function renderFoundrySummary(foundry) {
  const root = document.getElementById("foundry-summary");
  if (root === null) {
    throw new Error("Missing Foundry summary surface.");
  }
  const eligible = foundry.boundary.shadow_eligible === true;
  root.classList.toggle("eligible", eligible);
  root.classList.toggle("blocked", !eligible);
  root.innerHTML = `
    <div>
      <p class="eyebrow">operator state</p>
      <strong>${escapeHtml(foundry.operator_state)}</strong>
      <p>${escapeHtml(foundry.summary)}</p>
    </div>
    <dl>
      <div><dt>origin</dt><dd>${escapeHtml(foundry.origin)}</dd></div>
      <div><dt>shadow eligible</dt><dd>${escapeHtml(foundry.boundary.shadow_eligible)}</dd></div>
      <div><dt>production ready</dt><dd class="denied">${escapeHtml(foundry.boundary.production_ready)}</dd></div>
    </dl>
  `;
}

function renderFoundryEvaluators(evaluators) {
  const root = document.getElementById("foundry-evaluators");
  if (root === null) {
    throw new Error("Missing Foundry evaluator surface.");
  }
  root.innerHTML = evaluators.map((evaluator) => `
    <article class="foundry-evaluator-card">
      <div>
        <strong>${escapeHtml(evaluator.role)}</strong>
        <span>${escapeHtml(evaluator.status)}</span>
      </div>
      <dl>
        <div><dt>signature</dt><dd class="verified-text">${escapeHtml(evaluator.signature_verified)}</dd></div>
        <div><dt>OS contract</dt><dd class="verified-text">${escapeHtml(evaluator.isolation_boundary_verified)}</dd></div>
        <div><dt>live enforcement</dt><dd class="${evaluator.production_isolation_verified ? "verified-text" : "denied"}">${escapeHtml(evaluator.production_isolation_verified)}</dd></div>
        <div><dt>process</dt><dd>${escapeHtml(evaluator.process_id)}</dd></div>
      </dl>
      <code title="${escapeHtml(evaluator.envelope_digest)}">${escapeHtml(evaluator.envelope_digest)}</code>
    </article>
  `).join("");
}

function renderFoundryResources(resourceLineage) {
  const root = document.getElementById("foundry-resource-ledger");
  if (root === null) {
    throw new Error("Missing Foundry resource-ledger surface.");
  }
  const totals = resourceLineage.totals;
  const rows = [
    ["candidate lineage", resourceLineage.entry_count, "entries"],
    ["cycle time", totals.total_cycle_seconds, "seconds"],
    ["compute", totals.total_compute_units, "units"],
    ["peak memory", totals.peak_memory_megabytes, "MiB"],
    ["peak storage", totals.peak_storage_megabytes, "MiB"]
  ];
  root.innerHTML = `
    <div class="resource-ledger-heading">
      <span>${escapeHtml(resourceLineage.status)}</span>
      <code title="${escapeHtml(resourceLineage.head_entry_digest)}">${escapeHtml(resourceLineage.head_entry_digest)}</code>
    </div>
    <div class="resource-meter-grid">
      ${rows.map(([label, value, unit]) => `
        <div><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong><small>${escapeHtml(unit)}</small></div>
      `).join("")}
    </div>
  `;
}

function renderFoundryBoundary(boundary) {
  const root = document.getElementById("foundry-boundary");
  if (root === null) {
    throw new Error("Missing Foundry boundary surface.");
  }
  const controls = [
    ["signed evaluators", boundary.signed_evaluators_complete],
    ["OS isolation contract", boundary.os_isolation_contract_complete],
    ["live OS enforcement", boundary.live_os_enforcement_verified],
    ["resource lineage", boundary.resource_ledger_within_constitution],
    ["shadow eligible", boundary.shadow_eligible],
    ["production ready", boundary.production_ready]
  ];
  root.innerHTML = controls.map(([label, value]) => `
    <div class="boundary-row">
      <span>${escapeHtml(label)}</span>
      <strong class="${value ? "verified-text" : "denied"}">${escapeHtml(value)}</strong>
    </div>
  `).join("") + `
    <div class="foundry-blockers">
      ${boundary.missing_controls.map((control) => `<span>${escapeHtml(control)}</span>`).join("")}
    </div>
  `;
}

function renderPlatformAssurance(platformAssurance) {
  const root = document.getElementById("platform-assurance");
  if (root === null) {
    throw new Error("Missing platform-assurance surface.");
  }
  const isolation = platformAssurance.windows_isolation;
  const evaluator = platformAssurance.independent_evaluator;
  const meter = platformAssurance.resource_meter;
  const custody = platformAssurance.custody_readiness;
  const cards = [
    {
      eyebrow: "windows isolation",
      title: `${isolation.verified_control_count} / ${isolation.control_count} controls verified`,
      state: isolation.boundary_verified,
      facts: [
        ["origin", isolation.origin],
        ["signed", isolation.signed_attestation_verified],
        ["DACL rights", isolation.effective_acl_rights_computed],
        ["egress blocks", isolation.all_traffic_target_block_rule_count]
      ],
      blockers: isolation.blockers
    },
    {
      eyebrow: "independent evaluator",
      title: `${evaluator.implementation_language} / ${evaluator.runtime_cryptography}`,
      state: evaluator.shared_python_verification_logic === false,
      facts: [
        ["origin", evaluator.origin],
        ["adversarial", evaluator.adversarial_case_count],
        ["shared Python", evaluator.shared_python_verification_logic]
      ],
      blockers: []
    },
    {
      eyebrow: "windows resource meter",
      title: "Job Object lineage receipt",
      state: meter.job_object_assigned && meter.lineage_ledger_within_constitution,
      facts: [
        ["assigned before resume", meter.assigned_before_first_resume],
        ["abrupt recovery", meter.abrupt_process_crash_recovery_verified],
        ["write through", meter.write_through_publish_verified],
        ["power loss", meter.power_loss_durability_verified]
      ],
      blockers: meter.power_loss_durability_verified ? [] : ["PHYSICAL_POWER_LOSS_TEST_UNPROVEN"]
    },
    {
      eyebrow: "hardware custody",
      title: `${custody.provider_count} CNG providers observed`,
      state: custody.production_custody_verified,
      facts: [
        ["origin", custody.origin],
        ["platform provider", custody.platform_crypto_provider_present],
        ["TPM query", custody.tpm_management_query_succeeded],
        ["key created", custody.key_created]
      ],
      blockers: custody.blockers
    }
  ];
  root.innerHTML = cards.map((card) => `
    <article class="platform-assurance-card">
      <p class="eyebrow">${escapeHtml(card.eyebrow)}</p>
      <div class="platform-assurance-title">
        <strong>${escapeHtml(card.title)}</strong>
        <span class="${card.state ? "verified-text" : "denied"}">${escapeHtml(card.state ? "verified" : "blocked")}</span>
      </div>
      <dl>
        ${card.facts.map(([label, value]) => `<div><dt>${escapeHtml(label)}</dt><dd>${escapeHtml(value)}</dd></div>`).join("")}
      </dl>
      <div class="platform-assurance-blockers">
        ${card.blockers.map((blocker) => `<span>${escapeHtml(blocker)}</span>`).join("")}
      </div>
    </article>
  `).join("");
}

function renderFoundry(foundry, platformAssurance) {
  renderFoundrySummary(foundry);
  renderPlatformAssurance(platformAssurance);
  renderFoundryEvaluators(foundry.evaluator_mesh);
  renderFoundryResources(foundry.resource_lineage);
  renderFoundryBoundary(foundry.boundary);
}

function renderLeaseFacts(authorization) {
  const root = document.getElementById("lease-facts");
  if (root === null) {
    throw new Error("Missing lease facts.");
  }
  const facts = [
    ["lease", authorization.lease_id],
    ["policy", authorization.policy_id],
    ["algorithm", authorization.algorithm],
    ["expires", authorization.expires_at],
    ["nonce", authorization.nonce_state],
    ["kill", authorization.kill_switch]
  ];
  root.innerHTML = facts.map(([label, value]) => `
    <div><dt>${escapeHtml(label)}</dt><dd title="${escapeHtml(value)}">${escapeHtml(value)}</dd></div>
  `).join("");
}

function renderBudgets(budgets) {
  const root = document.getElementById("budget-list");
  if (root === null) {
    throw new Error("Missing budget list.");
  }
  root.innerHTML = budgets.map((budget) => {
    const fill = budget.maximum === 0 ? 0 : Math.min(100, Math.round((budget.used / budget.maximum) * 100));
    return `
      <div class="budget-row">
        <div class="budget-label"><span>${escapeHtml(budget.label)}</span><strong>${escapeHtml(`${budget.used} / ${budget.maximum}`)}</strong></div>
        <div class="budget-bar"><div class="budget-fill" style="width:${fill}%"></div></div>
      </div>
    `;
  }).join("");
}

function renderTarget(target) {
  setText("target-name", target.id);
  setText("target-class", target.environment);
  setText("effect-ceiling", target.effect_ceiling);
  const root = document.getElementById("prohibited-list");
  if (root === null) {
    throw new Error("Missing prohibited-effect list.");
  }
  root.innerHTML = target.prohibited.map((item) => `<li>${escapeHtml(item)}</li>`).join("");
}

function renderProof(proof) {
  const root = document.getElementById("proof-console");
  if (root === null) {
    throw new Error("Missing proof console.");
  }
  root.textContent = JSON.stringify(proof, null, 2);
}

function renderEdgePreview(edge) {
  const summary = document.getElementById("edge-summary");
  const flow = document.getElementById("edge-proof-flow");
  const explanation = document.getElementById("edge-explanation");
  const uncertainties = document.getElementById("edge-uncertainties");
  const references = document.getElementById("edge-references");
  if (summary === null || flow === null || explanation === null || uncertainties === null || references === null) {
    throw new Error("Missing Edge preview control-board elements.");
  }

  const verification = edge.independent_verification;
  summary.innerHTML = `
    <div>
      <p class="eyebrow">current replay verdict</p>
      <strong>${escapeHtml(edge.status)}</strong>
      <p>${escapeHtml(edge.security_claim)}</p>
    </div>
    <dl>
      <div><dt>risk</dt><dd>${escapeHtml(edge.risk.level)} // ${escapeHtml(edge.risk.confidence_interval.join("–"))}</dd></div>
      <div><dt>policy</dt><dd>${escapeHtml(edge.matched_rule_id)}</dd></div>
      <div><dt>verifier</dt><dd>${escapeHtml(verification.status)}</dd></div>
      <div><dt>outcome verified</dt><dd class="denied">${escapeHtml(verification.verified_outcome)}</dd></div>
      <div><dt>execution</dt><dd class="denied">${escapeHtml(edge.authority.can_execute)}</dd></div>
    </dl>
  `;

  const stages = [
    ["01", "replayed observation", edge.origin, "Offline fixture; no live endpoint sensor"],
    ["02", "deterministic policy", "challenge", "Budget 1 requires user confirmation"],
    ["03", "typed proposal", "proposal only", "Reversible per-process egress recommendation"],
    ["04", "independent verifier", "structure valid", "Distinct process; no execution surface"],
    ["05", "post-state", "unobserved", "No containment or recovery claim"],
  ];
  flow.innerHTML = stages.map(([index, title, state, detail]) => `
    <article class="edge-proof-stage">
      <span>${escapeHtml(index)}</span>
      <h3>${escapeHtml(title)}</h3>
      <strong>${escapeHtml(state)}</strong>
      <p>${escapeHtml(detail)}</p>
    </article>
  `).join("");

  explanation.innerHTML = edge.explanation.map((item, index) => `
    <div class="edge-evidence-line"><span>${escapeHtml(String(index + 1).padStart(2, "0"))}</span><p>${escapeHtml(item)}</p></div>
  `).join("");
  uncertainties.innerHTML = edge.uncertainties.map((item) => `
    <div class="edge-uncertainty"><strong>unresolved</strong><p>${escapeHtml(item)}</p></div>
  `).join("");
  references.innerHTML = Object.entries(edge.references).map(([name, reference]) => `
    <div><span>${escapeHtml(name.replaceAll("_", " "))}</span><strong>${escapeHtml(reference.id)}</strong><code>${escapeHtml(reference.digest)}</code></div>
  `).join("");
}

function renderEdgeAuthorityDeck(edge) {
  const threshold = document.getElementById("threshold-visual");
  const facts = document.getElementById("lease-facts");
  const budget = document.getElementById("budget-list");
  const gateFacts = document.getElementById("verifier-gate-facts");
  if (threshold === null || facts === null || budget === null || gateFacts === null) {
    throw new Error("Missing Edge authority-deck elements.");
  }
  threshold.hidden = true;
  setText("authority-kicker", "deterministic policy");
  setText("authority-title", "Budget 1 gate");
  setText("authority-seal", "proposal only");
  facts.innerHTML = [
    ["policy", edge.matched_rule_id],
    ["origin", edge.origin],
    ["decision", "challenge"],
    ["confirmation", "required"],
    ["execution", edge.authority.can_execute],
  ].map(([label, value]) => `<div><dt>${escapeHtml(label)}</dt><dd>${escapeHtml(value)}</dd></div>`).join("");
  setText("target-name", `scenario:${edge.scenario_id}`);
  setText("target-class", "replayed Windows process");
  setText("effect-ceiling", "proposal_only");
  const prohibited = document.getElementById("prohibited-list");
  if (prohibited === null) {
    throw new Error("Missing prohibited-list element.");
  }
  prohibited.innerHTML = ["endpoint mutation", "network policy change", "unverified recovery"]
    .map((item) => `<li>${escapeHtml(item)}</li>`).join("");
  budget.innerHTML = [
    ["autonomy", "1 / challenge"],
    ["targets", "0 live / 1 replayed"],
    ["actions", "0 executed"],
    ["witness", `${edge.witness.entry_count} verified`],
  ].map(([label, value]) => `
    <div class="budget-row">
      <div class="budget-label"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong></div>
      <div class="budget-bar"><div class="budget-fill" style="width:0%"></div></div>
    </div>
  `).join("");
  setText("verifier-gate-state", "unobserved");
  gateFacts.innerHTML = [
    ["distinct process", "true"],
    ["structure", "valid"],
    ["post-state", "unobserved"],
    ["outcome verified", edge.independent_verification.verified_outcome],
    ["recovery", edge.authority.recovery_verified],
  ].map(([label, value]) => `<div><dt>${escapeHtml(label)}</dt><dd>${escapeHtml(value)}</dd></div>`).join("");
}

function renderViewContext(viewName, state, edge) {
  const cryptoPill = document.getElementById("crypto-pill");
  if (cryptoPill === null) {
    throw new Error("Missing crypto-pill element.");
  }
  if (viewName === "edge") {
    setText("mode-pill", "replayed // budget 1");
    cryptoPill.innerHTML = `<span class="pulse-dot"></span>witness // ${escapeHtml(edge.witness.entry_count)} verified`;
    setText("ingress-pill", "policy // challenge");
    setText("verifier-pill", "verifier // post-state unobserved");
    setText("mission-code", "EDGE-RPL-001");
    setText("mission-title", "Review replayed process egress evidence without changing endpoint state");
    setText("mission-origin", "origin replayed");
    setText("mission-time", "window offline fixture");
    setText("role-diversity", "1 policy / 1 verifier");
    setText("footer-origin", "replayed");
    setText("footer-verdict", "challenge");
    setText("footer-ingress-state", "witnessed");
    setText("footer-verifier-state", "post_state_unobserved");
    setText("status-message", "Edge replay loaded. Proposal only; endpoint and recovery state remain unobserved.");
    renderEdgeAuthorityDeck(edge);
    return;
  }
  setText("mode-pill", "simulated // no execution");
  cryptoPill.innerHTML = '<span class="pulse-dot"></span>ed25519 2/2 verified';
  setText("mission-code", state.mission.code);
  setText("mission-title", state.mission.title);
  setText("mission-origin", `origin ${state.origin}`);
  setText("mission-time", `window ${state.mission.window}`);
  setText("role-diversity", `${state.cells.length} / ${state.cells.length}`);
  setText("footer-origin", state.origin);
  setText("footer-verdict", "proposal_ready");
  document.getElementById("threshold-visual").hidden = false;
  setText("authority-kicker", "authority threshold");
  setText("authority-title", "Lease proof");
  setText("authority-seal", "verified");
  renderBoardIngress(state.ingress);
  renderVerifierGate(state.verifier, state.ingress);
  renderLeaseFacts(state.authorization);
  renderTarget(state.target);
  renderBudgets(state.budgets);
}

function activateView(viewName, state, edge) {
  document.querySelectorAll(".tab").forEach((button) => {
    const active = button.dataset.view === viewName;
    button.classList.toggle("active", active);
    button.setAttribute("aria-selected", String(active));
  });
  document.querySelectorAll("[data-view-panel]").forEach((panel) => {
    const active = panel.dataset.viewPanel === viewName;
    panel.classList.toggle("active", active);
    panel.hidden = !active;
  });
  renderViewContext(viewName, state, edge);
}

function bindTabs(state, edge) {
  document.querySelectorAll(".tab").forEach((button) => {
    button.addEventListener("click", () => activateView(button.dataset.view, state, edge));
  });
}

function bindCellFilter() {
  const input = document.getElementById("cell-filter");
  if (!(input instanceof HTMLInputElement)) {
    throw new Error("Missing cell filter input.");
  }
  input.addEventListener("input", () => {
    const query = input.value.trim().toLowerCase();
    document.querySelectorAll(".cell-card").forEach((card) => {
      card.hidden = query.length > 0 && !String(card.dataset.search).includes(query);
    });
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "/" && document.activeElement !== input) {
      event.preventDefault();
      input.focus();
    }
  });
}

function bindKillSwitch() {
  const button = document.getElementById("kill-switch");
  const compile = document.getElementById("compile-proposal");
  if (!(button instanceof HTMLButtonElement) || !(compile instanceof HTMLButtonElement)) {
    throw new Error("Missing kill-switch controls.");
  }
  button.addEventListener("click", () => {
    const engaged = button.getAttribute("aria-pressed") !== "true";
    button.setAttribute("aria-pressed", String(engaged));
    button.textContent = engaged ? "kill engaged" : "engage kill";
    compile.disabled = engaged;
    setText("mode-pill", engaged ? "simulated // kill engaged" : "simulated // no execution");
    setText(
      "status-message",
      engaged
        ? "Local preview kill state engaged. New proposal compilation is disabled."
        : "Local preview kill state released. No backend authority exists."
    );
  });
}

function bindWorkspaceActions(state, edge) {
  const focusButton = document.getElementById("focus-gaps");
  const compileButton = document.getElementById("compile-proposal");
  const copyButton = document.getElementById("copy-proof");
  const causalMap = document.getElementById("causal-map");
  const proof = document.getElementById("proof-console");
  if (!(focusButton instanceof HTMLButtonElement) || !(compileButton instanceof HTMLButtonElement)
      || !(copyButton instanceof HTMLButtonElement) || causalMap === null || proof === null) {
    throw new Error("Missing workspace action controls.");
  }
  focusButton.addEventListener("click", () => {
    causalMap.classList.toggle("focus-gaps");
    setText("status-message", causalMap.classList.contains("focus-gaps")
      ? "Showing only unresolved causal gaps."
      : "Showing the complete causal field.");
  });
  compileButton.addEventListener("click", () => {
    setText("status-message", "Typed proposal compiled locally. Execution authority remains false.");
    activateView("proof", state, edge);
  });
  copyButton.addEventListener("click", async () => {
    await navigator.clipboard.writeText(proof.textContent ?? "");
    setText("status-message", "Visible simulated proof copied to the clipboard.");
  });
}

function renderState(state, edgeState, worldModelState, worldIntakeState, worldIntakeGovernanceState, immuneRuntimeState, intelligenceResearchState, homeostasisChronosState, genomeEvaluationState, arenasObservatoryState, contractConformanceState, verifierIdentityReadinessState, autonomousPromotionState, completionAuditState) {
  setText("mission-code", state.mission.code);
  setText("mission-title", state.mission.title);
  setText("mission-origin", `origin ${state.origin}`);
  setText("mission-time", `window ${state.mission.window}`);
  setText("role-diversity", `${state.cells.length} / ${state.cells.length}`);
  renderCells(state.cells);
  renderCausalMap(state.causal_chain);
  renderTruthBraid(state.truth_braid);
  renderDissent(state.dissent);
  renderLedger(state.ledger);
  renderSwarmMatrix(state.cells);
  renderVerifier(state.verifier, state.ingress);
  renderRangeGate(state.range_execution_gate);
  renderFoundry(state.foundry, state.platform_assurance);
  renderWorldModel(worldModelState, worldIntakeState, worldIntakeGovernanceState);
  renderImmuneRuntime(immuneRuntimeState);
  renderIntelligenceResearch(intelligenceResearchState);
  renderHomeostasisChronos(homeostasisChronosState);
  renderGenomeAndArenas(genomeEvaluationState, arenasObservatoryState);
  renderContractConformance(contractConformanceState);
  renderVerifierIdentityReadiness(verifierIdentityReadinessState);
  renderAutonomousPromotion(autonomousPromotionState);
  renderCompletionAudit(completionAuditState);
  renderEdgePreview(edgeState);
  renderLeaseFacts(state.authorization);
  renderTarget(state.target);
  renderBudgets(state.budgets);
  renderProof({edge_preview: edgeState, world_model: worldModelState, world_intake: worldIntakeState, world_intake_governance: worldIntakeGovernanceState, immune_runtime: immuneRuntimeState, intelligence_research: intelligenceResearchState, homeostasis_chronos: homeostasisChronosState, genome_evaluation: genomeEvaluationState, arenas_observatory: arenasObservatoryState, contract_conformance: contractConformanceState, verifier_identity_readiness: verifierIdentityReadinessState, autonomous_promotion: autonomousPromotionState, completion_audit: completionAuditState, swarm: state.proof, ingress: state.ingress, verifier: state.verifier, range_execution_gate: state.range_execution_gate, foundry: state.foundry, platform_assurance: state.platform_assurance});
}

async function loadJson(url) {
  const response = await fetch(url, {cache: "no-store"});
  if (!response.ok) {
    throw new Error(`Unable to load ${url}: HTTP ${response.status}.`);
  }
  return response.json();
}

async function loadState() {
  return Promise.all([loadJson(stateUrl), loadJson(edgeStateUrl), loadJson(worldModelStateUrl), loadJson(worldIntakeStateUrl), loadJson(worldIntakeGovernanceStateUrl), loadJson(immuneRuntimeStateUrl), loadJson(intelligenceResearchStateUrl), loadJson(homeostasisChronosStateUrl), loadJson(genomeEvaluationStateUrl), loadJson(arenasObservatoryStateUrl), loadJson(contractConformanceStateUrl), loadJson(verifierIdentityReadinessStateUrl), loadJson(autonomousPromotionStateUrl), loadJson(completionAuditStateUrl)]);
}

async function main() {
  try {
    const [state, edgeState, worldModelState, worldIntakeState, worldIntakeGovernanceState, immuneRuntimeState, intelligenceResearchState, homeostasisChronosState, genomeEvaluationState, arenasObservatoryState, contractConformanceState, verifierIdentityReadinessState, autonomousPromotionState, completionAuditState] = await loadState();
    renderState(state, edgeState, worldModelState, worldIntakeState, worldIntakeGovernanceState, immuneRuntimeState, intelligenceResearchState, homeostasisChronosState, genomeEvaluationState, arenasObservatoryState, contractConformanceState, verifierIdentityReadinessState, autonomousPromotionState, completionAuditState);
    activateView("edge", state, edgeState);
    bindTabs(state, edgeState);
    bindCellFilter();
    bindKillSwitch();
    bindWorkspaceActions(state, edgeState);
  } catch (error) {
    setText("status-message", `Control-board initialization failed: ${error instanceof Error ? error.message : String(error)}`);
    throw error;
  }
}

void main();
