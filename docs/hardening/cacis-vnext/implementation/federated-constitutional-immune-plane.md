# Implementation Plan: Federated constitutional immune plane

## Selected Design And Constraints

Implement Option 2 from `../proposals/constitutional-immune-plane.md` as eight evidence-gated waves. Doctrine v0.1, current authority classes, proposal-only organisms, independent verification, candidate-only evolution, signed display ingress, offline-replica targeting, and existing Crucible effect gates are non-negotiable. W0 is planning and contract validation only.

## Source Revision And Drift Check

Evidence collection: `sha256:fc36f3e6528925b88081da0f4b1d26b1acc549d60a1101d9348a9541bcab985e`. Base Git revision: `d8b28e03082d302c49c41b20478d83411c549bf4`. Source drift was present during review because prior Edge waves are uncommitted. Before each implementation wave, hash and compare `DOCTRINE.md`, `REFERENCE_ARCHITECTURE.md`, `CRUCIBLE.md`, `EVOLUTION_FOUNDRY.md`, and `SWARM_CONTROL_BOARD.md`. Authority-relevant drift returns to design review.

## Affected Components

- `specs/` for world state, organism lifecycle, hypothesis, settlement, genome, arena, and Observatory contracts;
- cohesive reference packages under `src/`, created only when a real implementation boundary exists;
- `tools/` for replay, adversarial, resource, and manifest validation;
- `ui/` for signed display-only projections;
- `docs/` and `reports/` for current-state truth and evidence.

## Ordered Work Packages

1. W0 validates the target roadmap, records ADR-069, integrates current documentation, and preserves false operational authority.
2. W1 implements immutable observations, versioned six-domain derived state, provenance, contradiction, freshness, and deterministic replay.
3. W2 implements typed missions, Governor scheduling, ephemeral topology, capability/resource leases, Shadow controls, termination, and knowledge-retention receipts.
4. W3 implements competing hypotheses, counter-evidence, confidence vectors, metacognition, challenge, abstention, and independent settlement.
5. W4 implements metabolism, homeostasis, backpressure, health, and Chronos deadlines without resource or authority expansion.
6. W5 implements memory strata, genome candidates, evaluation partitions, reward-hacking defenses, complexity gates, and lineage.
7. W6 implements deterministic security arenas and signed display-only Observatory projections.
8. W7 integrates with existing Crucible effects only after all current live authorization, isolation, evidence, abort, cleanup, and recovery gates pass.

## Compatibility And Migration

Use versioned additive contracts and deterministic migrations. Run the W1 world model beside the existing projection without changing policy inputs. Introduce organism output as a new proposal source with an explicit feature gate and unchanged kernel contract. Keep old projections readable until signed Observatory consumers demonstrate compatibility.

## Tactical Protections During Migration

- No action or policy edge in W1–W2.
- No unrestricted chat-to-contract conversion.
- No raw telemetry retention without a reviewed data contract.
- No organism self-verification or shared verifier principal/process identity.
- No public host, owner repository, or unknown-ownership targeting.
- No aggregate score overriding a hard failure.
- No genome output retained as executable instruction.

## Tests And Security Validation

Each wave adds a positive fixture, one schema-negative mutation, a dedicated semantic harness, and adversarial cases for authority widening, identity substitution, evidence tamper, replay, stale state, correlated verification, and claimed effects without evidence. Prefer integration and replay tests over isolated mocks. Preserve explicit blocked and inconclusive states.

## Performance And Resource Benchmarks

For a fixed incident replay corpus, record baseline and candidate p50/p95 generation latency, sustained events per second, peak RSS, retained bytes per event, rebuild time, organism startup/termination time, verifier backlog, and deterministic digest equality. Thresholds require owner approval before they become release gates. Do not infer service decomposition from unmeasured intuition.

## Rollout And Rollback

Roll out by wave behind explicit version and feature gates. Start with offline fixtures, then consented local read-only observations, then isolated ranges. Rollback disables CACIS consumers and organism scheduling, drains the active generation, and returns to current evidence projections. Immutable observations and Witness records are retained under policy; no rollback may erase evidence or reset kill state.

## Acceptance Criteria

- W0: roadmap and all repository validators pass; authority and runtime claims remain false.
- W1: deterministic replay, causal lineage, explicit unknown/stale/contradictory state, and crash recovery pass within approved budgets.
- W2: every organism is capability/resource leased, independently shadowed, terminable, and unable to authorize or execute.
- W3: competing hypotheses, dissent, abstention, and independent settlement survive adversarial replay.
- Later waves satisfy their named evidence gates without widening authority.
- W7 cannot begin from elapsed time, aggregate score, simulated evidence, or a prior Edge/Crucible release.

## Open Decisions

- W1 workload and resource budgets;
- world-model storage engine after replay measurements;
- privacy and retention policy by memory stratum;
- independent evaluator ownership and sealed-partition custody;
- process/service isolation trigger based on measured scale and threat model.
