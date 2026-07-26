# ADR-074: replay-safe continuous observation advances the World Model through recoverable cursor-bound succession

Status: `ACCEPTED_IMPLEMENTATION_REPLAY_ONLY`
Decision owner: project owner
Decision date: 2026-07-16
Review date: before live sensor admission, policy consumption, distributed collection, or retention compaction

## Context and threat-model impact

ADR-070 intentionally stopped at one replayed generation. Continuous observation adds replay, duplication, source gaps, unavailable sensors, and a crash window between publishing derived state and advancing each source cursor. Treating an event batch, process exit, or cursor write as truth could silently lose evidence, repeat evidence, conceal gaps, or expose an inconsistent generation as policy input.

## Options considered

1. Replace the active generation and cursors in place.
2. Advance content-addressed generations and immutable cursor transitions independently, then recover the bounded world-ahead/cursor-prepared crash state through exact causal bindings.
3. Introduce a distributed broker, database, and production sensor admission before local succession semantics are validated.

## Decision and consequences

Option 2 is accepted for replay only. Every batch binds the prior generation, complete continuous-observation session digest, prior cursor digest, per-source accepted records, replay count, gap evidence, typed sensor health, candidate generation, and resulting cursor. A separately launched read-only verifier recomputes record monotonicity, deduplication, gaps, typed observations, scenario binding, and generation succession.

The World Model head advances before the cursor head. If the process stops in that bounded window, recovery reports `world_advanced_cursor_prepared`, keeps policy and execution false, and finalizes only the single prepared cursor transition bound to the active generation. Any other divergence fails closed.

## Privacy, authority, and trust

Only typed event metadata and digests enter the replay. Raw Windows event payloads remain discarded. The intake cannot authorize, execute, change policy, contact targets, or claim policy readiness. A separate process improves fault separation but does not prove a separately administered OS identity, host, account, or organization.

Live-origin sessions are rejected by this implementation. Production sensor admission requires signed source identity and health, retention policy, privacy review, calibrated freshness and backpressure, independently administered verification, and a new decision.

## Validation evidence

- Three immutable generations and two cursor transitions survive deterministic construction and recovery.
- Previously consumed records are deduplicated without suppressing new evidence.
- One internal record gap remains explicit as one missing record.
- Nine typed health, continuity, and new-event-count observations update endpoint and network state while the remaining domains stay honestly unknown.
- A separate verifier process recomputes eleven causal claims.
- Sixteen adversarial cases reject authority widening, digest or predecessor substitution, cursor jumps, evidence omission, hidden gaps, sensor-health laundering, typed-observation substitution, stale commits, live-origin admission, active-head corruption, and digest-path escape.

No live sensor was admitted into the World Model and no policy, target contact, containment, recovery, execution, promotion, or production truth was authorized.
