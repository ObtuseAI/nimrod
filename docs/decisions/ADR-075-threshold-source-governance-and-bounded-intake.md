# ADR-075: World Model source intake is threshold-governed, purpose-bound, retention-bounded, and backpressured

Status: `ACCEPTED_IMPLEMENTATION_REPLAY_ONLY`
Decision owner: project owner
Decision date: 2026-07-16
Review date: before live source admission, production retention enforcement, or production verifier independence

## Context

Durable cursors prevent silent replay, but they do not prove that a source is approved, healthy, collected for an allowed purpose, fresh enough, within privacy retention, or safe to admit under load. A valid signature alone also cannot prove the underlying sensor or verifier is independent.

## Decision

Replay intake requires three independently validated threshold-signed objects:

1. a short-lived source policy binding the exact PowerShell, optional Sysmon, and DNS channels, defensive purpose, source configuration digests, zero raw-payload retention, metadata retention, immutable-store ceilings, queue and event budgets, and immutable false authority;
2. a short-lived health attestation binding the exact continuous-observation session, source policy, per-source status, event count, newest observation, freshness age, future clock skew, configuration digest, and error digest;
3. an intake decision binding policy, health, session, admitted projection, verifier boundary, store projections, queue state, deferred events, retention status, and live-admission denial.

The canonical queue starts at depth two with capacity four. Two events are accepted, three are deferred in stable order, and zero are dropped. The signed projection must match actual immutable generation and cursor-transition counts immediately before publication.

## Authority and privacy

Signatures authenticate governed replay statements; they do not establish live sensor identity, policy readiness, production truth, action authority, or production verifier independence. Raw event payload retention remains zero. Automatic evidence deletion is forbidden; future compaction requires witnessed evidence.

This implementation rejects any caller assertion of dedicated verifier administration or production independence. Live-origin admission remains blocked even when signatures validate.

## Validation evidence

- Three document classes each verify with two distinct roles.
- Two fresh sources and one unavailable source remain distinct.
- Queue depth advances from two to four; two events are accepted, three deferred, and none dropped.
- The admitted replay advances the immutable World Model only after actual store cardinality matches the signed retention projection.
- A separate read-only process recomputes signatures, purpose, retention, budget, backpressure, freshness, clock skew, admitted projection, cursor/generation causality, and live-admission denial.
- Nineteen adversarial cases reject threshold loss, re-signed policy weakening, source substitution, expiration, health/freshness laundering, dropped-event laundering, live-admission widening, non-prefix selection, projection substitution, verifier-independence fabrication, full-queue admission, and immutable-store projection mismatch.

No live sensor, containment, recovery action, target contact, execution, promotion, or production policy input was authorized.
