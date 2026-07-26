# ADR-070: CACIS World Model uses immutable observations and derived generations

Status: `ACCEPTED_IMPLEMENTATION_REPLAY_ONLY`  
Decision owner: project owner  
Decision date: 2026-07-15  
Review date: before live sensor admission, multi-generation succession, or policy consumption

## Context and threat-model impact

CACIS W1 needs shared state without allowing mutable model state to overwrite evidence, erase contradictions, become policy, or claim truth. A crash between derived-state computation and publication must not expose a partial generation as active.

## Options considered

1. Maintain one mutable current-state document.
2. Keep immutable observations, content-addressed derived generations, and an atomic active-head publication.
3. Introduce a distributed graph and event broker before replay semantics are measured.

## Decision and consequences

Option 2 is accepted for W1. Every observation is an immutable content-addressed artifact. The reducer creates a separate canonical generation that binds the ordered observation digests and preserves known, partially known, unknown, contradictory, and stale state. A prepared head has no active meaning; one atomic replacement publishes the first generation only after all referenced artifacts exist.

W1 intentionally supports one replayed first generation. Multi-generation concurrency, retention, compaction, distributed consensus, and live sensor admission require later decisions and evidence.

## Privacy, data, and authority changes

The replay fixture contains synthetic reserved-example identities and addresses. No live telemetry, credentials, target contact, or external data is admitted. Observations and generations have immutable false authorization, execution, policy, target-contact, and production-truth fields.

## Migration and rollback

There is no existing World Model state to migrate. W1 output lives in a caller-selected local directory. Rollback disables the replay CLI and consumers; immutable artifacts remain reviewable until the caller removes the disposable output directory. Existing Edge, Crucible, Witness, verifier, and Foundry paths are unchanged.

## Validation evidence

- Eight replay observations produce the same generation digest on repeated construction.
- Domain states are one contradictory, one partially known, two known, and two unknown.
- One stale fact and one explicit unknown fact remain visible.
- Recovery distinguishes prepared-uncommitted from active generation.
- Twenty-six adversarial cases reject authority widening, epistemic laundering, sequence/time/scope defects, digest and summary substitution, immutable artifact tamper, and missing active state.

No live sensing, containment, recovery, policy readiness, or production protection is claimed.
