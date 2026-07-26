# CACIS W1 Cyber World Model replay

Status: `CACIS_WORLD_MODEL_W1_REPLAY_VALID_NON_AUTHORIZING`  
Origin: `replayed`  
Authority: none  
Runtime scope: offline deterministic reducer and local immutable-generation store

## Implemented boundary

W1 turns typed replay observations into a content-addressed six-domain world-model generation. It preserves source observations as immutable artifacts, derives a separate generation, publishes the active generation through one atomic head transition, and recovers an interrupted prepare without treating it as active state.

The succession extension admits bounded **replayed** continuous-observation sessions through durable per-source cursors. Each transition binds the prior cursor and generation, accepted and replayed record identifiers, explicit gaps, typed sensor health, the derived successor generation, and the resulting cursor. Live-origin admission remains blocked.

The canonical credential-theft replay contains eight observations and eight declared requirements across identity, endpoint, network, cloud, threat, and recovery. Its deterministic outcome is:

| Domain | Knowledge state | Reason |
|---|---|---|
| Identity | `contradictory` | Two independent replay sources disagree on privilege level |
| Endpoint | `partially_known` | Process integrity is known while sensor health is stale |
| Network | `known` | One current destination fact is present |
| Cloud | `unknown` | The declared IAM requirement has no observation |
| Threat | `known` | One current credential-access signal is present |
| Recovery | `unknown` | The recovery verifier explicitly reports snapshot health unknown |

No conflict is averaged away. Every candidate keeps source identity, confidence, observation and validity time, evidence references, and the digest of the immutable observation from which it was derived.

## Continuous-observation succession

The canonical succession replay starts from the W1 credential-theft generation, then applies two bounded PowerShell, optional Sysmon, and DNS sessions:

- three immutable World Model generations are retained;
- two immutable cursor transitions are retained;
- two previously consumed records are deduplicated;
- one internal event-record gap remains visible as one missing record;
- unavailable Sysmon health remains literal instead of being inferred healthy;
- each successor contains nine typed health, continuity, and new-event-count observations;
- a separate read-only process recomputes causal bindings and cannot authorize action.

Publication uses two heads. The generation head advances first. If a crash occurs before cursor publication, recovery accepts only one prepared cursor transition whose candidate-generation digest equals the active World Model head; it keeps policy and execution false until that transition is finalized. Unbound divergence is an integrity error.

## Governed source intake

Replay succession now has a governance gate in front of publication:

- a 2-of-3 short-lived source policy pins exact channels, source configuration, defensive purpose, zero raw-payload retention, metadata retention, immutable-store ceilings, queue depth, event budgets, and no-drop backpressure;
- a 2-of-3 source-health attestation binds the exact session and independently recomputable status, freshness age, future clock skew, event count, error digest, and configuration digest for each source;
- a 2-of-3 intake decision binds policy, health, original and admitted sessions, verifier boundary, queue state, deferred events, retention projections, and immutable false live-admission and policy authority;
- the commit seam checks signed generation and cursor-transition projections against actual immutable-store cardinality immediately before publication;
- a separate process recomputes all governance and causal bindings without receiving credentials or write access to its inputs.

The canonical queue accepts two events, defers three, drops none, and remains at its signed maximum depth. Two sources are fresh; unavailable Sysmon remains a literal source gap. These are replay governance claims only. Live source identity, production retention enforcement, trusted time, and separately administered verification remain blockers.

## Generation protocol

1. Validate every observation contract and cross-field semantic.
2. Require unique, contiguous replay sequence and observation identity.
3. Require all six domains in the declared requirement set.
4. Hash and retain every observation independently.
5. Derive facts and domain knowledge without modifying observations.
6. Hash the complete generation body and store it immutably.
7. Write a prepared head that has no active-state meaning.
8. Atomically publish `HEAD.json` only after every immutable artifact exists.
9. On recovery, validate filenames, canonical content digests, generation semantics, and head binding.

A crash after preparation produces `prepared_uncommitted` and `active_generation_digest: null`. It cannot be interpreted as current world state.

## Constitutional ceilings

Observations cannot authorize, execute, change policy, or claim truth. Generations cannot authorize, execute, change policy, contact targets, become policy-ready, or claim production truth. W1 has no sensor, network, credential, containment, recovery, target, or executor interface.

The generated state is evidence-bearing investigative context only. Later policy use requires a separately reviewed consumer contract, independent verification, freshness policy, privacy review, and the existing Constitutional Kernel.

## Validation evidence

- `world-observation-envelope.schema.json`
- `world-model-generation.schema.json`
- `world-model-replay-credential-theft.json`
- `nimrod_cacis.world_model`
- `validate_world_model.py`
- `CACIS_WORLD_MODEL_VALIDATION.json`

The harness proves deterministic reproduction, eight immutable observation artifacts, one immutable generation, prepared-crash recovery, active-generation recovery, explicit world-state counts, and 26 fail-closed cases across authority, epistemic, sequence, time, scope, digest, summary, store-tamper, and missing-artifact boundaries.

## Still incomplete

Continuous live sensing, multi-generation succession, cross-device federation, tenant isolation, production storage selection, signed collector identity, privacy retention enforcement, independent settlement, policy consumption, organism scheduling, containment, recovery action, and production truth remain unimplemented.

## Next boundary

W2 may consume only the immutable generation contract to schedule proposal-only ephemeral organisms. It must not read raw source text as instruction, make the generation policy-ready, or create an executor edge.
