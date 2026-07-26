# Security Hardening Proposal: Constitutional immune plane

## Decision

Choose how nimrod can add a living world model, dynamic immune organisms, hypothesis competition, metacognition, and recursive learning without allowing mutable intelligence to become truth, authority, or execution.

## Executive Recommendation

The complete choice is **Option 1: Extend the current swarm**, **Option 2: Federated constitutional immune plane**, or **Option 3: Service-per-cell immune mesh**. I recommend Option 2 under the current evidence and delivery constraints. Option 1 is the fastest path to a replay prototype but leaves the most ownership drift. Option 3 becomes preferable only after measured scale or fault-containment needs justify distributed-system cost.

## Evidence

I inspected the six hashed documents recorded in `../context.md`. E-02 and E-03 most influenced the diagnosis: doctrine requires deterministic authority and visible uncertainty, while the current architecture already separates analysis, policy, execution, verification, and Witness. E-01 asks us to add powerful mutable state and recursive organization; that new responsibility should not be folded across existing trust edges casually.

| Evidence | Finding or document | What it establishes |
|---|---|---|
| `E-01` | [CACIS vNext owner brief](../../../source/cacis_vnext_owner_brief.md) | Requests world modeling, temporary organisms, metacognition, genome learning, and immutable authority. |
| `E-02` | [nimrod doctrine](../../../DOCTRINE.md) | Analysis cannot authorize; evidence, uncertainty, recovery, and operator control are constitutional. |
| `E-03` | [Reference architecture](../../../REFERENCE_ARCHITECTURE.md) | Current control ownership separates kernel, executor, verifier, Witness, and display projection. |
| `E-04` | [nimrod Crucible](../../../CRUCIBLE.md) | Offensive effects require signed scope, isolation, abort, cleanup, recovery, and independent evidence. |
| `E-05` | [Constitutional Evolution Foundry](../../../EVOLUTION_FOUNDRY.md) | Improvement is candidate-only and cannot change evaluators, trust, resources, or authority. |
| `E-06` | [Governed swarm and control board](../../../SWARM_CONTROL_BOARD.md) | The present seven-cell swarm has proposal-only maximum outcome and signed display ingress. |

## Current Design And Failure Mode

Observed in E-03, E-05, and E-06, nimrod has strong separated controls but no implemented six-domain world model or temporary organism runtime. The current swarm is a fixed set of roles for producing a proposal; the Foundry separately evaluates candidates; the board renders signed state.

Inferred from adding E-01 directly to that shape, a long-lived enlarged swarm would tend to own collection interpretation, derived world state, scheduling, hypothesis scoring, reusable memory, and mutation requests. Even if every final action still reaches the kernel, compromised or correlated cells could poison the state from which all later proposals are derived, suppress alternatives, retain unsafe instruction-like memory, or make a structurally self-produced verification look independent. The risk is not one vulnerable line. It is ownership concentration across truth formation, lifecycle control, and learning.

## Desired Invariants

- Immutable observations and derived world-state generations remain distinct and causally linked.
- Only the existing Constitutional Kernel can make deterministic authorization decisions; it cannot execute.
- The Governor schedules and meters but never authorizes an operational effect.
- Organisms are short-lived, least-capability, resource-bounded, and proposal-only.
- Consequential claims and recovery cannot be self-verified.
- Unknown, dissent, stale, deceptive, timeout, and outside-authority states remain representable.
- Genome output is inert candidate data until partitioned evaluation and independent promotion gates complete.
- Offensive effects remain behind the existing Crucible path and cannot target public hosts or unknown ownership.
- The Observatory remains a signed display projection.

## Constraints And Non-Goals

Doctrine v0.1 and current authority classes are fixed. This proposal does not choose a graph database, message broker, model provider, cloud platform, endpoint sensor, or production deployment topology. It does not implement containment, C2, source acquisition, range provisioning, or production promotion. No CACIS runtime performance or scale has been measured.

## Before Architecture

[The before diagram](../diagrams/constitutional-immune-plane-before.mmd) shows the current abstraction: typed evidence reaches a fixed proposal swarm, the kernel owns authorization, narrow executors own effects, independent verification and Witness own outcome evidence, the Foundry remains candidate-only, and the board is display-only. That separation is the asset all options must preserve.

## Options

### Option 1: Extend the current swarm

This baseline adds more permanent roles and keeps the world model in the present application boundary. Its strongest case is delivery speed: we can reuse current typed messages, projection code, and Foundry integration to prove early replay semantics with few new deployment concerns. The kernel and executor edge need not change.

The security concern is not that the extended swarm directly executes. It is that one long-lived ownership domain would accumulate observation interpretation, derived state, scheduling, hypotheses, and memory. Local checks can preserve proposal-only authority, but independence becomes organizational rather than structural, and future contributors can accidentally create internal bypasses between roles. A process crash also couples more of the cognitive state.

Performance and memory should be favorable for small replay workloads because there are no serialization or network hops and the model can share objects. That same shared state makes resource accounting and reproducible replay harder as the system grows. Rollout is straightforward behind a simulator flag; rollback removes the new roles and state tables. We should use this only as a disposable spike, not the target architecture.

[Option 1 diagram](../diagrams/constitutional-immune-plane-current-extension-after.mmd)

| Change | Before | After | Security consequence | Cost |
|---|---|---|---|---|
| World state | No CACIS world model | Shared in-process model | Adds causal context but concentrates poisoning blast radius | Low initial engineering cost |
| Organisms | Fixed seven roles | Larger long-lived swarm | Proposal ceiling remains; lifecycle and independence are weaker | Low migration cost |
| Learning | Separate Foundry projection | Foundry configuration feeds swarm | Fast experimentation; stronger contamination risk | Moderate replay discipline |

### Option 2: Federated constitutional immune plane

This option adds a distinct logical plane while preserving current trusted controls. Immutable typed observations feed a versioned derived world model. A non-authorizing Governor creates a short-lived organism from capability-bound cells. Hypothesis and adversarial roles compete; independent settlement verifies consequential claims; governed memory can emit only inert genome candidates. The existing kernel, executors, Witness, Crucible gates, Foundry, and signed board ingress remain the authority and effect path.

The attractive part is that each new responsibility gets an explicit maximum outcome. The world model can derive state but cannot authorize; the Governor can schedule but cannot authorize; an organism can propose but cannot execute; settlement can verify but cannot perform the action; the genome can create candidates but cannot promote. A poisoned cell can still produce bad evidence or a bad proposal, but it cannot silently turn that output into permission. Event generations and typed parent digests make replay and disagreement inspectable.

This design adds serialization, immutable generation retention, queues, indexes, and resource leases. Those costs are not measured. We can control them initially with a single-process reference implementation whose module boundaries and contracts mirror the future plane; process or service separation remains an implementation decision. Reliability improves because organism state is disposable and derived state can be rebuilt, though the world-model store becomes a critical availability dependency. Rollout proceeds wave by wave with dual-read comparisons and no action edge. Rollback stops CACIS scheduling and returns consumers to existing evidence projections; immutable source observations remain usable.

[Option 2 diagram](../diagrams/constitutional-immune-plane-federated-after.mmd)

| Change | Before | After | Security consequence | Cost |
|---|---|---|---|---|
| Truth formation | Fixed swarm consumes evidence | Immutable observations plus versioned derived generations | Poisoning and contradiction become replayable; world-model integrity is a new critical control | Moderate contract and storage work |
| Lifecycle | Permanent roles | Ephemeral capability/resource-leased organisms with shadows | Narrows credential, state, and correlated-failure lifetime | Scheduler and cleanup complexity |
| Verification | Existing independent verifier | Independent settlement also covers claims and recovery | Prevents organism self-verification | More verifier capacity and latency |
| Learning | Separate candidate-only Foundry | Governed memory/genome feeds Foundry candidates | Enables recursive learning without active mutation | Retention, privacy, and partition governance |

### Option 3: Service-per-cell immune mesh

This foundational alternative deploys the world model, Governor, organism cells, hypothesis challengers, settlement, genome, and Observatory as independently identified services over an authenticated event mesh. Its strongest case is fault and compromise containment: different roles can run under distinct accounts, policies, release trains, and resource quotas. High-volume perception and expensive simulation can scale independently.

What gives me pause is the new distributed trusted surface. Service identity, message ordering, exactly-once semantics, schema evolution, queue poisoning, replay, backpressure, clock skew, tenant routing, and partial failure all become security-relevant. More processes do not automatically create verifier independence if they share operators, images, keys, or data paths. The event mesh and identity plane become high-value dependencies.

Network serialization and multiple hops would increase latency; per-service runtimes, buffers, caches, and sidecars increase memory. Failure isolation improves, but system-level reliability can regress until retry, dead-letter, idempotency, and degraded-mode semantics mature. Migration requires dual publishing, compatibility windows, service identity rollout, and observability. Rollback must drain a versioned generation and revert routing without accepting stale messages. This option should win when measured event volume, tenant isolation, or separate operational ownership exceeds what the federated logical plane can safely support.

[Option 3 diagram](../diagrams/constitutional-immune-plane-service-mesh-after.mmd)

| Change | Before | After | Security consequence | Cost |
|---|---|---|---|---|
| Isolation | Logical roles in current runtime | Separately identified cell services | Stronger blast-radius options; larger identity and network attack surface | High deployment and key-management cost |
| Transport | Local typed contracts | Authenticated event mesh | Enforceable inter-role policy; ordering and replay become distributed concerns | Latency, buffers, broker operations |
| Scaling | One reference runtime | Independent horizontal scaling | Handles heterogeneous workloads | Capacity planning and backpressure complexity |

## Comparison

| Dimension | Option 1: Current extension | Option 2: Federated plane | Option 3: Service mesh |
|---|---|---|---|
| Security | Improves proposal context; highest ownership concentration | Strong explicit outcomes and causal generations; new world-model criticality | Strongest potential isolation; largest distributed attack surface |
| Performance | Likely lowest latency; unmeasured | Added local serialization and generation cost; unmeasured | Multiple network hops and serialization; unmeasured |
| Memory | Shared state likely lowest initially | Retained generations, queues, and indexes | Per-service runtimes, buffers, caches, and sidecars |
| Reliability | Simple deployment; larger coupled crash domain | Rebuildable derived state and disposable organisms; critical model dependency | Better local isolation; harder partial-failure semantics |
| Operability | Lowest initial burden; hidden coupling risk | Moderate new lifecycle, replay, and health operations | Highest deployment, identity, telemetry, and incident burden |
| Migration | Fast simulator spike | Incremental wave-by-wave dual-read path | Long dual-publish and service-identity migration |

No performance or memory direction in this table is measured. For W1 we should replay a fixed incident corpus, measure p50/p95 generation latency, events per second, peak RSS, retained bytes per event, and deterministic digest equality, then compare the single-process baseline with the federated contract boundary. A service mesh should not be selected until a stated workload misses a reviewed threshold.

## Recommendation

I recommend Option 2. It best matches E-01 without eroding E-02 through E-06, and it lets nimrod become substantially more capable while making every new plane state what it cannot do. We can implement the first waves in one unprivileged reference runtime and still preserve the logical controls needed for later isolation.

Option 1 should win only for a time-boxed semantic spike that will be discarded. Option 3 should win if measured throughput, tenant isolation, fault containment, or distinct team ownership requires deployable separation and the project is prepared to govern the event mesh as a critical security subsystem.

## Evidence Coverage And Residual Risk

| Evidence | Effect | Tactical protection still required | Residual risk |
|---|---|---|---|
| E-01 — CACIS owner brief | Addresses | Preserve all requested capabilities in staged contracts | Runtime remains unbuilt |
| E-02 — nimrod doctrine | Mitigates | Keep kernel and immutable laws outside evolution | Implementation defects can still violate intent |
| E-03 — Reference architecture | Addresses | Reuse current authority, executor, verifier, Witness, and board edges | World-model integrity becomes critical |
| E-04 — Crucible gates | Addresses | Keep all operational effects on the existing isolated authorization route | No live range evidence exists |
| E-05 — Evolution Foundry | Addresses | Keep genome output candidate-only and evaluators sealed | Evaluation leakage and correlated evaluators remain threats |
| E-06 — Governed swarm | Mitigates | Preserve typed proposal ceiling while replacing fixed topology with lifecycle contracts | Ephemeral cells can still collude or share poisoned inputs |

## Migration And Rollout

Begin with W1 offline replay and no action edge. Feed the same immutable observation fixtures to the existing evidence projection and new world model, compare digests and explicit unknown states, and keep all consumers on the old path. W2 adds ephemeral organism scheduling against replay only. W3 adds hypothesis and settlement. Subsequent waves introduce metabolism, genome, and Observatory views. Crucible integration remains last and blocked until its existing live evidence gates pass.

Rollback at every pre-Crucible wave disables CACIS consumers and scheduling while preserving source observations. Schema changes require versioned readers and deterministic migrations. Any drift in kernel, executor, verifier, Witness, or Foundry authority returns the work to design review.

## Validation Plan

- Validate the roadmap schema, exact invariant set, plane outcomes, wave ordering, recursive ceilings, arena safety, evaluation partitions, and false operational authority.
- Reject governor authorization, organism execution, public or owner-repository targeting, raw-command bridges, self-verification, hard-failure averaging, reward-defense removal, recursive authority change, and Crucible gate laundering.
- For W1, replay fixed credential-theft and suspicious-script event sets; require deterministic generation digests, preserved contradictions, explicit staleness, and complete provenance.
- Measure latency, throughput, peak RSS, retained bytes per event, recovery time, and digest equality against an agreed workload before choosing storage or service topology.
- Exercise crash between observation commit and derived generation, corrupted generation head, replay, reorder, duplicate, clock skew, sensor conflict, and unavailable verifier.

## Implementation Work Packages

- W0: decision record, source brief, roadmap contract, hardening portfolio, validation, manifest, and documentation integration.
- W1: typed observation/world-state contracts, immutable generation store, deterministic reducer, replay CLI, contradiction and freshness semantics.
- W2: mission, Governor schedule, capability/resource lease, organism topology, Shadow, termination, and knowledge-retention receipts.
- W3: hypothesis, counter-evidence, confidence vector, challenge, abstention, independent settlement, and two replay arenas.
- W4–W7: follow the stage gates in `VNEXT_CACIS_MASTER_PLAN.md`; do not pre-create operational authority.

## Open Questions

- What event volume, retention, recovery-time objective, and device footprint should W1 target?
- Which telemetry classes may enter customer-local world models, and which may enter federated or genome memory?
- What process/account isolation is required for independent settlement in Edge versus Crucible?
- Who owns the private and external evaluation partitions and their key custody?
