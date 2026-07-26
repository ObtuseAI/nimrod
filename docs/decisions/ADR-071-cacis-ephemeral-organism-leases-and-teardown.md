# ADR-071: CACIS ephemeral organism leases and teardown

Status: accepted, replay-only implementation  
Date: 2026-07-15  
Decision owner: project owner through the accepted CACIS plan  
Review date: before W3 settlement integration or any live organism isolation

## Context

A dynamic security swarm becomes a permanent privileged actor if scheduling, capabilities, resources, scratch state, conversational context, or learned output survive without an explicit boundary. A Shadow can also become a hidden authority source if pause or termination decisions imply policy permission.

## Options considered

1. Extend the permanent seven-cell swarm with mutable shared state.
2. Create temporary replay-only organisms with separate capability and resource leases, one bounded Shadow, typed outputs, mandatory teardown, and candidate-only retention.
3. Deploy each cell as an independently privileged service before lifecycle semantics and workloads are measured.

## Decision

Option 2 is accepted for W2. The Governor may schedule and meter but cannot authorize or execute. Every organism is bound to one immutable World Model generation, one time window, exact capabilities, finite resources, unique cell identities, and one Shadow. The Shadow may pause, resume, downgrade, challenge, abstain, or terminate but cannot authorize or execute.

The organism must end in `disposed`. Cells terminate, leases revoke, scratch and conversational context are destroyed, and no credential, target contact, or execution may occur. Only typed digest-addressed candidate knowledge survives. Independent verification remains required and unperformed.

## Consequences

The runtime is replayable, auditable, and unable to accumulate ambient privilege. Contradiction and abstention remain visible. The cost is more lifecycle bookkeeping and no claim that in-process logical separation equals production isolation.

## Migration and rollback

W2 reads only the additive W1 generation contract and has no consumer or action edge. Rollback disables organism replay and deletes caller-selected disposable output while retaining source observations, generations, and review evidence. Rollback cannot erase Witness evidence or widen authority.

## Validation

The canonical replay produces eight cells, 15 chained events, seven contributions, one abstention, three candidate-only knowledge records, complete teardown, and 49 fail-closed cases. Contract, CLI, deterministic replay, control-board, and repository-wide validation remain required.
