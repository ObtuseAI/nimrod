# ADR-073: Bound scheduling with homeostasis and domain-specific clocks

Status: accepted for replay implementation  
Date: 2026-07-16

## Context

CACIS W3 can identify research opportunities, but recurring investigation without explicit cost, pressure, and time semantics would create unbounded resource consumption and confidence laundering. A single global freshness window is also unsafe because endpoint, identity, recovery, threat-intelligence, architecture, and capability evidence decay at different rates.

## Decision

Implement W4 as a deterministic, replay-only scheduling layer beneath constitutional authority.

Every work item carries an exact nine-dimensional cost vector, expected information gain, expected risk reduction, expected recovery improvement, affected health signals, prerequisites, observation time, and one of seven domain clocks. The Governor may order and lease bounded work but cannot authorize it. Resource exhaustion produces an explicit deferral. Expired evidence produces abstention.

Homeostasis retains thirteen signals without collapsing them into a success score. Confidence inflation is independently recomputed from the W3 confidence vector, and verifier backlog remains visible. W4 emits only a content-addressed schedule proposal with immutable false authority.

## Consequences

- Idle-cycle or recursive research cannot proceed without a bounded resource proposal.
- Fast endpoint evidence and slow architecture evidence no longer share one misleading clock.
- Health pressure can reprioritize work but cannot widen permissions.
- W5 may consume W4 evidence only after separate evaluation gates; W4 cannot promote a theory or genome.
- Production scheduling, external time, continuous sensing, and operating-system resource enforcement remain unproven.

## Rejected alternatives

- One scalar health or utility score that averages away hard failures.
- A global timestamp or time-to-live for every security domain.
- Automatic work execution after a successful allocation.
- Allowing high threat pressure, high confidence, or an empty backlog to increase authority.
