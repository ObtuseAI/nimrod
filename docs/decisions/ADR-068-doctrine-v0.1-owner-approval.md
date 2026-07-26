# ADR-068: doctrine v0.1 owner approval

Status: `ACCEPTED_BY_OWNER`  
Decision owner: project owner  
Decision date: 2026-07-15  
Review date: before any doctrine change or Stage 2 privileged implementation

## Context and threat-model impact

The Stage 0 backlog required explicit owner approval before the doctrine could govern implementation. The owner directed completion of the recommended decision-record wave, which explicitly included formalizing the doctrine, Windows-first Edge wedge, and private identity and distribution boundary. The latter decisions already have accepted ADRs; this record closes only the missing doctrine approval.

The doctrine constrains every Edge, Crucible, AI, update, recovery, evidence, and product-claim path. Approval does not authorize privileged installation, live containment, offensive execution, source staging, construction-zone provisioning, external distribution, or public launch.

## Options considered

1. Keep doctrine at draft status and block implementation.
2. Approve doctrine v0.1 as written while preserving its change protocol.
3. Approve selected clauses and leave the remaining constitution undefined.

## Decision and consequences

Option 2 is accepted. `docs/DOCTRINE.md` version 0.1 is the governing constitution for private Stage 0 and unprivileged Stage 1 work.

- Deterministic authorization remains separate from analysis and model output.
- Evidence, uncertainty, dissent, degraded state, and residual risk remain visible.
- Edge remains the first product; Crucible retains separate execution gates.
- No product or component may widen its own authority.
- A future doctrine change requires the complete doctrine change protocol and a new owner decision.

## Privacy, data, and authority changes

This decision creates no data collection, credential, network, execution, provisioning, release, or distribution authority. Local-first and no-raw-centralization defaults remain binding.

## Migration and rollback

Existing specifications already target the approved doctrine and need no migration. Rolling back this approval returns doctrine to draft status and blocks further implementation decisions; it does not weaken any existing safety boundary.

## Validation evidence

- Owner directive dated 2026-07-15 to complete the recommended wave that included Stage 0 decision formalization.
- ADR-002 and ADR-016 preserve the Windows-first Edge and dual-surface product boundary.
- ADR-001, ADR-009, ADR-021, and ADR-024 preserve lowercase private identity, private repository, and no-license boundaries.
- Repository validators continue to enforce lowercase naming and literal launch blockers.

No cryptographic owner signature is claimed by this record.
