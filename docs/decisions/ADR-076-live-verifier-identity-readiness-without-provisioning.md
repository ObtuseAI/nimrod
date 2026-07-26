# ADR-076: Live verifier identity readiness without provisioning

Status: `ACCEPTED_IMPLEMENTATION_LIVE_READ_ONLY_BLOCKED`
Decision owner: operator
Authority change: none

## Context

Distinct processes do not establish independent verification when they share one desktop identity, writable inputs, ambient egress, administration, or signing custody. Creating service accounts, changing ACLs, changing firewall policy, or provisioning keys would alter the host and requires a separate operational decision.

## Decision

Probe the World Model intake, Constitutional Intelligence Research, and Observatory verifier identity surfaces with three benign hold-open processes. Launch each with an allowlisted credential-free environment; collect its Windows process identity and effective input ACL from another process; perform no active network operation; and preserve every unmeasured control as false.

The evidence may prove process distinctness and expose blockers. It cannot create an account, modify an ACL or firewall rule, provision custody, claim separate administration, or make a verifier production eligible.

## Consequences

The current desktop proves three distinct processes and zero dedicated accounts, zero read-only input ACLs, zero enforced-egress proofs, zero separately administered identities, zero production custody, and zero production-eligible verifier surfaces. Future readiness requires separately authorized infrastructure and independently retained evidence.

## Validation

`tools/validate_verifier_identity_readiness.py` collects the live evidence and rejects eight removal, process-reuse, identity, ACL, egress, custody, production, and authority mutations.
