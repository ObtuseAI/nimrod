# Range evidence completion

Status: `RANGE_EVIDENCE_COMPLETION_SIGNED_DENIAL_RETAINED_REAL_COMPLETION_BLOCKED`

This boundary separates independently accepted evidence from the authority to mark an evidence packet complete. It implements backlog item `nim-105` without creating collection, connection, or execution capability.

## Three-document gate

1. A short-lived 2-of-3 signed completion policy binds the exact acceptance report, scope, environment, all nine required controls, nine accepted controls, nine verified attestations, and at least two real independent verifiers.
2. A separate short-lived 2-of-3 authorization records either `authorize_completion` or `deny_completion`. Simulated evidence can only be denied.
3. A deterministic receipt records the decision. A successful real path may set `evidence_complete: true`, but always leaves range connection and execution authorization false.

The policy has no operational authority. The authorization can grant only the narrow transition `can_mark_evidence_complete`; it can never collect, install, provision, mutate policy, access credentials, connect, execute, or authorize an action. The resulting receipt has no authority at all.

## Canonical state

The canonical policy and authorization each have two valid governance signatures. The authorization explicitly denies completion because the input is simulated, no range is owner-named, accepted controls and verified attestations are zero, and real independent verifiers are zero. The receipt retains every blocker and reports:

- `completion_prerequisites_satisfied: false`
- `completion_authorized: false`
- `evidence_complete: false`
- `range_connection_authorized: false`
- `execution_authorized: false`

## Positive contract path

The harness also constructs a real-shaped, owner-named sacrificial-range acceptance report with nine accepted controls, nine verified attestations, two real independent verifiers, and a threshold-signed completion authorization. That path produces `evidence_complete_pending_separate_connection_authorization`. It proves the transition semantics only; it is not evidence that such a range or observations exist.

## Validation and residual risk

`tools/validate_range_evidence_completion.py` regenerates the three canonical examples, verifies policy and authorization thresholds, validates exact bindings and freshness, proves real completion remains non-operational, and rejects 36 adversarial cases. The contract harness independently validates all three Draft 2020-12 schemas and semantic invariants.

The remaining operational prerequisite is an owner-supplied immutable sacrificial-range identity. Real collection, independent verifier deployment, external evidence retention, and connection authorization require later separately approved work.
