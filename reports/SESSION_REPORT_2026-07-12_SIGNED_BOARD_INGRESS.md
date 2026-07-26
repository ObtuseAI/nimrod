# Session report: signed control-board ingress

Date: 2026-07-12  
Project: `nimrod`  
Scope: next items 7 and 8; signed freshness-bound supervisor snapshots and durable anti-replay board ingress  
Outcome: `FOUNDATION_CONTROL_BOARD_SIGNED_INGRESS_VALID_OS_ACCOUNT_BLOCKED`  
Execution posture: simulated, local, no execution

## Delivered state

The supervisor-to-board boundary no longer relies on an unsigned local projection. A domain-separated control-board snapshot binds the exact verifier-projection digest, supervisor identity, board audience, evidence origin, governance-state digest, issuance/activation/expiry window, monotonic sequence, predecessor digest, and immutable false authorization/execution fields. A 2-of-3 Ed25519 governance quorum with at least two roles signs the canonical bytes.

The filesystem ingress connector validates signatures and freshness before mutation. It persists an immutable preparation, exclusive sequence owner, acceptance record, and bound head. Recovery completes an owned transition after a process interruption; an unowned preparation remains quarantined. The next snapshot must be exactly consecutive and bind the current accepted snapshot digest.

The verifier mesh now displays the signed-ingress status, issuer, audience, sequence, freshness, signer/role counts, replay guard, stale-state guard, and snapshot digest. A valid transport receipt does not change the unresolved production boundary: the board remains `boundary_unproven`, verification acceptance remains false, and execution remains false.

## Validation evidence

- 25 Draft 2020-12 schemas and canonical examples pass, with 25 negative mutations and 20 semantic families.
- A generated signed snapshot and generated ingress receipt validate against their public contracts.
- A two-snapshot predecessor chain persists across store restart.
- Four injected crash boundaries recover without double acceptance.
- Sixteen concurrent attempts produce exactly one acceptance and fifteen replay denials.
- Eighteen adversarial cases deny signature tamper, insufficient or duplicate signers, projection/governance/issuer/audience substitution, projection authority injection, stale, future, timezone-free, and overlong snapshots, replay, rollback, sequence gap, predecessor substitution, record tamper, and head tamper.
- Desktop rendering shows signed/fresh simulated transport beside the literal `boundary_unproven` verifier state.
- The 390-pixel responsive check has no horizontal overflow; verifier-tab interaction succeeds with zero browser console warnings or errors.
- No C2, offensive connector, active-response tool, credential, target control, or live execution path was installed or invoked.

## Residual blockers

- dedicated Windows verifier service account/SID not provisioned;
- OS-enforced read-only ACL not proven;
- production supervisor/IPC identity and secure clock not proven;
- real HSM/KMS custody and external anti-rollback pin not proven;
- power-loss and hostile privileged-deletion durability not proven;
- real range, sacrificial-replica, and live evidence absent.

## Next recommended increment

Design the first fixture-only isolated-range adapter boundary for Atomic Red Team and Caldera using the existing typed connector contract. The increment must compile imported definitions into allowlisted no-execution steps, reject arbitrary commands and target discovery expansion, emit simulated receipts only, and leave all tool installation and range execution behind a later explicit gate.

No commit or GitHub repository change was made.
