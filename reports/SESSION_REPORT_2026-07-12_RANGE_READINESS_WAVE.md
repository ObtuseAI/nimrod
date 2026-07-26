# Range-readiness wave session report

Date: 2026-07-12  
Scope: threshold-signed adapter policy, read-only local corpus compatibility, and disposable-range preflight  
Status: `RANGE_READINESS_GATES_VALID_CONNECTION_BLOCKED`

## Delivered

- Added a domain-separated short-lived 2-of-3 Ed25519 adapter-policy envelope with exact policy/governance digest binding, active-key checks, signer uniqueness, role diversity, and immutable false authority.
- Added an exact read-only local Atomic/Caldera corpus scanner. It rejects fetch/compile/execute authority, path escape, symlinks, duplicate identities/paths, snapshot mismatch, missing/unexpected YAML, source drift, unsafe imports, and unpinned mappings.
- Added a fresh nine-control disposable-range preflight. It binds the signed policy and corpus report and cannot authorize installation, connection, or execution.
- Added five Draft 2020-12 contracts and canonical examples, five contract semantics, a full integration/adversarial harness, doctrine decisions ADR-042 through ADR-044, and threat path TM-34.
- Repaired a prepared-record publication race exposed by the broader regression ladder: authorization state now writes and flushes a private temporary record before atomically publishing a complete hard link. Three consecutive 128-process contention runs passed after the fix.

## Validation evidence

- Contract harness: 33 schemas, 33 positive examples, 33 negative mutations, 28 semantic families, one migration.
- Range-readiness harness: two valid policy signers across two roles, two compatible local fixture entries, nine required preflight controls, and 31 adversarial cases.
- Authorization-state regression after the publication fix: three consecutive passes, 384 process claims, exactly one success in each contention round, and 372 replay denials.
- Canonical real preflight state: blocked because all nine environment controls are unproven.
- Contract-only all-proven state: connection evidence gate satisfied, while installation, connection, and execution authorization remain false.

## Authority and activity record

- Offensive tools installed or launched: false.
- Source tools contacted: false.
- Network access performed: false.
- Range connected: false.
- Agent or payload deployed: false.
- Compilation performed by the corpus scanner: false.
- Live execution performed: false.
- Connection or execution authorized: false.

## Remaining blockers

Real signing custody, trusted time, dedicated service identity and read-only ACL, disposable infrastructure, dedicated credentials, default-deny egress, out-of-band kill, snapshot restoration, cleanup, telemetry separation, independent verification, upstream tool compatibility, and any range connection remain unproven.

## Shared handoff

Canonical handoff directory: `Z:\nimrod-range-readiness-20260712-204632`. The directory carries the mechanically generated v12 foundation manifest; archive digest and copy audit are stored beside it in the shared destination.
