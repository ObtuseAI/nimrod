# Range lifecycle wave session report

Date: 2026-07-12  
Scope: declaration-only topology, irreversible kill/revocation state, and snapshot/cleanup verification  
Status: `RANGE_LIFECYCLE_GATES_VALID_ENVIRONMENT_AND_CONNECTION_BLOCKED`

## Delivered

- Added exact three-zone, three-node, two-route disposable topology contracts and a pure validator that cannot provision, connect, or execute.
- Added a short-lived 2-of-3 Ed25519 kill command bound to the topology generation and governance state.
- Added an atomically published one-way filesystem kill state. There is no disengage or reset transition; replay and conflict fail closed.
- Added snapshot/cleanup evidence and receipts requiring six obligations and two distinct verifier identities, principals, and processes.
- Added six Draft 2020-12 contracts and examples, six semantic validators, ADR-045 through ADR-047, and threat path TM-35.
- Refactored range policy and kill documents onto a reusable domain-separated threshold-signing primitive without changing the range-readiness result.

## Focused validation evidence

- Contract harness: 39 schemas, 39 positive examples, 39 negative mutations, 34 semantic families, and one migration.
- Lifecycle harness: 38 adversarial cases.
- Process-crash proof: one crash before state publication remains retryable; one crash after publication preserves engagement and denies replay.
- Contention proof: 16 simultaneous valid kill attempts produce one accepted engagement and 15 replay denials.
- Canonical recovery state: blocked because no real environment or cleanup evidence exists.
- Contract-only verified recovery: snapshot and obligations verified in fixtures while kill remains engaged and reuse/connection/execution remain false.

## Authority and activity record

- Infrastructure provisioned: false.
- Network or source tool contacted: false.
- Offensive tools installed or launched: false.
- Range connected: false.
- Agent or payload deployed: false.
- Kill disengagement implemented or authorized: false.
- Range reuse authorized: false.
- Live execution performed: false.

## Remaining blockers

Actual isolation, network enforcement, dedicated credentials, trusted time, independent kill infrastructure, provider snapshot semantics, cleanup, restoration, verifier OS identities, hardware-backed signing, power-loss durability, connector capability review, provisioning, and range connectivity remain unproven.

## Shared handoff

Canonical handoff root: `Z:\nimrod-range-lifecycle-20260712-212200`; canonical project copy: `Z:\nimrod-range-lifecycle-20260712-212200\nimrod`. The v13 manifest travels inside the project copy; archive digest and copied-tree validation proof are stored beside it in the shared folder.
