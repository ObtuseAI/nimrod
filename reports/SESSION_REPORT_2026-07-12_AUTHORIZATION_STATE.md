# nimrod authorization-state recovery and concurrency session report

Date: 2026-07-12  
Outcome: `FOUNDATION_AUTHORIZATION_STATE_RECOVERY_AND_CONCURRENCY_VALID`  
Scope: Sprint 3 items 1 and 2 only; no-execution authorization state, crash recovery, failure injection, and concurrent nonce claiming

## Delivered state

The simulator now uses a three-stage single-use authorization-state protocol:

1. A complete prepared claim is written and file-synchronized before ownership is attempted.
2. A fully synchronized owner record is published through an exclusive atomic hard link. Exactly one process can publish it, and readers never observe a partially written owner record.
3. A committed consumed-nonce record is published. If the process dies after ownership, a later process reconstructs the commit from the durable preparation.

A crash before ownership leaves an explicit orphan preparation and permits a safe retry because no simulated action could have passed the claim boundary. A crash at or after owner creation permanently consumes the nonce. If an owner marker survives without usable identity material, recovery writes a `consumed_ambiguous` tombstone instead of allowing reuse. A malformed committed record blocks store initialization with `AuthorizationStateIntegrityError`.

## Process-level evidence

| Validation | Result |
|---|---:|
| Abrupt OS-process exit points | 5 |
| Post-ownership crash points that recovered fail closed | 4 / 4 |
| Pre-ownership crash points safely retried | 1 / 1 |
| Simultaneous OS processes per contention round | 32 |
| Contention rounds | 4 |
| Total process claim attempts | 128 |
| Successful claims | 4 |
| Replay denials | 124 |
| Exactly one success in every round | yes |
| Ambiguous owner tombstone cases | 1 / 1 |
| Corrupt committed-state denials | 1 / 1 |
| Owner/preparation/commit mismatch denials | 1 / 1 |

The failure worker terminates with `os._exit(91)` at the selected persistence boundary. The concurrency proof starts independent Python processes behind a shared gate and reads one result artifact per process. It does not substitute threads, mocks, or an in-memory lock for filesystem contention.

## Regression evidence

- Foundation: 74 required files, 30 parsed JSON documents, lowercase brand enforced.
- Contracts: 12 schemas, 12 positive examples, 12 negative mutations, 7 semantic families, 1 migration.
- Simulator: API, CLI, independent verifier, 25 fail-closed cases, no live execution.
- Swarm: API, CLI, independent verifier, 13 fail-closed cases, 7 roles, dissent preserved, execution authority false.
- Control board: local-only resources, 4 responsive breakpoints, execution authority false.
- Python policy: 21 checked files, zero default parameters, zero untyped function signatures.
- Dependencies: project environment reports no broken requirements.

## Files added or materially changed

- `src/nimrod_simulator/state_journal.py`
- `src/nimrod_simulator/errors.py`
- `src/nimrod_simulator/runtime.py`
- `src/nimrod_simulator/witness.py`
- `tools/authorization_state_worker.py`
- `tools/validate_authorization_state.py`
- `tools/validate_simulator.py`
- `tools/validate-foundation.ps1`
- `reports/AUTHORIZATION_STATE_VALIDATION.json`
- current-state README, master plan, backlog, decision register, threat model, and launch gate

## Safety and claim boundary

- No connector, payload, target, network, shell, model, or agent execution path was added.
- No offensive tool was installed or launched.
- The proof is local, simulated, and unprivileged.
- The evidence establishes tested process-crash behavior, not sudden-power-loss durability, hostile privileged-storage resistance, network-filesystem correctness, or production security.
- Public launch remains `BLOCKED_NO_DEPLOYABLE_PRODUCT`.

## Next recommended increment

Proceed to Sprint 3 item 3: production-shaped key governance with 2-of-3 ceremonies, rotation, revocation, lost-key and compromised-signer recovery, and connector interfaces for HSM/KMS custody. External Witness anchoring and the separately supervised verifier service remain later items; isolated range integration remains blocked until those trust-root gates pass.

## Shared handoff

The verified handoff root is planned as `nimrod-authorization-state-20260712-165313` in the FRANKENSTEIN shared folder. Its sibling `copy_proof.json` records source and destination counts, manifest verification, archive membership, and archive SHA-256 after the final copy is complete.
