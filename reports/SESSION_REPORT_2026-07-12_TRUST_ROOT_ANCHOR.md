# nimrod key governance and external Witness anchor session report

Date: 2026-07-12  
Outcome: `FOUNDATION_KEY_GOVERNANCE_AND_EXTERNAL_WITNESS_ANCHOR_VALID`  
Scope: Sprint 3 items 3 and 4; simulated trust-root lifecycle, custody connector boundary, signed Witness transparency roots, external receipts, and independent pinned heads

## Delivered key governance

- Exactly three active Ed25519 governance keys per epoch.
- 2-of-3 authorization with at least two distinct separation-of-duties roles.
- Prior-epoch signatures authorize consecutive state transitions; a next state never authorizes itself.
- Positive ceremonies cover rotation, lost-key recovery, compromise recovery, and revocation.
- Every ceremony terminalizes the affected key and adds a replacement while retaining historical records.
- Retired, revoked, lost, and compromised statuses are monotonic.
- Key IDs and public material are unique; immutable identity, role, algorithm, custody, and validity-start fields cannot be rewritten.
- Custody is non-exportable and sign-only. PKCS#11, AWS KMS, Azure Key Vault, and Google Cloud KMS are declared connector kinds; production kinds require hardware-backed custody and an attestation digest.
- Validation uses in-memory ephemeral keys only. No private key is written or committed and no provider call is made.

The key-governance harness validates four positive transitions and fifteen fail-closed attacks, including insufficient or duplicate quorum, lost/compromised signers, threshold downgrade, exportability, operation widening, missing attestation, missing replacement, digest substitution, affected-key omission, terminal-key resurrection, public-key reuse, future transition, and epoch rollback.

## Delivered Witness anchoring

- A verified journal prefix is committed by tree size, canonical prefix digest, latest entry digest, and a domain-separated SHA-256 Merkle root using the RFC 9162 tree shape.
- Every checkpoint binds governance ID, epoch, full governance-state digest, prior checkpoint digest, and 2-of-3 active governance signatures.
- A separate non-nested anchor root stores checkpoints by digest and issues a separately signed monotonic receipt and signed head for every sequence.
- Receipts and heads bind the exact anchor-policy digest.
- Every historical head is verified against its matching receipt and checkpoint.
- A third non-nested root retains an independently observed monotonic signed head.
- The verifier accepts an older valid pin only when the complete receipt/checkpoint/head history advances consistently, and rejects an anchor older than or different from the pin.
- An independent OS process verifies governance, the full journal, checkpoint quorum, Merkle roots, policy binding, receipt/checkpoint chains, complete head history, and the pin.

The anchor harness validates two growing checkpoints over five entries plus sixteen fail-closed cases covering artifact tamper, journal truncation/reorder, receipt/checkpoint/head tamper, forked chain, pinned rollback, governance substitution, Merkle substitution, one-signer checkpoint, policy/key substitution, nested roots, and missing current head.

## Contract and regression state

- Contracts: 18 Draft 2020-12 schemas, 18 positive examples, 18 negative mutations, 13 semantic families, 1 explicit migration.
- Foundation: 94 required files and 44 parsed JSON documents before this session report and final manifest.
- Key governance: `KEY_GOVERNANCE_VALID`.
- External Witness anchor: `WITNESS_EXTERNAL_ANCHOR_VALID`.
- Live execution: false.
- External custody provider calls: zero.
- External network anchor calls: zero.
- Offensive tools installed or launched: false.

## Safety and residual boundary

This is a simulated local reference, not production key custody and not a public transparency service. It does not establish HSM/KMS provider identity, attestation validity, audit delivery, retry behavior, deletion, insider controls, disaster recovery, trusted time, split-view resistance, gossip, external availability, multi-region consensus, storage-controller power-loss durability, or any live security outcome.

Public launch remains `BLOCKED_NO_DEPLOYABLE_PRODUCT`. Isolated range adapters remain blocked behind the remaining trust-root and supervised-verifier gates.

## Next recommended increment

Proceed to Sprint 3 item 5: a separately supervised verifier service running under a distinct OS identity with read-only Witness/anchor access, no planner/executor credentials, health and timeout evidence, and literal verifier-disagreement states. Then integrate these signed trust-root and anchor states into the control board before beginning isolated range alpha.

## Shared handoff

The verified handoff root is planned as `nimrod-trust-root-anchor-20260712-174118` in the FRANKENSTEIN shared folder. Its sibling `copy_proof.json` records manifest verification, shared-path validator results, archive membership, and archive SHA-256 after the final copy is complete.
