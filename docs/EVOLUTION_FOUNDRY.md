# Constitutional Evolution Foundry

## Current state

`DEPLOYMENT_ASSURANCE_RACE_CLOSED_EFFECTIVE_ACCESS_OBSERVED_CUSTODY_AND_PHYSICAL_POWER_LOSS_BLOCKED`

The Foundry is a no-execution reference architecture for governed recursive improvement. It compiles a quarantined planning candidate, records it in immutable content-addressed storage, verifies evaluator identity and evidence through signed envelopes, accounts for resources across the full candidate lineage, evaluates supplied simulated evidence in a separate process, and accepts a threshold-signed transition into a shadow-only registry through a third process.

It does not call a model API, train or modify weights, execute candidate code, modify the active baseline, access sealed answers, provision compute, obtain credentials, connect to a network, replicate, persist outside its explicit local state root, or authorize production.

## Separation of powers

1. **Foundry worker:** receives the signed constitution, immutable baseline, epistemic posture, resource lease, and v0.1 planning candidate. It hashes and discards proposed mutation material, emits a quarantined candidate bundle, and writes only to the candidate artifact store.
2. **Evaluator worker:** receives the immutable candidate, a threshold-signed evaluator policy, four individually signed evaluator observations, four threshold-certified isolation attestations, and a threshold-signed lineage resource ledger. It verifies every binding before emitting an assurance receipt, capability-threshold report, and lexicographic evaluation vector. It has no signing or promotion capability.
3. **Promoter worker:** verifies an externally signed transition envelope and atomically records shadow registration, demotion, or rollback. It cannot generate candidates, edit evaluations, execute a candidate, modify the baseline, or authorize production.

Validation proves distinct OS process IDs for these three surfaces. It does not yet prove distinct OS accounts, binaries, administrators, machines, or supply chains.

## Evolution Constitution

The Constitution is short-lived, domain-separated canonical JSON signed by 2-of-3 governance keys across at least two roles. Its exact contents include:

- 20 non-waivable axioms;
- eight lexicographic hard failures;
- six capability triggers and mandatory responses;
- Tier A through D promotion ceilings;
- cycle, compute, memory, storage, and child-candidate ceilings;
- immutable false self-modification, evaluator-selection, signer-selection, authority-expansion, and execution fields.

The candidate system cannot alter the Constitution. Validation keys remain ephemeral and simulated; real custody is unproven.

## Epistemic posture

Philosophical modes become typed operational metadata:

- deterministic reasoning requires exact proof;
- probabilistic reasoning requires calibrated evidence;
- plural-context reasoning requires explicit context boundaries.

Every claim is typed. A counterfactual cannot be relabeled as observed fact, and no posture can waive a hard failure.

## Candidate-only mutation

The active baseline is immutable and denies candidate writes. The Foundry migrates improvement-candidate v0.1 into a candidate bundle containing only digests, provenance, prediction, uncertainty, budgets, rollback commitment, and false authority. Proposed mutation content is hashed and not retained in the compiled bundle.

The initial resource lease cannot self-extend or purchase compute. Exceeding any constitutional ceiling raises an explicit error.

## Lexicographic evaluation

Four independent logical roles are required: public regression, sealed holdout, adversarial evaluation, and rights/recovery. Evaluations also require all eight hard gates and five champion floors. No scalar or aggregate score field is accepted.

Any failed or inconclusive evaluator, hard gate, champion regression, regressed/unknown metric, unbounded uncertainty, capability escalation, or ineligible authority tier blocks shadow registration.

Evaluator independence is no longer represented by role names alone. A threshold-signed policy pins four evaluator identities, roles, logical principals, OS accounts/SIDs, and public keys. Each evaluator signs a short-lived observation envelope binding its identity and process to the exact candidate, Constitution, capability report, evaluation-input digest, resource ledger, isolation attestation, result, and evidence. Substitution, expiry, signature forgery, identity collapse, digest drift, or an unsigned observation fails before evaluation.

## Isolation and resource assurance

Each evaluator observation requires a threshold-certified OS isolation attestation with seven exact controls: credential isolation, dedicated OS account, distinct process, executable identity, denied network egress, OS-enforced read-only input ACL, and a separate output ACL. The reference fixtures prove the contract and signature path only. Their `simulated` origin and fixture collector force `live_os_enforcement_verified: false`, so they cannot unlock production.

The lineage resource ledger is threshold-signed and hash-chained. Every entry binds a candidate to its parent, lease, measured cycle/compute/memory/storage use, and child-candidate count. Totals are recomputed across the lineage and checked against the signed Constitution. Entry deletion, reorder, parent substitution, hash drift, signer failure, resource overrun, or child-count laundering fails closed.

### Platform-assurance implementation

The first deployment-facing assurance slice is deliberately read-only and non-promoting:

- A separate Windows collector process measures the target process image, token SID, credential-like environment-key categories, input/output DACL effective rights, firewall profiles, and exact-executable block rules without reading credential values, changing ACLs/firewall state, probing the network, or executing a candidate. It emits a threshold-signed live isolation attestation. On the current desktop it verifies distinct-process and executable-identity controls only; the target shares the desktop SID, can write input, both processes can write output, and no all-traffic target block rule exists.
- A strict TypeScript/Node verifier independently implements canonical JSON, SHA-256, raw-key Ed25519 verification, governance quorum semantics, evaluator-envelope binding, seven-control isolation semantics, and lineage-ledger verification. It shares contract data with Python but imports no Python verification logic. Rust remains the preferred future privileged implementation; it was not installed in this project environment, so the conformance lane uses a pinned project-local TypeScript toolchain.
- A Windows Job Object meter creates a benign worker suspended, assigns it to a memory-limited kill-on-close Job before first resume, measures CPU, memory, storage, and I/O, publishes flushed records with write-through atomic rename, and recovers the receipt in a separate process after abrupt termination. The receipt binds into the signed lineage ledger. This proves process-crash recovery, not storage-controller or physical power-loss durability.
- A read-only custody collector enumerates CNG storage providers and queries TPM management state without creating or deleting a key, signing, exporting private material, or authorizing production. This machine exposes the platform provider, but TPM management access, a hardware key reference, provider attestation, and an independent custody operator remain blockers.

These measurements improve evidence quality but do not change Foundry authority. A live origin means the host was observed, not that the complete isolation boundary or production promotion gate passed.

## Capability-triggered safeguards

The Foundry evaluates autonomous AI R&D, long-range autonomy, replication/adaptation, persistence/resource acquisition, sandbagging, and safeguard undermining. Unknown evidence pauses. Present replication, persistence, sandbagging, or safeguard-undermining evidence pauses. Autonomous AI R&D requires an isolated enclave; long-range autonomy requires elevated safeguards. The current promoter accepts only a clear baseline-level report.

## Transition state

The transition envelope binds the exact candidate, evaluation, capability report, Constitution, and active baseline. Tier A/B may register in shadow. Tier C/D, production, canary execution, and active-baseline replacement are unavailable.

Publication writes and flushes a private temporary receipt before one atomic hard-link transition. A pre-publication crash is retryable; a post-publication crash preserves the receipt. Sixteen simultaneous registrations yield exactly one acceptance and 15 replay denials. Signed demotion is independently validated.

## Evidence and residual risk

The Foundry harness covers 36 adversarial cases across constitutional weakening, signature thresholds, epistemic laundering, resource expansion, baseline mutability, capability omission, hard-failure averaging, scalar injection, evaluator collapse, champion regression, transition substitution, authority widening, CAS corruption, crash recovery, replay, and contention. The assurance harness adds ten adversarial cases for evaluator-policy substitution, signature forgery, identity/role mismatch, observation expiry, isolation-attestation substitution, missing isolation controls, ledger tamper, lineage overrun, and authority widening.

Still unproven: real model or architecture generation, evaluator quality, sealed-test secrecy, live distinct OS identities, enforced ACL separation, denied network egress, hardware-backed signing-key custody, independent custody operations, physical power-loss durability, energy and cost metering, real canary behavior, production compatibility, online learning, model-weight changes, enclave isolation, and beneficial recursive capability improvement.

## Next boundary

The next safe boundary is deployment-grade evaluator isolation: provision dedicated service accounts/SIDs, apply and independently verify read-only input plus separated output ACLs, enforce default-deny egress, separate collector administration, bind real non-exportable hardware keys with attestation and human custody, and run an operator-approved sacrificial-host power-loss campaign. Production promotion and candidate execution remain separate later decisions.
