# nimrod platform assurance wave

## Session outcome

Status: `PLATFORM_ASSURANCE_LIVE_OBSERVED_INDEPENDENT_CONFORMANCE_VALID_BOUNDARY_INCOMPLETE_PRODUCTION_BLOCKED`

This wave completed the next three platform-assurance items: read-only live Windows isolation observation, an independent second-language evaluator verifier, and durable Windows resource metering with signed lineage binding. The work remains an uncommitted review state on `main`; no Git commit or remote update was requested.

## 1. Read-only Windows isolation collector

- Runs in a process separate from the benign measured target.
- Reads the process image, token SID, credential-like environment-key categories, input/output security descriptors, and Windows Firewall profile configuration.
- Hashes sensitive identifiers and raw platform evidence; it never reads credential values.
- Performs no ACL or firewall modification, active network probe, candidate execution, target discovery, or production action.
- Emits and verifies a threshold-signed live isolation attestation with seven exact controls.
- Current desktop result: two controls verified and five blockers preserved: `CREDENTIAL_ISOLATION`, `DEDICATED_OS_ACCOUNT`, `NETWORK_EGRESS_DENIED`, `READ_ONLY_INPUT_ACL`, and `SEPARATE_OUTPUT_ACL`.

## 2. Independent evaluator conformance

- Uses pinned project-local TypeScript 5.9 and Node 24 types; Rust was not available in the project environment.
- Independently implements canonical JSON, SHA-256, raw-public-key Ed25519 verification, governance thresholds and role diversity, evaluator trust and envelope binding, isolation semantics, resource-ledger chains and ceilings, expiry, and immutable false authority.
- Imports no Python verification logic.
- Rejects eight adversarial bundles covering signature tamper, role collapse, expiry, candidate substitution, missing isolation controls, ledger-total tamper, authority widening, and insufficient quorum.
- This proves implementation diversity for contract verification, not independent ownership, custody, sealed-evaluator quality, or live production isolation.

## 3. Windows resource meter

- Creates a Windows Job Object with a process-memory ceiling and kill-on-close.
- Assigns and measures only a benign local worker; no candidate/model/tool payload is executed.
- Records actual CPU, peak memory, storage, and I/O evidence.
- Publishes immutable prepared, observation, and completed records.
- Recovers a receipt after an injected post-observation process crash without rerunning work and denies replay, duplicate recovery, record tamper, subject/lease substitution, authority widening, ledger tamper, and resource overrun.
- Converts the measured receipt into a signed candidate-lineage ledger entry that remains within the Constitution.
- Explicitly preserves `ASSIGNMENT_RACE_UNPROVEN` and `POWER_LOSS_DURABILITY_UNPROVEN`.

## Contracts and operator surface

Three Draft 2020-12 schemas and examples were added for the evaluator conformance bundle, resource-meter receipt, and Windows isolation measurement. The contract ladder now covers 56 schemas, 56 positive examples, 56 negative mutations, 51 semantic contracts, and one migration. The Evolution Foundry control board now shows the partial live isolation result, independent TypeScript verifier, Job Object lineage receipt, and all remaining blockers without adding authority.

## Validation evidence

- Windows isolation: one threshold-signed live attestation, seven controls, two verified controls, five blockers, and six adversarial cases.
- Independent evaluator: four evaluator envelopes, four isolation attestations, one resource-ledger entry, independent canonical JSON and Ed25519 verification, and eight adversarial cases.
- Resource meter: live Job Object assignment, kill-on-close, measured CPU/memory/storage, one injected process-crash recovery boundary, signed lineage conformance, and eight adversarial cases.
- Production promotion, candidate execution, host-policy mutation, credential-value access, model/API use, and network access remain false.

## Honest boundary and next safe step

Live observation is not complete enforcement. The next safe boundary is a dedicated service-account deployment with effective-access ACL verification, deny-by-default egress and independent observation, suspended process creation before Job Object assignment, administrator-separated collection, hardware-backed governance custody, and journaled power-loss testing. Candidate execution and production promotion remain separately gated later decisions.
