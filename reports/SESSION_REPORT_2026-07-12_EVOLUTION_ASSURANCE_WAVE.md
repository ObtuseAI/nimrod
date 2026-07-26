# nimrod evolution assurance wave

## Session outcome

Status: `EVOLUTION_ASSURANCE_VALID_SHADOW_ONLY_LIVE_OS_AND_PRODUCTION_BLOCKED`

This wave replaced trust-by-boolean in the recursive-improvement path with signed, subject-bound assurance contracts. It also added lineage-wide resource accounting and a display-only Evolution Foundry workspace. The work remains an uncommitted review state on `main` after baseline commit `e178ed3`; no Git commit or remote update was requested in this wave.

## Implemented controls

- A threshold-signed evaluator trust policy pins four evaluator IDs, roles, logical principals, OS accounts/SIDs, and Ed25519 public keys.
- Four individually signed observation envelopes bind evaluator identity and process to the candidate, Constitution, capability report, evaluation input, resource ledger, isolation attestation, evidence, status, and expiry.
- The evaluator worker accepts only the signed assurance path and emits a typed assurance receipt before lexicographic evaluation.
- Four threshold-certified OS isolation attestations each require seven exact controls: credential isolation, dedicated OS account, distinct process, executable identity, denied network egress, OS-enforced read-only inputs, and separate output ACLs.
- A threshold-signed, hash-chained lineage ledger binds candidate parents, leases, actual cycle/compute/memory/storage use, child counts, cumulative totals, Constitution, and governance state.
- The verifier board consumes verified isolation attestations instead of accepting a raw ACL boolean.
- The Evolution Foundry projection shows signed evaluator identity, isolation state, lineage resources, and shadow eligibility while fixing promotion, execution, evaluator modification, and resource expansion to false.

## Contracts and implementation

Six Draft 2020-12 schemas and examples were added for OS isolation attestations, evaluator trust policy, evaluator observation envelopes, lineage resource ledgers, assurance receipts, and the Foundry board projection. Four focused simulator modules implement isolation verification, evaluator assurance, resource accounting, and board projection. Existing control-board and Foundry worker paths were migrated to consume the new evidence.

## Validation evidence

- Contract harness: 53 schemas, 53 positive examples, 53 negative mutations, 48 semantic contracts, and the existing migration.
- Assurance harness: four signed evaluator observations, four threshold-certified isolation attestations, seven controls per process, one within-Constitution lineage entry, and ten adversarial cases.
- Foundry regression: 20 axioms, eight hard gates, six capability triggers, five champion floors, three separated worker processes, 36 adversarial cases, two crash boundaries, and exactly one acceptance under 16-way contention.
- Control-board regression: four Foundry evaluator cards, six verifier states, seven verifier projection negative cases, canonical example/UI equality, and false production readiness.
- Browser QA: desktop and 390-pixel mobile layouts, Evolution Foundry tab interaction, no horizontal overflow, and zero console errors.

## Honest boundary

All origins and keys are simulated fixtures. The reference did not call a model API, execute a candidate, modify the baseline, contact a network or target, acquire credentials, expand compute, replicate, persist autonomously, or authorize production. Fixture-origin isolation attestations prove contract behavior only and force `live_os_enforcement_verified: false`. Real service accounts/SIDs, ACL inspection, executable measurement, denied-egress enforcement, independent collectors and implementations, HSM/KMS custody, durable host metering, and production behavior remain unproven.

## Next safe boundary

Build a deployment-grade isolation collector and evaluator service package under real restricted identities, then validate its attestations from an independent administrator context. Keep candidate execution and production promotion closed until that evidence, independent evaluator quality evidence, custody, durable metering, and rollback behavior are separately authorized and proven.
