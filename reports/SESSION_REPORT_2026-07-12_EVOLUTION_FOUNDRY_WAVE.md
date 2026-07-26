# Constitutional Evolution Foundry implementation report

Date: 2026-07-12  
Selected design: Option 2, separated Constitutional Evolution Foundry  
Status: `CONSTITUTIONAL_EVOLUTION_FOUNDRY_VALID_SHADOW_ONLY`

## Delivered

- Added eight Draft 2020-12 contracts for baseline, Constitution, epistemic posture, cognitive candidate, capability thresholds, evaluation vectors, transition envelopes, and transition receipts.
- Added a domain-separated 2-of-3 signed Evolution Constitution with 20 exact axioms, eight hard failures, six capability triggers, four tier policies, and five resource ceilings.
- Added v0.1 improvement-candidate migration into a quarantined digest-only candidate bundle that does not retain or execute proposed mutation material.
- Added a content-addressed immutable artifact connector.
- Added a lexicographic evaluator with four required logical roles, eight hard gates, five champion floors, no scalar score, and capability-trigger escalation or pause.
- Added a threshold-authorized shadow-only transition connector with signed demotion, atomic publication, replay/conflict denial, and no active-baseline write.
- Added separate Foundry, evaluator, and promoter worker processes.

## Focused validation

- Contract harness: 47 schemas, 47 positive examples, 47 negative mutations, 42 semantic families, and one migration.
- Foundry harness: three distinct control-process IDs, two crash boundaries, 16 simultaneous transition attempts with one acceptance and 15 replay denials, signed demotion, CAS corruption detection, and 36 adversarial cases.
- Maximum outcome: `shadow_candidate_registered`.
- Active baseline modified: false.
- Candidate executed: false.
- Model API, network, credential, compute-expansion, replication, persistence, and production-promotion activity: false.

## Residual blockers

Real model generation, model-weight changes, evaluator competence and secrecy, distinct OS accounts/binaries/operators, hardware-backed keys, power-loss durability, lineage-wide resource metering, real shadow/canary behavior, and any production transition remain unproven.

## Shared handoff

Canonical handoff root: `Z:\nimrod-evolution-foundry-20260712-220456`; canonical project copy: `Z:\nimrod-evolution-foundry-20260712-220456\nimrod`. The v14 manifest travels inside the project copy; archive digest, copied-tree validation proof, and the selected hardening design packet are stored beside it in the shared folder.
