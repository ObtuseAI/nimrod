# Range evidence acceptance

Status: `RANGE_EVIDENCE_ACCEPTANCE_SIGNED_FIXTURE_DECISIONS_RETAINED_REAL_INDEPENDENT_ACCEPTANCE_BLOCKED`

This boundary gives independent verifiers a narrow, signed way to evaluate retained range observations without granting them collection, environment contact, evidence-completion, connection, or execution authority. It is the implementation evidence for backlog item `nim-104`.

## Separation of powers

The boundary consists of three versioned documents:

1. A threshold-signed verifier policy binds the admission report, exact scope, environment, allowed decision vocabulary, minimum decision count, and three distinct verifier identities.
2. Each verifier emits its own signed decision over one retained observation and raw-evidence digest. The decision is one of `accept`, `reject`, `abstain`, or `timeout`.
3. A deterministic acceptance report retains every decision and resolves each of the nine mandatory controls as `accepted`, `rejected`, `abstained`, `disagreement`, or `timeout`.

Two matching accepts can resolve a control as accepted only when the observation and verifier identities are real, independently attested, current, and bound to an owner-named `range` or `sacrificial_replica` environment. Fixture or simulated evidence can never be accepted. A reject is not softened, abstention is not agreement, disagreement is not averaged, and timeout is not treated as absence of opposition.

Acceptance is an evidence opinion, not evidence completion. Even nine valid real acceptances would produce only `accepted_controls_pending_separate_evidence_completion_authority`. This component has no API capable of marking the evidence packet complete or authorizing a connection or action.

## Canonical fixture state

The deterministic fixture policy has two governance signatures and three logical verifier identities. Two verifier keys sign 18 decisions over nine retained simulated observations. The resolved outcomes are:

| Outcome | Controls |
|---|---:|
| Accepted | 0 |
| Rejected | 2 |
| Abstained | 2 |
| Disagreement | 2 |
| Timeout | 3 |

All three verifier identities remain `fixture_logical_only`, real independent verifier count is zero, accepted control count is zero, verified attestation count is zero, and `evidence_complete` is false.

## Authority ceiling

The policy, every decision, and the final report permanently set all authority fields false. The implementation performs no environment contact, collection, installation, provisioning, policy mutation, credential access, network contact, range connection, or campaign execution.

The pure resolver is tested with valid real-shaped documents to prove the contract semantics for all five outcomes. That test does not claim that real evidence, a real verifier process, or an owner-named range exists.

## Validation

`tools/validate_range_evidence_acceptance.py` regenerates the canonical examples and report, verifies threshold and individual signatures, checks all cross-document bindings, proves the five resolution paths, rejects simulated acceptance, and exercises 46 adversarial cases. `tools/validate_contracts.py` independently validates the three Draft 2020-12 contracts and semantic invariants.

## Next operational prerequisite

The owner must name a sacrificial range and provide its immutable environment identity before a real collector or verifier deployment can be planned. That later work requires separately governed deployment and evidence-completion contracts; these fixture documents must not be reused as credentials or operational authorization.
