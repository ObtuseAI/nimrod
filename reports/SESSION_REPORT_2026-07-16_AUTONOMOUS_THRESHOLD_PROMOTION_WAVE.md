# Autonomous threshold promotion wave

Date: 2026-07-16
Repository: nimrod
Branch: `codex/takeover-w5-w6`
State: uncommitted review work

## Outcome

Tier A and Tier B improvement candidates now use autonomous threshold promotion as the default. A candidate advances only to the shadow lane after four independently bound evaluators, lexicographic hard gates and champion floors, constitutional resource checks, capability-threshold clearance, and a two-signer/two-role transition quorum all agree. No human approval is required in these bounded tiers.

Fresh independently assured regression evidence triggers an automatic, threshold-signed demotion to quarantine. Tier C production candidates and Tier D quarantine remain outside autonomous promotion.

## Implemented surfaces

- `src/nimrod_simulator/autonomous_promotion.py`: pure verification and crash-safe application functions.
- `tools/autonomous_promotion_worker.py`: separate-process promotion and demotion worker.
- `tools/validate_autonomous_promotion.py`: contention, crash, replay, substitution, false-demotion, and authority-widening validation.
- `ui/app.js` and `ui/index.html`: Observatory projection for tier, quorum, evaluator, human-gate, demotion, and production-boundary evidence.
- `docs/AUTONOMOUS_THRESHOLD_PROMOTION.md` and ADR-077: current doctrine-subordinate behavior.
- completion, control-board, foundation, assurance, roadmap, README, and threat-model evidence updated.

## Focused proof

- Eligible tiers: A and B.
- Human approval required in eligible tiers: false.
- Independent evaluators: four.
- Transition quorum: two signers across two roles.
- Shadow promotions: one.
- Regression demotions: one.
- Contention: eight workers, one acceptance, seven replay denials.
- Crash boundaries: two.
- Fail-closed adversarial cases: ten.
- Candidate execution, active-baseline mutation, production promotion, Constitution mutation, trust-root mutation, model API use, and network access: false.
- Local completion audit: fourteen of fourteen local gates complete; six of six external operational gates remain blocked.

## Constitutional boundary

The controller cannot sign, select signers, select evaluators, execute a candidate, mutate the active baseline or Constitution, expand authority, or promote to production. It consumes independently produced signed evidence; it does not manufacture authority. Replay validation is not production protection evidence.

## Recommended next waves

1. Connect the controller to a durable governor-owned candidate queue with bounded scheduling, backpressure, expiry, and dead-letter quarantine.
2. Replace fixture signer and evaluator identities with separately administered service identities, read-only input ACLs, hardware-backed custody, and independently owned hidden evaluation partitions.
3. Add forward shadow observation and automatic rollback evidence so promoted candidates must survive time-bounded real behavior before any Tier C package can be assembled.

No commit or push was performed in this wave.
