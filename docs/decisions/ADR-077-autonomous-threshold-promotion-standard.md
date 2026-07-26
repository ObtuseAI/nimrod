# ADR-077: Autonomous threshold promotion is the Tier A/B standard

Status: `ACCEPTED_BY_OWNER_IMPLEMENTED_REPLAY_ONLY`
Decision owner: project owner
Authority change: none

## Context

The doctrine already permits autonomous improvement inside an authority tier, but the Foundry previously stopped at a manually invoked signed shadow transition. Requiring a human for every non-executing knowledge, rule, fixture, scoring, or test candidate would make bounded recursive improvement operationally inert. Allowing a candidate, evaluator, or controller to approve itself would violate the Constitution.

## Decision

Make autonomous threshold promotion the default for Tier A and Tier B. Promotion requires a valid Evolution Constitution, four independently bound evaluator roles, a within-Constitution resource lineage, blocker-free lexicographic gates, clear capability thresholds, and a 2-role threshold-signed transition. No human signature is required for these two tiers because their constitutional destination is limited to shadow.

Make regression demotion equally automatic. A fresh blocked evaluation with a bound regression signal and a 2-role threshold-signed predecessor transition moves the shadow candidate to quarantine.

Tier C and Tier D do not inherit this autonomy. Production promotion, execution, installation, active-baseline mutation, trust-root movement, Constitution modification, and evaluator or signer selection remain unavailable.

## Consequences

The safe default becomes evidence-driven advancement rather than manual review, while the maximum autonomous effect remains an immutable shadow receipt. Threshold roles and evaluators are independent control surfaces; agreement alone cannot waive hard failures. Replay, contention, crash, substitution, authority expansion, evaluator collapse, resource expansion, and false-demotion cases fail closed.

## Validation

`tools/validate_autonomous_promotion.py` proves automatic shadow registration, automatic regression demotion, exactly-once concurrency, both crash boundaries, independent assurance binding, and adversarial denial. `tools/autonomous_promotion_worker.py` is the separate-process controller and contains no model or network client.

