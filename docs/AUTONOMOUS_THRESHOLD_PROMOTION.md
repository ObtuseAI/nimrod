# Autonomous threshold promotion

Tier A and Tier B improvement candidates advance automatically when every constitutional gate is satisfied. Human approval is not part of these two tier policies; independent threshold evidence is the standard.

The controller accepts only an explicitly typed `autonomous_threshold` job containing the candidate, lexicographic evaluation, capability report, evaluator-assurance receipt, Evolution Constitution, governance state, and threshold-signed transition envelope. It independently recomputes the evaluation-input digest and requires:

- a valid, active, externally rooted Evolution Constitution;
- Tier A or Tier B with a maximum destination of `shadow` and `threshold_humans_required=false`;
- four distinct evaluator roles, identities, logical principals, and processes;
- individually signed evaluator observations and verified isolation-contract boundaries;
- a signed resource lineage that remains within constitutional ceilings;
- all hard gates and champion floors passing without scalar-score override;
- a clear capability-threshold report with no pause or safeguard escalation;
- at least two valid transition signers from at least two governance roles;
- immutable candidate, Constitution, baseline, capability, evaluation, assurance, and predecessor bindings.

Once those conditions hold, a separate process atomically registers exactly one shadow receipt. Concurrent attempts become replay denials. A pre-publication crash remains retryable; a post-publication crash preserves the receipt.

Regression reverses the default. A fresh independently assured evaluation with any failed evaluator, hard gate, champion floor, regressed metric, or unknown metric makes a threshold-signed demotion mandatory. The controller records a predecessor-bound terminal quarantine receipt. A healthy candidate cannot be demoted through the regression path.

This standard does not create an active-baseline write, candidate execution, policy installation, production promotion, signer selection, evaluator selection, Constitution modification, trust-root movement, resource expansion, network access, or target contact. Tier C remains a candidate package requiring threshold human approval for production. Tier D remains non-autonomous and quarantined.

Canonical replay evidence: `reports/AUTONOMOUS_PROMOTION_VALIDATION.json`.

