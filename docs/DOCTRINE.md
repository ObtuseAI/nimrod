# nimrod doctrine

Version: 0.1
Authority: project owner approved on 2026-07-15; see ADR-068
Scope: product, company, engineering, operations, marketing, and ecosystem

## Mission

nimrod exists to reduce material digital harm by coordinating prevention, detection, containment, verified recovery, and trustworthy evidence under bounded authority.

It is not an omniscient security agent. It is a security operating fabric whose analytic components may propose and whose deterministic authority kernel decides.

## Constitutional rule

> Every sensitive object, claim, identity, model, communication, action, repair, and update carries evidence and bounded authority.

This rule is stronger than convenience, growth, model capability, customer pressure, or incident urgency. Emergency behavior must be designed and preauthorized before the emergency.

## Definition of complete protection

nimrod never promises prevention of every attack. “Complete protection” means continuously improving the ability to:

1. prevent what can be prevented;
2. detect what bypasses prevention;
3. contain it before material harm;
4. recover to an independently verified state;
5. preserve trustworthy evidence; and
6. learn without gaining uncontrolled authority.

## Non-negotiable invariants

### Authority

1. **No ambient authority.** Every principal receives a narrow, expiring, purpose-bound capability.
2. **No direct AI execution.** Model output is untrusted data until validated, compiled into a typed action, and authorized by deterministic policy.
3. **No content-to-command transition.** Retrieved or observed content cannot silently become instructions.
4. **No self-authorization.** A component cannot approve its own capabilities, policy, evaluator, promotion, or evidence.
5. **No single-controller takeover.** No vendor service, administrator, model, or signing key can silently assume universal control.

### Evidence

6. **No single-signal truth for high-impact decisions.** Use independent corroboration or a deterministic oracle.
7. **No success without post-state verification.** A return code or API response is not a verified outcome.
8. **No unverifiable repair.** A repair requires reproduction, provenance, tests, postconditions, residual-risk disclosure, and rollback.
9. **No missing chain of custody.** Consequential observations and actions generate integrity-protected receipts.
10. **No erased uncertainty.** Contradicting evidence, missing evidence, assumptions, and residual risk remain visible.

### Safety and resilience

11. **No irreversible automation without independent authorization.** Reversible containment may be preauthorized only with bounded blast radius and tested recovery.
12. **No counter-hacking.** nimrod observes, protects, isolates, investigates, reports, and recovers; it does not attack external infrastructure.
13. **No cloud dependency for essential protection.** A supported endpoint retains core enforcement and recovery behavior while disconnected.
14. **No unsafe update.** Code, model, policy, rule, and dataset updates require provenance, signature verification, anti-rollback, staged release, and rollback.
15. **No deceptive safe state.** Degraded, unavailable, partial, stale, or unverified conditions are displayed literally.

### Privacy and user sovereignty

16. **No invisible surveillance.** Collection, purpose, access, retention, export, and model processing are inspectable and controllable.
17. **No raw centralization by default.** Sensitive telemetry remains local unless a defined purpose and lawful, informed choice permit transfer.
18. **No monetized surveillance.** Security data is never repurposed for advertising, unrelated profiling, or data brokerage.
19. **No hidden master key.** Users retain a vendor-independent recovery path and nimrod maintains no universal decryption credential.
20. **No coercive lock-in.** Users can export evidence, policy, and recovery material in documented formats and can safely remove the product.

### Product integrity

21. **No fabricated proof.** Demos, simulations, test fixtures, and production evidence are unmistakably separated.
22. **No security theater.** Product claims name scope, evidence, measurement date, limitations, and residual risk.
23. **No expansion by assertion.** A capability becomes supported only after its release gate is satisfied.
24. **No unowned risk.** Every material risk has an accountable owner, treatment, due date, and acceptance authority.
25. **No exception without expiry.** Policy exceptions are scoped, time-bounded, recorded, and reviewed.
26. **No unilateral trust-root movement.** Key rotation, revocation, loss recovery, and compromise recovery require the standing threshold under the prior valid epoch; a new state cannot authorize itself.
27. **No silent evidence rollback.** Witness history is checked against threshold-signed checkpoints and an independently retained anchor head; missing or older state is reported as rollback, not accepted as current truth.
28. **No verifier authority bleed.** A verifier receives read-only evidence and trust inputs only; it receives no planner, signer, policy-authoring, executor, target, or credential capability.
29. **No consensus by omission.** Disagreement, timeout, outage, missing isolation, and invalid evidence remain literal non-success states; the remaining verifier cannot silently stand in for the missing one.
30. **No presentation-layer evidence laundering.** The operator shell binds verifier observations to consensus digests and renders invalid, disagreement, timeout, outage, and boundary-unproven states literally; UI copy or styling cannot promote them to success.
31. **No display authority.** A verifier dashboard may explain and export evidence, but it cannot authorize, execute, change policy, suppress dissent, or mark verification accepted without the complete machine-validated production boundary.
32. **No unsigned verifier presentation.** A board may render a verifier projection only when a domain-separated threshold signature binds the exact projection digest, issuer, audience, governance state, validity window, sequence, and predecessor.
33. **No stale-state recovery by optimism.** Replay, rollback, sequence gap, expired/future snapshot, chain substitution, or corrupt ingress state blocks rendering advancement; elapsed time and UI refresh cannot repair evidence.
34. **No source-to-command transduction.** Atomic definitions, Caldera abilities, playbooks, and tool plans are hostile data; their command, cleanup, payload, variable, and executor fields cannot cross into a nimrod campaign or connector request.
35. **No unpinned adapter mapping.** A fixture-only source can produce a simulated typed step only when source kind, object identity, artifact digest, technique, platform, and executor match one exact local policy entry.

## Separation of powers

| Power | Responsibility | Must not be combined with |
|---|---|---|
| Observe | Collect and normalize events | Authorize action |
| Analyze | Form hypotheses and recommendations | Grant capabilities or declare verification |
| Authorize | Apply deterministic policy and approval rules | Create its own evidence or evaluator |
| Execute | Perform one typed, scoped operation | Expand the operation or alter policy |
| Verify | Measure actual post-state independently | Be the executor for high-impact changes |
| Witness | Preserve evidence and chain of custody | Rewrite or delete adverse evidence |
| Promote | Release signed artifacts after gates pass | Modify gates or hidden evaluation results |

For low-risk, local, reversible operations, components may share a process only if the logical boundaries, identities, and evidence remain independently testable. High-impact paths require runtime and operational separation.

## Autonomy budget

nimrod grants autonomy based on evidence quality, reversibility, blast radius, urgency, and observed calibration—not product tier or model confidence alone.

| Budget | Allowed behavior | Example |
|---:|---|---|
| 0 | Observe and explain | Record unsigned executable launch |
| 1 | Recommend and request confirmation | Suggest isolating a suspicious process |
| 2 | Automatically apply a reversible local restriction | Temporarily block one process egress |
| 3 | Execute preauthorized containment with independent verification | Suspend a process tree and verify it stopped |
| 4 | Execute recovery with explicit approval and tested rollback | Restore a known-good configuration |
| 5 | High-impact action with multi-party authorization | Enterprise credential rotation |

No initial public release may exceed Budget 2. Budget 3 requires independent red-team evidence and production-calibration data. Budgets 4–5 are later-product capabilities.

## Adversary-emulation constitution

nimrod Crucible may execute authorized adversary emulation, but offensive tooling remains outside the trusted core and subordinate to the same evidence and authority rules as every other consequential action.

1. **No campaign without an authorization lease.** Every campaign requires a signed, expiring lease that identifies the customer authority, target graph, permitted techniques, effect ceiling, time window, resource budget, approvals, kill switch, and recovery contract.
2. **No target inference.** A hostname, IP address, account name, discovery result, or model assertion cannot expand the authorized target graph.
3. **No uncontrolled propagation.** Self-spreading behavior, internet-wide scanning, counter-hacking, and actions against third-party infrastructure are forbidden.
4. **No arbitrary command bridge.** External playbooks, C2 output, SIEM events, queries, model responses, and tool results are untrusted data. They must compile into typed allowlisted actions before authorization.
5. **No ordinary-production destructive effects.** Ransomware impact, destructive deletion, real secret exfiltration, firmware changes, and physical-safety effects run only in a counterfactual twin or an explicitly sacrificial isolated replica.
6. **No campaign success without cleanup proof.** Completion requires target post-state, artifact cleanup, credential disposition, network-policy restoration, and recovery verification.
7. **No hidden red infrastructure.** Every payload, redirector, listener, agent, credential, route, and retention period is inventoried and tied to the campaign lease.
8. **No single-path abort.** A customer-controlled out-of-band kill switch can revoke the lease and stop new actions even when the orchestrator, model, or vendor tool is compromised.
9. **No unsigned range policy.** Adapter mappings require threshold signatures, role diversity, exact policy/governance binding, and a short validity window before any compatibility decision.
10. **No compatibility-by-partial-snapshot.** A local source corpus must exactly match its manifest; compatibility scanning cannot fetch, compile, install, connect, discover, or execute.
11. **No readiness-to-authority conversion.** A complete disposable-range preflight may satisfy an evidence gate, but it cannot authorize installation, connection, or execution; those require a separate explicit authority path.
12. **No topology-to-provisioning conversion.** A topology declaration describes required isolation but cannot create infrastructure, credentials, routes, targets, or connector capabilities.
13. **No reversible kill fiction.** Once a range-generation kill is engaged, no orchestrator, model, cleanup result, replay, or ordinary operator action may disengage it; reuse requires a new generation.
14. **No cleanup-to-reuse conversion.** Snapshot and cleanup verification records evidence only. It cannot reset kill state, authorize reconnection, or certify an unobserved environment.

## Constitutional recursive improvement

Recursive improvement is autonomous inside an authority tier; it cannot promote itself into a higher tier.

| Tier | Candidate class | Maximum autonomous outcome |
|---:|---|---|
| A | Mappings, reports, fixtures, documentation, non-executable knowledge | Signed promotion after deterministic validation |
| B | Detection queries, rules, scoring features, test scenarios | Shadow or canary promotion after sealed evaluation and automatic rollback proof |
| C | Executables, connectors, response playbooks, model versions, production policies | Candidate package only; threshold human approval required for production |
| D | Doctrine, root policy, signing keys, evaluator definitions, sealed tests, authority ceilings | No autonomous modification or promotion |

All learning material is quarantined, provenance-checked, license-checked, secret-scanned, deduplicated, replayed, and challenged by independent evaluation before it can affect a supported product. Failed, reverted, contradicted, and inconclusive candidates remain durable learning evidence.

The Constitutional Evolution Foundry adds three non-waivable implementation rules:

1. the active baseline is immutable to candidate systems; recursive change produces content-addressed candidates only;
2. hard failures and champion regressions are lexicographic blockers and cannot be averaged against capability or utility;
3. capability triggers can only preserve safeguards, increase safeguards, require isolation, or pause the lineage; they cannot expand authority.

The Constitutional Intelligence Research Engine may study better methods of discovery, reasoning, creativity, research, planning, evaluation, and improvement. Every study preregisters competing null, candidate, rival, and unknown hypotheses; preserves counter-evidence and falsifiers; and emits at most a scoped candidate theory. Research success cannot authorize execution, modify the active baseline, promote itself, redefine its evaluator, generalize beyond its evidence, or change constitutional authority. ADR-072 records the first replay implementation.

## Product promises

nimrod may promise:

- local-first operation within documented boundaries;
- evidence for consequential decisions;
- deterministic authorization of typed actions;
- reversible containment where explicitly supported;
- verified recovery for tested scenarios;
- visible data collection and retention;
- honest degraded and uncertain states.

nimrod must not promise:

- total, perfect, or future-proof protection;
- detection of every zero-day, scam, insider, or hardware compromise;
- that AI output is correct because multiple models agree;
- that a signed artifact is benign or a ledger statement is true;
- that a successful action means the intended outcome occurred;
- compliance or certification without an applicable independent assessment.

## Doctrine change protocol

A doctrine change requires:

1. a written problem and proposed text;
2. affected invariants and threat-model paths;
3. user, privacy, and failure-mode impact;
4. alternatives and evidence;
5. independent security review;
6. project owner approval;
7. versioned publication and migration plan.

No incident responder, model, automated optimizer, or ordinary pull request may waive this protocol.
