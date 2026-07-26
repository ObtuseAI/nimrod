# Public launch and release gates

nimrod launches only when evidence supports a bounded product claim. Dates, fundraising, competitor moves, demos, and model capability cannot waive these gates.

The curated source-preview repository is public and source-available in the `ObtuseAI` GitHub organization under ADR-078. This is a technical portfolio and defensive-research publication, not a product, binary, hosted-service, connector, customer, or production launch. Trademark clearance remains a separate commercial gate; repository naming does not claim registration or exclusivity.

Authorized offensive testing is a required Crucible capability. Its inclusion never waives authorization, target, effect, isolation, abort, cleanup, evidence, or legal gates.

Current Crucible evidence stops before operations. A threshold-signed non-provisioning connector declaration, exact scope compiler, and nine-control packet are validated. A successor admission layer verifies a second governance-signed policy plus nine individually signed, content-addressed fixture observations, but the owner-named range is missing and the result has zero real observations, zero independent verifiers, and zero verified attestations. These contracts cannot install, provision, change policy, access credentials, contact tools or networks, connect, mark evidence complete, verify their own claims, or execute. This proof does not satisfy a public-release efficacy or safety gate.

## Gate states

- `NOT_STARTED`
- `IN_PROGRESS`
- `BLOCKED`
- `PASS_WITH_RESIDUAL_RISK`
- `PASS`

Only `PASS` and explicitly approved `PASS_WITH_RESIDUAL_RISK` satisfy a gate. Missing evidence is not a pass.

## Gate A — Founding and product identity

- [ ] Corporate entity, ownership, cap table, and contracting authority established.
- [x] Trademark clearance marked `TRADEMARK_CLEARANCE_PAUSED_BY_OWNER`; private development may continue.
- [x] Public source-preview identity approved under ADR-078; externally marketed product identity remains separately gated.
- [x] Source-repository target recorded as `PUBLIC_SOURCE_PREVIEW_SOURCE_AVAILABLE` in the `ObtuseAI` GitHub organization with no open-source license claim.
- [ ] Public GitHub visibility, organization ownership, branch protection, security reporting, access controls, and audit settings verified after publication.
- [ ] IP assignment and invention/confidentiality agreements operational.
- [ ] Customer, binary, service, and evaluation terms approved before external distribution or access.
- [ ] Initial customer, jurisdiction, price hypothesis, and support promise approved.

Current state: `BLOCKED_OWNER_AND_COUNSEL_DECISIONS`

## Gate B — Product scope and claims

- [ ] Supported use cases and non-targets frozen for the release.
- [ ] Every public claim maps to dated reproducible evidence.
- [ ] No total-protection, zero-risk, universal-replacement, or unsupported compliance claim.
- [ ] Coverage gaps, residual risk, model limitations, and degraded states are user-visible.
- [ ] Pricing, refund, support, update, and end-of-life terms reviewed.

Current state: `IN_PROGRESS`

## Gate C — Architecture and authority

- [ ] Threat model independently reviewed.
- [ ] Analytics has no executor, policy-write, signing, or verification credentials.
- [ ] Consequential operations use a validated action envelope.
- [ ] Authority Kernel is deterministic and deny-by-default.
- [ ] Every executor is single-capability, target-bound, expiring, and independently verified.
- [ ] Emergency disable, rollback, export, and safe uninstall work offline.

Current state: `IN_PROGRESS_UNPRIVILEGED_SIMULATOR_ONLY`

## Gate D — Product security and supply chain

- [ ] Release build isolated, reproducible to approved target, and provenance-bearing.
- [ ] SBOM/AIBOM, dependency review, secret scan, static analysis, and applicable fuzzing pass.
- [ ] Artifacts and update metadata are threshold-signed and anti-rollback protected.
- [ ] Staged rollout, freeze, rollback, and key-compromise exercises pass.
- [ ] Independent penetration test findings closed or explicitly risk-accepted.
- [ ] No unresolved critical/high release-blocking vulnerability.

Current state: `NOT_STARTED_IMPLEMENTATION`

## Gate E — Safety, efficacy, and recovery

- [ ] Scenario suite measures prevention/detection, precision, containment, and verified recovery.
- [ ] Zero unauthorized consequential actions in the approved release evaluation.
- [ ] False-interruption and performance budgets pass on representative hardware.
- [ ] Every supported action has tested idempotency, timeout, compensation, rollback, and verifier behavior.
- [ ] Partial, stale, contradicted, and `inconclusive_timeout` outcomes remain literal.
- [ ] Independent red team attempts prompt injection, target widening, evidence tamper, and update compromise.

Current state: `NOT_STARTED_IMPLEMENTATION`

## Gate F — Privacy and legal

- [ ] Actual field-level data inventory and data-flow diagram approved.
- [ ] Privacy notice, consent/choice, retention, export, deletion, and support-access flows match behavior.
- [ ] Telemetry disabled state is verified network-silent.
- [ ] GDPR/DPIA, state privacy, AI Act, CRA, product liability, and sector applicability memos completed as relevant.
- [ ] Export classification/notification/reporting path completed before global availability.
- [ ] Processor/subprocessor contracts and international transfer mechanism approved.

Current state: `BLOCKED_ACTUAL_PRODUCT_AND_COUNSEL_REVIEW`

## Gate G — Reliability and operations

- [ ] Compatibility matrix, install, upgrade, rollback, uninstall, and coexistence tests pass.
- [ ] SLOs and alerting operate without excessive sensitive telemetry.
- [ ] Incident response, vulnerability response, privacy incident, outage, and release rollback exercises pass.
- [ ] Monitored private security-reporting channel and disclosure policy are live.
- [ ] Status page, support intake, escalation, on-call, and customer communications are staffed.
- [ ] Backup, restoration, business continuity, and vendor-failure plans are exercised.

Current state: `NOT_STARTED`

## Gate H — Crucible authorization and production safety

- [ ] Authorization leases are signed, expiring, replay-resistant, and bound to stable target identities.
- [ ] Discovery cannot enlarge an active target graph.
- [ ] The out-of-band customer kill switch works during orchestrator, model, connector, and network failure.
- [ ] Red connectors cannot reach policy, signing, Witness mutation, sealed tests, other tenants, or non-target routes.
- [ ] Safe-realism effect classification denies destructive, exfiltration, firmware, propagation, and physical-safety effects in ordinary production.
- [ ] Cleanup, credential disposition, route closure, and independent recovery verification pass.
- [ ] Cross-tenant, DNS rebinding, cloud-resource replacement, delayed callback, and lease-expiry tests pass.
- [ ] Counsel approves customer authorization, acceptable use, export, insurance, and incident handling for each launch jurisdiction.

Current state: `IN_PROGRESS_CONSTRUCTION_ZONE_PROVISIONING_SIGNED_DENIAL_OPERATOR_PROVIDER_INDEPENDENT_ATTESTATION_STAGING_BUILD_CONNECTION_AND_EXECUTION_BLOCKED`

## Gate I — AI Capsule and recursive improvement

- [ ] Model, prompt, policy, memory, retrieval, tool, data, capability, and recovery state are versioned and witnessed.
- [ ] Prompt, context, memory, tool, and model output cannot grant authority.
- [ ] Every AI action uses an expiring capability and independent post-state verification.
- [ ] Imported learning material passes quarantine, provenance, license, secret, replay, contradiction, and poisoning gates.
- [ ] Candidate systems cannot access sealed answers, modify evaluators, lower thresholds, select signers, or erase failures.
- [ ] Tier A/B automation cannot promote Tier C/D artifacts or authority.
- [ ] Champion floors, canary rollback, and automatic demotion pass adversarial evaluation.
- [ ] AI repair reproduces the original failure, restores supported behavior, and independently verifies the running state.
- [x] Independent second-language contract verification rejects evaluator, isolation, resource, signature, expiry, substitution, and authority-widening tamper cases.
- [x] Read-only live Windows process/isolation observation computes DACL effective rights and exact-executable egress policy while preserving observed violations.
- [x] Benign worker creation is suspended until successful Job Object assignment; write-through records survive abrupt-process recovery in a separate process.
- [x] Read-only CNG/TPM readiness preserves missing key-reference, attestation, TPM-management, and independent-custodian blockers without provisioning keys.
- [ ] Dedicated service identities, enforced ACL separation, denied egress, hardware-backed custody, independent custody operations, and physical power-loss durability are proven.

Current state: `IN_PROGRESS_DEPLOYMENT_ASSURANCE_RACE_CLOSED_EFFECTIVE_ACCESS_OBSERVED_CUSTODY_AND_PHYSICAL_POWER_LOSS_BLOCKED_NO_MODEL_EXECUTION_OR_PRODUCTION_EVIDENCE`

## Gate J — User experience and accessibility

- [ ] Non-experts complete warning, containment, override, evidence, privacy, and recovery tasks safely.
- [ ] Applicable UI meets WCAG 2.2 AA target and manual keyboard/screen-reader checks.
- [ ] Critical state is not communicated by color alone.
- [ ] Explanations distinguish observation, inference, prediction, and human assertion.
- [ ] Emergency controls explain side effects and preserve recovery.
- [ ] At-risk user research confirms the product does not create coercive or deceptive workflows.

Current state: `NOT_STARTED`

## Gate K — Commercial readiness

- [ ] Design partners demonstrate retained use and measurable value.
- [ ] Support-adjusted unit economics fit the approved business model.
- [ ] Billing and entitlement cannot disable local recovery or evidence export.
- [ ] Insurance, terms, acceptable use, privacy terms, and customer agreements approved.
- [ ] Public documentation, onboarding, limitations, pricing, and offboarding are complete.
- [ ] Launch load, rollback capacity, and support demand are rehearsed.

Current state: `NOT_STARTED`

## Release-specific authority ceilings

| Release | Maximum autonomy |
|---|---|
| Prototype | Budget 0: observe/no-op only |
| Alpha | Budget 1: recommend and require confirmation |
| Private beta | Budget 2 for named reversible local controls |
| Public preview | Budget 2 only after safety metrics and red-team gate |
| GA | Budget 2; Budget 3 requires a separate approved release case |

Crucible uses a separate ceiling:

| Crucible release | Maximum authority |
|---|---|
| No-execution simulator | Compile, predict, replay fixtures, and emit no-op receipts |
| Isolated range alpha | Leased execution only inside disposable ranges |
| C2 range beta | Isolated C2 connectors under compromise-tested egress and kill-switch controls |
| Authorized-production private beta | Safe-realism techniques on exact leased targets with independent cleanup/recovery |
| Enterprise GA | Only the capability classes supported by the signed release evidence package |

## Launch decision record

A launch decision package contains:

- release identity and immutable artifact hashes;
- scope and claims;
- gate status with evidence links;
- known issues and residual risks;
- open vulnerabilities and treatment;
- operational readiness and rollback authority;
- counsel signoffs where applicable;
- independent security signoff;
- product owner approval;
- explicit no-go triggers.

The issuer of a launch decision cannot be the sole author of its evidence.
