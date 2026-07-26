# Universal AI assurance and repair

Status: `SPECIFICATION_ONLY_NO_RUNTIME_AUTHORITY`  
Objective: make AI systems observable, controllable, repairable, and independently verifiable across models, agents, tools, devices, and safety domains

## AI Capsule

Every supported AI system runs behind a logical AI Capsule. The capsule is model- and vendor-independent and records:

- system, model, adapter, and deployment identity;
- model, prompt, policy, evaluator, and safety-control versions;
- context and retrieval provenance;
- memory reads, writes, lineage, retention, and quarantine state;
- tool registry, connector manifest, capability leases, and destinations;
- data classes, purposes, residency, and disclosure decisions;
- token, time, cost, concurrency, network, and physical-effect budgets;
- proposed, authorized, attempted, and verified actions;
- confidence, alternatives, contradictions, and uncertainty;
- snapshots, rollback, compensation, and recovery oracles.

The capsule is not a prompt wrapper. Its authority boundary is deterministic and outside the model runtime.

## Universal Protection Profile

Every device, workload, AI agent, robot, application, service, or safety system is represented by a versioned `ProtectionProfile`.

```text
identity and attestation
supported sensors
allowed action classes
prohibited effects
data and jurisdiction
operational dependencies
safety interlocks
resource budgets
recovery method
independent oracles
offline behavior
known limitations
```

Initial profiles cover Windows endpoints, Linux workloads, cloud services, identity systems, and software AI agents. Mobile, robotics, IoT, OT, vehicles, medical, and other physical systems require distinct safety cases and cannot inherit software-only authority.

## AI threat coverage

Crucible campaigns map to MITRE ATLAS, ATT&CK, OWASP agentic threats, and product-specific hazards. Required families include:

- direct and indirect prompt injection;
- retrieval and context poisoning;
- model, dataset, dependency, and tool supply-chain compromise;
- tool metadata, argument, and output poisoning;
- memory poisoning, stale authority, and cross-mission contamination;
- credential harvesting and secret leakage;
- unsafe code, command, URL, document, and UI rendering;
- excessive agency, runaway delegation, and capability laundering;
- goal manipulation, reward hacking, evaluator gaming, and benchmark leakage;
- unsafe self-replication and persistence;
- model extraction, evasion, denial of service, and resource exhaustion;
- false evidence, hallucinated verification, and concealed uncertainty;
- biased or inaccessible intervention that creates human harm;
- failed rollback, incomplete repair, and unsafe degraded mode.

## Controllability model

The capsule enforces:

1. model output is always a proposal;
2. tool arguments are schema-validated and taint-aware;
3. every tool call names purpose, target, data, expiry, budget, rollback, and verifier;
4. capabilities are audience-bound, non-transferable, expiring, and revocable;
5. delegation cannot exceed the delegator's scope or lease lifetime;
6. memory cannot grant authority;
7. retrieved content cannot change policy;
8. the model cannot access signing, evaluator, root-policy, or kill-switch credentials;
9. high-impact actions require independent deterministic and human authorization;
10. actual post-state, not model narrative, determines success.

## Fixable AI state

nimrod snapshots the smallest recoverable AI state:

- prompt and policy packages;
- model and adapter versions;
- tool registry and capability assignments;
- retrieval indexes and source manifests;
- durable and episodic memory with provenance;
- workflow state and pending actions;
- safety configuration and evaluator versions;
- secrets by reference, never plaintext;
- environment and dependency provenance.

Repair may quarantine memory, revoke tools, restore policy, roll back a model or index, rebuild an environment, rotate referenced credentials, or invalidate sessions. A repair succeeds only when the original failure path no longer reproduces, intended behavior still works, prohibited effects remain absent, and independent oracles verify the running state.

## AI Red, Blue, and Purple roles

| Cell | Role | Authority ceiling |
|---|---|---|
| AI Red | Generate adversarial inputs, sequences, tool conditions, and counterexamples | Twin/range execution under campaign lease; no production authority |
| AI Blue | Observe prompts, context, memory, tools, data flow, model behavior, and resulting system state | Read-only evidence by default; response separately authorized |
| AI Purple | Compile campaigns, predict expected evidence, correlate causal outcomes, and identify gaps | Propose tests and improvements; cannot self-authorize or self-verify |
| Independent verifier | Reproduce failures and measure post-state through separate oracles | No candidate-generation or execution authority for the action it verifies |

Cells are ephemeral, receive only incident/campaign-scoped data, and dissolve after signed evidence is produced. Validated lessons may enter the Improvement Forge; raw conversations and private data do not.

## Evaluation dimensions

AI assurance reports:

- task correctness and safe completion;
- policy adherence and unauthorized-action rate;
- prompt/context/tool/memory attack resistance;
- data minimization and privacy leakage;
- calibration and uncertainty disclosure;
- evidence traceability and citation support;
- containment, rollback, and verified recovery;
- model/provider outage behavior;
- latency, cost, compute, energy, and availability;
- fairness, accessibility, and human-override safety;
- degradation under distribution shift and novel compositions.

No aggregate grade may hide a hard failure. Unauthorized consequential action, fabricated evidence, secret disclosure, evaluator manipulation, or falsely successful recovery fails the release regardless of average performance.

## Standards posture

- NIST AI RMF and Generative AI Profile guide lifecycle risk management and evaluation.
- NIST Cyber AI Profile informs secure, defend, and thwart outcomes as it matures.
- MITRE ATLAS supplies AI adversary behavior and evidence maturity.
- MITRE ATT&CK and D3FEND connect conventional attack paths and countermeasures.
- OWASP Agentic AI guidance informs system-level agent threats.
- ISO/IEC 42001 informs the organizational continuous-improvement management system.

These references guide mappings and evidence. They do not create automatic compliance, safety, or certification claims.

## Constitutional Evolution Foundry reference implementation

The selected Option 2 architecture is implemented as a no-execution reference. A threshold-signed Evolution Constitution governs candidate-only mutation against an immutable baseline. Foundry, evaluator, promoter, and autonomous-promotion workers run in separate processes. The assurance layer pins four evaluator identities in a threshold-signed policy, verifies individually signed observation envelopes, requires seven-control threshold-certified isolation attestations, and recomputes a threshold-signed hash-chained resource ledger across the candidate lineage. Evaluation is vector-valued and lexicographic, and capability evidence can only escalate or pause. Independently assured Tier A/B candidates that satisfy a 2-role transition quorum are now autonomously registered in the crash-safe shadow lane; proven regression autonomously demotes them to quarantine. The controller cannot select signers or evaluators, sign its own transition, execute candidates, mutate the baseline or Constitution, widen authority, or promote to production. No model API, candidate execution, baseline mutation, production promotion, online learning, credential, network, replication, persistence, or autonomous compute-expansion path exists.

This is architectural control evidence, not evidence of recursive intelligence improvement. A separate read-only Windows collector now supplies live DACL-effective-rights and target-firewall observations; a strict TypeScript/Node implementation independently verifies evaluator, isolation, and resource contracts; a Windows Job Object meter closes the assignment race and produces live usage receipts with write-through abrupt-crash recovery and lineage binding; and a read-only CNG/TPM collector exposes custody blockers without provisioning keys. Those proofs do not establish dedicated OS accounts, enforced ACL or egress separation, independent evaluator ownership, sealed-test secrecy, hardware-key custody, independent custodians, physical power-loss durability, real model changes, evaluator quality, or production behavior.
