# nimrod Edge Preview product requirements

Status: proposed  
Release: first public product  
Platform: supported Windows 11 editions, exact matrix to be validated

## Product contract

nimrod Edge Preview helps a user understand and safely restrict selected process and network behavior on one Windows device. It is local-first, evidence-bearing, deterministic at the authority boundary, and honest about uncertainty.

## Personas

### Primary: technical owner-operator

Protects personal accounts, source code, documents, and business activity on one to ten Windows devices. Understands processes and network destinations but does not run a SOC.

### Secondary: small-team security administrator

Needs consistent local policies, exportable evidence, and safe response without enterprise platform complexity. Fleet control is not part of the first public release.

### Affected user: non-expert device user

May receive an intervention and must understand it, continue legitimate work, safely override, and recover without security jargon.

## Supported use cases

### UC-01 Explain a suspicious process

Given a new or materially changed process, nimrod shows provenance, parentage, signer/hash where available, observed file/network behavior, applicable policy, uncertainty, and safe next actions.

Acceptance:

- observation is labeled live, replayed, simulated, or imported;
- every displayed claim links to evidence or is labeled inference;
- missing platform evidence is explicit;
- content from the process cannot create instructions or capabilities.

### UC-02 Temporarily restrict process egress

The user or preauthorized reversible policy requests a time-bounded restriction for one process identity and descendants where technically enforceable.

Acceptance:

- action envelope names actor, target, capability, purpose, expiry, preconditions, prohibited side effects, and rollback;
- deterministic policy returns allow, limit, challenge, deny, or escalate;
- executor cannot widen target or duration;
- verifier observes actual network-policy state;
- expiry and rollback are independently verified and receipted.

### UC-03 Suspend or terminate a process tree

The user responds to active suspicious behavior.

Acceptance:

- open work and expected side effects are explained before execution when urgency permits;
- suspend is preferred when it safely preserves rollback;
- critical and protected processes are denylisted by invariant, not model judgment;
- descendants and respawn behavior are checked;
- incomplete containment is reported literally.

### UC-04 Verify recovery

The user restores a supported policy/configuration snapshot after containment.

Acceptance:

- pre-state, intended delta, artifact provenance, and rollback are recorded;
- executor and verifier have separate identities;
- supported postconditions are tested;
- unsupported clean-state claims are not made;
- unresolved persistence or integrity uncertainty remains visible.

### UC-05 Inspect and control data handling

The user sees collected fields, storage location, retention, access history, optional exports, and model/service processing.

Acceptance:

- telemetry export is off by default;
- purpose and retention are field-level or event-class-level policy;
- export and deletion produce receipts;
- evidence needed for an active incident is handled through an explicit retention conflict workflow.

### UC-06 Operate during cloud loss

Essential observation, local policy, manual containment, evidence access, and safe uninstall remain available without vendor cloud connectivity.

## Functional requirements

| ID | Requirement | Release priority |
|---|---|---|
| FR-001 | Versioned principal, event, evidence, action, policy-decision, verification, and receipt schemas | Must |
| FR-002 | Local process creation/ancestry and executable provenance observation | Must |
| FR-003 | Selected file-change and process-correlated DNS/connection observations | Must |
| FR-004 | Deterministic policy decision point with explainable rule trace | Must |
| FR-005 | No-op, suspend/terminate, and egress-restriction executors as separate capabilities | Must |
| FR-006 | Independent post-state verifier and literal partial/failure states | Must |
| FR-007 | Append-only local journal and content-addressed evidence artifacts | Must |
| FR-008 | Protection, explanation, privacy, emergency, and proof views | Must |
| FR-009 | Signed staged update, anti-rollback, offline verification, rollback, and safe uninstall | Must |
| FR-010 | Evidence export with integrity manifest and documented schema | Must |
| FR-011 | Local deterministic analysis rules | Must |
| FR-012 | Optional governed model analysis that has no action authority | Should |
| FR-013 | User-defined narrow policies through safe templates | Should |
| FR-014 | Design-partner fleet policy synchronization | Later |

Current foundation evidence partially satisfies the contract portion of FR-002 and FR-009 only. One caller-selected process identity can be observed through supported read-only APIs, but ancestry, publisher, file-change, DNS, and connection evidence are absent. Candidate update signatures, exact anti-rollback progression, artifact binding, rollback declarations, and plugin capability manifests are verified offline, but no production custody, installer, staged rollout, rollback execution, safe-uninstall execution, or plugin runtime enforcement exists. The design-partner plan is validated, but recruitment and fleet synchronization have not started.

## Non-functional requirements

- **Safety:** zero accepted unauthorized consequential actions in release evaluation.
- **Privacy:** no raw telemetry leaves the device by default; data minimization is measurable.
- **Availability:** essential local functions survive loss of the analytics service and vendor cloud.
- **Performance:** budgets are defined per hardware class and measured at idle, interactive, build, and high-event load.
- **Accessibility:** applicable interfaces target WCAG 2.2 AA, full keyboard operation, screen-reader support, non-color-only status, reduced motion, and plain-language explanations.
- **Compatibility:** install, coexistence, update, rollback, and uninstall are tested across the approved Windows/security-product matrix.
- **Forensics:** timestamps, identities, transformations, and evidence integrity remain reconstructable.
- **Maintainability:** public contracts are versioned and model/provider dependencies are replaceable.
- **Recoverability:** every action declares fail mode, timeout, idempotency, compensation, and verifier.

## Explicitly deferred requirements

- kernel telemetry or enforcement driver;
- organization-wide remote response;
- automated credential rotation;
- browser, mail, chat, phone, or payment intervention;
- autonomous code repair;
- model training from customer data;
- cross-customer intelligence exchange;
- macOS, Linux, mobile, IoT, cloud-workload, and critical-infrastructure agents.

## Separate Crucible product contract

The Edge Preview does not include adversary emulation. nimrod Crucible is independently specified in `CRUCIBLE.md` and receives no execution authority from Edge installation, licensing, release status, or customer consent. Crucible begins with a no-execution simulator, then isolated range validation, then C2 range validation, and only then an authorized-production private beta under the safe-realism ceiling.

## CACIS vNext relationship

CACIS is the long-term intelligence architecture shared by Edge and Crucible, not an additional release authority. Edge may consume bounded World Model, immune-organism, Constitutional Intelligence Research Engine, Homeostasis/Chronos, genome, and arena proposals only after its own product and privacy gates. The World Model replay proves durable cursors, deduplication, explicit gaps, predecessor-bound generations, recoverable publication, threshold-signed replay source governance, no-drop backpressure, and retention projection checks; it does not admit live sensors, prove production custody or retention, or create policy input. Crucible may consume the same intelligence only while retaining its separate authorization lease, exact target, isolated range, effect ceiling, abort, cleanup, recovery, and independent verification requirements. W1 through W6 replay evidence does not satisfy any Edge or Crucible product requirement and creates no runtime protection, production scheduler, production-independent settlement, or generalized-intelligence claim.

## Release acceptance

The product requirements are satisfied only when the public launch gates, threat-model mitigations, privacy review, supported-scenario evaluation, operations exercises, and legal claims review all pass. Feature completion alone is insufficient.
