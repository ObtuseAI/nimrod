# Security, privacy, and compliance program

Research baseline: 2026-07-12  
Status: planning guidance, not legal advice

## Assurance strategy

nimrod will use control frameworks as maps, not marketing badges. Product safety is demonstrated through scoped claims, executable tests, independent review, operational exercises, and release evidence.

### Primary references

| Reference | nimrod use |
|---|---|
| [NIST Cybersecurity Framework 2.0](https://www.nist.gov/publications/nist-cybersecurity-framework-csf-20) | Govern, Identify, Protect, Detect, Respond, and Recover program outcomes |
| [NIST Secure Software Development Framework](https://csrc.nist.gov/Projects/ssdf) | Secure development and AI-specific development practices |
| [CISA Secure by Design](https://www.cisa.gov/securebydesign) | Ownership of customer security outcomes, secure defaults, transparency |
| [W3C WCAG 2.2](https://www.w3.org/WAI/standards-guidelines/wcag/) | Accessible web and application experience target |
| [OWASP Agentic Security Initiative](https://owasp.org/www-project-top-10-for-large-language-model-applications/) | AI/agent abuse-case input; never a substitute for system threat modeling |
| [NIST AI RMF and Generative AI Profile](https://www.nist.gov/itl/ai-risk-management-framework) | Govern, map, measure, and manage AI lifecycle risks |
| [NIST Cyber AI Profile](https://csrc.nist.gov/pubs/ir/8596/iprd) | Track secure, defend, and thwart outcomes as the draft matures |
| [MITRE ATLAS](https://atlas.mitre.org/) | AI and agentic adversary techniques and evidence maturity |
| [MITRE D3FEND](https://d3fend.mitre.org/about/) | Countermeasure semantics and attack-defense graph mappings |
| [OCSF](https://ocsf.io/) | Vendor-neutral security-event normalization |
| [CACAO/OpenC2](https://docs.oasis-open.org/openc2/openc2-cacao-ext/v1.0/openc2-cacao-ext-v1.0.html) | Structured playbook/command interchange compiled through nimrod authority |
| [ISO/IEC 42001](https://www.iso.org/standard/42001) | Organizational AI management and continuous-improvement readiness |
| SLSA, in-toto, Sigstore, and TUF | Build provenance, step attestation, artifact identity/transparency, and resilient updates |

### Target assurance maturity

| Release | Minimum assurance |
|---|---|
| Prototype | Threat model, conformance tests, dependency review, no production claims |
| Alpha | Secure build, SBOM, signed artifacts, recovery tests, privileged-code review |
| Beta | External penetration test, incident exercises, privacy validation, staged rollback |
| Public preview | Coordinated disclosure/bug bounty, public limitations, provenance verification |
| GA | Independent audit appropriate to claims, sustained operational metrics, applicable conformity plan |

## Secure development lifecycle

### Govern

- named product security owner and executive risk acceptor;
- security requirements traceable to threats and release gates;
- protected doctrine and decision records;
- separation of release, signing, review, and incident authority;
- annual and event-driven risk review.

### Design

- threat model before implementation and at every authority expansion;
- privacy data-flow and abuse-case review;
- memory-safe language for new trusted components;
- no custom cryptographic primitive;
- deny-by-default capabilities and explicit fail-mode table;
- recovery, safe uninstall, and product end-of-life designed with the feature.

### Build

- isolated ephemeral builds from reviewed source;
- locked dependencies and automated vulnerability/license review;
- secret-free source/build logs;
- compiler hardening, static analysis, unsafe-code inventory, fuzzing, and sanitizer runs where applicable;
- generated SBOM/AIBOM, provenance, checksums, and signatures;
- reproducible-build target for release-critical components.

### Verify

- schema and policy conformance;
- integration and end-to-end tests against supported platform APIs;
- hostile-content, confused-deputy, race, rollback, and evidence-tamper tests;
- fault injection and degraded-mode tests;
- independent post-state verification;
- external review of privileged, update, cryptographic, policy, and evidence paths.

### Release and operate

- progressive signed rollout with automatic pause criteria;
- monitored health without default raw-data centralization;
- emergency freeze and rollback rehearsed before preview;
- vulnerability intake, triage, remediation, notification, and disclosure workflow;
- explicit supported versions and end-of-life;
- evidence-preserving incident response and customer communication.

## Privacy program

### Data principles

1. Purpose before collection.
2. Minimum fields and minimum retention.
3. Local processing before external processing.
4. No model training from customer data by default.
5. No sale, advertising, or unrelated profiling.
6. User-visible access and export.
7. Deletion with a verifiable outcome, subject to documented legal/security retention conflicts.
8. Separate production, support, analytics, and research datasets.

### Required data inventory

For every field/event class record:

- source and collection method;
- purpose and lawful basis where applicable;
- live/replayed/simulated origin;
- sensitivity and jurisdiction;
- local and remote storage locations;
- processor/subprocessor;
- retention and deletion rule;
- user and operator access;
- model/tool exposure;
- export and cross-border path;
- security and privacy controls.

### Privacy threat tests

- secret and personal-data canaries through every export/model path;
- disabled telemetry remains network-silent;
- consent withdrawal stops future processing;
- export contains only selected scope;
- deletion removes active and scheduled copies and records lawful exceptions;
- support cannot access device evidence without authenticated, visible, expiring consent;
- incident retention does not silently become indefinite product analytics.

## Regulatory and legal readiness map

Applicability depends on entity, customer, data, features, and jurisdiction. Counsel must convert this map into an applicability memo before preview.

| Area | Why it matters | Pre-launch action |
|---|---|---|
| FTC Act and US privacy/security enforcement | Security/privacy promises and unreasonable practices can create enforcement risk | Substantiate every claim; align privacy notice and actual behavior; maintain reasonable security |
| State privacy laws including CCPA as amended | Rights, notices, sensitive-data limits, sharing/sale rules may apply at statutory thresholds | Determine applicability; build access/delete/correct/limit/opt-out workflows before they are needed |
| GDPR and ePrivacy | Endpoint events and identities can be personal data; monitoring may be high risk | Privacy by design/default, lawful basis, processor roles, DPIA screening, rights, transfers, DPA/SCC plan |
| EU Cyber Resilience Act | nimrod is a product with digital elements and security functionality | Product classification and conformity strategy; vulnerability/incident reporting readiness; technical file; support period |
| EU AI Act | Optional model analysis and later interventions may create provider/deployer duties | Classify each AI use, document human oversight, transparency, data/model governance, logs, and post-market monitoring |
| Consumer protection and product liability | Overbroad protection claims or harmful automation create risk | Claims matrix, limitations, safe defaults, insurance, incident and recall/rollback process |
| US export controls | Encryption and some security/digital-forensics functionality may require classification/reporting | Counsel-led ECCN/ENC analysis before public download or foreign access |
| Offensive security and dual-use controls | C2, adversary emulation, payload handling, testing services, and cross-border access create authorization, export, contract, and misuse risk | Connector license review, customer proof of authority, acceptable use, sanctions/export analysis, abuse response, and no third-party targeting |
| Sanctions and restricted-party rules | Global downloads/support may reach prohibited users/destinations | Distribution and payment screening appropriate to counsel’s scope |
| Trademark, patent, copyright, and software licenses | nimrod name has known prior uses; private source and integrations create IP and license duties | Keep nimrod internal while clearance is paused; block external release under that name; maintain freedom-to-operate triage, license inventory, access controls, and contribution/IP agreements |
| Sector laws | Health, finance, children, education, government, and critical infrastructure add duties | Exclude regulated use claims initially; run sector review before adding a profile |

### Time-sensitive EU baseline

As of the research date:

- The EU Cyber Resilience Act entered into force on 10 December 2024; vulnerability/incident reporting obligations begin 11 September 2026 and the main provisions apply from 11 December 2027 according to the [European Commission implementation timeline](https://digital-strategy.ec.europa.eu/en/factpages/cyber-resilience-act-implementation).
- EU AI Act obligations phase in across 2025–2027, while 2026 simplification proposals and implementation details continue to evolve. Use the [official AI Act Service Desk timeline](https://ai-act-service-desk.ec.europa.eu/en/ai-act/eu-ai-act-implementation-timeline) and obtain current counsel review rather than freezing dates from this plan.
- GDPR requires data protection by design and default, including data minimization and restricted access, as summarized by the [European Commission](https://commission.europa.eu/law/law-topic/data-protection/rules-business-and-organisations/obligations/what-does-data-protection-design-and-default-mean_en).

### US product baseline

- The [FTC privacy and security guidance](https://www.ftc.gov/business-guidance/privacy-security) anchors reasonable security, data minimization, and accurate promises.
- The [California Attorney General’s CCPA guidance](https://oag.ca.gov/privacy/ccpa) describes rights and statutory applicability thresholds; counsel must assess current thresholds and related state laws at launch.
- The [BIS encryption controls guidance](https://www.bis.gov/learn-support/encryption-controls) shows that public or mass-market encryption can still require classification, notification, or reporting before release; do not assume open publication removes every obligation.
- The [USPTO clearance guidance](https://www.uspto.gov/trademarks/search/federal-trademark-searching) states that federal search is only one part of comprehensive clearance and recommends considering trademark counsel.

## Certifications and attestations

Do not pursue certifications as substitutes for product evidence. Likely sequence:

1. Internal CSF/SSDF profile and evidence map.
2. Independent penetration test and secure-development assessment.
3. SOC 2 readiness only when a hosted service and enterprise buyers justify it.
4. ISO 27001 only when organizational maturity and market need justify the operating cost.
5. CRA conformity and other product-specific assessment based on final classification and market date.

## Required public transparency

Before preview publish:

- supported/unsupported platforms and scenarios;
- threat-model summary and residual-risk statement;
- data inventory summary and privacy notice;
- model/provider use and whether customer data trains models;
- security architecture and authority boundary summary;
- signed release artifacts, SBOM, provenance, and verification instructions;
- known issues, update, rollback, support, and end-of-life policies;
- vulnerability disclosure and security-contact details;
- evaluation methods, dates, environments, and limitations.
