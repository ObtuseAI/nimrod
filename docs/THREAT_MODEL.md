# nimrod threat model

Version: 0.1  
Method: asset/adversary/abuse-case model with STRIDE-style completeness checks  
Scope: first Windows Edge product and its release system

## Security objectives

1. A compromise of analytics must not grant action authority.
2. A compromise of one executor must not create broader or permanent capability.
3. nimrod must not falsely represent an action, repair, or recovery as verified.
4. Security data remains confidential and purpose-bound.
5. Users retain access, recovery, evidence export, and safe removal.
6. Updates cannot silently weaken policy, evidence, or authority boundaries.

## Crown-jewel assets

| Asset | Why it matters |
|---|---|
| Root/update trust anchors | Compromise enables persistent malicious releases |
| Authority policy and mandatory approvals | Compromise converts proposals into unauthorized actions |
| Executor capability tokens | Compromise enables device changes |
| Device and recovery keys | Compromise exposes data or defeats recovery |
| Evidence journal and artifacts | Tampering corrupts incident truth and accountability |
| User telemetry and protected content | Contains sensitive behavioral and business data |
| Emergency-disable and uninstall path | Loss can trap users under a compromised control plane |
| Release CI identity and signing workflow | Compromise scales harm to every installation |
| Detector/evaluator corpus | Poisoning hides threats or inflates claims |
| Privacy and retention policy | Weakening creates surveillance and legal exposure |

## Adversaries

- commodity malware and ransomware;
- targeted attacker with local user access;
- malicious or compromised browser/application content;
- compromised model, retrieval source, plugin, threat feed, or external service;
- software-supply-chain attacker;
- malicious insider, support operator, release engineer, or administrator;
- coercive or fraudulent actor manipulating a user;
- customer with legitimate access attempting tenant or policy boundary escape;
- researcher or competitor testing claims and failure modes;
- accidental operator, developer, or user error;
- compromised operating system, firmware, or hardware root beyond nimrod’s reliable control.

## Trust boundaries and entry points

- Windows event and control APIs;
- local inter-process communication;
- UI rendering and user approvals;
- imported files, URLs, messages, rule packs, policies, and evidence;
- model prompts, responses, retrieval, memory, and tool results;
- plugin packages and manifests;
- update metadata, artifacts, mirrors, and signing services;
- optional telemetry/export channel;
- support and vulnerability-intake systems;
- future design-partner synchronization service.

## Priority abuse cases

### TM-01 Hostile content becomes a command

**Path:** malicious document/page/event text instructs analytics to isolate a process, reveal a secret, or change policy.  
**Controls:** data/instruction separation, taint labels, schema-only model output, action compiler allowlist, deterministic policy, no model credentials, destination allowlist, adversarial corpus.  
**Verification:** inject hostile instructions into every content-bearing field and prove no capability issuance changes.  
**Residual risk:** parser, UI, or integration bugs may bypass taint propagation.

### TM-02 Analytics compromise reaches executor

**Path:** model or detection service calls an executor or forges an approved envelope.  
**Controls:** runtime identity separation, authenticated IPC, signed/short-lived capabilities, policy-issued audience-bound token, executor-side schema and target checks.  
**Verification:** red-team analytics process with arbitrary code execution and demonstrate inability to invoke or widen actions.  
**Residual risk:** shared OS compromise can undermine process isolation.

### TM-03 Evidence forgery or deletion

**Path:** attacker changes timestamps, removes failed actions, swaps artifacts, or reclassifies simulated events as live.  
**Controls:** append-only journal, hash-linked receipts, content addressing, source identity, origin classification, restricted retention process, optional external transparency witness.  
**Verification:** tamper, truncation, reordering, replay, clock-skew, and storage-corruption tests.  
**Residual risk:** a fully compromised device can forge future local observations; external anchors only bound the forgery window.

### TM-04 Update supply-chain takeover

**Path:** CI, dependency, maintainer, build runner, signing key, or mirror distributes malicious code/policy/model.  
**Controls:** protected branches, isolated ephemeral builds, pinned dependencies, SBOM, provenance, reproducibility, threshold signing, TUF-style roles, transparency, staged rollout, anti-rollback, emergency freeze.  
**Verification:** key compromise tabletop, malicious dependency drill, mirror rollback, freeze/rollback exercise, independent artifact verification.  
**Residual risk:** coordinated compromise of multiple trusted roles or toolchains.

### TM-05 Executor target widening

**Path:** process-specific restriction becomes host-wide isolation or termination includes unrelated processes.  
**Controls:** typed target identity, PID reuse defense, process start-time/hash/ancestry binding, prohibited-side-effect contract, capability-specific executor, blast-radius guard, post-state verifier.  
**Verification:** PID reuse, respawn, service-host, protected-process, race, symlink, and confused-deputy tests.  
**Residual risk:** platform semantics may not provide stable identity for every object.

### TM-06 False verification

**Path:** executor return code, stale cache, mocked connector, or UI value is accepted as the actual post-state.  
**Controls:** separate verifier identity and connector, freshness requirements, logical/visible dual check, explicit partial/timeout states, test-fixture provenance.  
**Verification:** force success-return/no-state-change, stale reads, partial changes, verifier outage, and UI overlay scenarios.  
**Residual risk:** executor and verifier may share a compromised underlying platform oracle.

### TM-07 Privacy exfiltration through support, telemetry, or models

**Path:** sensitive events/content leave the device beyond user purpose or are retained for training.  
**Controls:** local-first defaults, field-level classification, purpose binding, egress allowlist, redaction, explicit opt-in, provider contracts, deletion receipts, no training by default.  
**Verification:** data-flow tests, canary secrets, provider configuration audit, export inspection, deletion exercise.  
**Residual risk:** users may intentionally export sensitive evidence without understanding context.

### TM-08 Malicious or overbroad policy

**Path:** update, administrator, or compromised account weakens protection or grants surveillance/authority.  
**Controls:** signed versioned policy, protected constitutional rules, diff preview, mandatory-approval floor, expiry, two-person review, Witness receipt, safe rollback.  
**Verification:** attempt to lower mandatory gates, disable logging, extend retention, and create global grants.  
**Residual risk:** legitimate governance can approve harmful policy; technical controls cannot replace institutional accountability.

### TM-09 Denial of service and resource exhaustion

**Path:** event flood, large artifact, policy loop, model backlog, or full disk disables protection or the host.  
**Controls:** bounded queues, quotas, sampling rules that preserve critical events, priority lanes, circuit breakers, local degraded mode, disk reserve, watchdog.  
**Verification:** boot storm, process storm, network storm, full disk, slow verifier, and cloud outage.  
**Residual risk:** severe host resource exhaustion can prevent all local software from functioning.

### TM-10 nimrod traps or locks out the owner

**Path:** bad policy or compromised controller blocks uninstall, network, authentication, or recovery.  
**Controls:** owner-controlled recovery, offline safe mode, signed emergency-disable, time-bounded restrictions, no hidden master key, uninstall and data-export tests.  
**Verification:** expired cloud account, vendor outage, corrupted policy, lost secondary device, and compromised admin exercises.  
**Residual risk:** device/OS compromise can obstruct recovery outside nimrod.

### TM-11 Detector/evaluator poisoning

**Path:** crafted incidents or feedback teach the system to ignore threats, target legitimate tools, or promote a weak detector.  
**Controls:** verified-incident admission, provenance, isolated forge, sealed tests, poisoning tests, shadow/canary, no self-selected evaluator, threshold promotion.  
**Verification:** label-flip, backdoor, benchmark-gaming, data duplication, hidden-test leakage, and rollback tests.  
**Residual risk:** unknown distribution shifts and correlated evaluator blind spots.

### TM-12 Insider or support abuse

**Path:** privileged operator reads telemetry, issues policy, signs a release, or suppresses a report.  
**Controls:** least privilege, just-in-time access, separation of duties, threshold keys, tamper-evident access receipts, customer-visible access, immutable incident record.  
**Verification:** access review, orphaned account, break-glass, support impersonation, collusion tabletop.  
**Residual risk:** multi-party collusion and coercion.

### TM-13 Forged or overbroad campaign authorization

**Path:** attacker, customer operator, model, or connector forges authority, replays an old lease, substitutes a target, or expands scope through discovery.  
**Controls:** customer signatures, nonce and expiry, stable resource bindings, immutable target graph, two-person approval for high impact, revocation, amendment workflow, policy-side technique/effect allowlist.  
**Verification:** forged signer, replay, expired lease, DNS rebinding, cloud-resource replacement, hostname alias, nested tenant, and discovered-target tests.  
**Residual risk:** a legitimately authorized customer authority can approve harmful testing inside its legal domain.

### TM-14 Red connector or C2 compromise

**Path:** compromised Red platform steals secrets, widens targets, persists beyond the campaign, attacks the control plane, or hides cleanup failure.  
**Controls:** isolated disposable connector identity, leased egress proxy, no generic command API, separate Witness, no signing/policy access, bounded credentials, independent cleanup verifier, out-of-band kill switch.  
**Verification:** arbitrary-code execution in connector, credential theft, route escape, control-plane reachability, forged receipt, delayed callback, and post-expiry beacon tests.  
**Residual risk:** compromise of the customer network or target platform may weaken isolation below nimrod.

### TM-15 Target escape and uncontrolled propagation

**Path:** a campaign reaches third-party infrastructure, adjacent tenants, unmanaged assets, or internet destinations.  
**Controls:** exact target graph, stable IDs, route allowlist, DNS/IP pinning policy, connection budget, propagation prohibition, synthetic external services, continuous lease validation.  
**Verification:** redirect, proxy, NAT, service discovery, lateral movement, multi-homed host, cross-account role, and callback-domain tests.  
**Residual risk:** shared infrastructure can obscure ownership and routing boundaries.

### TM-16 Unsafe production effect

**Path:** an authorized test deletes data, exfiltrates secrets, encrypts files, modifies firmware, or affects physical safety.  
**Controls:** effect classification, safe-realism ceiling, twin/sacrificial-only classes, preflight recovery oracle, action compiler denylist, blast-radius budget, independent abort.  
**Verification:** every prohibited effect is attempted through direct, encoded, delegated, and vendor-specific representations and remains non-executable in ordinary production.  
**Residual risk:** a nominally reversible technique may interact with unknown application or physical dependencies.

### TM-17 Telemetry spoofing and causal misattribution

**Path:** attacker replays events, manipulates time, creates coincidental alerts, suppresses sensor health, or causes the wrong campaign to receive credit.  
**Controls:** signed source identity, trusted-time bounds, process/resource lineage, campaign markers, negative controls, raw-event digests, sensor-health evidence, independent target state.  
**Verification:** clock skew, duplicated events, cross-campaign overlap, stale indexes, dropped telemetry, forged rule IDs, and unrelated-alert tests.  
**Residual risk:** a fully compromised sensor and target can collude unless an independent oracle exists.

### TM-18 Kill-switch or cleanup failure

**Path:** orchestrator failure, connector compromise, network partition, stale credentials, or delayed agents prevent abort and cleanup.  
**Controls:** customer-side independent switch, short leases, capability revocation, route closure, dead-man expiry, cleanup playbook, post-expiry monitoring, literal incomplete state.  
**Verification:** control-plane outage, model outage, lost connector, partition, partial cleanup, delayed task, and revoked-token tests.  
**Residual risk:** an already completed irreversible external effect cannot be recalled.

### TM-19 Recursive-improvement takeover

**Path:** poisoned evidence, evaluator gaming, sealed-test leakage, threshold reduction, or self-selected signer promotes a malicious rule/model/playbook.  
**Controls:** quarantine, replay fixtures, provenance/license/secret checks, independent four-lens candidates, sealed evaluator, protected validation/rollback families, champion floor, tiered promotion, canary, automatic demotion.  
**Verification:** label flip, backdoor, benchmark leak, duplicate corpus, score manipulation, evaluator edit, authority-tier escalation, and rollback regression.  
**Residual risk:** correlated blind spots can exist across independently designed evaluators.

### TM-20 AI Capsule state or memory compromise

**Path:** prompt, context, tool, memory, retrieval, or model update changes agent behavior or launders authority.  
**Controls:** provenance and taint labels, versioned capsule state, non-transferable leases, memory quarantine, tool schemas, independent policy, signed snapshots, repair replay.  
**Verification:** prompt injection, tool-output injection, memory persistence, cross-mission leakage, poisoned retrieval, delegated capability, model rollback, and verifier disagreement.  
**Residual risk:** vendor-hosted model internals may not be independently observable.

### TM-21 Swarm coalition capture and quorum gaming

**Path:** duplicated agents, shared prompts, colluding providers, or role impersonation manufacture apparent consensus and suppress minority findings.  
**Controls:** unique agent identities, one contribution per constitutional role, distinct-role quorum, preserved opposition/abstention, mandatory Safety and independent-verifier roles, no executor.  
**Verification:** duplicate-role, missing-governor, planner-self-verification, forged contribution, quorum-count, and dissent-erasure tests.  
**Residual risk:** legitimately distinct humans, models, or providers may still share correlated blind spots or collude.

### TM-22 Semantic cascade and content-to-authority transition

**Path:** hostile objective text or one cell's prose becomes another cell's instruction, target expansion, executable field, or success claim.  
**Controls:** typed work items, role/output allowlists, command-like key rejection, immutable lease target graph, proposal-only contract, execution authority fixed false.  
**Verification:** hostile objective, nested directive, unknown target/technique, executable mission, and altered-authority tests.  
**Residual risk:** future model connectors can encode harmful intent inside allowed semantic fields unless independent evaluation remains effective.

### TM-23 Trust-policy replacement or threshold downgrade

**Path:** an attacker changes trusted keys, roles, threshold, or policy lifetime while replaying otherwise valid lease signatures.  
**Controls:** signatures cover domain-separated canonical lease bytes and trust-policy digest; minimum threshold two; distinct signer IDs; required roles; explicit policy window; local trusted input boundary.  
**Verification:** forged signature, changed lease, changed policy digest, duplicate signer, insufficient threshold, untrusted signer, and expired-policy tests.  
**Residual risk:** compromise of the local trust-policy distribution channel or all threshold keys defeats this reference boundary; production requires HSM/KMS and root-policy governance.

### TM-24 Control-board deception

**Path:** the UI hides origin, uncertainty, dissent, kill state, or authority limits and causes an operator to treat a proposal as executed or verified.  
**Controls:** literal simulated/no-execution banner, persistent dissent lane, exact authority matrix, false execution state, blast-radius pane, local-only demo data, no aggregate safety score.  
**Verification:** DOM/state checks, browser interaction tests, zero-console-error check, mobile overflow check, and kill-state disable behavior.  
**Residual risk:** a polished interface can still create overtrust; external usability and accessibility assessments remain required.

### TM-25 Authorization-state crash, replay, or split ownership

**Path:** a process dies between nonce preparation and commit, concurrent workers claim the same lease, or an attacker corrupts a durable claim so a consumed nonce appears reusable.  
**Controls:** durable prepared records, an atomically hard-linked complete owner record, deterministic commit recovery, fail-closed ambiguous-owner tombstones, immutable nonce digests, and cross-record consistency denial.  
**Verification:** abrupt process exit at five persistence boundaries, four rounds of 32 simultaneous OS-process claims, missing owner identity, replay, and committed-record corruption.  
**Residual risk:** the current Python/filesystem proof covers process crashes on the tested host; sudden power loss, filesystem/controller behavior, network filesystems, and hostile privileged storage mutation require platform-specific durability and anti-rollback evidence.

### TM-26 Trust-root takeover, downgrade, or key resurrection

**Path:** one signer lowers the threshold, reuses old public material under a new identity, reactivates a retired/lost/compromised key, widens custody operations, or signs recovery with a terminal key.  
**Controls:** 2-of-3 prior-epoch signatures, two-role minimum, exactly three active keys, immutable key identity/material/custody, non-exportable sign-only interfaces, terminal status monotonicity, consecutive epochs, and state-digest chaining.  
**Verification:** rotation, revocation, lost-key recovery, compromise recovery, one-signer, duplicate-signer, terminal-signer, threshold downgrade, export, operation widening, public-key reuse, affected-key omission, future transition, and epoch rollback cases.  
**Residual risk:** no real HSM or KMS was exercised; provider identity, attestation, availability, rate limits, audit export, deletion semantics, insider access, and cross-region recovery remain unverified.

### TM-27 Witness equivocation, truncation, fork, or anchor rollback

**Path:** an attacker rewrites evidence, reorders journal entries, truncates after an older valid prefix, forks receipts, substitutes a checkpoint or policy key, rolls back the anchor store, or presents different heads to different verifiers.  
**Controls:** content-addressed evidence, journal hash chain, RFC 9162-style domain-separated Merkle roots, 2-of-3 checkpoint signatures, content-addressed external checkpoint copies, signed receipt chain, signed head history, and a separately retained monotonic pin.  
**Verification:** artifact tamper, journal truncation/reorder, Merkle substitution, insufficient checkpoint quorum, receipt/checkpoint/head tamper, receipt fork, policy key substitution, missing head, nested storage, stale-pin forward consistency, and pinned-head rollback cases.  
**Residual risk:** the external anchor is a separate local filesystem connector, not a public or mutually witnessed transparency service; split-view resistance, gossip, external availability, timestamp authority, and power-loss durability remain unproven.

### TM-28 Verifier capture, credential bleed, or evidence mutation

**Path:** a verifier inherits cloud, signing, orchestration, planner, executor, or target credentials; writes the evidence it checks; shares a process with its supervisor; or impersonates a second verifier identity.  
**Controls:** fixed capability allowlist, explicit prohibited capabilities, replacement environment allowlist, credential-prefix denial, read-only source implementation, before/after input snapshots, distinct process IDs, distinct logical principals, and no signer/executor connector.  
**Verification:** two healthy service sessions, five separate verifier processes, credential-contaminated startup, duplicate identity, same-process dual identity, input hash equality, source write/process-token scan, identity-mismatch health, and explicit production-readiness false.  
**Residual risk:** both verifier processes run under the desktop user; Windows SID separation, restricted token, service ACL, read-only filesystem enforcement, and separate implementation diversity remain unproven.

### TM-29 Verifier disagreement suppression or availability laundering

**Path:** an orchestrator discards a dissenting invalid result, converts timeout/outage to success, accepts two verifiers checking different subjects, or lets one service replace a missing peer.  
**Controls:** subject digests, observation digests, distinct service/process/principal checks, literal reconciliation states, verification acceptance only for isolated `agreed_valid`, bounded process deadline, and durable error type/message.  
**Verification:** valid/invalid disagreement, agreed invalid, real killed timeout, real nonzero-exit outage, different-subject handling, missing-isolation agreement, and duplicate-service denial.  
**Residual risk:** supervisor compromise can suppress observations before persistence; production needs an independently monitored supervisor, durable signed observations, and process/account-level telemetry.

### TM-30 Control-board verifier-state laundering

**Path:** UI code substitutes an observation, accepts duplicated identities, hides a timeout or dissent, treats healthy reference processes as production-ready, or uses color/copy to imply accepted verification without the required OS boundary.  
**Controls:** versioned projection schema, exact two-observation digest binding, service/principal/process association, six literal operator states, persistent blocker codes, immutable false authorize/execute fields, and acceptance gated on consensus, health, dedicated OS identity, and read-only ACL evidence.  
**Verification:** six-state projection matrix; consensus-digest substitution, same-process, duplicate-principal, unknown-health, acceptance-mismatch, missing-health, and missing-ACL cases; canonical UI/example equality; desktop/mobile browser interaction; horizontal-overflow and console-error checks.  
**Residual risk:** the static prototype consumes local simulated JSON and has not undergone assistive-technology testing, hostile browser-extension testing, production transport-identity validation, or independent UX safety research.

### TM-31 Supervisor-to-board snapshot forgery or staleness

**Path:** an attacker substitutes a verifier projection, signs under the wrong governance epoch, redirects a valid snapshot to another audience, replays an expired snapshot, advances a future snapshot, or strips authority limits before presentation.  
**Controls:** domain-separated canonical bytes, 2-of-3 Ed25519 threshold and two-role diversity, exact issuer/audience/origin/governance/projection binding, bounded lifetime and future skew, monotonic sequence and predecessor digest, immutable false authorization and execution fields.  
**Verification:** signature tamper, insufficient and duplicate signer, projection/governance/issuer/audience substitution, stale expiry, future activation, and schema authority mutation cases.  
**Residual risk:** validation uses ephemeral in-memory keys and a local simulated supervisor; production service identity, HSM/KMS custody, secure clock, IPC authentication, and key-compromise response remain unproven.

### TM-32 Control-board ingress replay, rollback, or crash ambiguity

**Path:** concurrent consumers accept one snapshot twice, a process dies between preparation and head publication, an attacker inserts a sequence gap or predecessor substitution, or durable records/head are modified to make old state current.  
**Controls:** immutable preparation, exclusive per-sequence owner, content-bound acceptance record, monotonic snapshot digest chain, bound head, deterministic owned-transition recovery, and unowned-preparation quarantine.  
**Verification:** four injected crash boundaries; 16 concurrent accept attempts with one acceptance and 15 replay denials; older-sequence replay, gap, predecessor substitution, record tamper, and head tamper cases.  
**Residual risk:** process-crash behavior is validated on the local Windows filesystem; sudden power loss, malicious privileged deletion of all state, network filesystems, independent external pinning, and long-duration durability remain unproven.

### TM-33 External range-definition command smuggling

**Path:** hostile or drifted Atomic/Caldera YAML uses commands, cleanup, payloads, variables, YAML object tags, aliases, duplicate keys, technique substitution, platform/executor widening, or discovered targets to cross from source data into execution authority.  
**Controls:** 64 KiB UTF-8 cap; safe YAML parsing; alias/anchor/tag and duplicate-key denial; JSON-only value conversion; raw command/cleanup hashing then discard; privilege, payload/input, variable, missing-cleanup, URL, and prohibited-command findings; exact source kind/object/artifact/technique/platform/executor mapping; fixed simulated connector/capability; false connection/execution/discovery authority.  
**Verification:** two positive source formats and 23 adversarial parsing, mutation, drift, substitution, widening, authority, target-discovery, command-injection, sequence, and lease-ID cases; generated campaigns and receipts validate against public contracts and contain no prohibited command keys or fixture command text.  
**Residual risk:** semantic command screening is intentionally conservative and incomplete, validation keys are ephemeral, and no real tool/range isolation, egress, abort, cleanup, snapshot, or verifier behavior has been tested.

### TM-34 Range-policy, corpus, or preflight substitution

**Path:** an attacker replaces the adapter policy, lowers signer diversity, replays an expired envelope, swaps or omits corpus files, changes a source identity/digest, fabricates a proven control, reuses stale evidence, or turns preparation success into connection authority.  
**Controls:** domain-separated 2-of-3 Ed25519 policy envelope; exact policy and governance digests; active unique signers and role diversity; bounded time window; manifest entry digest; exact complete YAML file set; safe local normalization; exact pinned mapping; nine unique preflight controls; content-addressed evidence; preflight freshness; immutable false installation, connection, discovery, compilation, and execution authority.  
**Verification:** two valid signer roles and two corpus entries plus 31 adversarial signature, threshold, signer, time, authority, snapshot, identity, file-set, digest, evidence, freshness, and report-activity cases.  
**Residual risk:** keys and control evidence are simulated fixtures; no HSM/KMS, trusted-time service, real corpus version, disposable target, credential boundary, egress enforcement, kill path, restoration, cleanup, verifier, telemetry plane, tool, or network was tested.

### TM-35 Topology widening, kill rollback, or cleanup laundering

**Path:** architecture data provisions a route, a target reaches control or internet, credentials are reused, two kill commands race, a crash loses an engaged kill, replay resets state, cleanup evidence refers to another topology/generation, verifier identities collapse, snapshot drift is hidden, or a cleanup receipt authorizes reuse.  
**Controls:** declaration-only topology with three exact zones/nodes and two one-way routes; unique credential scopes; immutable default deny; short-lived 2-of-3 role-diverse kill signature; exact topology/generation/governance binding; one atomic state slot; no disengage transition; exact kill-state digest; six unique evidence-backed cleanup obligations; two distinct verifier IDs/principals/processes; common subject digest; baseline/post-state equality; immutable false reset/reuse/connection/execution authority.  
**Verification:** two injected crash boundaries; 16 concurrent kill attempts with one acceptance and 15 replay denials; signature, time, topology, route, credential, identity, snapshot, subject, obligation, authority, corruption, replay, and conflict cases among 38 adversarial tests.  
**Residual risk:** topology, evidence, processes, signers, snapshots, cleanup, and network behavior are simulated local fixtures; OS identity separation, power-loss durability, actual infrastructure control planes, provider snapshots, credentials, telemetry, route enforcement, tools, agents, and restoration remain unproven.

### TM-36 Constitutional capture or recursive promotion laundering

**Path:** a candidate rewrites the active baseline, weakens or replaces its Constitution, relabels a counterfactual as evidence, expands its resource lease, accesses sealed answers, collapses evaluator identities, averages away a hard failure, suppresses a capability trigger, self-selects signers, widens shadow into production, corrupts immutable artifacts, or races transition publication.  
**Controls:** short-lived 2-of-3 Constitution signatures; 20 exact axioms; immutable baseline with candidate writes false; digest-only candidate bundle; typed epistemic posture; constitutional resource ceilings; content-addressed artifacts; four distinct evaluator roles; eight lexicographic hard gates; five champion floors; scalar-score denial; six capability-trigger responses; Tier A/B shadow ceiling; threshold transition signatures; atomic receipts; signed demotion; and false execution, baseline-write, production, credential, network, compute-expansion, replication, and persistence authority. The autonomous controller recomputes assurance binding, accepts only pre-signed two-role transitions, cannot select signers or evaluators, and automatically demotes a shadow candidate when independently evaluated regression evidence crosses a hard gate or champion floor.
**Verification:** three distinct control-process IDs; signed demotion; two Foundry crash boundaries; 16 concurrent registrations with one acceptance and 15 replay denials; CAS corruption; and 36 adversarial constitution, epistemic, resource, capability, evaluator, gate, floor, transition, and authority cases. The autonomous-controller harness adds four evaluator bindings, two more crash boundaries, eight-worker contention with one acceptance and seven replay denials, one regression demotion, and ten fail-closed substitution, quorum, tier, resource, boundary, and authority cases.
**Residual risk:** Foundry control processes still share one desktop OS account; keys, candidate behavior, and evaluator results are simulated; sealed evaluator secrecy, model honesty, evaluator completeness, supply-chain diversity, power-loss durability, real candidate behavior, and production compatibility remain unproven. The independent TypeScript verifier reduces shared-implementation risk but does not establish operational independence or separate custody.

### TM-37 Evaluator identity forgery or evidence substitution

**Path:** one evaluator impersonates another role, reuses a signature for a different candidate, substitutes a capability report or ledger, changes evidence after signing, supplies an expired result, or collapses four logical roles into one principal/process/account.

**Controls:** threshold-signed evaluator trust policy; pinned evaluator ID, role, principal, account/SID, and Ed25519 key; individually signed short-lived observation envelopes; exact candidate, Constitution, capability-report, evaluation-input, ledger, isolation-attestation, process, and evidence binding; four unique identities and roles.

**Verification:** policy substitution, envelope signature forgery, role/identity mismatch, expiry, subject drift, duplicate identity, and authority-widening denial across the assurance and Foundry regressions.

**Residual risk:** identities, keys, accounts, and evaluator results are local simulated fixtures; independent ownership, sealed-test custody, key protection, and process launch identity remain unproven. A separate TypeScript/Node verifier now provides implementation diversity for contract verification only.

### TM-38 Isolation-attestation laundering

**Path:** a caller relabels a boolean as isolation proof, omits a control, swaps process or executable identity, claims fixture evidence is live, signs with an insufficient quorum, replays stale evidence, or lets the measured process collect its own attestation.

**Controls:** domain-separated threshold signatures; bounded freshness; exact governance/component/principal/process/executable/account/SID binding; seven mandatory controls; independent collector identity; explicit origin; immutable false authority; production eligibility only for verified live non-fixture evidence.

**Verification:** attestation substitution, missing control, process mismatch, signature failure, expiry, fixture-origin live-enforcement denial, and projection acceptance mismatch.

**Residual risk:** the read-only Windows collector now inspects a real process image, token SID, credential-key categories, DACL effective rights, firewall profiles, and rules bound to the exact executable. DACL evaluation is not a complete Windows authorization-context proof: privileges, conditional claims, share permissions, reparse behavior, and kernel or administrator compromise remain outside it. The collector does not create service accounts, apply ACLs, enforce egress, or close the five observed control gaps.

### TM-39 Resource-lineage reset or budget laundering

**Path:** a child candidate drops parent usage, rewrites history, reorders entries, understates measured use, resets a lease, creates uncounted children, substitutes a Constitution, or expands resources through a display or transition path.

**Controls:** threshold-signed ledger; content-addressed entry chain; exact parent/lineage/Constitution/governance binding; per-entry lease and measured usage; recomputed cycle, compute, peak memory/storage, and candidate totals; child-count consistency; immutable false resource-expansion authority.

**Verification:** entry tamper, head substitution, lineage/parent drift, signer failure, compute/storage/child overrun, and Foundry projection authority mutation.

**Residual risk:** a Windows Job Object now supplies live CPU, memory, storage, and I/O evidence for a benign worker and binds it into the ledger. The worker is created suspended and assigned before first resume, closing the assignment race. Energy and monetary cost are not metered, and file flush plus write-through publication with separate-process abrupt-crash recovery is not proof of physical power-loss durability or independent external accounting.

### TM-40 Platform-assurance evidence laundering

**Path:** a caller treats a live origin as complete enforcement, substitutes a validation report, lets the Python implementation validate itself, reports process-crash recovery as power-loss durability, hides a measured ACL/egress violation, or converts provider discovery into hardware-key custody.

**Controls:** exact versioned Windows measurement, resource-receipt, custody-readiness, and conformance-bundle schemas; independent TypeScript canonical JSON and Ed25519 verification; report-to-board field equality; immutable false authority; explicit verified-control count and blocker list; target-specific DACL and firewall evidence; separate process-crash and physical-power-loss fields; explicit suspended-assignment state; fixed false key/signing/private-material operations.

**Verification:** six isolation-collector adversarial cases, eight independent-evaluator cases, eight resource-meter cases, six custody-readiness cases, schema negatives, report binding in the board validator, and browser rendering of blockers.

**Residual risk:** local administrator compromise can forge observation context or alter both source and reports; the TypeScript verifier shares the same host and package supply chain; trusted time, hardware-backed keys and attestation, independent administration, enforced ACL/egress policy, and physical power-loss tests remain future gates.

### TM-41 Custody-readiness laundering

**Path:** provider enumeration is treated as proof that a hardware key exists, a failed TPM management query is relabeled as healthy, a software provider is represented as hardware-backed, or read-only discovery silently creates or uses key material.

**Controls:** provider names are retained only as digests; platform/software-provider presence is separate from a key reference; TPM values become unknown when the query fails; hardware key, signing, attestation, and private-material fields are fixed false; production custody is fixed false; authority contains no key or production capability.

**Verification:** live CNG enumeration, bounded read-only CIM inspection, exact blocker derivation, provider-count consistency, and six adversarial authority, count, blocker, production, key-creation, and TPM-laundering cases.

**Residual risk:** this desktop exposes a platform provider but TPM management state is inaccessible to the current identity. No non-exportable hardware key, provider attestation, audit trail, deletion/recovery ceremony, independent custodian, or production signing path was created or tested.

### TM-42 Range capability, scope, or attestation laundering

**Path:** an attacker adds an execute operation or network destination to a connector declaration, substitutes its source or governance state, widens a signed lease to production or multiple targets, maps the target to another topology node, weakens the out-of-band kill binding, treats valid signatures as environmental proof, duplicates or omits a control, replays stale evidence, assigns a verifier to an unproven claim, relabels simulated evidence as real, or changes a blocked packet into connection/execution authority.

**Controls:** short-lived domain-separated 2-of-3 connector signatures with role diversity; exact source-manifest and governance digests; one fixed simulation capability and compile/preflight/verify-only operation set; empty destinations and secrets; cryptographic authorization verification; exact single-target, topology, capability, kill-switch, effect, and budget binding; nine exact fresh attestations; verified evidence restricted to `range` or `sacrificial_replica` origin with content-addressed evidence and independent verifier identity; deterministic packet recomputation; immutable false installation, provisioning, discovery, evidence-completion, connection, and execution authority.

**Verification:** deterministic regeneration of the three canonical artifacts and 30 adversarial signature, threshold, freshness, substitution, widening, topology, proof, preflight, attestation, status, and authority cases. The control board binds the same blocked validation report and renders all nine missing real controls.

**Residual risk:** keys, topology, target, controls, and verifier records are simulated fixtures. The gate proves no actual isolation, credentials, egress policy, trusted clock, snapshot, telemetry separation, independent verifier, source-tool compatibility, licensing right, connector runtime, abort behavior, cleanup, network connection, or offensive action. Local privileged compromise could modify both code and generated evidence; production requires independent custody and externally retained evidence.

### TM-43 Collector capture, raw-evidence substitution, or self-verification

**Path:** one collector impersonates multiple controls, reuses a process or key, widens observe-only operations, adds a network destination or secret reference, substitutes an environment or scope, replays a stale observation, relabels a fixture as range evidence, changes retained bytes after signing, signs a different control, claims credential-bearing evidence is safe, or converts collector signatures into independent verification and execution authority.

**Controls:** short-lived domain-separated 2-of-3 collector-policy signatures; exact governance and scope digests; one unique collector ID, principal, process, key, and control assignment for every required control; observe/digest/emit-attestation-only operations; empty destinations and secret references; individual domain-separated Ed25519 observation signatures; exact policy, environment, scope, control, collector, and time binding; canonical base64 raw payload with recomputed byte length and SHA-256 digest; explicit no-credential/no-secret fields; attestation-only deterministic projection; verifier identity fixed absent; immutable false mutation, credential, installation, network, connection, verification, completion, and execution authority.

**Verification:** deterministic regeneration of three contracts, integration of nine emitted attestations into the existing pre-execution packet, and 41 adversarial policy, threshold, capture, scope, freshness, origin, signature, raw-content, credential, activity, report, and authority cases. The control board binds the admission report and renders nine signed fixtures as unproven.

**Residual risk:** policy signers, collectors, processes, raw payloads, and observations are deterministic local fixtures. Signature validity does not establish collector independence, OS identity, truthful measurement, trusted time, owner authorization, environment existence, or external retention. No sacrificial range has been named or contacted, and no independent verifier has accepted evidence. A privileged local attacker could modify code and regenerate internally consistent artifacts.

### TM-44 Verifier capture, outcome collapse, or fixture-acceptance laundering

**Path:** one verifier impersonates a quorum, shares a collector identity or key, substitutes another observation or raw digest, emits after expiry, widens its operations, converts abstention or timeout into agreement, hides dissent, accepts simulated evidence, or turns accepted controls into evidence-completion or execution authority.

**Controls:** short-lived domain-separated 2-of-3 verifier-policy signatures; exact admission-report, scope, environment, governance, and minimum-decision binding; unique verifier IDs, principals, processes, and Ed25519 keys; collector-identity separation; empty destinations and secrets; individually signed observation and raw-evidence bindings; exact `accept`, `reject`, `abstain`, and `timeout` vocabulary; deterministic five-state resolution; simulated/fixture acceptance denial; immutable false collection, completion, connection, and action authority.

**Verification:** deterministic regeneration of three contracts and 18 signed decisions; pure tests of accepted, rejected, abstained, disagreement, and timeout resolution; explicit simulated-acceptance denial; and 46 adversarial policy, identity, signature, freshness, binding, outcome-collapse, laundering, and authority cases. The control board binds the validation report and renders zero accepted controls.

**Residual risk:** all canonical verifiers and decisions are local deterministic fixtures with logical-only identities. The pure real-shaped accept test proves contract behavior, not independent operation. No owner-named range, separately administered verifier host, trusted clock, hardware key, external evidence retention, or evidence-completion authority exists.

### TM-45 Completion laundering or completion-to-execution escalation

**Path:** a caller weakens the required control, attestation, or verifier counts; substitutes another acceptance report, scope, or environment; replays an expired authorization; completes simulated evidence; changes a denial to authorization; or treats evidence completion as permission to connect or execute.

**Controls:** separate short-lived domain-separated 2-of-3 policy and authorization signatures; exact governance, acceptance-report, scope, and environment binding; nine exact accepted controls; nine verified attestations; two real independent verifiers; owner-named real origin; literal deny outcome; deterministic receipt; immutable false collection, installation, provisioning, credential, connection, execution, and action authority.

**Verification:** deterministic regeneration of three contracts, explicit canonical denial, positive real-shaped completion that remains non-operational, incomplete-real denial, and 36 adversarial threshold, signature, substitution, freshness, status, count, completion, connection, execution, activity, and authority cases. The board binds the completion report and renders the denial.

**Residual risk:** the positive path is contract-shaped test data, not real evidence. Local governance keys are ephemeral fixtures, and no owner-named range, real collector, externally administered verifier, trusted time, hardware custody, or external retention exists.

### TM-46 Public-source laundering or owner-scope collision

**Path:** a caller treats repository visibility as testing authorization; targets GitHub, CI, APIs, registries, a hosted demo, maintainers, or a third-party deployment; stages an owner-controlled repository omitted from an incomplete denylist; follows a moving branch; substitutes a revision or license; enables build-time Internet access; or converts source eligibility into connection or execution authority.

**Controls:** deny-first owner boundary with unknown ownership rejected; exact repository, branch, 40-character commit, and license metadata; explicit metadata-only state; eight forbidden public target classes; empty authorized network targets; separately declared offline replicas; no upstream, Internet egress, public ingress, GitHub, registry, or external DNS access; immutable false download, build, provision, connect, execute, public-target, and self-authorization fields.

**Verification:** deterministic regeneration of three versioned contracts over five source candidates plus 38 adversarial owner-collision, moving-reference, revision, license, source-state, replica-network, target, activity, count, and authority cases. The control board binds the same report and renders five pinned sources with zero ready replicas.

**Residual risk:** metadata observations do not establish source integrity, commit-signature validity, full license obligations, safe dependencies, build reproducibility, or owner independence. The exclusion registry is incomplete. No content archive, content digest, build zone, network isolation, replica, cleanup proof, or execution authority exists.

### TM-47 Signed-source acquisition laundering

**Path:** a caller treats governance signatures as owner attestation; substitutes the owner, public-source, or replica-plan digest; omits requested sources; inserts an authorized source or content digest; names an unproven construction zone; weakens quarantine controls; enables GitHub, registry, DNS, ingress, or egress access; replays an expired decision; or converts staging into build, connection, public targeting, or execution authority.

**Controls:** explicit incomplete owner registry with no ownership proofs; unknown ownership denial; exact governance, owner-registry, public-registry, and replica-plan digest bindings; all five requested source IDs; domain-separated 2-of-3 signatures with role diversity and a short validity window; literal signed denial; zero authorized source IDs and content digests; null construction zone; eight exact quarantine requirements; offline default-deny network declaration; immutable false acquisition, staging, extraction, dependency, build, provisioning, connection, execution, public-target, and self-authorization fields.

**Verification:** deterministic regeneration of three contracts, two verified signing roles, zero authorized/staged sources, zero completed quarantine controls, and 36 adversarial completion, attestation, proof, binding, freshness, signature, source-widening, network, staging, quarantine, activity, and authority cases. The board binds the same terminal denial.

**Residual risk:** signatures use deterministic fixture keys and do not prove real operator identity or legal authority. No owner attestation, complete exclusion registry, source archive, content digest, signature proof, isolated construction zone, quarantine scanner, SBOM, replica, or external evidence retention exists.

### TM-48 Construction-zone declaration laundering

**Path:** a caller treats a zone name, intended network boundary, storage declaration, or signed staging denial as proof that isolation exists; inserts a source archive or fabricated quarantine result; marks a network policy as applied; claims identity, storage, kill control, scanner, or SBOM activity; changes unproven controls to verified; or converts a preflight result into staging, build, connection, execution, public-target, or self-authorization authority.

**Controls:** exact binding to the denied source-staging authorization; ten exact isolation controls with `unproven` status and empty evidence; declared offline network with `policy_applied` false; disposable storage with no created volume, mount, or snapshot; eight exact quarantine results with `missing` status, `performed` false, null evidence digests, and empty evidence; zero source archives; deterministic counts; immutable false activity and authority fields.

**Verification:** deterministic regeneration of three contracts, zero verified zone controls, zero evidenced quarantine requirements, zero archives, and 40 adversarial declaration, evidence, count, source, provisioning, network, scanning, SBOM, activity, and authority cases. The control board binds the same terminal blocked report.

**Residual risk:** all inputs are local simulated declarations. No independently administered construction environment, dedicated identity, disposable storage, enforced network isolation, out-of-band kill, source ingress, separate output store, scanner, SBOM generator, external evidence retention, or operator provisioning authorization exists.

### TM-49 Provisioning authorization or attestor-independence laundering

**Path:** a caller treats governance signatures as operator approval; selects a provider, account, or credential without authority; substitutes the zone, preflight, or attestation plan; weakens live-evidence requirements; assigns one principal or process as both collector and verifier; fabricates observer identities or observations; authorizes only part of a widened operation set; or converts a denial into identity, storage, network, kill-control, staging, build, connection, public-target, or execution authority.

**Controls:** exact governance, zone, preflight, and attestation-plan digest binding; short-lived domain-separated 2-of-3 signatures with role diversity; ten exact control-specific evidence contracts; live-only evidence; at least two distinct principals and processes per control; empty collector, verifier, observation, provider, approval, credential, and authorized-operation fields; literal `deny_provisioning`; deterministic result; immutable false infrastructure and operational authority.

**Verification:** deterministic regeneration of three contracts, two verified governance roles, ten required controls, zero assigned collectors, zero assigned verifiers, zero verified controls, and 55 adversarial binding, signature, validity, evidence-contract, observer, provider, approval, credential, operation, provisioning, activity, and authority cases. The control board binds the same signed denial.

**Residual risk:** governance keys and observer requirements are deterministic local fixtures. No external operator identity, provider, dedicated collector/verifier host, hardware-backed observer key, trusted clock, independently retained evidence store, provisioned isolation, or operational release authority exists.

### TM-50 World-model observation poisoning or contradiction suppression

**Path:** a producer supplies an unsupported domain, invalid knowledge state, duplicate observation, broken provenance link, future or reversed time interval, mismatched evidence digest, inflated confidence, or conflicting fact while attempting to make the reducer silently select a preferred reality.

**Controls:** closed six-domain vocabulary; typed observation envelopes; exact identifier, timestamp, interval, confidence, provenance, and digest validation; duplicate rejection; explicit `unknown`, `stale`, and `contradictory` states; deterministic fact grouping; contradiction preservation rather than winner selection; immutable false authority fields.

**Verification:** canonical eight-observation credential-theft replay plus adversarial semantic cases covering unsupported domains, invalid intervals and digests, duplicates, confidence inflation, missing evidence, contradiction collapse, and authority mutation. The resulting generation preserves one contradictory identity fact, one stale endpoint fact, and one unknown recovery fact.

**Residual risk:** the replay uses deterministic fixtures. It does not establish sensor authenticity, independent custody, real telemetry freshness, adversarial-source resistance, or production detection quality.

### TM-51 World-model generation, head, or recovery tampering

**Path:** a caller changes an immutable observation or generation after preparation, renames content under a false digest, publishes a head bound to different content, exploits a partial write, or recovers a generation without verifying every referenced observation.

**Controls:** canonical content-addressed observation and generation files; file-name-to-content digest verification; prepared non-active head; atomic active-head publication; recovery that revalidates generation semantics, generation digest, head binding, every referenced observation digest, and deterministic replay equality.

**Verification:** clean prepare/recover/commit/recover sequence, simulated crash before activation, active-generation recovery, deterministic replay, and isolated tamper cases for observation content, generation content, digest path, prepared head, active head, and missing referenced evidence.

**Residual risk:** the local filesystem is not an independently administered append-only store. No hardware-backed signing, trusted clock, external witness, cross-host replication, or production disaster-recovery exercise exists.

### TM-52 World-model authority laundering

**Path:** a caller treats a derived generation, high confidence, known fact, active head, or successful replay as authorization to contain, execute, change policy, contact a target, or claim production truth.

**Controls:** authority is outside the world-model reducer; observation and generation contracts require false execution, authorization, policy-input, target-contact, and production-truth fields; the CLI performs offline replay only; prepared and active heads represent storage state, not permission; downstream use requires separate constitutional gates.

**Verification:** schema and semantic rejection of authority-bit mutations, focused fail-closed cases, board language that labels the generation offline and non-authorizing, and a validation report that keeps all live sensing, policy, execution, target, and production claims false.

**Residual risk:** downstream integrations do not yet exist. W2 and later components must preserve this separation and cannot infer authority from confidence, knowledge state, recovery success, or generation activation.

### TM-52A Continuous-intake replay, gap, or cursor laundering

**Path:** an intake reuses an already consumed record as new evidence; advances a cursor past unseen records; hides a source gap or unavailable sensor; substitutes the prior cursor, session, event digest, predecessor generation, or typed health value; publishes a successor against a stale head; or treats a world-ahead/cursor-behind crash as consistent state.

**Controls:** immutable transition artifacts; exact prior-cursor, prior-generation, session, event-set, accepted-record, event-digest, and candidate-generation bindings; per-source monotonic cursors; explicit replay and missing-record counts; typed health and continuity facts; separate-process causal recomputation; generation-first publication; and one narrowly recoverable world-ahead/cursor-prepared state that keeps policy and execution false.

**Verification:** two successive continuous-observation replays produce three immutable generations and two cursor transitions; old records are deduplicated; an internal record gap remains visible; unavailable Sysmon remains literal; sixteen adversarial mutations, active-head corruption, and digest-path escape fail closed; a simulated stop after generation publication recovers only the single generation-bound prepared cursor.

**Residual risk:** the sessions are deterministic replay. Policy and health are signed only by ephemeral validation custody; live source identity is unproven, clocks are local, the verifier lacks a separately administered account or host, retention and backpressure are not production-enforced, and live-origin World Model admission remains blocked.

### TM-52B Source-policy, health, retention, or backpressure laundering

**Path:** a caller swaps an allowed channel or purpose; retains raw payloads; widens queue or retention limits; marks an unavailable or stale source healthy; suppresses future clock skew; drops evidence while reporting deferral; selects later events ahead of earlier queued evidence; fabricates production verifier independence; signs a live-admission claim; or signs store projections that do not match actual immutable state.

**Controls:** three domain-separated 2-of-3 Ed25519 documents; exact source configuration digests and purpose; zero raw-payload retention; fixed metadata, generation, cursor, event, and queue ceilings; deterministic `defer_newest` behavior with dropping forbidden; health recomputation from the bound session; explicit freshness and future-skew fields; immutable false live admission; canonical unproven verifier boundary; and precommit comparison of signed projections with actual store counts.

**Verification:** two roles validate policy, health, and decision; the canonical queue accepts two, defers three, drops zero, and advances one governed successor; a separate process recomputes ten governance and causal claims; nineteen adversarial cases include fully re-signed malicious policies, health attestations, and decisions.

**Residual risk:** signing keys are validation-only ephemeral custody; source health is replay-derived; clock evidence is not from a trusted time authority; retention and backpressure are local deterministic enforcement; the verifier is not separately administered; and live admission remains blocked.

### TM-53 Governor, capability-lease, or topology authority escalation

**Path:** a scheduler treats a World Model generation as permission; grants authorization, execution, credentials, target access, raw commands, self-verification, or promotion; omits a denylisted capability; duplicates cell identities or roles; removes the Shadow; or substitutes another generation.

**Controls:** exact replay origin and generation digest; deterministic minimum-capability scheduling; separate short-lived capability and resource leases; exact allowlist and denylist; unique cell identities and roles; exactly one mission-bound Shadow; no ambient credentials, model calls, sandbox runs, raw-command bridge, policy, target, authorization, execution, self-verification, or promotion authority.

**Verification:** schema and semantic validation plus adversarial mission cases for Governor authority, allowlist or denylist weakening, credential and command widening, cell authority, duplicated topology, Shadow removal or substitution, resource-window mismatch, and generation substitution.

**Residual risk:** W2 uses logical in-process identities and deterministic fixtures. It does not prove separate operating-system principals, process isolation, queue authenticity, scheduler availability, production tenancy, or workload-appropriate resource ceilings.

### TM-54 Shadow capture, lifecycle evasion, or resource escape

**Path:** an organism removes pause, resume, abstention, or termination controls; changes event order or parent digests; continues after lease expiry; exceeds CPU, memory, storage, or telemetry budgets; fabricates normal completion; or survives after its terminal event.

**Controls:** six exact Shadow controls; three automatic termination triggers; digest-linked contiguous event sequence; strictly increasing timestamps inside one lease; resource-use comparison against the mission lease; explicit Shadow termination; mandatory cell termination, scratch destruction, context destruction, lease revocation, and final `disposed` state.

**Verification:** canonical 15-event spawn-to-disposal replay plus event-sequence, parent-chain, time, pause, abstention, terminal-reason, CPU, memory, teardown, and lease-revocation mutations. The CLI-restored receipt must equal the pure deterministic result.

**Residual risk:** resource use is deterministic replay data rather than an independently measured operating-system meter. A process crash, hostile runtime, storage failure, or host compromise could violate logical teardown without later W2 production-isolation evidence.

### TM-55 Knowledge, verification, or activity laundering after organism death

**Path:** raw context, credentials, commands, authority, or untyped memory survives disposal; an abstention becomes a positive claim; retained knowledge is promoted; the organism names itself as verifier; or the receipt claims target contact, execution, containment, recovery, or production truth.

**Controls:** typed contributions bound to known non-Shadow cells and the source generation; explicit `proposed` or `abstained` status; candidate-only digest-addressed retention; no raw context or retained authority; external verification required and unperformed; null verifier identity; immutable false credential, target-contact, execution, policy, self-verification, and promotion fields.

**Verification:** mutations cover contribution identity and generation substitution, self-verification, abstention removal, unknown knowledge source, knowledge promotion, raw-context retention, authority retention, verifier fabrication, credential issuance, target contact, execution, and security-claim inflation.

**Residual risk:** no independent settlement service, privacy retention engine, secure erasure proof, cross-process identity, signed receipt, or externally witnessed knowledge store exists. W3 must keep all W2 outputs provisional.

### TM-56 Research preregistration, metric, or evidence laundering

**Path:** a researcher substitutes the W1 or W2 source digest; marks replay as live; removes the null, rival, or unknown hypothesis; changes a metric or threshold after observing results; suppresses a hard failure; duplicates a case; or reports held-out evidence that does not exist.

**Controls:** exact content-addressed W1/W2 bindings; replay-only origin; preregistered null, candidate, rival, and unknown hypotheses; unique predictions and case identities; fixed paired design and metric set; eight exact hard failures; immutable false held-out, network, model-call, and generalization fields.

**Verification:** deterministic reconstruction plus adversarial source, hypothesis, prediction, method, case, metric, threshold, activity, and authority mutations. The canonical settlement binds the mission digest and all four method/case result digests.

**Residual risk:** preregistration is a deterministic local fixture rather than an externally witnessed timestamped protocol. There is no hidden partition, independent data custodian, contamination detector, or external replication.

### TM-57 Cognitive monoculture, complexity gaming, or challenge suppression

**Path:** the engine treats more operators as intelligence; omits skeptical challenges; collapses dissent into one winning hypothesis; converts structural coverage into task success; or optimizes a single benchmark until a brittle method appears universal.

**Controls:** paired baseline/candidate comparison; explicit complexity ceiling; required-operation, uncertainty, challenge, efficiency, and complexity metrics; six material challenge classes; durable null, rival, and unknown states; explicit structural-proxy limitation; no scalar promotion rule.

**Verification:** independent aggregate recomputation, exact challenge-set validation, counter-evidence references on every hypothesis, a partially-known metacognitive state, low generalization confidence, and deterministic rejection of challenge removal, metric inflation, complexity-ceiling gaming, status inflation, and missing-evidence suppression.

**Residual risk:** both methods and both cases were designed in the same repository. Structural-operation coverage may not correlate with accuracy, novelty, usefulness, safety, latency, or resource efficiency on real tasks.

### TM-58 Verifier capture, theory promotion, or recursive authority growth

**Path:** the research engine bypasses its separate verifier process, fabricates production independence, removes verifier limitations, upgrades a candidate theory to a law, generalizes outside the experiment, retains authority, changes the active baseline, or modifies constitutional policy.

**Controls:** distinct read-only verifier role; exact recomputation rather than trust in researcher summaries; explicit same-process limitation; false production independence; candidate-only theory with scope and falsifiers; false generalization, promotion, retained-authority, execution, policy, credential, target, self-verification, and constitution-modification fields.

**Verification:** 71 total fail-closed research cases include verifier capture, separate-process removal, production-verification fabrication, verified-claim and limitation removal, theory promotion, generalization, authority retention, security-claim widening, and settlement authority mutation. The replay harness also launches a distinct read-only verifier process with an allowlisted non-credential environment; dedicated OS-account and production independence remain unproven.

**Residual risk:** verifier separation is logical, not operating-system or administrative. No external witness, separate account, hidden evaluator, independent implementation, human scientific review, or W5 genome-admission gate has accepted the theory.

### TM-59 Resource oversubscription or priority gaming

**Path:** a work item hides cost, changes priority weights, claims exaggerated information gain, averages away a scarce resource, or treats allocation as permission to execute.

**Controls:** exact nine-resource budgets and cost vectors; weights that sum to one; deterministic ordering; all-dimension lease admission; visible backpressure deferral; schedule-proposal-only maximum outcome; immutable false authority.

**Verification:** mission mutations cover missing, extra, negative, and fractional resources, weight drift, cost omission, and authority widening. Receipt reconstruction rejects priority tampering, decision laundering, and resource oversubscription.

**Residual risk:** costs and expected benefits are deterministic replay inputs rather than independently measured operating-system usage or calibrated production outcomes.

### TM-60 Health, confidence, or backlog laundering

**Path:** a caller omits an unhealthy signal, turns a breach healthy, suppresses verifier backlog, trusts self-reported confidence inflation, or reduces thirteen signals to a reassuring aggregate.

**Controls:** exact ordered health vector; direction-specific thresholds; confidence inflation recomputed from understanding, calibration, generalization, and verification; explicit breached-signal list; separate counts for scheduled, deferred, and abstained work.

**Verification:** signal omission, reorder, substitution, bounds, state, confidence, backlog, and healthy-state mutations fail closed. The canonical replay remains `degraded_bounded` with ten breaches, `0.72` confidence inflation, and `0.80` verifier backlog.

**Residual risk:** W4 does not yet ingest signed continuous health observations, establish calibrated thresholds, or use an independently administered verifier queue.

### TM-61 Clock collapse, stale-evidence promotion, or deadline gaming

**Path:** a universal clock hides domain-specific decay; work carries future timestamps; a stale item is mislabeled fresh; expired evidence is scheduled; or clock thresholds are inverted.

**Controls:** seven exact ordered domain clocks; explicit freshness and expiry boundaries; evaluation-time binding; future-evidence denial; per-work clock assessment; mandatory expired-evidence abstention.

**Verification:** missing, reordered, substituted, zero, and inverted clock policies fail; future evidence fails; clock and decision reconstruction rejects expiry laundering. The canonical replay preserves four stale and two expired cases.

**Residual risk:** timestamps are local replay values. No trusted time source, signed sensor time, queue-delay measurement, leap handling, or production deadline enforcement exists.

### TM-62 Process separation laundered into verifier independence

**Path:** a caller treats a different PID as a dedicated verifier, ignores a shared SID or writable input, assumes egress denial without measurement, or converts an ephemeral validation key into production custody.

**Controls:** three explicit verifier surface identities; one live probe process per surface; allowlisted credential-free environment; external Windows process/SID collection; effective input-rights computation; fixed false active probing, egress enforcement, separate administration, production custody, and production eligibility; immutable no-authority result.

**Verification:** the live desktop records three distinct processes and zero dedicated accounts, read-only input ACLs, production custody, or production eligibility. Eight adversarial cases reject missing surfaces, PID reuse, identity and ACL fabrication, egress and custody fabrication, production laundering, and authority widening.

**Residual risk:** the probes are benign identity-readiness workers, not installed services. No dedicated service SID, independently administered host, enforced ACL, default-deny egress, trusted time, HSM/KMS custody, or external evidence store exists.

## Systemic hazards

| Hazard | Treatment |
|---|---|
| User overtrusts the product | Coverage gaps, uncertainty, known limitations, no universal score |
| Safety control disrupts legitimate work | Reversible-first ladder, impact preview, suspend before terminate, recovery rehearsal |
| Product becomes surveillance infrastructure | Local-first data, no advertising, visible access, purpose/retention controls |
| Product creates market-wide monoculture | Replaceable tools/models, open contracts, diverse detectors, staged rollouts |
| Strong defense is repurposed offensively | Defensive policy, connector scope, distribution controls, acceptable-use enforcement |
| Company failure strands users | Offline operation, documented export, owner recovery, safe uninstall, escrow/continuity planning |

## Out-of-scope assumptions that remain visible

The first product cannot guarantee trustworthy operation after arbitrary kernel, firmware, hypervisor, hardware, physical, or signing-authority compromise. These are not dismissed; they bound claims and drive later attestation and recovery work.

## Threat-model maintenance

Review this model at every authority expansion, new data class, connector, platform, model provider, release-system change, security incident, and major architecture revision. Each release evidence package maps relevant abuse cases to test results and residual risk.
