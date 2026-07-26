# nimrod World Model intake succession wave report

Date: 2026-07-16
Branch: `codex/takeover-w5-w6`
Base revision: `b1b65dd8eecbf11f8c9cbc5fa6463b2b69f17a9d`
Working state: uncommitted owner-review tree containing the takeover and World Model succession waves
Outcome: `nimrod_world_intake_succession_replay_valid_live_admission_blocked`

## Delivered

- Extended the immutable World Model store from one first generation to predecessor-bound successor generations without changing the canonical W1 digest.
- Added durable per-source cursors for PowerShell, optional Sysmon, and DNS Event Log evidence.
- Added replay-safe record deduplication, explicit missing-record counts, unavailable/access-denied health preservation, and nine typed health/continuity/new-event-count observations per successor.
- Added immutable cursor-transition artifacts bound to the prior cursor, prior generation, continuous-observation session, event set, accepted event digests, candidate generation, and resulting cursor.
- Added recoverable two-head publication. A generation may advance before its cursor, but the intermediate state remains non-authorizing and only the single generation-bound prepared cursor may finalize.
- Added a separate read-only verifier process that recomputes eleven causal claims under a credential-free ambient environment and verifies its four input files were not modified.
- Added a product CLI, ADR-074, threat path TM-52A, control-board projection, roadmap rebaseline, validation report, and current-state documentation.

## Canonical replay evidence

| Evidence | Result |
|---|---|
| Immutable World Model generations | 3 |
| Immutable cursor transitions | 2 |
| Continuous sources | 3 |
| Typed observations per successor | 9 |
| Replayed records deduplicated | 2 |
| Sources with explicit record gaps | 1 |
| Missing records preserved | 1 |
| Separate-process causal verification | Performed |
| Production verifier independence | Not proven |
| Live sensor admission | Not performed |
| Policy or execution authority | False |

## Validation evidence

- W1 first-generation validation remains unchanged: digest `sha256:4f679eb5e8ff1e00761369a928247aed55e10a581b9b257b617a78e8000b5766`, 26 fail-closed cases.
- Succession intake: 16 fail-closed cases covering authority widening, digest and predecessor substitution, cursor jumps, record or event omission, hidden gaps, sensor-health laundering, typed-observation substitution, stale successor commit, live-origin admission, active-head corruption, and digest-path escape.
- Contract ladder remains 97 schemas, 97 positive examples, 97 negative mutations, 92 semantic contracts, and one migration.
- CACIS roadmap remains 21 fail-closed cases and now names signed live source health, production retention/backpressure, and separately administered verification as blockers.
- Control board loads nine local evidence sources and renders generation count, cursor transitions, gaps, and verifier state without display authority.
- Full non-manifest regression ladder: 39 of 39 validators passed.
- Canonical manifest: 484 indexed files, zero hash mismatches, and zero normalization failures. Foundation: 469 required files, 238 parsed JSON documents, and all 97 schema/example pairs.

## Authority and privacy boundary

This wave admits replayed continuous-observation sessions only. Raw Windows Event Log payloads are not retained. No live session enters the World Model. No generation, cursor, verifier, CLI result, recovery state, dashboard value, or signed evidence can authorize policy, execution, containment, recovery, target contact, promotion, or production truth.

## Honest limits

- Event source identity and health are not yet threshold-signed or independently administered.
- The causal verifier is a separate process but not a separately administered Windows identity, host, account, or organization.
- Retention, compaction, backpressure, trusted time, cross-host replication, and external witnessing are not production-enforced.
- The canonical events are deterministic replay. The real read-only Edge observer remains collection evidence only and is not a World Model input.
- No offensive tool, public target, live range, containment, recovery action, model API, installation, promotion, or production execution was used.

## Next recommended waves

1. Add signed source identity and health, retention enforcement, bounded intake backpressure, and separately administered verification before considering live World Model sensor admission.
2. Put CIRE and Observatory verifier/evaluator roles under dedicated OS identities or hosts and run genuinely sealed private and external evaluations.
3. Expand W6 replay evidence across the remaining thirteen arenas and publish the 97-contract runtime-conformance gap matrix.
4. Keep W7 blocked until an owner-controlled isolated range proves authorization, abort, cleanup, recovery, and independent post-state verification.

## Goal and publication state

The explicit long-running goal is active: complete nimrod through its evidence-gated roadmap, then update GitHub presentation, commit, push, and verify the private remote. This wave is not the terminal roadmap state, so no commit, push, pull request, target contact, or external publication was performed.
