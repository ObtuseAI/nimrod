# nimrod session report — governed intake and contract conformance

Date: 2026-07-16
Branch: `codex/takeover-w5-w6`
Authority change: none
Execution performed: no
Target contact performed: no

## Delivered

- Added two-role threshold-signed replay source policy, source-health attestations, and intake decisions for PowerShell, Sysmon, and DNS observations.
- Bound source purpose, exact collector configuration digests, freshness, future clock skew, gaps, a zero-second raw-event retention policy, immutable-history projections, and no-drop `defer_newest` backpressure.
- Revalidated the signed retention projections against the actual immutable World Model store immediately before commit.
- Added a separate verifier process that independently recomputes policy, health, admitted-event, queue, retention, generation, cursor, and governance bindings.
- Exposed governance, health, backpressure, retention, and contract-conformance evidence on the display-only Observatory.
- Published an exact 97-contract matrix separating schema validation, semantic validation, runtime-source filename references, independent-harness filename references, live evidence, and production claims.

## Validation evidence

- Complete sequential validation ladder: 41 of 41 validators passed.
- Contract suite: 97 schemas, 97 positive examples, 97 negative mutations, 92 semantic validators, one migration.
- Governed intake: 2 accepted events, 3 deferred events, 0 dropped events, 2 fresh sources, 1 explicit source gap.
- Governed intake adversarial ladder: 19 fail-closed cases passed.
- Contract conformance: 97 rows, 91 exact independent-harness references, 27 exact runtime-source references, 0 live-runtime evidence claims.
- Contract-conformance adversarial ladder: 8 fail-closed cases passed.
- Control board: all local evidence sources loaded with no network, credential, authorization, or execution bridge.

## Honest boundary

The signing keys and collector sessions in this wave are ephemeral replay evidence. The verifier is a distinct process, not a separately administered production identity or host. Live World Model admission, production signing custody, trusted time, enforced production retention, production backpressure, production-independent verification, containment, execution, and protection claims remain blocked.

## Recommended next waves

1. Expand deterministic replay scenarios across the remaining thirteen W6 arenas without fabricating live range outcomes.
2. Close the exact schema-only, semantic-only, and missing runtime-reference rows reported by `CONTRACT_CONFORMANCE_MATRIX.json`.
3. Add dedicated OS-account and custody evidence for the World Model, CIRE, and Observatory verifiers; keep W7 blocked until an owner-controlled disposable range supplies independent post-state evidence.
