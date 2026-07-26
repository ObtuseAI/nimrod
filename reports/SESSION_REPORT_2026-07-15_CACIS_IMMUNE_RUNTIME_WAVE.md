# CACIS W2 Immune Runtime wave report

Date: 2026-07-15  
Branch: `codex/edge-foundation-wave`  
Base revision: `d8b28e03082d302c49c41b20478d83411c549bf4`  
Working state: uncommitted review tree containing prior Edge and CACIS waves  
Outcome: `CACIS_IMMUNE_RUNTIME_W2_REPLAY_VALID_PROPOSAL_ONLY`

## Delivered

- Added versioned immune-organism mission and lifecycle-receipt contracts with canonical examples and semantic validation.
- Implemented a pure deterministic Governor scheduler over one immutable W1 generation.
- Added separate capability and resource leases, an exact prohibited-capability set, unique cells, and one bounded Shadow.
- Replayed an eight-cell credential-theft organism through 15 digest-linked lifecycle events.
- Preserved seven typed contributions, one explicit recovery abstention, and three candidate-only knowledge records.
- Proved Shadow pause, ambiguity-preserving resume, typed-proposal ceiling termination, complete cell teardown, scratch/context destruction, lease revocation, and final disposal.
- Added an offline CLI and 49 fail-closed cases spanning authority, leases, topology, Shadow control, event chains, resources, teardown, retention, verification, and activity claims.
- Advanced the CACIS roadmap W2 state to `validated_replay_only`; W3 and all operational effects remain blocked.
- Updated the Observatory to read the canonical lifecycle receipt and show evidence-derived counts, pending verification, and disposal state.
- Added ADR-071, W2 architecture documentation, TM-53 through TM-55, backlog, master-plan, reference-architecture, control-board, foundation, and manifest integration.

## Canonical replay result

| Evidence | Result |
|---|---|
| Cells | 8 unique roles including one Shadow |
| Events | 15 contiguous digest-linked lifecycle events |
| Contributions | 7 typed, generation-bound records |
| Abstentions | 1 explicit recovery abstention |
| Retained knowledge | 3 digest-addressed candidate-only records |
| Terminal state | `disposed` after `shadow_terminated` |
| Independent verification | required, not performed |
| Execution and target contact | false |

Mission digest: `sha256:2a62fccd7bbaa48dd98609d448092f6f1bb0fe75a2ab3f1054a5c601ed261e31`  
Lifecycle receipt digest: `sha256:6e860d5e51a210ce0056266b3b95fc460c078785ef0db8c0ff8fb143c9838cc8`

## Validation evidence

- Dedicated W2 harness: 49 adversarial cases rejected; deterministic API and CLI replay passed.
- Contract ladder: 93 schemas, 93 positive examples, 93 negative mutations, 88 semantic families, and one migration passed.
- CACIS roadmap harness: 17 fail-closed roadmap mutations passed.
- Control-board integration and JavaScript syntax validation passed.
- Full non-manifest regression ladder: all 33 validators passed in 70.29 seconds.
- Foundation gate passed with 419 required files, 223 parsed JSON documents, and 93 schema/example pairs; the v31 manifest was generated and independently validated after the evidence tree was sealed.

## Authority boundary

The Governor schedules but cannot authorize. The Shadow pauses or terminates but cannot authorize. Cells emit proposals or abstain but cannot verify, authorize, execute, change policy, contact a target, use credentials, run raw commands, or promote retained knowledge. Disposal and a valid receipt are lifecycle evidence only; they do not establish live isolation, secure erasure, independent settlement, or protection.

## Honest limits

This is deterministic single-process replay, not a live agent system. Resource use is replay evidence rather than operating-system measurement. There is no external queue, separate cell process or account, signed runtime identity, live telemetry, model call, sandbox, containment, recovery action, independent verifier, production tenant, or target connection.

## Next recommended waves

1. W3 Hypothesis Cortex: competing benign, malicious, unknown, novel, and deceptive hypotheses; counter-evidence; confidence vectors; metacognitive abstention; and independent settlement contracts.
2. W2 morphology expansion: add a suspicious-script replay with a different minimum-capability topology and require the same teardown invariants.
3. W4 Metabolism, Homeostasis, and Chronos: introduce measured information-gain budgets and multi-clock health controls only after W3 generates verifier and resource evidence.

## Publication state

No Git commit, push, pull request, external message, target contact, or operational action was requested or performed. The working tree remains available for review.
