# Disposable range lifecycle contracts

## Current state

`RANGE_EXECUTION_GATE_NON_PROVISIONING_SCOPE_COMPILED_REAL_EVIDENCE_BLOCKED`

This layer defines and validates a simulated topology, an irreversible out-of-band kill transition, and snapshot/cleanup evidence. It does not provision infrastructure, configure a network, issue credentials, install or contact a tool, connect to a range, deploy an agent, or execute an offensive action.

## Topology declaration

The topology is descriptive data, not infrastructure-as-code. It requires exactly three isolated zones and three disposable nodes:

- one sacrificial target in the target zone;
- one write-only telemetry collector in the telemetry zone;
- one independent kill switch in the control zone.

The only declared routes are one-way target-to-telemetry export and one-way control-to-target kill. Every zone denies internet access. Every node has a unique dedicated credential scope. Default-deny egress, no target-to-control route, no credential reuse, and false provisioning/connection/execution authority are immutable contract properties.

A valid declaration returns `declared_contract_valid_environment_unproven`. It does not prove that a real environment exists or enforces the declaration.

## Out-of-band kill and revocation

The kill command is a short-lived domain-separated canonical JSON document signed by at least two active governance keys across two roles. It binds the exact topology, generation, governance state, reason, and validity window. The only command is `engage`; there is no `disengage`, reset, or reuse transition.

The filesystem connector writes and flushes a private temporary state, then atomically publishes one complete hard link. One range generation has one state slot. The first valid command wins; identical replay and conflicting commands fail closed. A process crash before publication remains retryable. A crash after publication preserves the engaged state.

## Snapshot and cleanup verification

Recovery evidence binds the exact topology and durable kill state, a baseline snapshot digest, an observed post-cleanup digest, six cleanup obligations, and exactly two distinct verifier identities, principals, and processes.

Required obligations are:

1. agent absence;
2. credential disposition;
3. route closure;
4. target restoration;
5. telemetry finalization;
6. tool-artifact removal.

Every verified obligation requires content-addressed evidence. Both verifiers must bind the same cleanup subject. Snapshot mismatch, rejection, stale evidence, missing obligations, identity collapse, or digest substitution blocks the receipt.

Even `verified_contract_only` fixes `kill_remains_engaged: true` and keeps range reuse, connection, and execution unauthorized. A new range requires a new topology generation and a later separately authorized provisioning path.

## Evidence and limits

The lifecycle harness covers 38 adversarial cases, two injected process-crash boundaries, and 16 simultaneous kill attempts with exactly one accepted engagement and 15 replay denials. These are local simulated filesystem and contract proofs.

Still unproven: actual zone isolation, network policy, trusted time, dedicated credentials, independent kill infrastructure, platform snapshot semantics, agent/tool inventory, credential revocation, route closure, telemetry finalization, independent OS identities, hardware-backed signing, real cleanup, real restoration, provisioning, range connectivity, and execution.

## Successor execution gate

The non-provisioning successor is now implemented in `RANGE_EXECUTION_GATE.md`. It threshold-signs an exact connector capability declaration, compiles one authorized lease target into one topology binding, and requires nine real-environment attestations. The canonical packet remains blocked with zero real attestations and false installation, provisioning, source-tool contact, network contact, connection, and execution fields.

## Next safe boundary

The next recommended wave is a read-only environment-attestation collector design and fixture-independent verification harness for an owner-named sacrificial range. Actual provisioning, policy mutation, credential handling, tool installation, connection, or execution remains a later explicit owner-approved gate.
