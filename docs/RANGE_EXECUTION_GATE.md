# Range execution gate

## Current state

`RANGE_EXECUTION_GATE_NON_PROVISIONING_SCOPE_COMPILED_REAL_EVIDENCE_BLOCKED`

The range execution gate is the deterministic boundary between validated architecture data and any future connector or environment activity. It verifies a threshold-signed connector declaration, compiles one cryptographically authorized lease target into one declared topology binding, and assembles a pre-execution evidence packet. It cannot provision infrastructure, install software, contact a source tool, discover targets, connect to a range, deploy an agent, or execute an action.

## Contract chain

```text
signed authorization lease
        +
threshold-signed non-provisioning connector manifest
        +
declaration-only disposable topology
        |
        v
exact lease-to-topology scope
        +
topology verdict + range preflight + environment attestations
        |
        v
pre-execution evidence packet
        |
        v
blocked_missing_real_environment_evidence
```

The chain is deliberately one-way. A successful cryptographic check establishes document integrity and authorized intent; it does not establish a real environment, operational isolation, or permission to connect or execute.

## Non-provisioning connector capability manifest

The connector manifest binds the exact source connector declaration and governance state by digest. A 2-of-3, role-diverse Ed25519 threshold signs a short-lived document. Version 0.1 permits only:

- capability `range.test.simulate`;
- operations `compile`, `preflight`, and `verify`;
- environment class `isolated_range`;
- content-addressed artifacts.

Network destinations and secret references are empty. Installation, source-tool contact, target discovery, provisioning, connection, and execution are false. The manifest remains blocked by missing runtime, unapproved license review, and missing real-range attestations. It is a capability declaration, not a connector implementation.

## Lease-to-topology scope compiler

The compiler verifies the existing authorization proof against its trust policy, validates the connector manifest and topology, and accepts exactly one `windows_device` target with environment class `range`. It computes the exact capability intersection, target binding, topology node and zone, effect ceiling, kill-switch binding, budgets, and source digests.

It rejects production targets, multiple targets, unsupported resource types, missing capability intersection, in-band kill switches, stale leases, forged proofs, substituted topology or governance, and any authority widening. Its terminal state is `compiled_contract_only_environment_unproven`.

## Real-environment evidence packet

The packet requires exactly nine fresh controls:

1. cleanup contract;
2. dedicated credentials;
3. default-deny egress;
4. disposable target;
5. independent verifier;
6. out-of-band kill;
7. restorable snapshot;
8. telemetry separation;
9. trusted time.

A verified control requires origin `range` or `sacrificial_replica`, content-addressed evidence, and a named verifier identity, logical principal, and process. Simulated evidence may exercise the contract but may not become verified. Unproven evidence may not claim a verifier. Duplicate, missing, stale, future, or origin-laundered attestations fail closed.

The current canonical packet contains nine simulated `unproven` attestations, zero real attestations, zero verified verifiers, and `evidence_complete: false`. It therefore reports every real control as missing.

## Immutable negative authority

Every generated artifact preserves false values for:

- installation and provisioning;
- source-tool and network contact;
- target discovery;
- range connection;
- evidence-completion authority;
- execution and live execution.

No model, swarm, UI, report, attestation, successful signature check, or compiler result can change those fields. A later operational design must introduce a separate owner-approved contract and cannot reuse these documents as execution credentials.

## Validation evidence and limits

The deterministic harness regenerates the three canonical examples, validates them against Draft 2020-12 schemas, and rejects 30 adversarial cases covering signature forgery and threshold underflow, manifest widening and substitution, lease and scope widening, proof tamper, topology/preflight laundering, attestation duplication, omission, freshness, origin and verifier misuse, packet substitution, status laundering, and authority expansion.

This evidence proves local contract behavior only. It does not prove that a disposable range exists, that network or credential isolation is enforced, that a snapshot is restorable, that an independent verifier or trusted clock is operational, that a tool license permits integration, or that any offensive tool is installed, safe, reachable, or controlled.

## Next safe boundary

The read-only environment-evidence admission boundary is now implemented in `RANGE_EVIDENCE_ADMISSION.md`. It defines a governance-signed collector policy, nine individually signed connector-neutral fixture observations, content-addressed raw retention, and an attestation-only projection. The owner-named environment, real observations, and independent verification remain missing.

The next safe boundary is an independent verifier acceptance contract for owner-supplied retained evidence. Creating infrastructure, changing host or network policy, handling credentials, installing tools, opening a connection, or executing a campaign remains a later explicit owner-approved gate.
