# Signed range-readiness gates

## Current state

`RANGE_READINESS_GATES_VALID_CONNECTION_BLOCKED`

This layer proves only that three fail-closed preparation contracts behave as specified against simulated local fixtures. It does not install or contact an offensive tool, provision or connect to a range, deploy an agent, discover a target, or authorize execution.

## Gate chain

```text
2-of-3 signed adapter policy
  -> exact local corpus manifest and read-only compatibility scan
  -> fresh disposable-range evidence preflight
  -> separately authorized connection request (not implemented)
```

Each step binds the digest of its upstream evidence. A downstream document cannot repair, widen, replace, or authorize an upstream document.

## Threshold-signed adapter policy

The policy envelope uses domain-separated canonical JSON and Ed25519 signatures. Verification requires:

- exact policy and key-governance state digests;
- a 2-of-3 threshold and at least two distinct governance roles;
- unique active signers and a bounded validity window;
- simulated origin and the `no_execution_fixture_only` policy stage;
- immutable false connection, execution, and target-discovery authority.

The reference signer is ephemeral validation-only custody. It is not HSM, KMS, production identity, or release-signing evidence.

## Read-only local corpus scanner

The scanner accepts an operator-supplied local directory and manifest. It never fetches definitions. It rejects manifest authority, duplicate entry IDs or paths, path escape, symbolic-link sources, snapshot-digest mismatch, missing files, and unexpected YAML files. Each declared Atomic or Caldera object must normalize safely, match its declared artifact digest, and match an exact signed policy mapping.

Compatibility means only `compatible_no_execution`. The report explicitly records that compilation, source-tool contact, network access, and live execution were not performed. Compatibility does not imply that an upstream project version, tool API, or real connector is supported.

## Disposable-range preflight

The preflight is fresh evidence for exactly nine controls:

1. cleanup contract;
2. dedicated credentials;
3. default-deny egress;
4. disposable target;
5. independent verifier;
6. out-of-band kill;
7. restorable snapshot;
8. telemetry separation;
9. trusted time.

Every control appears exactly once. A `proven` control requires content-addressed evidence. Stale, future, incomplete, duplicated, unknown, substituted, or authority-bearing input fails closed. A compatible corpus is also mandatory.

When every control is proven, the maximum result is `ready_for_separately_authorized_range_connection`. That result still fixes `tool_installation_authorized`, `range_connection_authorized`, and `execution_authorized` to false. A later connector design must introduce a separate, explicit authorization path; this gate cannot be reused as authority.

## Evidence and residual risk

The validation harness exercises 31 adversarial cases across policy signatures, time windows, digest substitution, authority widening, corpus identity/file-set drift, evidence completeness, report activity, and preflight freshness. The canonical corpus contains two controlled local fixtures, not upstream Atomic Red Team or Caldera repositories.

Still unproven: real signing custody, trusted-time infrastructure, an independently enforced service account and read-only ACL, actual disposable infrastructure, snapshot restoration, default-deny egress, kill-switch behavior, cleanup, telemetry separation, credentials, source-tool compatibility, range connectivity, and any offensive action. Those remain hard blockers.

## Implemented successor boundary

The declaration-only topology, irreversible out-of-band kill state, and snapshot/cleanup verification receipts are now implemented in `RANGE_LIFECYCLE.md`. They remain local and simulated. Actual provisioning, topology enforcement, connection, and execution still require a separately approved isolated environment and independently verifiable preflight evidence.
