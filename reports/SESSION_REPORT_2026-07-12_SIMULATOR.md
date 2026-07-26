# nimrod no-execution simulator implementation report

Date: 2026-07-12  
Workspace: `C:\Users\developer\OneDrive\Documents\C\nimrod`
Outcome: `FOUNDATION_AND_CRUCIBLE_SIMULATOR_VALID`  
Launch readiness: `BLOCKED_NO_DEPLOYABLE_PRODUCT`

## Implemented

- Added an installable Python 3.11+ `nimrod-simulator` package and `nimrod-simulate` CLI.
- Compiles the existing Authorization Lease and Validation Campaign contracts into schema-valid Action and Evidence Envelopes.
- Enforces lease validity windows, explicit revocations, customer kill-switch state, preflight evidence, immutable target scope, fixed capability scope, effect ceilings, budgets, cleanup obligations, and campaign-to-lease binding.
- Atomically consumes lease nonces in a separate local state store so replay fails across independent invocations.
- Rejects command-like keys hidden inside target bindings or expected-state objects.
- Provides a fixed no-op connector with one capability, no secrets, simulated-only destinations, closed lifecycle operations, and no command, network, payload, or target-mutation path.
- Writes content-addressed JSON artifacts and a hash-chained append-only Witness journal with post-write verification.
- Emits schema-valid Evidence Receipts and Causal Coverage Verdicts.
- Keeps no-op verdicts literally `ineffective`; successful simulator completion never becomes a claim of defensive coverage.
- Records `live_execution_performed: false` and `cryptographic_authorization_verified: false` in every run summary.

## Integration and adversarial evidence

The validation harness executes one API flow, one CLI flow, and 21 fail-closed cases covering:

- expired and not-yet-active leases;
- explicit lease revocation;
- caller-supplied and atomically persisted nonce replay;
- customer kill-switch denial before output or connector lifecycle;
- target, capability, connector, and effect-ceiling escape;
- sacrificial effects requested against ordinary production;
- action-budget exhaustion;
- missing preflight and cleanup evidence;
- campaign/lease mismatch;
- ambiguous origin and unsupported cryptographic claims;
- nested command-like execution directives;
- overlapping Witness and lease-state directories;
- hostile natural-language content attempting authority expansion;
- non-empty output reuse;
- content-addressed artifact tampering.

Validation results:

- foundation status `FOUNDATION_AND_CRUCIBLE_SIMULATOR_VALID`;
- all eight Draft 2020-12 contracts and positive examples valid;
- all eight contract mutations rejected;
- simulator status `SIMULATOR_INTEGRATION_VALID`;
- project dependency check clean;
- nine runtime Python files compile;
- 44 typed functions contain no default parameters and no `typing.Any` use;
- lowercase `nimrod` enforcement remains active;
- source brief hash remains `E070C8EF1A0356A5981824598A39EEEF7390428FBA8C8CCA3EE3BD899094F4FC`.

## Honest limitations

- Lease approval and signature references are structurally validated but not cryptographically authenticated.
- The Witness detects artifact/journal inconsistencies but has no external signature or transparency anchor; an attacker controlling the entire store could rewrite all local evidence.
- Crash recovery, concurrent nonce claims across network filesystems, retention/compaction, schema migration, latency/storage characterization, and independent verifier process separation remain incomplete.
- No range, live target, sensor, SIEM, EDR, C2, payload, active-response, containment, cleanup, recovery, or product protection behavior was exercised.
- No offensive tool was installed or launched.
- No GitHub repository was created or modified.
- No git commit was created.

## Next engineering gate

The next safe increment is cryptographically verifiable authorization and independent process separation, followed by crash/recovery and concurrency testing. Only after those pass should the first isolated-range Atomic/Caldera connector be implemented; Mythic or Sliver remains behind the dedicated C2 range gate.

Shared handoff root: `Z:\nimrod-simulator-sprint1-20260712-154906`
