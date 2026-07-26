# Session report: range execution gate wave

Date: 2026-07-13
Workspace: `C:\Users\developer\OneDrive\Documents\C\nimrod`
Branch: `codex/deployment-assurance-wave`
State: uncommitted owner-review worktree

## Outcome

Implemented the next non-provisioning Crucible boundary:

1. a short-lived 2-of-3 signed connector capability manifest;
2. a lease-to-topology scope compiler with one exact simulated Windows range target;
3. a pre-execution evidence packet requiring nine real-environment attestations;
4. a display-only range-gate workspace in the operator control board.

The terminal state is `RANGE_EXECUTION_GATE_NON_PROVISIONING_SCOPE_COMPILED_REAL_EVIDENCE_BLOCKED`. Cryptographic authorization verifies, but zero real attestations exist. Provisioning, installation, source-tool contact, network contact, range connection, and execution remain false.

## Primary implementation

- `src/nimrod_simulator/range_execution_gate.py`
- `specs/range-connector-capability-manifest.schema.json`
- `specs/range-lease-topology-scope.schema.json`
- `specs/range-preexecution-evidence-packet.schema.json`
- three deterministic canonical examples under `specs/examples/`
- `tools/validate_range_execution_gate.py`
- `reports/RANGE_EXECUTION_GATE_VALIDATION.json`

The dedicated harness verifies exact deterministic regeneration and rejects 30 adversarial cases. It denies signature and threshold failure, connector capability or authority widening, source/governance substitution, lease/scope widening, authorization-proof tamper, topology and preflight laundering, attestation omission/duplication/freshness/origin/verifier misuse, packet substitution, status laundering, and authority expansion.

## Foundation and UI integration

- registered 60 Draft 2020-12 schemas, positive examples, and negative mutations;
- registered 55 semantic contract validators and one migration;
- added the range-gate artifacts to the foundation validator;
- added a local-only control-board tab for connector, scope, evidence, and negative-authority state;
- bound UI range state to the validation report and canonical packet;
- kept the UI free of external resources, backend authority, credentials, target controls, and persistent storage.

## Documentation and doctrine

Added `docs/RANGE_EXECUTION_GATE.md` and updated the lifecycle, master plan, Crucible design, reference architecture, threat model, control-board design, public launch gates, Phase 0 backlog, decision register, and README. ADR-060 and TM-42 record the capability/scope/evidence separation and its abuse resistance.

## Validation

- Python compileall: pass.
- Dedicated range execution gate: pass, 30 adversarial cases.
- Contract conformance: pass, 60 schemas, 60 positive examples, 60 negative mutations, 55 semantic contracts, one migration.
- Control-board validator: pass, 32 required UI surfaces, zero external resources, range state report-bound, connection/execution false.
- Foundation validator: pass, 258 required artifacts, 140 parsed JSON documents, 60 schemas and examples.
- Full Python regression ladder: pass, 19 validators.
- Independent TypeScript evaluator build: pass.
- In-app browser QA: pass, range-gate panel visible, 0/9 real attestations, all operational authority false, zero browser errors, and no horizontal overflow.
- Presentation screenshot: refreshed at `docs/assets/nimrod-control-board.png` from the validated local-only range-gate view.

## Explicit non-events

- no infrastructure was provisioned;
- no host or network policy was changed;
- no credential was requested or accessed;
- no Atomic, Caldera, Mythic, Sliver, or commercial offensive tool was installed, launched, or contacted;
- no range or target connection was opened;
- no offensive action or live execution occurred;
- no commit or push was created in this wave.

## Review handoff

A complete non-destructive source snapshot, validation evidence, refreshed control-board screenshot, file hashes, and copy proof were prepared at `Z:\nimrod-review-packets\range-execution-gate-wave-20260713-111125`. Repository metadata, project environments, dependency caches, build output, and transient artifacts are excluded.

## Next safe boundary

Design read-only, connector-neutral collectors for the nine environment controls on an owner-named sacrificial range, with independently identified verifiers and content-addressed raw observations. Provisioning, policy changes, credential handling, tool installation, connection, and execution remain separately owner-gated.
