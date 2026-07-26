# Session report: range evidence admission wave

Date: 2026-07-13
Workspace: `C:\Users\developer\OneDrive\Documents\C\nimrod`
Branch: `codex/deployment-assurance-wave`
State: private-publication candidate; operational authority remains false

## Outcome

Completed backlog item nim-103 as a local document-verification boundary:

1. a short-lived 2-of-3 governance-signed read-only collector policy;
2. nine independently identified collectors with unique principals, process IDs, Ed25519 keys, and control assignments;
3. nine individually signed observations with inline content-addressed raw fixture evidence;
4. a deterministic admission report that emits nine unproven attestations and cannot verify itself.

The terminal state is `RANGE_EVIDENCE_ADMISSION_SIGNED_FIXTURES_RETAINED_OWNER_RANGE_AND_INDEPENDENT_VERIFICATION_BLOCKED`. The owner has not named a sacrificial range. Real observations, verified attestations, and independent verifiers are all zero. Evidence completion, installation, provisioning, policy mutation, credential access, source-tool contact, network contact, range connection, and execution remain false.

## Primary implementation

- `src/nimrod_simulator/range_evidence_admission.py`
- `specs/range-collector-policy.schema.json`
- `specs/range-environment-observation.schema.json`
- `specs/range-evidence-admission-report.schema.json`
- three deterministic canonical examples under `specs/examples/`
- `tools/validate_range_evidence_admission.py`
- `reports/RANGE_EVIDENCE_ADMISSION_VALIDATION.json`

The fixture-independent document API verifies governance signatures, collector uniqueness, policy and scope binding, observation freshness, individual signatures, raw byte length and digest, and immutable negative authority. It projects admitted documents into the existing pre-execution packet without creating a verified attestation.

## Adversarial validation

The dedicated harness rejects 41 policy, threshold, identity-capture, control-duplication, operation-widening, destination, secret, environment, scope, freshness, origin, signature, payload, digest, credential, activity, report, and authority attacks.

## Contract and control-board integration

- contract conformance: 63 schemas, 63 positive examples, 63 negative mutations, 58 semantic contracts, and one migration;
- the range-gate workspace now renders nine signed content-addressed fixtures, zero real observations, zero independent verifiers, and zero verified attestations;
- control-board state is bound to both the execution-gate and evidence-admission validation reports;
- the UI remains local-only and exposes no backend authority, credentials, endpoints, collection control, connection control, or executor.

## Explicit non-events

- no sacrificial environment was named or contacted;
- no infrastructure was provisioned and no host or network policy was changed;
- no credential was requested, read, or stored;
- no Atomic, Caldera, Mythic, Sliver, or commercial offensive tool was installed, launched, or contacted;
- no source tool, endpoint, range, or target connection was opened;
- no offensive action, campaign, candidate, or live execution occurred;
- no attestation was marked verified and evidence was not marked complete;
- no release, deployment, installation, connection, or execution was created in this wave.

## Review handoff

A complete non-destructive source snapshot, validation evidence, file hashes, and copy proof were prepared at `Z:\nimrod-review-packets\range-evidence-admission-wave-20260713-114759`. Repository metadata, project environments, dependency caches, build output, and transient artifacts are excluded.

## Validation

- Dedicated evidence-admission harness: pass, 41 adversarial cases.
- Contract conformance: pass, 63 schemas, 63 positive examples, 63 negative mutations, 58 semantic contracts, one migration.
- Control-board validator: pass, report-bound admission state and all operational authority false.
- Foundation validator: pass, 270 required artifacts and 147 parsed JSON documents.
- Full Python regression ladder: pass, 21 validators including canonical manifest-byte parity.
- Independent TypeScript evaluator build: pass.
- In-app browser QA: pass, updated range-gate panel visible, nine signed fixtures, zero real attestations, zero independent verifiers, all rendered operational authority false, and no horizontal overflow at the active viewport.
- The README hero was refreshed from the validated range-gate view so the repository presentation shows the current admission boundary without implying that fixture signatures are independent verification.

## Next safe boundary

Implement an independent verifier acceptance contract that binds a separately identified verifier to retained owner-supplied observations and preserves accept, reject, abstain, disagreement, and timeout states. Real collection still requires an owner-named sacrificial environment and a separate approval for deployment, identities, credentials boundary, and network path.
