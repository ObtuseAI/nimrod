# Range evidence admission

Status: `RANGE_EVIDENCE_ADMISSION_SIGNED_FIXTURES_RETAINED_OWNER_RANGE_AND_INDEPENDENT_VERIFICATION_BLOCKED`

## Purpose

Range evidence admission is the read-only document boundary between an owner-controlled sacrificial environment and the existing pre-execution gate. It accepts supplied observation envelopes, verifies governance and collector signatures, verifies raw content digests, and emits unproven attestations. It has no environment client, infrastructure provider, credential interface, source-tool adapter, network destination, executor, or verification authority.

The canonical state uses simulated fixtures because the owner has not named a sacrificial range. Nine fixtures validate the contracts but produce zero real observations, zero verified attestations, and zero independent verifiers.

## Three separated powers

1. `range-collector-policy.schema.json` is a short-lived 2-of-3 governance-signed policy. It binds one control to each of nine distinct collector IDs, logical principals, process IDs, and Ed25519 keys. Every collector is limited to `observe`, `digest`, and `emit_attestation`; destinations and secret references are empty.
2. `range-environment-observation.schema.json` is an individually signed observation envelope. It binds environment, scope, policy, control, collector, time, and inline raw evidence. The verifier recomputes raw byte length and SHA-256 digest before accepting the envelope as structurally valid.
3. `range-evidence-admission-report.schema.json` is a deterministic projection. It retains nine observation references and emits nine `unproven` attestations with no verifier identity. It cannot label any attestation verified or mark evidence complete.

Collector signatures prove who signed specific bytes under the local fixture policy. They do not prove that an environment exists, that a process identity is OS-enforced, that an observation is truthful, or that an independent verifier accepted it.

## Admission invariants

- exactly nine controls and exactly one collector per control;
- unique collector ID, logical principal, process ID, and public key;
- short-lived threshold-signed policy with exact governance and scope digests;
- individual Ed25519 signature over every observation envelope;
- exact environment, policy, scope, control, and collector binding;
- fresh observation time and canonical base64 payload;
- raw evidence retained inline with recomputed byte length and SHA-256 digest;
- credential and secret presence fixed false;
- all infrastructure, policy mutation, credential, tool, source contact, network, connection, and execution activity fixed false;
- all installation, provisioning, policy, credential, connection, execution, evidence-completion, and verification authority fixed false.

An owner-named policy may admit externally supplied `range` or `sacrificial_replica` observations, but admission still emits only `unproven` attestations. A separately governed independent verifier must inspect the retained evidence and issue a verifier-bound attestation. This module cannot perform that transition.

## Validation and limits

`tools/validate_range_evidence_admission.py` uses a fixture-independent document API, deterministically regenerates the three canonical examples, integrates emitted attestations into the existing pre-execution packet, and rejects 41 adversarial signature, threshold, identity-capture, scope, freshness, origin, content, secret, activity, report, and authority cases.

The proof is local and simulated. No environment was named, contacted, provisioned, changed, connected, or executed against. No credentials, source tools, offensive tools, or network endpoints were accessed. The retained fixtures are not range evidence.

## Next safe boundary

The next wave is an independent verifier acceptance contract for owner-supplied evidence. It must bind a separately identified verifier to one retained observation, preserve disagreement and abstention, and remain unable to connect or execute. A real collection campaign cannot begin until the owner names the sacrificial environment and separately approves the collector deployment, identities, credentials boundary, and network path.
