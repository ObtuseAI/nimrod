# nimrod trust root and Witness anchoring

Status: `SIMULATED_KEY_GOVERNANCE_AND_EXTERNAL_ANCHOR_REFERENCE_VALIDATED`

## Current boundary

This reference implements trust-root and evidence-anchor contracts without claiming production custody or public transparency. All private signing keys are generated in memory by the validation harness and are never committed, serialized, or exported. PKCS#11, AWS KMS, Azure Key Vault, and Google Cloud KMS appear only as supported connector kinds in a sign-only, non-exportable interface. A separate read-only Windows readiness check enumerates CNG storage providers and queries TPM management state; it does not create, delete, reference, or use a key. No provider endpoint, credential, HSM, KMS, trusted timestamp service, or public log was contacted.

## Key governance

Each governance epoch has exactly three active Ed25519 keys, a threshold of two, and at least two separation-of-duties roles. The prior epoch authorizes every transition. The next state must advance exactly one epoch and bind the full prior and next state digests.

Supported ceremonies are rotation, revocation, lost-key recovery, and compromise recovery. Each ceremony simultaneously moves the affected key to a terminal status and introduces an active replacement so the system never silently degrades below 2-of-3. Historical keys cannot disappear, terminal keys cannot reactivate, public material cannot be reused, and custody metadata cannot widen beyond signing.

Production custody connectors must provide stable provider key references, non-exportability, hardware-backed status, public identity, signing, structured failures, bounded retry behavior, audit evidence, and attestation where available. The current protocol boundary is compatible with PKCS#11-style token signing, whose standard interface keeps cryptographic objects behind a token API, but no such integration is yet implemented. [OASIS PKCS #11 v3.1](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/pkcs11-spec-v3.1.html)

The lifecycle rules follow the key inventory, protection, compromise, recovery, and trust-anchor concerns described by [NIST SP 800-57 Part 1 Rev. 5](https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final). They are not a claim of NIST compliance or validation.

## Witness checkpoints

The checkpoint builder first verifies the existing Witness journal and all content-addressed artifacts. It then commits the selected journal prefix with:

- tree size;
- SHA-256 Merkle root using `0x00 || leaf` and `0x01 || left || right` domain separation;
- canonical journal-prefix digest;
- latest entry digest;
- previous checkpoint digest;
- governance state identity, epoch, and digest;
- 2-of-3 signatures from active governance keys.

The Merkle construction follows the core tree-hash shape in [RFC 9162](https://www.rfc-editor.org/rfc/rfc9162.html). nimrod does not implement the Certificate Transparency wire protocol, SCTs, or a public CT log.

## External anchor and pin

The anchor root must be separate and non-nested from Witness. It stores each signed checkpoint by digest, issues a separately signed monotonic receipt, chains receipts, and publishes a separately signed head for every sequence. A third root retains the independently observed pinned head. Verification recomputes every anchored prefix from Witness, verifies both signature domains and both chains, validates forward movement from an older pin, and rejects a current anchor older than or inconsistent with the pin.

This resembles transparency-log anchoring and inclusion verification patterns such as [Sigstore Rekor](https://docs.sigstore.dev/logging/overview/), but the implemented anchor remains a local filesystem connector. Production work still needs an external service, split-view/gossip analysis, availability policy, timestamp authority, privacy review, retention, cross-tenant isolation, provider authentication, and independent operations.

## Proven cases

The key harness validates four positive ceremonies and fifteen fail-closed attacks. The anchor harness validates two growing checkpoints, an older pinned head advancing consistently to the current head, an independent verifier process, and sixteen fail-closed tamper, truncation, reorder, fork, substitution, nesting, missing-state, and rollback cases. The Windows readiness harness observes five CNG storage providers including the platform provider, preserves the inaccessible TPM management state as unknown, and rejects six custody-laundering mutations. Provider presence is compatibility evidence only.

## Unproven properties

- a stable hardware key reference, real HSM/KMS identity, attestation, audit, retry, deletion, and disaster recovery;
- public transparency, gossip, split-view resistance, or trusted time;
- storage-controller or sudden-power-loss durability;
- multi-host consensus, quorum availability, or regional failover;
- production key ceremony operations, independent human custody, and TPM management access;
- any live defensive or offensive security outcome.
