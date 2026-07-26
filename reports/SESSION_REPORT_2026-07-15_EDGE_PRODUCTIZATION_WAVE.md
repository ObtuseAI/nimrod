# nimrod Edge productization foundation wave

## Session outcome

Status: `EDGE_LIVE_OBSERVATION_RELEASE_TRUST_AND_DESIGN_PARTNER_PLAN_VALID_PRODUCT_AUTHORITY_BLOCKED`

This wave completed three bounded items: a caller-scoped live Windows observation adapter, an offline signed update and deny-by-default plugin trust path, and a consent-first design-partner evidence kit. The implementation remains an uncommitted review state on `codex/edge-foundation-wave`; no commit or push was requested.

## 1. Live Windows Edge observation

- Measures exactly one caller-selected process through six supported read-only Win32 interfaces.
- Emits executable, path, account, and SID digests without retaining raw executable paths or SIDs.
- Does not enumerate processes, probe the network, inspect credentials, modify the host, or run continuously.
- Preserves destination, parent process, publisher, and writable-path classification as missing.
- Cannot produce an egress-policy decision, proposal, authorization, or execution request.
- Validation uses one real benign Windows process through both API and CLI paths and seven fail-closed cases.

## 2. Signed release and plugin trust

- Verifies a domain-separated Ed25519 candidate manifest with two distinct governance roles.
- Enforces exact predecessor sequence and digest, local artifact digest and size, governance binding, validity window, provenance/SBOM presence, and rollback/uninstall declarations.
- Binds the complete plugin-manifest set into the signed release.
- Restricts the foundation plugin to WASI Preview 2, 64 MiB memory, bounded fuel and time, one metadata capability, and explicit denial of networking, filesystem writes, host commands, process control, credentials, policy writes, and signing.
- Performs no plugin load, plugin execution, installation, rollout, rollback, uninstall, or network access.
- Rejects twelve artifact, signature, signer, anti-rollback, governance, rollback, plugin, expiry, and authority mutations.

## 3. Design-partner evidence kit

- Defines a 5–8 partner target and five evidence-comprehension, authority, privacy, and export tasks.
- Requires explicit consent and operator-chosen aliases.
- Forbids raw endpoint telemetry, external telemetry upload, credential collection, background surveillance, and default screen recording.
- Preserves zero participants, zero contact, zero consent records, zero installations, zero endpoint collection, zero external messages, and an unsatisfied exit gate.
- Rejects eight fabricated-activity, privacy, consent, task, exit, and product-claim mutations.

## Contract and safety evidence

- Contract ladder: 88 schemas, 88 positive examples, 88 negative mutations, 83 semantic contracts, and one migration.
- Product validators: live observation, release/plugin trust, and design-partner plan all pass.
- Host changes, process/network modification, action proposals, installation, plugin execution, participant contact, and production claims remain false.
- Production custody, continuous sensing, publisher/destination/parent correlation, actual rollback, enforced plugin runtime isolation, and real design-partner evidence remain blocked.

## Shared review packet

The handoff target is `\\fileserver\shared\nimrod-review-packets\edge-productization-wave-20260715`. The packet includes the complete review tree, prior Edge UI screenshot, SHA-256 inventory, and copy proof.

## Recommended next waves

1. Build a bounded continuous Windows event-source spike with measured privacy, performance, loss, ordering, and process/destination correlation while remaining observe-only.
2. Add reproducible-build verification, production-custody interfaces, MSIX inspection, revocation, and disposable-VM rollback/uninstall exercises without authorizing host installation.
3. Extend the control board with explicit live-versus-replayed origin, sensor gaps, update trust, plugin capability, and design-partner readiness views backed only by validated local reports.

Only after those gates should a separately approved disposable-VM containment prototype be considered, with user confirmation, narrow process scope, independent post-state verification, and tested recovery.
