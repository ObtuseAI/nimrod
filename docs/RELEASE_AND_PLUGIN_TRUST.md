# Release and plugin trust foundation

## Release chain

Every Edge release candidate binds its artifact digest and size, provenance digest, SBOM digest, governance epoch, monotonically increasing release sequence, exact predecessor manifest, plugin manifest set, rollback target, validity window, and zero-percent rollout. A threshold of active Ed25519 governance keys with distinct roles signs the canonical manifest under a release-specific domain.

Offline verification checks:

- artifact bytes against the signed digest and size;
- exact `current sequence + 1` anti-rollback progression;
- exact predecessor and rollback-target digest binding;
- governance-state digest, signer validity, threshold, and role diversity;
- provenance and SBOM presence;
- rollback, offline verification, and safe-uninstall evidence declarations;
- the complete referenced plugin-manifest set.

The current receipt proves contract verification only. Validation custody is ephemeral, no MSIX is installed, no rollout is started, and no rollback or uninstall is performed. Production requires hardware-backed release custody, reproducible-build and provenance verification, independent staging infrastructure, compatibility evidence, emergency revocation, and observed rollback/uninstall exercises.

## Plugin sandbox

The foundation plugin profile is a WASI Preview 2 component with a 64 MiB memory ceiling, fuel ceiling, 500 ms wall-clock ceiling, no threads, no filesystem paths, no network or DNS access, and no lifecycle authority. Its only declared capability is process-metadata observation. Credential access, filesystem writes, host commands, networking, policy writes, process control, and signing are explicitly denied.

A valid manifest does not load or execute plugin code. The release candidate binds the manifest digest, while a later runtime gate must independently enforce the declared limits and prove termination, isolation, deterministic inputs, output validation, and rollback.

## Fail-closed states

Verification remains installation-blocked while any of these are true:

- the production signing custody boundary is unproven;
- no separate installation authorization exists;
- a staged rollout and rollback exercise has not been observed;
- an artifact, predecessor, governance state, signature, plugin set, or rollback binding differs;
- a plugin requests an undeclared capability or lifecycle action.
