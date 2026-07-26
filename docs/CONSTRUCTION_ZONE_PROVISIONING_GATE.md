# Construction-zone provisioning gate

Status: `CONSTRUCTION_ZONE_PROVISIONING_SIGNED_DENIAL_INDEPENDENT_ATTESTATION_BLOCKED`

## Purpose

The provisioning gate separates a construction-zone design from permission to create infrastructure. It binds the existing declaration-only zone and preflight result to an independent isolation-attestation plan and a short-lived threshold-signed authorization decision.

The canonical decision is `deny_provisioning`. It contains no provider, account, subscription, operator approval, credential reference, authorized operation, or provisioning adapter.

## Independent attestation design

Every one of the ten isolation controls requires live evidence from at least two distinct principals running in at least two distinct processes:

- a collector observes and content-addresses the control state;
- a separately identified verifier evaluates the retained observation;
- the environment under test cannot attest to itself;
- fixture or simulated evidence cannot satisfy the live-evidence requirement;
- missing, stale, disagreeing, or incomplete evidence remains a blocked state.

The plan defines control-specific evidence kinds for base-image provenance, ephemeral identity, disposable storage, DNS, GitHub, Internet and registry denial, public-ingress absence, the out-of-band kill path, and output-store separation. The canonical plan assigns no collector or verifier identities and retains no observations.

## Signed denial

Two governance roles sign the exact governance state, zone, preflight result, attestation plan, validity window, requested operation set, denial outcome, blockers, and immutable false authority. Signatures authenticate the denial; they do not create operator approval, choose a provider, grant credentials, or provision anything.

## Deterministic result

The canonical result preserves:

- 2 verified governance signers in 2 roles;
- 10 required controls;
- 0 assigned collectors;
- 0 assigned verifiers;
- 0 verified controls;
- no operator approval or provider selection;
- provisioning authorization and activity false;
- staging, build, connection, and execution authority false.

The harness rejects 55 binding, signature, validity, observer-independence, evidence, operation, approval, provider, credential, provisioning, activity, and authority mutations.

## Residual boundary

No provider connector, independent collector, verifier service, dedicated principal, isolated host, storage, network rule, kill control, scanner, SBOM generator, source archive, replica, or campaign exists. A future owner-approved implementation must select the environment and evidence producers through a separate operational release gate.
