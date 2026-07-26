# Source staging gate

Status: `SOURCE_STAGING_SIGNED_DENIAL_OWNER_SCOPE_AND_QUARANTINE_BLOCKED`

The source staging gate separates public-source eligibility from acquisition. It accepts the pinned public corpus only as untrusted metadata and requires a complete owner-scope registry, owner attestation, exact source bindings, threshold authorization, an isolated construction zone, and quarantine evidence before any archive may be staged.

## Current decision

Two governance roles signed an explicit `deny_staging` decision over:

- the current governance-state digest;
- the incomplete owner-scope registry and its digest;
- the five-source public registry and its digest;
- the declaration-only replica plan and its digest;
- all five requested source identities;
- an offline default-deny network declaration;
- eight mandatory quarantine requirements.

The decision authorizes zero sources and zero content digests. It names no construction zone and exposes no download, staging, extraction, dependency-resolution, build, provisioning, connection, execution, public-target, or self-authorization capability.

## Owner boundary

The known deny set contains `obtuseai` and `obtuseai/nimrod`. The registry is intentionally incomplete because the owner has not supplied an exhaustive organization/repository list or ownership-proof digests. Unknown ownership remains denied. Neither a model nor a governance signature may fabricate owner attestation or mark the registry complete.

## Quarantine requirements

Every exact source archive must independently satisfy:

1. source provenance;
2. archive content digest;
3. commit-signature verification;
4. license-obligation review;
5. secret scanning;
6. malware scanning;
7. reproducible extraction;
8. SBOM generation.

All eight are currently unperformed. They are evidence requirements, not operations authorized by this contract.

## Current evidence and limits

The deterministic harness validates three Draft 2020-12 contracts and rejects 36 adversarial registry-completion, binding-substitution, freshness, signature, source-widening, network, staging, quarantine, build, activity, and authority cases. No repository content was downloaded; no source archive was staged or extracted; no dependency, image, replica, infrastructure, public testing target, range connection, or campaign was used.

The next operational step requires owner-supplied scope attestation and a separately reviewed design for a network-isolated construction zone. This repository does not implement that operational step.
