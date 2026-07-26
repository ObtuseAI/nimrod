# Construction-zone preflight

Status: `CONSTRUCTION_ZONE_DECLARED_QUARANTINE_EVIDENCE_MISSING_STAGING_BLOCKED`

## Purpose

The construction-zone preflight defines the evidence contract that must exist before any eligible public source can be staged. It is a declaration and verifier boundary only. It cannot create an identity, storage, network policy, kill control, scanner, source mount, output store, source archive, build, connection, or campaign.

## Isolation declaration

The canonical isolated-construction-zone declaration binds the denied source-staging authorization and declares ten required controls:

1. clean base image;
2. dedicated ephemeral identity;
3. disposable workspace;
4. no external DNS;
5. no GitHub access;
6. no Internet egress;
7. no public ingress;
8. no registry access;
9. out-of-band kill control;
10. separate output store.

Every control is `unproven`, every evidence list is empty, and the network policy is declared but not applied. The zone has not been provisioned.

## Quarantine evidence receipt

The quarantine receipt binds the same source-staging decision and requires eight separately evidenced results for provenance, commit integrity, license review, secret scanning, malware scanning, dependency lock/reproducibility, build reproducibility, and SBOM generation. The canonical receipt contains no source archives or content digests. Every result is `missing`, `performed` is false, and every evidence list is empty.

## Deterministic decision

The preflight may report readiness only from evidence already present in the two bound contracts. It cannot infer enforcement from declarations, signatures, intended topology, or a successful schema validation. The canonical result therefore preserves:

- 10 declared zone controls and 0 verified controls;
- 8 quarantine requirements and 0 evidenced requirements;
- 0 source archives;
- construction-zone provisioning false;
- quarantine completion false;
- staging, build, range connection, and execution authority false.

The adversarial harness rejects 40 declaration laundering, fabricated evidence, count drift, source insertion, provisioning, network-enforcement, scanning, SBOM, activity, and authority mutations.

## Required next evidence

A future operator-approved design must identify the separately administered construction environment and the independent evidence producers for each isolation and quarantine control. That design is not provisioning authority. Source acquisition, scanner execution, dependency resolution, builds, connections, and campaigns remain outside this implementation.
