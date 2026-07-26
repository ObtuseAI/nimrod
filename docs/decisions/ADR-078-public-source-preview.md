# ADR-078: Public source preview

Status: `ACCEPTED_BY_OWNER_PUBLIC_SOURCE_PREVIEW`

Decision date: 2026-07-26

Decision owner: project owner

## Context

nimrod was developed under a private, proprietary repository posture. The
owner requested a public portfolio release of the repository while the product,
operational, efficacy, legal, and commercial launch gates remain incomplete.

Making the historical private repository public would expose private operating
records and workstation-specific metadata. Describing the source preview as a
product or open-source launch would also exceed the available evidence and
license decision.

## Decision

Publish a curated, clean-history snapshot as a public source-available research
preview under the `ObtuseAI/nimrod` repository identity.

The release:

- uses the defensive-research edition of the ObtuseAI Source-Available License;
- permits non-commercial evaluation, education, defensive research, security
  review, and portfolio review on explicitly authorized systems;
- labels examples and screenshots by their actual simulated, replayed, or
  read-only origin;
- preserves every constitutional, authorization, evidence, abstention,
  validation, and recovery boundary;
- makes no production protection, efficacy, containment, response, or recovery
  claim; and
- does not approve binaries, hosted services, customer access, operational
  connectors, commercial use, offensive use, or critical-infrastructure use.

## Consequences

- Repository visibility may be public after release-readiness, secret, path,
  dependency, claim, and clean-clone validation pass.
- Historical private Git history remains in a private archive.
- GitHub private vulnerability reporting becomes the preferred disclosure
  channel after publication.
- The public repository name is a project identifier, not a trademark
  registration or claim of exclusivity.
- Gates A through K in `docs/PUBLIC_LAUNCH.md` continue to govern any later
  product or operational release.

## Rollback

If public-release evidence fails or sensitive material is discovered, stop
publication, keep the private archive authoritative, remove public access, and
rotate any affected credential before resuming review.

## Validation evidence

The publication requires:

- clean current-tree and clean-history secret scans of the curated snapshot;
- no personal workstation or private share identifiers in the public tree;
- passing canonical manifest, contract, conformance, CACIS, and Edge validation;
- passing GitHub quality workflow on the exact published commit; and
- verified public metadata, license, security policy, and release notes.
