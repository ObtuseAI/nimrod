# Public sacrificial source corpus

Status: `PUBLIC_SACRIFICIAL_CORPUS_PINNED_METADATA_ONLY_OWNER_REGISTRY_AND_OFFLINE_REPLICAS_BLOCKED`

This corpus is a deny-first source intake boundary for later owner-controlled, offline sacrificial replicas. A public repository is source material, not authorization to test GitHub, a maintainer, a hosted demo, a public deployment, or any third-party system.

## Pinned source candidates

| Repository | Commit | License metadata | Intended local replica |
|---|---|---|---|
| `juice-shop/juice-shop` | `33518f5a0911e25d9df747b1e70fb7af279a755c` | MIT | Offline web/API replica |
| `WebGoat/WebGoat` | `75d475f89a1130035cc34ff2085fc1d874c0881e` | GPL-2.0-or-later | Offline Java web replica |
| `digininja/DVWA` | `d45ba3c4e7efa7f023f25f58ab4af9912c887057` | GPL-3.0 | Offline PHP web replica |
| `OWASP/NodeGoat` | `c5cb68a7084e4ae7dcc60e6a98768720a81841e8` | Apache-2.0 | Offline Node.js web replica |
| `OWASP/IoTGoat` | `f67b7f961301d7a56b435fd7cffac73600f0c97b` | MIT | Static firmware analysis only |

These values are read-only metadata observations. No repository content was cloned or downloaded, no archive was retained, no dependency or container was resolved, no replica was built, and no campaign was executed.

## Non-target boundary

The following are always forbidden targets:

- GitHub-hosted repositories, APIs, CI, and content-delivery endpoints;
- maintainers and maintainer infrastructure;
- package and container registries;
- public demos and third-party deployments;
- any repository, organization, service, machine, device, or deployment owned by the project owner.

The known exclusions are `obtuseai` and `obtuseai/nimrod`. This list is intentionally marked incomplete. Unknown ownership is denied, so no source staging or replica build may proceed until the owner supplies the complete organization and repository exclusion registry.

## Replica network contract

Every future replica must be locally instantiated, owner-controlled, disposable, and bound to a named sacrificial range. Its network is default-deny with no upstream access, Internet egress, public ingress, GitHub access, registry access, or external DNS resolution. Build-time acquisition and run-time execution are separate approvals. Source eligibility never grants either.

## Required next evidence

1. Complete owner organization and repository exclusions.
2. Re-verify each exact revision, license, and commit-signature state.
3. Obtain a separate source-staging authorization and retain content digests.
4. Build only inside an owner-named offline construction zone.
5. Independently prove network isolation, disposability, cleanup, and recovery.
6. Obtain separate connection and execution authorization for the exact local replica.

The current artifacts prove only deterministic intake rules, three versioned contracts, and 38 adversarial denials. They do not prove a usable range or authorize offensive activity.
