# nimrod supervised verifier

Status: `REFERENCE_VALID_OS_ACCOUNT_AND_ACL_BLOCKED`

## Service boundary

The supervised verifier is a JSON-lines service running in a separate OS process. Its only permitted capabilities are health reporting, Witness verification, and external-anchor verification. Planning, authorization, signing, execution, evidence writing, and credential access are explicit prohibited capabilities.

The supervisor replaces the child environment with a small allowlist. Credential-like prefixes for AWS, Azure, Google, OpenAI, Anthropic, GitHub, Kubernetes, and Docker are denied at service startup. The service receives paths to Witness, anchor, governance, policy, and pinned-head inputs; it snapshots every file before verification, performs only read operations, snapshots again, and fails if any byte changes.

Two logical service principals run in distinct processes. Each produces a typed observation containing service and process identity, OS-account evidence, subject digest, validity state, read-only evidence, credential count, and exact error information. The supervisor never accepts a same-process or same-principal pair as independent.

The control-board boundary does not treat those observation booleans as OS proof. It requires a short-lived, threshold-signed isolation attestation for each process, with exact process/executable/account bindings and seven mandatory controls. Attestations are verified independently of the health and observation documents before the projection is constructed.

## Reconciliation states

| State | Meaning | Verification accepted |
|---|---|---:|
| `agreed_valid` | Two distinct verifier processes and principals agree on one valid subject and both prove dedicated OS-account isolation | yes |
| `agreed_valid_boundary_unproven` | Verifiers agree, but required OS-account isolation is not proven | no |
| `agreed_invalid` | Both verifiers reject the same subject | no |
| `disagreement` | Status or subject digest differs | no |
| `verifier_timeout` | At least one required process exceeded its deadline | no |
| `verifier_unavailable` | At least one required verifier failed to produce an observation | no |

The timeout harness launches a real process and kills it through the supervisor deadline. The unavailable harness launches a real process that exits nonzero without an observation. Neither condition is simulated into success.

## Current proof

- five separate verifier service processes;
- two distinct logical service identities;
- process IDs distinct from each other and the supervisor;
- five-input before/after snapshot equality;
- zero credential variables in healthy verifier environments;
- credential-contaminated startup denial;
- valid/invalid disagreement and agreed-invalid preservation;
- real timeout and unavailable process evidence;
- duplicate identity and shared-process denial;
- expected-account mismatch reported in health;
- verifier source contains no filesystem write or child-process primitives.

## Required production isolation

The current Windows desktop run cannot safely create or claim a dedicated service account. Both verifier processes therefore run under the same desktop user. The health contract reports `os_account_boundary_verified: false` and `production_ready: false`; agreeing results remain `agreed_valid_boundary_unproven` with `verification_accepted: false`. Simulated, threshold-certified isolation fixtures validate the attestation path but set `live_os_enforcement_verified: false` and cannot satisfy the production boundary.

Production work must install the verifier under a dedicated Windows service SID or equivalent OS account, grant read-only access only to required Witness/anchor/trust paths, deny planner/executor/signing secrets, restrict network egress, capture process/account telemetry, and validate ACL/SID behavior from an independent administrator context. A second implementation or independently maintained verifier is also required to reduce correlated defects.
