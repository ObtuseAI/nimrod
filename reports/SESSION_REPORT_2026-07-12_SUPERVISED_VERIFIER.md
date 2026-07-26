# nimrod supervised verifier session report

Date: 2026-07-12  
Outcome: `FOUNDATION_SUPERVISED_VERIFIER_REFERENCE_VALID_OS_ACCOUNT_BLOCKED`  
Scope: Sprint 3 item 5; supervised read-only verifier process protocol, health, environment isolation, deadlines, outages, and disagreement

## Delivered

- Versioned service policy, health, observation, and consensus contracts.
- JSON-lines verifier service with explicit health, verify, and shutdown requests.
- Two distinct logical service principals and five separate verifier processes.
- Allowlisted child environment and credential-prefix startup denial.
- Read-only implementation with complete input snapshots before and after verification.
- Subject-bound observations containing process/account identity and exact error evidence.
- Fail-closed consensus for isolation-unproven agreement, agreed invalid, disagreement, timeout, and unavailable states.
- Real process timeout and real nonzero-exit outage workers.
- Duplicate service identity and same-process dual-identity denial.
- Console entry point `nimrod-verifier-service`.

## Evidence

| Check | Result |
|---|---:|
| Separate verifier service processes | 5 |
| Distinct logical verifier identities | 2 |
| Healthy credential environment count | 0 |
| Before/after input snapshot equality | yes |
| Source filesystem-write capability | absent |
| Credential-contaminated startup | denied |
| Real timeout | preserved as `verifier_timeout` |
| Real outage | preserved as `verifier_unavailable` |
| Valid/invalid split | preserved as `disagreement` |
| Two invalid observations | preserved as `agreed_invalid` |
| Dedicated OS account/SID | not proven |
| OS-enforced read-only ACL | not proven |
| Verification accepted | no |

## Boundary

The desktop harness cannot create a dedicated Windows service SID/account without making a privileged machine-level change. Both verifier processes run under the desktop account, so the exact current state is `agreed_valid_boundary_unproven` and `verification_accepted: false`. This is a deliberate fail-closed result, not a partial success disguised as production isolation.

No planner, executor, signer, target, cloud, model, HSM/KMS, or offensive-tool credential was supplied. No target, payload, external service, or live security path was exercised.

## Next recommended increment

Proceed to Sprint 3 item 6: integrate signed trust-root health, supervised verifier health/disagreement, crash timeline, anchor freshness, and kill state into the evidence-first control board. A later privileged deployment gate must separately install and validate the verifier under a dedicated Windows service SID/account with OS-enforced read-only ACLs before any verification may be accepted as production-isolated.

## Shared handoff

The verified handoff root is planned as `nimrod-supervised-verifier-20260712-180813` in the FRANKENSTEIN shared folder. Its sibling `copy_proof.json` records manifest verification, shared-path validators, archive membership, and archive SHA-256.
