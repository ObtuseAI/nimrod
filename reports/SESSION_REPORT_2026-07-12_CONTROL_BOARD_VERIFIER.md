# Session report: verifier control-board integration

Date: 2026-07-12  
Project: `nimrod`  
Outcome: `FOUNDATION_CONTROL_BOARD_VERIFIER_INTEGRATION_VALID_OS_ACCOUNT_BLOCKED`  
Execution posture: simulated, local, no execution

## Delivered state

The supervised-verifier evidence path now terminates in a deterministic, versioned control-board projection rather than presentation-owned state. The projector binds exactly two observations to the consensus observation digests, associates health evidence by service, principal, and process identity, and preserves `agreed_valid`, `agreed_valid_boundary_unproven`, `agreed_invalid`, `disagreement`, `verifier_timeout`, and `verifier_unavailable` as literal operator outcomes.

The board adds a dedicated verifier mesh with consensus, two process-health cards, bound observations, isolation-boundary facts, persistent blockers, a verifier authority gate, proof-console inclusion, global state, and footer state. Its authority fields are fixed so the board cannot authorize or execute. It may render verification accepted only when accepted consensus, complete health, dedicated OS identity evidence, and OS-enforced read-only ACL evidence are all present.

The current desktop evidence remains intentionally blocked. Both verifier identities are logical/process-separated but the dedicated Windows service identity and read-only ACL are unproven. The canonical UI therefore renders `boundary_unproven`, `verification_accepted: false`, and three persistent blockers.

## Contracts and implementation

- Added `control-board-verifier-projection.schema.json` and canonical example.
- Added the pure `project_verifier_control_board` evidence projector.
- Added a specific `ControlBoardProjectionError` failure type.
- Expanded the contract harness to 23 Draft 2020-12 schemas, examples, and negative mutations with 18 semantic families.
- Expanded the control-board integration harness to cover all six consensus states and seven adversarial projection cases.
- Added verifier-mesh rendering, responsive styling, authority gate, and combined proof view.
- Added doctrine invariants 30 and 31, ADR-035 and ADR-036, and TM-30.

## Validation evidence

- Canonical verifier projection validates against its Draft 2020-12 schema.
- Consensus digest substitution is denied.
- Same-process dual identity and duplicate principal identity are denied.
- Health from an unknown service is denied.
- Non-success consensus cannot claim accepted verification.
- Missing peer health remains a visible health blocker.
- An otherwise accepted consensus with missing read-only ACL evidence remains `boundary_unproven`.
- Desktop browser rendering exposes all verifier evidence and blockers.
- A 390-pixel browser viewport has no horizontal overflow.
- Verifier-tab interaction succeeds with zero browser console errors.
- No external UI resources, WebSocket, storage, credential, or backend integration were added.
- No live execution or offensive tool installation occurred.

## Residual blockers

- dedicated Windows verifier service account/SID not provisioned;
- OS-enforced read-only ACL not proven;
- independent verifier implementation diversity not proven;
- signed transport from supervisor to UI not implemented;
- assistive-technology and independent UX safety assessment incomplete;
- real range, sacrificial-replica, and live evidence absent.

## Integrity and handoff

The source brief remains unchanged at SHA-256 `E070C8EF1A0356A5981824598A39EEEF7390428FBA8C8CCA3EE3BD899094F4FC`.

The planned verified handoff root is `nimrod-control-board-verifier-20260712-190526` in the FRANKENSTEIN shared folder. Its sibling `copy_proof.json` records source/destination manifest verification, shared-path validator results, archive membership, and archive SHA-256 after the final copy is complete.

No commit or GitHub repository change was made.
