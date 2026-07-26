# Session report: fixture-only range-adapter wave

Date: 2026-07-12  
Project: `nimrod`  
Scope: strategic three-item wave; source import, exact mapping, no-execution compilation  
Outcome: `FOUNDATION_FIXTURE_RANGE_ADAPTER_COMPILATION_VALID_OS_ACCOUNT_BLOCKED`  
Execution posture: simulated, local fixtures, no execution

## Completed items

1. Added bounded safe YAML intake and normalized quarantine receipts for one Atomic Red Team fixture and one Caldera ability fixture.
2. Added an exact source-kind/object/digest/technique/platform/executor mapping policy that cannot connect, execute, or discover targets.
3. Added deterministic compilation into schema-valid simulated campaigns plus receipts proving that raw execution material was not forwarded and no source tool, target discovery, or live execution occurred.

## Validation evidence

- 28 Draft 2020-12 schemas, positive examples, and negative mutations pass with 23 semantic families.
- Both source formats normalize without retaining command or cleanup strings.
- Both imports compile into the existing `connector.simulated.atomic` and `range.test.simulate` boundary.
- Two generated campaigns validate against the Validation Campaign contract.
- Two generated receipts validate against the range compilation receipt contract.
- The canonical Atomic import and compilation receipt exactly equal generated results.
- 23 adversarial cases cover unsafe tags, aliases/anchors, duplicate keys, oversized YAML, unknown object identity, missing cleanup, elevation, network destinations, prohibited command semantics, variables, payloads, source drift, digest/technique/platform/executor substitution, policy and import authority, connector widening, raw material retention, command injection, sequence, and lease identity.
- Compiled artifacts contain no prohibited command keys and no fixture command text.
- No Atomic, Invoke-AtomicRedTeam, Caldera, C2, agent, plugin, payload, range, target, credential, or network service was installed, launched, or contacted.

## Residual blockers

- adapter mapping policy is not threshold-signed;
- dedicated verifier Windows account/SID and OS read-only ACL remain unproven;
- no disposable isolated range, egress policy, tool identity, kill path, cleanup proof, snapshot restore, or telemetry connector exists;
- YAML compatibility is validated only against two controlled fixtures, not upstream corpus snapshots;
- no range, sacrificial-replica, or live evidence exists.

## Next strategic wave

Build a signed adapter-policy envelope, a static upstream-corpus compatibility scanner that produces quarantine reports without compiling or executing, and a disposable-range preflight contract covering network isolation, credentials, kill-switch independence, snapshots, cleanup, and verifier readiness. Tool installation and execution remain a later explicit gate.

No commit or GitHub repository change was made.
