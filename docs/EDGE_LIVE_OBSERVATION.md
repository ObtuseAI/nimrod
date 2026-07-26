# Edge live observation boundary

## Current capability

The Edge live adapter collects the identity of exactly one caller-selected Windows process using supported, read-only Win32 interfaces. It records the process ID, executable content digest, executable-path digest, account-identifier digest, and account-SID digest. Raw executable paths and SIDs are used only transiently for hashing and are not retained in the observation.

The adapter is a measurement boundary, not a sensor service. It does not enumerate all processes, subscribe to events, inspect network connections, query reputation, read credentials, install software, or modify endpoint state.

## Supported interface set

- `OpenProcess` with query-limited access;
- `QueryFullProcessImageNameW`;
- `OpenProcessToken` and `GetTokenInformation`;
- `LookupAccountSidW` and `ConvertSidToStringSidW`;
- local SHA-256 measurement of the resolved executable.

The caller must supply the process ID and collection time. Invalid, unavailable, or inaccessible processes fail closed with an actionable error.

## Evidence and privacy contract

Every observation has literal `live` origin and `requested_process_only` scope. The contract forbids raw path/SID fields, active network probes, writes, process modification, network modification, policy changes, and action authority.

Process identity alone cannot support the replay policy. The adapter therefore preserves four blockers:

1. destination observation missing;
2. parent-process observation missing;
3. publisher verification missing;
4. user-writable path classification missing.

The maximum outcome is `EDGE_LIVE_PROCESS_OBSERVED_POLICY_INPUT_INCOMPLETE`. It is not a detection, containment, recovery, or protection claim.

## Next release gate

Before this becomes a supported sensor, the project needs a bounded Windows event source, explicit local retention policy, publisher verification, parent and destination binding, performance and compatibility measurements, service identity and ACL isolation, consent and privacy review, and an independent post-collection verifier. Those additions still do not authorize containment.
