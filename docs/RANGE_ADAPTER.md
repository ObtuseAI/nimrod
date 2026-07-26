# Fixture-only Atomic and Caldera adapter

## Current boundary

This adapter is a quarantine and compilation boundary, not a tool integration. It reads local UTF-8 YAML fixtures, extracts bounded metadata, hashes command and cleanup material, discards the raw executable strings, and emits a simulated import receipt. It never installs, launches, contacts, authenticates to, or controls Atomic Red Team, Invoke-AtomicRedTeam, Caldera, an agent, a target, or a range.

Atomic Red Team defines portable ATT&CK-mapped tests and commonly carries `atomic_tests`, supported platforms, input arguments, executor commands, cleanup commands, elevation requirements, and payload/dependency material. Caldera abilities carry platform/executor commands, optional cleanup, payloads/uploads, parsers, requirements, timeouts, and `#{...}` fact variables. Those fields are treated as hostile source data because both formats are designed to describe behavior that an execution framework can run. See the official [Atomic Red Team repository](https://github.com/redcanaryco/atomic-red-team) and [Caldera v5.3 ability documentation](https://caldera.readthedocs.io/_/downloads/en/v5.3.0/pdf/).

## Three-gate flow

1. **Bounded safe parse.** Inputs are capped at 64 KiB, must be UTF-8, and reject YAML aliases, anchors, tags, duplicate keys, non-string mapping keys, and non-JSON value types. Parsing uses `yaml.safe_load`; no Python-object constructor is accepted.
2. **Quarantine normalization.** The receipt retains source kind, source/object IDs, ATT&CK technique, platform/executor names, source/command/cleanup digests, dynamic-reference count, and findings. Raw command and cleanup strings are never retained. Elevation, payload/input references, unresolved variables, missing cleanup, URLs, oversized commands, and prohibited command fragments block eligibility.
3. **Exact-digest compilation.** A local fixture policy must bind the exact source artifact digest, source object ID, source kind, technique, platforms, and executors. Compilation emits only `connector.simulated.atomic` plus `range.test.simulate`, a fixed mapped target that must later match an Authorization Lease, and a receipt proving that no source tool was contacted, no target was discovered, no executable material was forwarded, and no live execution occurred.

## Deliberate non-capabilities

- no generic command, shell, payload, script, or argument output;
- no Caldera REST API, C2 server, agent, plugin, or operation;
- no Atomic/Invoke-Atomic execution or prerequisite acquisition;
- no network destination, secret, credential, discovery, or target inference;
- no live, range, or sacrificial-replica evidence;
- no claim that a source definition is safe merely because it parses or its digest is pinned.

The mapping policy is local simulated evidence and is not yet threshold-signed. A later isolated-range design must add signed policy, customer proof of authority, disposable range identity, egress denial, independent kill/cleanup paths, range snapshots, separate telemetry, and supervised post-state verification before any external tool can be contacted.
