# Edge continuous defensive observation

The Edge continuous observer is a bounded, read-only Windows evidence connector. It polls exactly three allowlisted Event Log channels: PowerShell Operational, optional Sysmon Operational, and DNS Client Operational. A session has explicit cycle, interval, per-source event, and query-timeout bounds.

The connector stores event metadata and cryptographic digests only. Raw event XML, provider names, script bodies, DNS payloads, and messages are not retained. Record identifiers are deduplicated within the bounded session. Missing Sysmon, disabled channels, and access denial remain typed source states; they are never converted into healthy telemetry.

The output is not policy-ready. It cannot propose, authorize, execute, modify a process or network, change policy, perform an active probe, or claim that cross-source correlation or independent verification occurred. The live validation proved one real Windows query cycle against PowerShell, DNS, and optional Sysmon, while the replay path proved two-cycle deduplication and five fail-closed mutations.

Production work still requires service lifecycle, privacy retention policy, independent intake verification, trusted time, durable cursor recovery, backpressure, signed update custody, accessibility, packaging, and design-partner evidence.
