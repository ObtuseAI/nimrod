# CACIS W4 metabolism, homeostasis, and Chronos

Status: `CACIS_W4_HOMEOSTASIS_CHRONOS_REPLAY_VALID_SCHEDULE_PROPOSAL_ONLY`

W4 turns resource allocation and system health into versioned, inspectable evidence. It does not run investigations, models, sandboxes, verifiers, recovery actions, sensors, containment, or target operations. Its maximum output is a replayed scheduling proposal.

## Metabolism

Every work item declares expected information gain, risk reduction, recovery improvement, the unhealthy signals it addresses, and an exact cost vector across CPU, memory, storage, telemetry, model, sandbox, simulation, verification, and investigation capacity. A deterministic weighted score orders eligible work. Allocation succeeds only when every resource remains within its explicit budget; otherwise the work is visibly deferred under resource backpressure.

The canonical replay schedules verifier replication, recovery replay validation, and telemetry refresh. Model-diversity challenge is deferred because the remaining lease cannot satisfy its cost vector. Scheduling conveys no permission to perform the work.

## Homeostasis

The health vector preserves thirteen independent signals: telemetry freshness, evidence completeness, trust health, identity health, model diversity, sensor health, recovery health, verification backlog, threat pressure, false-positive rate, confidence inflation, agent diversity, and resource pressure.

Confidence inflation is recomputed rather than trusted from the mission. It is the difference between understanding confidence and the weakest of calibration, generalization, and verification confidence. The W3 vector therefore yields `0.72`, above the `0.20` ceiling. Ten signals remain breached and the canonical state is `degraded_bounded`, not healthy.

## Chronos

Seven clocks prevent one global freshness label from laundering stale evidence:

| Clock | Freshness scale | Subject |
|---|---:|---|
| endpoint | milliseconds | process and endpoint observation |
| identity | seconds | authentication and privilege state |
| containment | minutes | reversible response proposals |
| recovery | hours | restore and integrity evidence |
| threat intelligence | days | campaign and TTP context |
| architecture | weeks | system design evaluation |
| capability | months | governed capability evolution |

Each work item binds its own observation time and clock policy. Fresh work may be considered, stale work receives urgency without becoming current, and expired work must abstain. The canonical replay retains four stale items and rejects two expired items.

## Contracts and replay

- `homeostasis-chronos-mission.schema.json` defines source binding, budgets, weights, signals, confidence, clocks, work, and immutable false authority.
- `homeostasis-chronos-receipt.schema.json` defines signal assessment, clock state, allocation decisions, resource ledger, summary, and canonical digest.
- `nimrod-cacis-homeostasis-replay` produces the same content-addressed result as the pure API.
- `validate_homeostasis_chronos.py` covers deterministic API/CLI equality and sixty fail-closed mutations.

## Authority boundary and residual risk

W4 cannot authorize, execute, change policy, contact targets, use credentials, self-verify, promote, or modify the constitution. It uses deterministic fixture values rather than an operating-system resource meter, continuous sensor stream, independent clock, external queue, or production scheduler. A high priority, available lease, healthy signal, or valid receipt is not operational authorization.
