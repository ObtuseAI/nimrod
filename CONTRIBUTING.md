# Contributing

nimrod accepts narrowly scoped issues and pull requests for the public research
preview.

1. Read `AGENTS.md`, the doctrine, threat model, source-available license, and
   affected decision records.
2. Open a scoped proposal describing the defensive outcome, authority change,
   data impact, rollback, and verification plan.
3. Keep the patch minimal and preserve unrelated work.
4. Add the smallest meaningful integration, recovery, conformance, or
   adversarial test.
5. Provide reproducible evidence and state residual risk.
6. Obtain independent review for privileged code, schemas, cryptography,
   policy, update logic, evidence handling, or authority changes.

Generated code is untrusted until reviewed and validated. Changes that weaken a
hard invariant, create hidden telemetry, add a universal key, bypass approval,
enable unauthorized testing, or turn content into commands will not be
accepted.

Submitting a contribution indicates agreement with the contribution terms in
[`LICENSE`](LICENSE).
