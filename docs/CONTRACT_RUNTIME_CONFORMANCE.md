# Contract runtime conformance

nimrod publishes 97 Draft 2020-12 contracts. Contract validity is not equivalent to runtime capability, live evidence, or production readiness.

`tools/validate_contract_conformance.py` creates an exact row for every schema/example pair and separates four evidence levels:

1. schema and negative-mutation validation only;
2. an additional semantic validator;
3. an exact independent-harness reference to the contract or example;
4. exact runtime-source and independent-harness references.

References are discovered by exact schema or example filename. The matrix deliberately does not infer coverage from similar names, neighboring modules, broad test suites, or roadmap claims. A missing reference remains a visible gap.

The focused runtime-binding harness closes the six original schema-only or semantic-only rows with explicit fail-closed semantics. All 97 contracts now have an exact independent-harness reference; runtime-source references remain a narrower static signal and are not inferred where no exact binding exists.

Every row keeps `live_runtime_evidence_present` and `production_conformance_claimed` false. Those fields can change only through a future evidence contract backed by an independently retained live observation. The current matrix is a static repository-analysis artifact, not operational certification.

Canonical evidence: `reports/CONTRACT_CONFORMANCE_MATRIX.json`.
