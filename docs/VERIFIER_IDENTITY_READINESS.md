# Verifier identity readiness

nimrod measures the current Windows identity boundary for the World Model intake verifier, Constitutional Intelligence Research verifier, and Observatory projection verifier before treating process separation as operational independence.

The live read-only probe launches one benign process per verifier surface with an allowlisted, credential-free environment. An external collector records each process identity and SID, computes effective access to a surface-specific input artifact, and releases the process after collection. It performs no active network probe and does not create accounts, modify ACLs, modify firewall state, access credential values, or provision signing keys.

The current desktop evidence proves three distinct processes. It also proves the missing boundary: all probes share the supervisor account, can write their input artifacts under the inherited desktop ACL, have no verified default-deny egress, have no separately administered identity, and have no production signing custody. Production eligibility therefore remains zero of three.

A future operational release must replace this probe with independently administered service identities, externally verified read-only inputs and separate outputs, enforced default-deny egress, credential denial, production key custody, trusted time, and independent evidence retention. The current report cannot authorize those changes.

Canonical evidence: `reports/VERIFIER_IDENTITY_READINESS_VALIDATION.json`.
