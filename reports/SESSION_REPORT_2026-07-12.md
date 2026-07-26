# nimrod foundation session report

Historical note: this report records the initial foundation session. The later Crucible expansion report supersedes its current-path, brand-normalization, and conformance-harness status.

Date: 2026-07-12  
Workspace: `C:\Users\developer\OneDrive\Documents\C\nimrod`
Outcome: `FOUNDATION_VALID`  
Launch readiness: `BLOCKED_PRE_IMPLEMENTATION`

## Work completed

- Initially preserved the owner-supplied 1,463-line source brief byte-for-byte. A later explicit owner instruction normalized the brand and filename to `docs/source/nimrod_source_brief.md`; the original attachment remains outside the project.
- Created a project-level operating `AGENTS.md` and public repository foundation files.
- Defined the nimrod doctrine, constitutional invariants, separation of powers, autonomy budget, and claims boundary.
- Converted the universal vision into a staged master plan with a narrow Windows-first initial wedge.
- Defined first-product personas, use cases, requirements, non-targets, and release acceptance.
- Created the reference architecture, trust zones, action flow, failure modes, and technology posture.
- Created a first-product threat model with twelve priority abuse cases and explicit residual risks.
- Created security, privacy, accessibility, supply-chain, regulatory, export, IP, and assurance readiness plans.
- Created hard gates for preview, beta, GA, and future authority expansion.
- Created a Phase 0 backlog covering owner, product, legal, specification, architecture, security, and operations work.
- Created draft JSON Schemas and clearly simulated examples for action/evidence envelopes and evidence receipts.
- Created a Windows PowerShell-compatible foundation validator.

## Key planning decisions

The packet recommends, but does not silently approve:

1. Treat nimrod as a working codename until comprehensive trademark clearance.
2. Start with a Windows-first local Edge Preview rather than launching the universal platform at once.
3. Default to observer mode through alpha and cap public-preview autonomy at named reversible local controls.
4. Keep models and analytics outside the deterministic authority, executor, verifier, and release boundaries.
5. Avoid a custom kernel driver unless supported platform APIs cannot meet an approved requirement.
6. Publish inspectable schemas and conformance work before privileged product implementation.

## Research baseline

Current official sources were checked for:

- NIST CSF 2.0 and SSDF;
- CISA Secure by Design;
- European Union Cyber Resilience Act implementation dates;
- EU AI Act implementation status;
- GDPR privacy by design/default;
- FTC privacy and security expectations;
- California CCPA guidance;
- US BIS encryption export controls;
- USPTO trademark clearance guidance;
- W3C WCAG 2.2 accessibility guidance.

The compliance plan is a counsel-ready issue map, not legal advice or a compliance claim.

## Validation evidence

Command:

```powershell
./tools/validate-foundation.ps1
```

Result:

```json
{
  "status": "FOUNDATION_VALID",
  "required_file_count": 19,
  "parsed_json_count": 4,
  "parsed_schema_count": 2,
  "source_brief_sha256_before_lowercase_normalization": "209BB9FE42FA354CB02075BC3A653186F89E559BB5F8EF98DC2D9380B68D122F",
  "launch_readiness": "BLOCKED_PRE_IMPLEMENTATION"
}
```

Additional checks:

- all local Markdown links resolve;
- all four JSON documents parse in the workspace Windows PowerShell runtime;
- required blocker states remain present;
- the source brief hash matches the imported attachment;
- no git commit was created.

At the time of this initial report, the environment did not have Python `jsonschema` installed. The later Crucible expansion added a project-local dependency and Draft 2020-12 conformance harness.

## Honest blockers

- `product_wedge_owner_approval`
- `trademark_clearance`
- `license_model`
- `initial_customer`
- `legal_and_export_applicability`
- `private_vulnerability_reporting_channel`
- implementation and independent security evidence

These are expected preparation outcomes. They must not be upgraded to passed or launch-ready without owner decisions and evidence.

## Next authorized step

Hold an owner review of the five immediate decisions in `README.md`, then begin only the Phase 0 backlog. No privileged agent, live containment, public product claim, repository publication, or public launch was authorized or performed in this session.
