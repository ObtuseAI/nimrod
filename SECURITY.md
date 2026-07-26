# Security policy

nimrod is a defensive research preview. It is not safe to deploy as a
production protection or response system.

## Reporting a vulnerability

Use this repository's **Security** tab and **Report a vulnerability** to open a
private GitHub security advisory. Do not disclose suspected vulnerabilities,
authorization bypasses, target-widening paths, unsafe connectors, live
credentials, or exploit details in a public issue.

Include the affected revision, component, preconditions, source-to-sink path,
impact, and a minimal non-destructive reproducer. Good-faith, authorized
research that respects the license, avoids privacy violations and service
disruption, and gives the maintainers reasonable remediation time is welcome.

## Supported versions

Only the current default branch and latest tagged public research preview are
supported. Replayed fixtures, historical private-archive commits, range
packets, and generated reports are not independently supported products.

## Security claims

Only claims mapped to reproducible release evidence may be made. Passing tests,
valid signatures, model judgment, successful API responses, and completed
builds do not by themselves prove prevention, detection, containment, response,
recovery, or production safety.

## Prohibited behavior

nimrod may not be used for unauthorized access, counter-hacking, malware,
surveillance, destructive remediation, credential collection, target
enumeration outside explicit scope, or critical-infrastructure control.

## Release hygiene

Public releases require clean secret and private-path scans, dependency review,
canonical manifest and contract validation, explicit origin labeling,
read-only workflow permissions, and exact-SHA quality proof.
