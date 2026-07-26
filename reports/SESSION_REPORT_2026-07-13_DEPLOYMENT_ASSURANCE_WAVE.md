# nimrod deployment-assurance session report

## Outcome

Status: `DEPLOYMENT_ASSURANCE_RACE_CLOSED_EFFECTIVE_ACCESS_OBSERVED_CUSTODY_AND_PHYSICAL_POWER_LOSS_BLOCKED`

This wave closed the Windows Job Object assignment race, replaced ACL and egress unknowns with read-only target-specific observations, added hardware-custody readiness evidence, and upgraded receipt recovery to an abrupt-process/separate-recovery-process proof. It did not create accounts, change ACLs or firewall rules, create keys, sign through a hardware provider, interrupt power, execute a candidate, or authorize production.

## Evidence

- The benign resource worker is created suspended, assigned to the Job Object, and resumed only after successful assignment.
- Durable resource records are file-flushed and atomically published with Windows write-through semantics.
- A driver exits abruptly after observation publication; a separate process reconstructs and validates the receipt without rerunning the worker.
- The live isolation collector computes DACL effective rights for the target and collector and inspects outbound block rules for the exact target executable.
- Current isolation remains two of seven controls: the desktop identity can write input and output, the collector shares output write access, and no target-wide egress block exists.
- The live custody collector observes five CNG storage providers including the platform provider. TPM management inspection is unavailable to the current identity.
- No hardware key reference, provider attestation, independent custodian, signing operation, or private key access exists.
- The control board renders all three blocker families and remains display-only.

## Validation boundary

The contract harness covers 57 schemas, 57 positive examples, 57 negative mutations, 52 semantic contracts, and one migration. Platform assurance adds eight resource-meter, six isolation, and six custody-readiness adversarial cases. Physical power-loss durability, dedicated service identities, enforced ACL separation, denied egress, hardware-backed signing custody, independent custody operations, candidate execution, and production promotion remain blocked.
