"""Specific failures raised by the no-execution simulator."""


class SimulatorError(Exception):
    """Base class for actionable simulator failures."""


class EdgeObservationError(SimulatorError):
    """A replayed Edge observation is malformed, unsupported, or origin-ambiguous."""


class EdgePolicyError(SimulatorError):
    """An Edge policy is widened, unsupported, or inconsistent with its replayed evidence."""


class EdgeVerificationError(SimulatorError):
    """Independent Edge structural verification failed or claimed unsupported outcome evidence."""


class EdgeLiveObservationError(SimulatorError):
    """A live Edge process observation is invalid, over-scoped, or authority-bearing."""


class EdgeContinuousObservationError(SimulatorError):
    """A bounded continuous Edge observation is malformed, over-scoped, or authority-bearing."""


class PluginSandboxError(SimulatorError):
    """A plugin manifest widens its deny-by-default sandbox or lifecycle authority."""


class ReleaseVerificationError(SimulatorError):
    """A release candidate is unsigned, stale, misbound, or unsafe to stage."""


class DesignPartnerPlanError(SimulatorError):
    """A design-partner plan fabricates activity, weakens privacy, or claims authority."""


class JsonDocumentError(SimulatorError):
    """A required JSON document is malformed or has the wrong top-level type."""


class ContractValidationError(SimulatorError):
    """A document does not satisfy its versioned JSON Schema."""


class ProtectionProfileError(SimulatorError):
    """A protection profile lacks bounded sensing, action, recovery, or oracle semantics."""


class VerifierIdentityReadinessError(SimulatorError):
    """Verifier identity readiness evidence is malformed or launders production isolation."""


class ControlStateValidationError(SimulatorError):
    """Runtime control state is incomplete, ambiguous, or unsafe."""


class AuthorizationProofError(SimulatorError):
    """The authorization proof does not bind to the supplied lease and trust policy."""


class AuthorizationThresholdError(SimulatorError):
    """Valid distinct signatures do not satisfy the required threshold and roles."""


class AuthorizationSignatureError(SimulatorError):
    """An Ed25519 authorization signature or public key is invalid."""


class TrustPolicyError(SimulatorError):
    """The authorization trust policy is expired, inconsistent, or unsafe."""


class KeyGovernanceError(SimulatorError):
    """A key-governance state violates threshold, custody, or lifecycle invariants."""


class KeyTransitionError(SimulatorError):
    """A signed key-governance transition is invalid or unauthorized."""


class KeyCustodyError(SimulatorError):
    """A signing-custody connector cannot satisfy the requested non-exportable operation."""


class LeaseNotActiveError(SimulatorError):
    """The lease validity window has not started."""


class LeaseExpiredError(SimulatorError):
    """The lease validity window has ended."""


class LeaseRevokedError(SimulatorError):
    """The lease or its nonce has been revoked."""


class LeaseReplayError(SimulatorError):
    """The single-use lease nonce was already consumed."""


class AuthorizationStateIntegrityError(SimulatorError):
    """Durable authorization state is corrupt, contradictory, or unrecoverable."""


class InjectedStateCrashError(SimulatorError):
    """A validation-only failure injector interrupted an authorization-state transition."""


class KillSwitchEngagedError(SimulatorError):
    """The customer-controlled kill switch denies new simulated actions."""


class CampaignLeaseMismatchError(SimulatorError):
    """A campaign references a different authorization lease."""


class TargetScopeError(SimulatorError):
    """A campaign step targets a resource absent from the immutable target graph."""


class CapabilityScopeError(SimulatorError):
    """A campaign step requests a capability absent from the lease."""


class ConnectorScopeError(SimulatorError):
    """A campaign step requests a connector unavailable in the no-execution runtime."""


class EffectCeilingError(SimulatorError):
    """A campaign step exceeds the lease effect ceiling or environment boundary."""


class BudgetExceededError(SimulatorError):
    """Current usage plus the compiled campaign exceeds a lease budget."""


class PreflightError(SimulatorError):
    """A required preflight condition lacks explicit evidence."""


class CleanupContractError(SimulatorError):
    """A campaign step lacks a matching cleanup obligation."""


class ExecutionDirectiveError(SimulatorError):
    """Untrusted campaign data contains a command-like execution directive."""


class SwarmMissionError(SimulatorError):
    """A swarm mission has an invalid target, technique, assignment, or dependency graph."""


class SwarmSeparationError(SimulatorError):
    """A swarm mission violates role diversity or separation of powers."""


class SwarmBudgetError(SimulatorError):
    """A swarm cell exceeds its explicit work-item budget."""


class WitnessIntegrityError(SimulatorError):
    """Content-addressed Witness evidence is missing or has been modified."""


class WitnessCheckpointError(SimulatorError):
    """A Witness checkpoint signature, tree commitment, or governance binding is invalid."""


class AnchorIntegrityError(SimulatorError):
    """An external Witness anchor receipt, head, or signature is invalid."""


class AnchorRollbackError(SimulatorError):
    """An external Witness anchor is older than the independently pinned head."""


class VerifierServiceError(SimulatorError):
    """The supervised verifier service policy, protocol, or process boundary is invalid."""


class VerifierCredentialExposureError(SimulatorError):
    """A verifier process received a credential-like or non-allowlisted environment variable."""


class VerifierReadOnlyViolationError(SimulatorError):
    """Verifier inputs changed while a read-only verification request was executing."""


class VerifierDisagreementError(SimulatorError):
    """Verifier observations disagree and cannot produce an accepted verification state."""


class ControlBoardProjectionError(SimulatorError):
    """Verifier evidence cannot be projected into a safe control-board state."""


class ControlBoardSnapshotError(SimulatorError):
    """A supervisor snapshot is malformed, stale, misbound, or outside its policy window."""


class ControlBoardSnapshotSignatureError(ControlBoardSnapshotError):
    """A supervisor snapshot lacks valid threshold signatures and role diversity."""


class ControlBoardIngressError(SimulatorError):
    """The durable control-board ingress state cannot safely accept a snapshot."""


class ControlBoardIngressReplayError(ControlBoardIngressError):
    """A control-board snapshot sequence was already accepted or claimed."""


class ControlBoardIngressRollbackError(ControlBoardIngressError):
    """A control-board snapshot attempts rollback, gap insertion, or chain substitution."""


class ControlBoardIngressIntegrityError(ControlBoardIngressError):
    """Durable control-board ingress records are corrupt, contradictory, or unrecoverable."""


class ControlBoardIngressPathExistsError(ControlBoardIngressIntegrityError):
    """An atomic ingress publication lost to an already-existing durable path."""


class InjectedControlBoardIngressCrashError(ControlBoardIngressError):
    """A validation-only failure interrupted a control-board ingress transition."""


class RangeAdapterImportError(SimulatorError):
    """An imported Atomic or Caldera definition is malformed, ambiguous, or unsafe to normalize."""


class RangeAdapterPolicyError(SimulatorError):
    """A range-adapter mapping policy is incomplete, widened, or does not bind the imported source."""


class RangeAdapterCompilationError(SimulatorError):
    """A quarantined range definition cannot compile into the no-execution campaign contract."""


class ThresholdSignatureError(SimulatorError):
    """A domain-separated threshold-signed document is malformed or unauthorized."""


class IsolationBoundaryError(ThresholdSignatureError):
    """An OS-isolation attestation is unsigned, stale, misbound, or does not prove its controls."""


class EvaluatorTrustPolicyError(ThresholdSignatureError):
    """An evaluator trust policy is incomplete, stale, captured, or incorrectly signed."""


class EvaluatorObservationError(SimulatorError):
    """A signed evaluator observation is stale, substituted, or identity-mismatched."""


class ResourceLedgerError(ThresholdSignatureError):
    """A lineage resource ledger is malformed, unchained, over-budget, or incorrectly signed."""


class WindowsIsolationCollectionError(IsolationBoundaryError):
    """A read-only Windows isolation measurement failed or could not support its claimed control state."""


class WindowsCustodyReadinessError(SimulatorError):
    """Read-only Windows hardware-custody readiness evidence is invalid or unavailable."""


class ResourceMeterError(SimulatorError):
    """An OS resource measurement failed, exceeded its lease, or produced inconsistent evidence."""


class ResourceMeterStateError(ResourceMeterError):
    """Durable resource-meter state is missing, corrupt, conflicting, or replayed."""


class InjectedResourceMeterCrashError(ResourceMeterStateError):
    """A validation-only failure interrupted resource-meter receipt publication."""


class RangePolicySignatureError(ThresholdSignatureError):
    """A range-adapter policy envelope is stale, misbound, or lacks valid threshold signatures."""


class RangeCorpusError(SimulatorError):
    """A local range-definition corpus snapshot is incomplete, inconsistent, or unsafe to scan."""


class RangePreflightError(SimulatorError):
    """Disposable-range preflight evidence is malformed, substituted, or authority-bearing."""


class RangeTopologyError(SimulatorError):
    """A declared range topology is ambiguous, unsafe, or authority-bearing."""


class RangeKillSignatureError(ThresholdSignatureError):
    """An out-of-band range-kill command is stale, misbound, or lacks threshold signatures."""


class RangeKillStateError(SimulatorError):
    """Durable range-kill state is missing, corrupt, contradictory, or unsafe."""


class RangeKillReplayError(RangeKillStateError):
    """A range generation already consumed its one-way kill transition."""


class RangeKillConflictError(RangeKillStateError):
    """A different kill command conflicts with an already engaged range generation."""


class RangeRecoveryError(SimulatorError):
    """Snapshot or cleanup evidence is stale, substituted, incomplete, or authority-bearing."""


class RangeConnectorCapabilityError(ThresholdSignatureError):
    """A governed range connector declaration is unsigned, widened, stale, or authority-bearing."""


class RangeScopeCompilationError(SimulatorError):
    """An authorization lease cannot compile into the declaration-only disposable-range topology."""


class RangePreexecutionEvidenceError(SimulatorError):
    """A pre-execution evidence packet is stale, incomplete, substituted, or authority-bearing."""


class RangeCollectorPolicyError(ThresholdSignatureError):
    """A range collector policy is unsigned, stale, widened, captured, or authority-bearing."""


class RangeEnvironmentObservationError(SimulatorError):
    """A range environment observation is stale, unsigned, misbound, or not content-addressed."""


class RangeEvidenceAdmissionError(SimulatorError):
    """A range evidence admission report is incomplete, substituted, or authority-bearing."""


class RangeVerifierPolicyError(ThresholdSignatureError):
    """A range verifier policy is unsigned, stale, captured, misbound, or authority-bearing."""


class RangeVerifierDecisionError(SimulatorError):
    """A range verifier decision is unsigned, stale, substituted, or identity-mismatched."""


class RangeEvidenceAcceptanceError(SimulatorError):
    """A range evidence acceptance report launders, omits, or collapses verifier outcomes."""


class RangeEvidenceCompletionPolicyError(ThresholdSignatureError):
    """A range evidence-completion policy is unsigned, stale, weakened, or authority-bearing."""


class RangeEvidenceCompletionAuthorizationError(ThresholdSignatureError):
    """A range evidence-completion authorization is unsigned, stale, misbound, or unsafe."""


class RangeEvidenceCompletionError(SimulatorError):
    """A range evidence-completion receipt is incomplete, substituted, or authority-bearing."""


class PublicCorpusRegistryError(SimulatorError):
    """A public source registry is unpinned, owner-ambiguous, unsafe, or authority-bearing."""


class SacrificialReplicaPlanError(SimulatorError):
    """A sacrificial replica plan targets public infrastructure or exposes operational authority."""


class PublicCorpusIntakeError(SimulatorError):
    """A public corpus intake report launders metadata into a ready or executable replica."""


class OwnerScopeRegistryError(SimulatorError):
    """An owner-scope exclusion registry is incomplete, ambiguous, substituted, or authority-bearing."""


class SourceStagingAuthorizationError(ThresholdSignatureError):
    """A source-staging authorization is unsigned, stale, misbound, widened, or authority-bearing."""


class SourceStagingGateError(SimulatorError):
    """A source-staging gate report launders a denial into acquisition, quarantine, build, or execution."""


class ConstructionZoneDeclarationError(SimulatorError):
    """A construction-zone declaration claims provisioning, isolation evidence, or operational authority."""


class QuarantineEvidenceReceiptError(SimulatorError):
    """A quarantine receipt fabricates source, scanner, provenance, or completion evidence."""


class ConstructionZonePreflightError(SimulatorError):
    """A construction-zone preflight launders declarations into staging, build, connection, or execution."""


class ConstructionZoneAttestationPlanError(SimulatorError):
    """A construction-zone attestation plan fabricates observers, evidence, independence, or authority."""


class ConstructionZoneProvisioningAuthorizationError(ThresholdSignatureError):
    """A construction-zone provisioning authorization is unsigned, stale, misbound, widened, or unsafe."""


class ConstructionZoneProvisioningGateError(SimulatorError):
    """A construction-zone provisioning gate launders a denial into infrastructure or operational authority."""


class WorldModelError(SimulatorError):
    """A CACIS world-model observation, generation, or immutable store is invalid."""


class WorldIntakeError(WorldModelError):
    """A continuous-observation cursor, causal transition, or World Model intake is invalid."""


class WorldIntakeGovernanceError(ThresholdSignatureError):
    """World Model source policy, health evidence, retention, or backpressure governance is invalid."""


class ImmuneRuntimeError(SimulatorError):
    """A CACIS organism mission, lease, lifecycle, teardown, or retention receipt is invalid."""


class IntelligenceResearchError(SimulatorError):
    """An intelligence-research mission, experiment, verification, or theory settlement is invalid."""


class HomeostasisChronosError(SimulatorError):
    """A CACIS metabolism mission, health assessment, clock decision, or resource lease is invalid."""


class GenomeEvaluationError(SimulatorError):
    """A CACIS genome lineage, partition, reward defense, complexity gate, or distillation is invalid."""


class ArenaObservatoryError(ThresholdSignatureError):
    """A CACIS arena report or signed display-only Observatory projection is invalid."""


class EvolutionConstitutionError(ThresholdSignatureError):
    """The Evolution Constitution is unsigned, stale, incomplete, weakened, or authority-bearing."""


class EvolutionCandidateError(SimulatorError):
    """A cognitive candidate is malformed, misbound, over-budget, or authority-bearing."""


class EvolutionEvaluationError(SimulatorError):
    """Candidate evaluation is incomplete, substituted, scalar-laundered, or evaluator-captured."""


class EvolutionArtifactError(SimulatorError):
    """An immutable Foundry artifact is missing, corrupt, conflicting, or outside its content address."""


class EvolutionTransitionError(ThresholdSignatureError):
    """A Foundry transition is unsigned, stale, misbound, invalid, or authority-bearing."""


class EvolutionTransitionReplayError(EvolutionTransitionError):
    """A Foundry transition was already consumed for the candidate lineage."""


class EvolutionTransitionConflictError(EvolutionTransitionError):
    """A Foundry transition conflicts with an existing candidate-lineage state."""


class AutonomousPromotionError(EvolutionTransitionError):
    """An autonomous Tier A/B promotion or regression demotion is unassured or authority-bearing."""
