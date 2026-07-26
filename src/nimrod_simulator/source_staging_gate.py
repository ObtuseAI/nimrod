"""Deny-first owner scope and signed source-staging authorization gate."""

from __future__ import annotations

import copy
from collections.abc import Mapping
from datetime import datetime

from nimrod_simulator.authorization import parse_timestamp
from nimrod_simulator.compiler import deterministic_uuid, format_timestamp
from nimrod_simulator.errors import (
    ControlStateValidationError,
    OwnerScopeRegistryError,
    SourceStagingAuthorizationError,
    SourceStagingGateError,
)
from nimrod_simulator.jsonio import (
    require_boolean,
    require_integer,
    require_list,
    require_object,
    require_string,
    require_string_list,
    sha256_digest,
)
from nimrod_simulator.key_governance import SigningConnector, validate_governance_state
from nimrod_simulator.model import JsonObject
from nimrod_simulator.public_sacrificial_corpus import (
    PINNED_PUBLIC_REPOSITORIES,
    validate_public_source_registry,
    validate_sacrificial_replica_plan,
)
from nimrod_simulator.threshold_signing import sign_threshold_document, verify_threshold_signatures


STAGING_AUTHORIZATION_DOMAIN: bytes = b"nimrod.source-staging-authorization.v0.1\x00"
KNOWN_OWNER_ORGANIZATIONS: frozenset[str] = frozenset({"obtuseai"})
KNOWN_OWNER_REPOSITORIES: frozenset[str] = frozenset({"obtuseai/nimrod"})
QUARANTINE_REQUIREMENTS: tuple[str, ...] = (
    "ARCHIVE_DIGEST",
    "COMMIT_SIGNATURE",
    "LICENSE_OBLIGATIONS",
    "MALWARE_SCAN",
    "REPRODUCIBLE_EXTRACTION",
    "SBOM_GENERATION",
    "SECRET_SCAN",
    "SOURCE_PROVENANCE",
)
OWNER_REGISTRY_AUTHORITY: JsonObject = {
    "can_complete_registry": False,
    "can_attest_ownership": False,
    "can_stage_source": False,
    "can_authorize_action": False,
}
STAGING_AUTHORITY: JsonObject = {
    "can_download_source": False,
    "can_stage_source": False,
    "can_extract_source": False,
    "can_resolve_dependencies": False,
    "can_build_replica": False,
    "can_provision": False,
    "can_connect": False,
    "can_execute": False,
    "can_target_public_host": False,
    "can_authorize_action": False,
}
STAGING_ACTIVITY: JsonObject = {
    "repository_content_downloaded": False,
    "source_archive_staged": False,
    "source_extracted": False,
    "quarantine_checks_performed": False,
    "dependency_resolution_performed": False,
    "replica_built": False,
    "infrastructure_provisioned": False,
    "public_host_contacted_for_testing": False,
    "range_connected": False,
    "campaign_executed": False,
}
EXPECTED_OWNER_BLOCKERS: frozenset[str] = frozenset(
    {
        "OWNER_ATTESTATION_MISSING",
        "OWNER_EXCLUSION_REGISTRY_INCOMPLETE",
        "OWNER_SCOPE_PROOF_MISSING",
    }
)
EXPECTED_STAGING_BLOCKERS: frozenset[str] = frozenset(
    {
        *EXPECTED_OWNER_BLOCKERS,
        "CONTENT_DIGEST_NOT_RETAINED",
        "ISOLATED_CONSTRUCTION_ZONE_MISSING",
        "PINNED_COMMIT_SIGNATURE_UNVERIFIED",
        "SOURCE_ARCHIVE_NOT_STAGED",
        "SOURCE_STAGING_AUTHORIZATION_DENIED",
    }
)


def _casefold_set(values: list[str]) -> set[str]:
    return {value.casefold() for value in values}


def validate_owner_scope_registry(registry: JsonObject) -> None:
    if registry.get("registry_version") != "0.1.0":
        raise OwnerScopeRegistryError("Owner-scope registry must use version 0.1.0.")
    if registry.get("origin") != "simulated" or registry.get("status") != "incomplete_owner_attestation_required":
        raise OwnerScopeRegistryError("Owner-scope registry must preserve its simulated incomplete state.")
    if require_boolean(registry.get("registry_complete"), "registry.registry_complete") is not False:
        raise OwnerScopeRegistryError("Owner-scope registry cannot claim completeness without owner attestation.")
    if require_boolean(registry.get("owner_attestation_present"), "registry.owner_attestation_present") is not False:
        raise OwnerScopeRegistryError("Canonical owner-scope registry cannot fabricate owner attestation.")
    if registry.get("unknown_ownership_action") != "deny":
        raise OwnerScopeRegistryError("Unknown ownership must remain denied.")
    organizations = require_string_list(registry.get("excluded_organizations"), "registry.excluded_organizations")
    repositories = require_string_list(registry.get("excluded_repositories"), "registry.excluded_repositories")
    if _casefold_set(organizations) != KNOWN_OWNER_ORGANIZATIONS or len(organizations) != len(KNOWN_OWNER_ORGANIZATIONS):
        raise OwnerScopeRegistryError("Owner organization exclusions differ from the known deny set.")
    if _casefold_set(repositories) != KNOWN_OWNER_REPOSITORIES or len(repositories) != len(KNOWN_OWNER_REPOSITORIES):
        raise OwnerScopeRegistryError("Owner repository exclusions differ from the known deny set.")
    if require_list(registry.get("ownership_proof_digests"), "registry.ownership_proof_digests"):
        raise OwnerScopeRegistryError("Owner-scope registry cannot claim unprovided ownership proofs.")
    if set(require_string_list(registry.get("blockers"), "registry.blockers")) != EXPECTED_OWNER_BLOCKERS:
        raise OwnerScopeRegistryError("Owner-scope registry blockers are incomplete or laundered.")
    if require_object(registry.get("authority"), "registry.authority") != OWNER_REGISTRY_AUTHORITY:
        raise OwnerScopeRegistryError("Owner-scope registry exposes prohibited authority.")


def sign_source_staging_authorization(
    unsigned_authorization: JsonObject,
    connectors: list[SigningConnector],
) -> JsonObject:
    return sign_threshold_document(
        unsigned_authorization,
        connectors,
        STAGING_AUTHORIZATION_DOMAIN,
        "source staging authorization",
        SourceStagingAuthorizationError,
    )


def _parse_timestamp(value: object, field: str) -> datetime:
    try:
        return parse_timestamp(value, field)
    except ControlStateValidationError as error:
        raise SourceStagingAuthorizationError(f"Source-staging timestamp '{field}' is invalid: {error}.") from error


def verify_source_staging_authorization(
    authorization: JsonObject,
    governance_state: JsonObject,
    owner_registry: JsonObject,
    public_registry: JsonObject,
    replica_plan: JsonObject,
    evaluated_at: datetime,
    maximum_lifetime_seconds: int,
) -> JsonObject:
    validate_governance_state(governance_state)
    validate_owner_scope_registry(owner_registry)
    validate_public_source_registry(public_registry)
    validate_sacrificial_replica_plan(replica_plan, public_registry)
    if evaluated_at.utcoffset() is None or maximum_lifetime_seconds <= 0:
        raise SourceStagingAuthorizationError("Source-staging evaluation time and lifetime must be valid.")
    if authorization.get("authorization_version") != "0.1.0":
        raise SourceStagingAuthorizationError("Source-staging authorization must use version 0.1.0.")
    bindings: Mapping[str, object] = {
        "governance_state_digest": sha256_digest(governance_state),
        "owner_registry_id": owner_registry.get("registry_id"),
        "owner_registry_digest": sha256_digest(owner_registry),
        "public_registry_id": public_registry.get("registry_id"),
        "public_registry_digest": sha256_digest(public_registry),
        "replica_plan_id": replica_plan.get("plan_id"),
        "replica_plan_digest": sha256_digest(replica_plan),
    }
    for field, expected in bindings.items():
        if authorization.get(field) != expected:
            raise SourceStagingAuthorizationError(f"Source-staging authorization {field} binding mismatch.")
    issued_at = _parse_timestamp(authorization.get("issued_at"), "authorization.issued_at")
    not_before = _parse_timestamp(authorization.get("not_before"), "authorization.not_before")
    expires_at = _parse_timestamp(authorization.get("expires_at"), "authorization.expires_at")
    if issued_at > not_before or not_before >= expires_at:
        raise SourceStagingAuthorizationError("Source-staging validity window is inconsistent.")
    if int((expires_at - issued_at).total_seconds()) > maximum_lifetime_seconds:
        raise SourceStagingAuthorizationError("Source-staging authorization lifetime exceeds the maximum.")
    if evaluated_at < not_before or evaluated_at > expires_at:
        raise SourceStagingAuthorizationError("Source-staging authorization is outside its active window.")
    if authorization.get("origin") != "simulated":
        raise SourceStagingAuthorizationError("Canonical source-staging authorization must remain simulated.")
    if authorization.get("status") != "signed_denial_owner_scope_incomplete" or authorization.get("outcome") != "deny_staging":
        raise SourceStagingAuthorizationError("Incomplete owner scope requires an explicit signed staging denial.")
    requested_source_ids = require_string_list(
        authorization.get("requested_source_ids"), "authorization.requested_source_ids"
    )
    expected_source_ids = {
        require_string(require_object(value, "public_registry.source").get("source_id"), "source.source_id")
        for value in require_list(public_registry.get("sources"), "public_registry.sources")
    }
    if set(requested_source_ids) != expected_source_ids or len(requested_source_ids) != len(expected_source_ids):
        raise SourceStagingAuthorizationError("Source-staging request does not bind every reviewed source exactly once.")
    if require_list(authorization.get("authorized_source_ids"), "authorization.authorized_source_ids"):
        raise SourceStagingAuthorizationError("Denied source staging cannot authorize source IDs.")
    if require_list(authorization.get("authorized_content_digests"), "authorization.authorized_content_digests"):
        raise SourceStagingAuthorizationError("Denied source staging cannot authorize content digests.")
    if authorization.get("construction_zone_id") is not None:
        raise SourceStagingAuthorizationError("Denied source staging cannot name an unproven construction zone.")
    if set(require_string_list(authorization.get("quarantine_requirements"), "authorization.quarantine_requirements")) != set(QUARANTINE_REQUIREMENTS):
        raise SourceStagingAuthorizationError("Source-staging quarantine requirements are incomplete.")
    network = require_object(authorization.get("network"), "authorization.network")
    if network != {
        "mode": "offline_default_deny",
        "internet_egress": False,
        "public_ingress": False,
        "github_access": False,
        "registry_access": False,
        "external_dns_resolution": False,
    }:
        raise SourceStagingAuthorizationError("Source-staging network declaration must remain offline and default-deny.")
    if set(require_string_list(authorization.get("blockers"), "authorization.blockers")) != EXPECTED_STAGING_BLOCKERS:
        raise SourceStagingAuthorizationError("Source-staging blockers are incomplete or laundered.")
    if require_object(authorization.get("authority"), "authorization.authority") != STAGING_AUTHORITY:
        raise SourceStagingAuthorizationError("Source-staging authorization exposes prohibited authority.")
    verified_signers, verified_roles = verify_threshold_signatures(
        authorization,
        governance_state,
        issued_at,
        STAGING_AUTHORIZATION_DOMAIN,
        "source staging authorization",
        SourceStagingAuthorizationError,
    )
    return {
        "authorization_id": require_string(authorization.get("authorization_id"), "authorization.authorization_id"),
        "authorization_digest": sha256_digest(authorization),
        "verified_signer_ids": verified_signers,
        "verified_roles": verified_roles,
    }


def build_source_staging_gate_report(
    authorization: JsonObject,
    governance_state: JsonObject,
    owner_registry: JsonObject,
    public_registry: JsonObject,
    replica_plan: JsonObject,
    assessed_at: datetime,
    maximum_lifetime_seconds: int,
) -> JsonObject:
    verification = verify_source_staging_authorization(
        authorization,
        governance_state,
        owner_registry,
        public_registry,
        replica_plan,
        assessed_at,
        maximum_lifetime_seconds,
    )
    source_count = len(require_list(public_registry.get("sources"), "public_registry.sources"))
    return {
        "report_version": "0.1.0",
        "report_id": deterministic_uuid(
            str(owner_registry["registry_id"]),
            str(authorization["authorization_id"]),
            "source-staging-gate",
        ),
        "origin": "simulated",
        "status": "SOURCE_STAGING_SIGNED_DENIAL_OWNER_SCOPE_AND_QUARANTINE_BLOCKED",
        "assessed_at": format_timestamp(assessed_at),
        "authorization_id": verification["authorization_id"],
        "authorization_digest": verification["authorization_digest"],
        "verified_signer_ids": verification["verified_signer_ids"],
        "verified_roles": verification["verified_roles"],
        "requested_source_count": source_count,
        "authorized_source_count": 0,
        "staged_source_count": 0,
        "quarantine_requirement_count": len(QUARANTINE_REQUIREMENTS),
        "quarantine_completed_count": 0,
        "owner_exclusion_registry_complete": False,
        "owner_attestation_present": False,
        "staging_authorized": False,
        "build_authorized": False,
        "range_connection_authorized": False,
        "execution_authorized": False,
        "blockers": sorted(EXPECTED_STAGING_BLOCKERS),
        "activity": copy.deepcopy(STAGING_ACTIVITY),
        "authority": copy.deepcopy(STAGING_AUTHORITY),
    }


def validate_source_staging_gate_report(
    report: JsonObject,
    authorization: JsonObject,
    governance_state: JsonObject,
    owner_registry: JsonObject,
    public_registry: JsonObject,
    replica_plan: JsonObject,
    assessed_at: datetime,
    maximum_lifetime_seconds: int,
) -> None:
    expected = build_source_staging_gate_report(
        authorization,
        governance_state,
        owner_registry,
        public_registry,
        replica_plan,
        assessed_at,
        maximum_lifetime_seconds,
    )
    if report != expected:
        raise SourceStagingGateError("Source-staging gate report differs from the deterministic signed denial.")
