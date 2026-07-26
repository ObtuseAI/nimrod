"""Pinned public source intake for declaration-only offline sacrificial replicas."""

from __future__ import annotations

import copy
import re
from collections.abc import Mapping
from datetime import datetime

from nimrod_simulator.compiler import deterministic_uuid, format_timestamp
from nimrod_simulator.errors import (
    PublicCorpusIntakeError,
    PublicCorpusRegistryError,
    SacrificialReplicaPlanError,
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
from nimrod_simulator.model import JsonObject


PINNED_PUBLIC_REPOSITORIES: frozenset[str] = frozenset({
    "OWASP/IoTGoat",
    "OWASP/NodeGoat",
    "WebGoat/WebGoat",
    "digininja/DVWA",
    "juice-shop/juice-shop",
})
EXPECTED_COMMITS: Mapping[str, str] = {
    "OWASP/IoTGoat": "f67b7f961301d7a56b435fd7cffac73600f0c97b",
    "OWASP/NodeGoat": "c5cb68a7084e4ae7dcc60e6a98768720a81841e8",
    "WebGoat/WebGoat": "75d475f89a1130035cc34ff2085fc1d874c0881e",
    "digininja/DVWA": "d45ba3c4e7efa7f023f25f58ab4af9912c887057",
    "juice-shop/juice-shop": "33518f5a0911e25d9df747b1e70fb7af279a755c",
}
EXPECTED_DEFAULT_BRANCHES: Mapping[str, str] = {
    "OWASP/IoTGoat": "master",
    "OWASP/NodeGoat": "master",
    "WebGoat/WebGoat": "main",
    "digininja/DVWA": "master",
    "juice-shop/juice-shop": "master",
}
EXPECTED_LICENSES: Mapping[str, str] = {
    "OWASP/IoTGoat": "MIT",
    "OWASP/NodeGoat": "Apache-2.0",
    "WebGoat/WebGoat": "GPL-2.0-or-later",
    "digininja/DVWA": "GPL-3.0",
    "juice-shop/juice-shop": "MIT",
}
EXPECTED_LICENSE_PATHS: Mapping[str, str] = {
    "OWASP/IoTGoat": "LICENSE.md",
    "OWASP/NodeGoat": "LICENSE",
    "WebGoat/WebGoat": "LICENSE.txt",
    "digininja/DVWA": "COPYING.txt",
    "juice-shop/juice-shop": "LICENSE",
}
EXPECTED_REPLICA_KINDS: Mapping[str, str] = {
    "OWASP/IoTGoat": "firmware_static_analysis_only",
    "OWASP/NodeGoat": "web_application_offline_replica",
    "WebGoat/WebGoat": "web_application_offline_replica",
    "digininja/DVWA": "web_application_offline_replica",
    "juice-shop/juice-shop": "web_application_offline_replica",
}
FORBIDDEN_TARGET_CLASSES: frozenset[str] = frozenset({
    "github_api",
    "github_ci",
    "github_content_delivery",
    "github_hosted_repository",
    "maintainer_infrastructure",
    "package_or_container_registry",
    "public_demo",
    "third_party_deployment",
})
CORPUS_AUTHORITY: JsonObject = {
    "can_download_source": False,
    "can_build_replica": False,
    "can_provision": False,
    "can_connect": False,
    "can_execute": False,
    "can_target_public_host": False,
    "can_authorize_action": False,
}
REPLICA_PLAN_AUTHORITY: JsonObject = copy.deepcopy(CORPUS_AUTHORITY)
INTAKE_ACTIVITY: JsonObject = {
    "github_metadata_network_read_performed": True,
    "repository_content_downloaded": False,
    "source_archive_staged": False,
    "dependency_resolution_performed": False,
    "container_image_pulled": False,
    "replica_built": False,
    "infrastructure_provisioned": False,
    "public_host_contacted_for_testing": False,
    "campaign_executed": False,
}
INTAKE_AUTHORITY: JsonObject = copy.deepcopy(CORPUS_AUTHORITY)
COMMIT_PATTERN: re.Pattern[str] = re.compile(r"^[0-9a-f]{40}$")


def validate_public_source_registry(registry: JsonObject) -> None:
    if registry.get("registry_version") != "0.1.0":
        raise PublicCorpusRegistryError("Public source registry must use version 0.1.0.")
    if registry.get("status") != "blocked_owner_exclusion_registry_incomplete":
        raise PublicCorpusRegistryError("Public source registry must preserve the incomplete owner registry blocker.")
    owner_boundary = require_object(registry.get("owner_boundary"), "registry.owner_boundary")
    if owner_boundary.get("mode") != "deny_first" or owner_boundary.get("unknown_ownership_action") != "deny":
        raise PublicCorpusRegistryError("Unknown or owner-linked repository ownership must fail closed.")
    if require_boolean(owner_boundary.get("registry_complete"), "owner_boundary.registry_complete") is not False:
        raise PublicCorpusRegistryError("Owner exclusion registry cannot claim completeness without owner input.")
    excluded_organizations = set(
        require_string_list(owner_boundary.get("excluded_organizations"), "owner_boundary.excluded_organizations")
    )
    if "obtuseai" not in {value.casefold() for value in excluded_organizations}:
        raise PublicCorpusRegistryError("Owner exclusion registry must deny the obtuseai organization.")
    excluded_repositories = set(
        require_string_list(owner_boundary.get("excluded_repositories"), "owner_boundary.excluded_repositories")
    )
    if "obtuseai/nimrod" not in {value.casefold() for value in excluded_repositories}:
        raise PublicCorpusRegistryError("Owner exclusion registry must deny the nimrod source repository.")
    entries = [
        require_object(value, f"registry.sources[{index}]")
        for index, value in enumerate(require_list(registry.get("sources"), "registry.sources"))
    ]
    if len(entries) != len(PINNED_PUBLIC_REPOSITORIES):
        raise PublicCorpusRegistryError("Public source registry requires exactly five reviewed repositories.")
    source_ids: set[str] = set()
    repositories: set[str] = set()
    commit_shas: set[str] = set()
    for index, source in enumerate(entries):
        source_id = require_string(source.get("source_id"), f"sources[{index}].source_id")
        repository = require_string(source.get("repository"), f"sources[{index}].repository")
        commit_sha = require_string(source.get("commit_sha"), f"sources[{index}].commit_sha")
        if repository not in PINNED_PUBLIC_REPOSITORIES:
            raise PublicCorpusRegistryError(f"Repository '{repository}' is not in the reviewed corpus.")
        if repository.split("/", maxsplit=1)[0].casefold() in {value.casefold() for value in excluded_organizations}:
            raise PublicCorpusRegistryError(f"Repository '{repository}' belongs to an excluded organization.")
        if repository.casefold() in {value.casefold() for value in excluded_repositories}:
            raise PublicCorpusRegistryError(f"Repository '{repository}' is owner-excluded.")
        if source.get("repository_url") != f"https://github.com/{repository}":
            raise PublicCorpusRegistryError(f"Repository '{repository}' URL is not canonical GitHub HTTPS.")
        if source.get("clone_url") != f"https://github.com/{repository}.git":
            raise PublicCorpusRegistryError(f"Repository '{repository}' clone URL is not canonical GitHub HTTPS.")
        if COMMIT_PATTERN.fullmatch(commit_sha) is None:
            raise PublicCorpusRegistryError(f"Repository '{repository}' is not pinned to a full lowercase commit SHA.")
        if commit_sha != EXPECTED_COMMITS[repository]:
            raise PublicCorpusRegistryError(f"Repository '{repository}' revision differs from the reviewed commit.")
        if source.get("default_branch") != EXPECTED_DEFAULT_BRANCHES[repository]:
            raise PublicCorpusRegistryError(f"Repository '{repository}' default branch differs from reviewed metadata.")
        if source.get("pinned_ref") != f"commit:{commit_sha}":
            raise PublicCorpusRegistryError(f"Repository '{repository}' pinned ref differs from its commit SHA.")
        if source.get("visibility") != "public" or source.get("intentionally_vulnerable") is not True:
            raise PublicCorpusRegistryError(f"Repository '{repository}' is not explicitly public and intentional.")
        license_review = require_object(source.get("license_review"), f"sources[{index}].license_review")
        if license_review.get("spdx_id") != EXPECTED_LICENSES[repository]:
            raise PublicCorpusRegistryError(f"Repository '{repository}' license differs from the reviewed SPDX value.")
        if license_review.get("license_path") != EXPECTED_LICENSE_PATHS[repository]:
            raise PublicCorpusRegistryError(f"Repository '{repository}' license path differs from reviewed metadata.")
        if license_review.get("review_status") != "metadata_reviewed_source_use_only":
            raise PublicCorpusRegistryError(f"Repository '{repository}' license review does not limit source use.")
        if source.get("use_mode") != "source_metadata_only":
            raise PublicCorpusRegistryError(f"Repository '{repository}' use mode exceeds metadata intake.")
        if source.get("source_downloaded") is not False or source.get("public_target_authorized") is not False:
            raise PublicCorpusRegistryError(f"Repository '{repository}' claims download or public targeting authority.")
        if require_list(source.get("authorized_network_targets"), f"sources[{index}].authorized_network_targets"):
            raise PublicCorpusRegistryError(f"Repository '{repository}' cannot declare a network target.")
        source_ids.add(source_id)
        repositories.add(repository)
        commit_shas.add(commit_sha)
    if len(source_ids) != len(entries) or repositories != PINNED_PUBLIC_REPOSITORIES or len(commit_shas) != len(entries):
        raise PublicCorpusRegistryError("Public source identities, repositories, and commits must be unique and complete.")
    if set(require_string_list(registry.get("forbidden_target_classes"), "registry.forbidden_target_classes")) != FORBIDDEN_TARGET_CLASSES:
        raise PublicCorpusRegistryError("Public source registry forbidden target classes are incomplete.")
    expected_blockers = {
        "CONTENT_DIGEST_NOT_RETAINED",
        "OWNER_EXCLUSION_REGISTRY_INCOMPLETE",
        "PINNED_COMMIT_SIGNATURE_UNVERIFIED",
        "REPLICA_NOT_BUILT",
        "SOURCE_ARCHIVE_NOT_STAGED",
    }
    if set(require_string_list(registry.get("blockers"), "registry.blockers")) != expected_blockers:
        raise PublicCorpusRegistryError("Public source registry blockers are incomplete or laundered.")
    if require_object(registry.get("authority"), "registry.authority") != CORPUS_AUTHORITY:
        raise PublicCorpusRegistryError("Public source registry exposes prohibited authority.")


def validate_sacrificial_replica_plan(plan: JsonObject, registry: JsonObject) -> None:
    validate_public_source_registry(registry)
    if plan.get("plan_version") != "0.1.0":
        raise SacrificialReplicaPlanError("Sacrificial replica plan must use version 0.1.0.")
    if plan.get("registry_id") != registry.get("registry_id") or plan.get("registry_digest") != sha256_digest(registry):
        raise SacrificialReplicaPlanError("Sacrificial replica plan registry binding mismatch.")
    if plan.get("status") != "declaration_only_sources_not_staged_or_built":
        raise SacrificialReplicaPlanError("Sacrificial replica plan must remain declaration-only.")
    network = require_object(plan.get("network"), "plan.network")
    expected_network = {
        "mode": "internal_only_default_deny",
        "upstream_access": False,
        "internet_egress": False,
        "public_ingress": False,
        "github_access": False,
        "registry_access": False,
        "dns_external_resolution": False,
    }
    if network != expected_network:
        raise SacrificialReplicaPlanError("Sacrificial replica network must remain offline and default-deny.")
    sources = {
        require_string(require_object(value, f"registry.sources[{index}]").get("source_id"), "source.source_id"):
        require_object(value, f"registry.sources[{index}]")
        for index, value in enumerate(require_list(registry.get("sources"), "registry.sources"))
    }
    replicas = [
        require_object(value, f"plan.replicas[{index}]")
        for index, value in enumerate(require_list(plan.get("replicas"), "plan.replicas"))
    ]
    if len(replicas) != len(sources):
        raise SacrificialReplicaPlanError("Sacrificial replica plan requires one declaration per source.")
    replica_ids: set[str] = set()
    used_sources: set[str] = set()
    for index, replica in enumerate(replicas):
        replica_id = require_string(replica.get("replica_id"), f"replicas[{index}].replica_id")
        source_id = require_string(replica.get("source_id"), f"replicas[{index}].source_id")
        source = sources.get(source_id)
        if source is None:
            raise SacrificialReplicaPlanError(f"Replica '{replica_id}' references an unknown source.")
        repository = require_string(source.get("repository"), "source.repository")
        if replica.get("source_commit_sha") != source.get("commit_sha"):
            raise SacrificialReplicaPlanError(f"Replica '{replica_id}' commit binding mismatch.")
        if replica.get("replica_kind") != EXPECTED_REPLICA_KINDS[repository]:
            raise SacrificialReplicaPlanError(f"Replica '{replica_id}' kind is unsafe or inconsistent.")
        if replica.get("zone") != "sacrificial_target" or replica.get("state") != "declared_not_built":
            raise SacrificialReplicaPlanError(f"Replica '{replica_id}' claims deployment or the wrong zone.")
        for field in (
            "source_archive_present",
            "content_digest_verified",
            "dependencies_resolved",
            "image_built",
            "replica_provisioned",
            "network_connected",
            "public_target_authorized",
            "execution_authorized",
        ):
            if require_boolean(replica.get(field), f"replicas[{index}].{field}") is not False:
                raise SacrificialReplicaPlanError(f"Replica '{replica_id}' field '{field}' must remain false.")
        replica_ids.add(replica_id)
        used_sources.add(source_id)
    if len(replica_ids) != len(replicas) or used_sources != set(sources):
        raise SacrificialReplicaPlanError("Replica identities and source mappings must be unique and complete.")
    if set(require_string_list(plan.get("forbidden_targets"), "plan.forbidden_targets")) != FORBIDDEN_TARGET_CLASSES:
        raise SacrificialReplicaPlanError("Sacrificial replica plan forbidden targets are incomplete.")
    if require_object(plan.get("authority"), "plan.authority") != REPLICA_PLAN_AUTHORITY:
        raise SacrificialReplicaPlanError("Sacrificial replica plan exposes prohibited authority.")


def build_public_corpus_intake_report(
    registry: JsonObject,
    plan: JsonObject,
    assessed_at: datetime,
) -> JsonObject:
    if assessed_at.utcoffset() is None:
        raise PublicCorpusIntakeError("Public corpus assessment time must be timezone-aware.")
    validate_public_source_registry(registry)
    validate_sacrificial_replica_plan(plan, registry)
    sources = require_list(registry.get("sources"), "registry.sources")
    replicas = require_list(plan.get("replicas"), "plan.replicas")
    registry_id = require_string(registry.get("registry_id"), "registry.registry_id")
    plan_id = require_string(plan.get("plan_id"), "plan.plan_id")
    return {
        "report_version": "0.1.0",
        "report_id": deterministic_uuid(registry_id, plan_id, "public-sacrificial-corpus"),
        "origin": "live_metadata_observation",
        "status": "PUBLIC_SACRIFICIAL_CORPUS_PINNED_METADATA_ONLY_OWNER_REGISTRY_AND_OFFLINE_REPLICAS_BLOCKED",
        "assessed_at": format_timestamp(assessed_at),
        "registry_id": registry_id,
        "registry_digest": sha256_digest(registry),
        "plan_id": plan_id,
        "plan_digest": sha256_digest(plan),
        "pinned_source_count": len(sources),
        "metadata_reviewed_source_count": len(sources),
        "source_archive_count": 0,
        "replica_declared_count": len(replicas),
        "replica_ready_count": 0,
        "owner_exclusion_registry_complete": False,
        "public_host_target_authorized": False,
        "range_connection_authorized": False,
        "execution_authorized": False,
        "blockers": sorted(
            {
                *require_string_list(registry.get("blockers"), "registry.blockers"),
                "OWNER_NAMED_SACRIFICIAL_RANGE_MISSING",
            }
        ),
        "activity": copy.deepcopy(INTAKE_ACTIVITY),
        "authority": copy.deepcopy(INTAKE_AUTHORITY),
    }


def validate_public_corpus_intake_report(
    report: JsonObject,
    registry: JsonObject,
    plan: JsonObject,
    assessed_at: datetime,
) -> None:
    expected = build_public_corpus_intake_report(registry, plan, assessed_at)
    if report != expected:
        raise PublicCorpusIntakeError(
            "Public corpus intake report differs from the deterministic safe-source projection."
        )
