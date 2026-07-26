"""Validate pinned public sources and declaration-only offline sacrificial replicas."""

from __future__ import annotations

import copy
import json
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import TypeVar

from jsonschema import Draft202012Validator, FormatChecker

from nimrod_simulator.errors import (
    PublicCorpusIntakeError,
    PublicCorpusRegistryError,
    SacrificialReplicaPlanError,
)
from nimrod_simulator.jsonio import read_json_object, sha256_digest
from nimrod_simulator.model import JsonObject
from nimrod_simulator.public_sacrificial_corpus import (
    CORPUS_AUTHORITY,
    FORBIDDEN_TARGET_CLASSES,
    INTAKE_ACTIVITY,
    INTAKE_AUTHORITY,
    REPLICA_PLAN_AUTHORITY,
    build_public_corpus_intake_report,
    validate_public_corpus_intake_report,
    validate_public_source_registry,
    validate_sacrificial_replica_plan,
)


TError = TypeVar("TError", bound=Exception)
PROJECT_ROOT = Path(__file__).resolve().parents[1]
ASSESSMENT_TIME = datetime(2026, 7, 13, 18, 45, 0, tzinfo=timezone.utc)


def expect_error(
    error_type: type[TError],
    operation: Callable[[], object],
    label: str,
) -> None:
    try:
        operation()
    except error_type:
        return
    except Exception as error:
        raise AssertionError(
            f"{label} raised {type(error).__name__}; expected {error_type.__name__}: {error}"
        ) from error
    raise AssertionError(f"Expected {error_type.__name__} for {label}.")


def validate_contract(value: JsonObject, schema_path: Path, label: str) -> None:
    schema = read_json_object(schema_path)
    errors = sorted(
        Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(value),
        key=lambda item: list(item.absolute_path),
    )
    if errors:
        rendered = "; ".join(error.message for error in errors)
        raise AssertionError(f"{label} failed schema validation: {rendered}")


def source(
    source_id: str,
    repository: str,
    default_branch: str,
    commit_sha: str,
    purpose: str,
    spdx_id: str,
    license_path: str,
    detection_source: str,
) -> JsonObject:
    return {
        "source_id": source_id,
        "repository": repository,
        "repository_url": f"https://github.com/{repository}",
        "clone_url": f"https://github.com/{repository}.git",
        "default_branch": default_branch,
        "commit_sha": commit_sha,
        "pinned_ref": f"commit:{commit_sha}",
        "visibility": "public",
        "intentionally_vulnerable": True,
        "purpose": purpose,
        "license_review": {
            "spdx_id": spdx_id,
            "license_path": license_path,
            "license_url": f"https://github.com/{repository}/blob/{commit_sha}/{license_path}",
            "detection_source": detection_source,
            "review_status": "metadata_reviewed_source_use_only",
        },
        "use_mode": "source_metadata_only",
        "source_downloaded": False,
        "public_target_authorized": False,
        "authorized_network_targets": [],
    }


def public_source_registry() -> JsonObject:
    return {
        "registry_version": "0.1.0",
        "registry_id": "f21d7658-b092-45c2-a314-f812533b6a05",
        "origin": "live_metadata_observation",
        "status": "blocked_owner_exclusion_registry_incomplete",
        "observed_at": "2026-07-13T18:45:00Z",
        "owner_boundary": {
            "mode": "deny_first",
            "registry_complete": False,
            "unknown_ownership_action": "deny",
            "excluded_organizations": ["obtuseai"],
            "excluded_repositories": ["obtuseai/nimrod"],
        },
        "sources": [
            source(
                "public-source:juice-shop",
                "juice-shop/juice-shop",
                "master",
                "33518f5a0911e25d9df747b1e70fb7af279a755c",
                "api_and_web_assurance",
                "MIT",
                "LICENSE",
                "github_license_api",
            ),
            source(
                "public-source:webgoat",
                "WebGoat/WebGoat",
                "main",
                "75d475f89a1130035cc34ff2085fc1d874c0881e",
                "java_web_assurance",
                "GPL-2.0-or-later",
                "LICENSE.txt",
                "manual_spdx_header",
            ),
            source(
                "public-source:dvwa",
                "digininja/DVWA",
                "master",
                "d45ba3c4e7efa7f023f25f58ab4af9912c887057",
                "php_web_assurance",
                "GPL-3.0",
                "COPYING.txt",
                "github_license_api",
            ),
            source(
                "public-source:nodegoat",
                "OWASP/NodeGoat",
                "master",
                "c5cb68a7084e4ae7dcc60e6a98768720a81841e8",
                "node_web_assurance",
                "Apache-2.0",
                "LICENSE",
                "github_license_api",
            ),
            source(
                "public-source:iotgoat",
                "OWASP/IoTGoat",
                "master",
                "f67b7f961301d7a56b435fd7cffac73600f0c97b",
                "firmware_static_assurance",
                "MIT",
                "LICENSE.md",
                "github_license_api",
            ),
        ],
        "forbidden_target_classes": sorted(FORBIDDEN_TARGET_CLASSES),
        "blockers": [
            "CONTENT_DIGEST_NOT_RETAINED",
            "OWNER_EXCLUSION_REGISTRY_INCOMPLETE",
            "PINNED_COMMIT_SIGNATURE_UNVERIFIED",
            "REPLICA_NOT_BUILT",
            "SOURCE_ARCHIVE_NOT_STAGED",
        ],
        "authority": copy.deepcopy(CORPUS_AUTHORITY),
    }


def replica_plan(registry: JsonObject) -> JsonObject:
    kinds = {
        "public-source:juice-shop": "web_application_offline_replica",
        "public-source:webgoat": "web_application_offline_replica",
        "public-source:dvwa": "web_application_offline_replica",
        "public-source:nodegoat": "web_application_offline_replica",
        "public-source:iotgoat": "firmware_static_analysis_only",
    }
    sources = registry["sources"]
    if not isinstance(sources, list):
        raise TypeError("Registry sources must be a list.")
    replicas: list[JsonObject] = []
    for item in sources:
        if not isinstance(item, dict):
            raise TypeError("Registry source must be an object.")
        source_id = str(item["source_id"])
        replicas.append(
            {
                "replica_id": source_id.replace("public-source:", "sacrificial-replica:"),
                "source_id": source_id,
                "source_commit_sha": item["commit_sha"],
                "replica_kind": kinds[source_id],
                "zone": "sacrificial_target",
                "state": "declared_not_built",
                "source_archive_present": False,
                "content_digest_verified": False,
                "dependencies_resolved": False,
                "image_built": False,
                "replica_provisioned": False,
                "network_connected": False,
                "public_target_authorized": False,
                "execution_authorized": False,
            }
        )
    return {
        "plan_version": "0.1.0",
        "plan_id": "7f6e5311-3a30-42b8-b451-c7a3a853c5ba",
        "origin": "simulated",
        "status": "declaration_only_sources_not_staged_or_built",
        "registry_id": registry["registry_id"],
        "registry_digest": sha256_digest(registry),
        "network": {
            "mode": "internal_only_default_deny",
            "upstream_access": False,
            "internet_egress": False,
            "public_ingress": False,
            "github_access": False,
            "registry_access": False,
            "dns_external_resolution": False,
        },
        "replicas": replicas,
        "forbidden_targets": sorted(FORBIDDEN_TARGET_CLASSES),
        "authority": copy.deepcopy(REPLICA_PLAN_AUTHORITY),
    }


def write_or_compare_example(path: Path, value: JsonObject) -> None:
    rendered = json.dumps(value, indent=2, ensure_ascii=False) + "\n"
    if path.exists() and path.read_text(encoding="utf-8") != rendered:
        raise AssertionError(f"Canonical example drifted from deterministic regeneration: {path}")
    if not path.exists():
        path.write_bytes(rendered.encode("utf-8"))


def main() -> None:
    schemas = PROJECT_ROOT / "specs"
    examples = schemas / "examples"
    registry = public_source_registry()
    plan = replica_plan(registry)
    report = build_public_corpus_intake_report(registry, plan, ASSESSMENT_TIME)
    validate_public_source_registry(registry)
    validate_sacrificial_replica_plan(plan, registry)
    validate_public_corpus_intake_report(report, registry, plan, ASSESSMENT_TIME)
    write_or_compare_example(examples / "public-sacrificial-source-registry.example.json", registry)
    write_or_compare_example(examples / "sacrificial-replica-plan.example.json", plan)
    write_or_compare_example(examples / "public-corpus-intake-report.example.json", report)
    validate_contract(registry, schemas / "public-sacrificial-source-registry.schema.json", "source registry")
    validate_contract(plan, schemas / "sacrificial-replica-plan.schema.json", "replica plan")
    validate_contract(report, schemas / "public-corpus-intake-report.schema.json", "intake report")

    registry_cases: list[tuple[str, Callable[[JsonObject], None]]] = [
        ("owner registry laundering", lambda value: value["owner_boundary"].__setitem__("registry_complete", True)),
        ("unknown ownership allowed", lambda value: value["owner_boundary"].__setitem__("unknown_ownership_action", "allow")),
        ("obtuseai exclusion removed", lambda value: value["owner_boundary"].__setitem__("excluded_organizations", [])),
        ("nimrod exclusion removed", lambda value: value["owner_boundary"].__setitem__("excluded_repositories", [])),
        ("owner repository inserted", lambda value: value["sources"][0].__setitem__("repository", "obtuseai/nimrod")),
        ("short commit", lambda value: value["sources"][0].__setitem__("commit_sha", "abc123")),
        ("full commit substitution", lambda value: value["sources"][0].__setitem__("commit_sha", "0" * 40)),
        ("moving branch substitution", lambda value: value["sources"][0].__setitem__("default_branch", "main")),
        ("ref substitution", lambda value: value["sources"][0].__setitem__("pinned_ref", "branch:master")),
        ("private source", lambda value: value["sources"][0].__setitem__("visibility", "private")),
        ("ordinary project", lambda value: value["sources"][0].__setitem__("intentionally_vulnerable", False)),
        ("license substitution", lambda value: value["sources"][0]["license_review"].__setitem__("spdx_id", "GPL-3.0")),
        ("license path substitution", lambda value: value["sources"][0]["license_review"].__setitem__("license_path", "COPYING")),
        ("source download laundering", lambda value: value["sources"][0].__setitem__("source_downloaded", True)),
        ("public targeting", lambda value: value["sources"][0].__setitem__("public_target_authorized", True)),
        ("network target", lambda value: value["sources"][0].__setitem__("authorized_network_targets", ["github.com"])),
        ("forbidden target omission", lambda value: value.__setitem__("forbidden_target_classes", value["forbidden_target_classes"][:-1])),
        ("registry authority", lambda value: value["authority"].__setitem__("can_download_source", True)),
    ]
    adversarial_count = 0
    for label, mutate in registry_cases:
        candidate = copy.deepcopy(registry)
        mutate(candidate)
        expect_error(PublicCorpusRegistryError, lambda candidate=candidate: validate_public_source_registry(candidate), label)
        adversarial_count += 1

    plan_cases: list[tuple[str, Callable[[JsonObject], None]]] = [
        ("registry substitution", lambda value: value.__setitem__("registry_digest", "sha256:" + "0" * 64)),
        ("upstream access", lambda value: value["network"].__setitem__("upstream_access", True)),
        ("internet egress", lambda value: value["network"].__setitem__("internet_egress", True)),
        ("public ingress", lambda value: value["network"].__setitem__("public_ingress", True)),
        ("GitHub access", lambda value: value["network"].__setitem__("github_access", True)),
        ("registry access", lambda value: value["network"].__setitem__("registry_access", True)),
        ("replica built laundering", lambda value: value["replicas"][0].__setitem__("image_built", True)),
        ("replica provisioned laundering", lambda value: value["replicas"][0].__setitem__("replica_provisioned", True)),
        ("replica network connection", lambda value: value["replicas"][0].__setitem__("network_connected", True)),
        ("replica public target", lambda value: value["replicas"][0].__setitem__("public_target_authorized", True)),
        ("firmware execution widening", lambda value: value["replicas"][4].__setitem__("replica_kind", "web_application_offline_replica")),
        ("plan execution authority", lambda value: value["authority"].__setitem__("can_execute", True)),
    ]
    for label, mutate in plan_cases:
        candidate = copy.deepcopy(plan)
        mutate(candidate)
        expect_error(
            SacrificialReplicaPlanError,
            lambda candidate=candidate: validate_sacrificial_replica_plan(candidate, registry),
            label,
        )
        adversarial_count += 1

    report_cases: list[tuple[str, Callable[[JsonObject], None]]] = [
        ("archive count laundering", lambda value: value.__setitem__("source_archive_count", 5)),
        ("replica readiness laundering", lambda value: value.__setitem__("replica_ready_count", 5)),
        ("owner registry completion laundering", lambda value: value.__setitem__("owner_exclusion_registry_complete", True)),
        ("public host target laundering", lambda value: value.__setitem__("public_host_target_authorized", True)),
        ("connection laundering", lambda value: value.__setitem__("range_connection_authorized", True)),
        ("execution laundering", lambda value: value.__setitem__("execution_authorized", True)),
        ("testing contact laundering", lambda value: value["activity"].__setitem__("public_host_contacted_for_testing", True)),
        ("report authority laundering", lambda value: value["authority"].__setitem__("can_target_public_host", True)),
    ]
    for label, mutate in report_cases:
        candidate = copy.deepcopy(report)
        mutate(candidate)
        expect_error(
            PublicCorpusIntakeError,
            lambda candidate=candidate: validate_public_corpus_intake_report(
                candidate, registry, plan, ASSESSMENT_TIME
            ),
            label,
        )
        adversarial_count += 1

    validation_report: JsonObject = {
        "status": report["status"],
        "origin": report["origin"],
        "pinned_source_count": report["pinned_source_count"],
        "metadata_reviewed_source_count": report["metadata_reviewed_source_count"],
        "source_archive_count": report["source_archive_count"],
        "replica_declared_count": report["replica_declared_count"],
        "replica_ready_count": report["replica_ready_count"],
        "owner_exclusion_registry_complete": report["owner_exclusion_registry_complete"],
        "unknown_ownership_action": registry["owner_boundary"]["unknown_ownership_action"],
        "excluded_organizations": registry["owner_boundary"]["excluded_organizations"],
        "public_host_target_authorized": report["public_host_target_authorized"],
        "range_connection_authorized": report["range_connection_authorized"],
        "execution_authorized": report["execution_authorized"],
        "forbidden_target_class_count": len(registry["forbidden_target_classes"]),
        "adversarial_case_count": adversarial_count,
        "blockers": report["blockers"],
        "activity": copy.deepcopy(INTAKE_ACTIVITY),
        "authority": copy.deepcopy(INTAKE_AUTHORITY),
    }
    report_path = PROJECT_ROOT / "reports" / "PUBLIC_SACRIFICIAL_CORPUS_VALIDATION.json"
    report_path.write_text(
        json.dumps(validation_report, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(json.dumps(validation_report, indent=2))


if __name__ == "__main__":
    main()
