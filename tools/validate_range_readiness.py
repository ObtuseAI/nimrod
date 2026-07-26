from __future__ import annotations

import copy
import json
import shutil
import tempfile
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import cast

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from nimrod_simulator.errors import RangeCorpusError, RangePolicySignatureError, RangePreflightError, SimulatorError
from nimrod_simulator.jsonio import read_json_object, sha256_digest, validate_contract
from nimrod_simulator.key_governance import EphemeralEd25519SigningConnector, governance_key
from nimrod_simulator.model import JsonObject
from nimrod_simulator.range_corpus import scan_range_corpus
from nimrod_simulator.range_policy import sign_range_adapter_policy_envelope, verify_range_adapter_policy_envelope
from nimrod_simulator.range_preflight import REQUIRED_CONTROLS, evaluate_disposable_range_preflight


VALIDATION_TIME = datetime(2026, 7, 12, 23, 31, 30, tzinfo=timezone.utc)
POLICY_LIFETIME_SECONDS = 600
PREFLIGHT_AGE_SECONDS = 120


def require_condition(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def expect_error(expected: type[SimulatorError], operation: Callable[[], object], label: str) -> None:
    try:
        operation()
    except expected:
        return
    raise AssertionError(f"Expected {expected.__name__} for {label}.")


def signing_connectors() -> list[EphemeralEd25519SigningConnector]:
    return [
        EphemeralEd25519SigningConnector("key:range-owner", "customer_authority", Ed25519PrivateKey.generate()),
        EphemeralEd25519SigningConnector("key:range-safety", "safety_officer", Ed25519PrivateKey.generate()),
        EphemeralEd25519SigningConnector("key:range-recovery", "recovery_officer", Ed25519PrivateKey.generate()),
    ]


def governance_state(connectors: list[EphemeralEd25519SigningConnector]) -> JsonObject:
    issued_at = "2026-07-12T23:00:00Z"
    keys = [
        governance_key(
            connector,
            "active",
            issued_at,
            None,
            "test_ephemeral",
            f"connector:custody:{connector.key_id}",
            f"memory:{connector.key_id}",
            False,
            None,
        )
        for connector in connectors
    ]
    return {
        "state_version": "0.1.0",
        "governance_id": "436ddf25-9001-433a-91e8-ea2a80f9f335",
        "origin": "simulated",
        "epoch": 1,
        "issued_at": issued_at,
        "previous_state_digest": None,
        "threshold": 2,
        "ceremony_key_count": 3,
        "minimum_distinct_roles": 2,
        "keys": keys,
    }


def signed_policy_envelope(
    policy: JsonObject,
    governance: JsonObject,
    connectors: list[EphemeralEd25519SigningConnector],
    issued_at: datetime,
    not_before: datetime,
    expires_at: datetime,
) -> JsonObject:
    unsigned: JsonObject = {
        "envelope_version": "0.1.0",
        "envelope_id": "29177df8-867b-44fb-a0d7-f206a12090da",
        "origin": "simulated",
        "policy_id": policy["policy_id"],
        "policy_digest": sha256_digest(policy),
        "governance_state_digest": sha256_digest(governance),
        "issued_at": issued_at.isoformat().replace("+00:00", "Z"),
        "not_before": not_before.isoformat().replace("+00:00", "Z"),
        "expires_at": expires_at.isoformat().replace("+00:00", "Z"),
        "authority": {"can_connect": False, "can_execute": False, "can_discover_targets": False},
    }
    return sign_range_adapter_policy_envelope(unsigned, connectors[:2])


def preflight_document(
    envelope: JsonObject,
    report: JsonObject,
    captured_at: datetime,
    status: str,
) -> JsonObject:
    evidence = []
    if status == "proven":
        evidence = [{"id": "evidence:simulated-contract-only", "digest": "sha256:" + "a" * 64}]
    return {
        "preflight_version": "0.1.0",
        "preflight_id": "31d91e46-e78d-4f70-9200-6062ec01ad42",
        "origin": "simulated",
        "range_id": "range:disposable-unprovisioned-01",
        "environment_class": "isolated_range",
        "captured_at": captured_at.isoformat().replace("+00:00", "Z"),
        "policy_envelope_digest": sha256_digest(envelope),
        "corpus_report_digest": sha256_digest(report),
        "controls": [
            {"control_id": control_id, "status": status, "evidence": copy.deepcopy(evidence)}
            for control_id in sorted(REQUIRED_CONTROLS)
        ],
        "authority": {"can_connect": False, "can_execute": False},
    }


def evaluate(
    preflight: JsonObject,
    policy: JsonObject,
    envelope: JsonObject,
    governance: JsonObject,
    report: JsonObject,
    evaluated_at: datetime,
) -> JsonObject:
    return evaluate_disposable_range_preflight(
        preflight,
        policy,
        envelope,
        governance,
        report,
        evaluated_at,
        POLICY_LIFETIME_SECONDS,
        PREFLIGHT_AGE_SECONDS,
    )


def update_snapshot_digest(manifest: JsonObject) -> JsonObject:
    mutated = copy.deepcopy(manifest)
    mutated["snapshot_digest"] = sha256_digest(mutated["entries"])
    return mutated


def validate_range_readiness(project_root: Path) -> JsonObject:
    policy = read_json_object(project_root / "specs" / "examples" / "range-adapter-policy.example.json")
    manifest = read_json_object(project_root / "specs" / "examples" / "range-corpus-manifest.example.json")
    connectors = signing_connectors()
    governance = governance_state(connectors)
    issued_at = VALIDATION_TIME - timedelta(seconds=30)
    envelope = signed_policy_envelope(
        policy,
        governance,
        connectors,
        issued_at,
        issued_at,
        VALIDATION_TIME + timedelta(seconds=300),
    )
    verification = verify_range_adapter_policy_envelope(
        envelope,
        policy,
        governance,
        VALIDATION_TIME,
        POLICY_LIFETIME_SECONDS,
    )
    validate_contract(
        envelope,
        project_root / "specs" / "range-adapter-policy-envelope.schema.json",
        "generated signed range policy envelope",
    )
    fixture_root = project_root / "tests" / "fixtures" / "range_adapter"
    report = scan_range_corpus(
        fixture_root,
        manifest,
        policy,
        envelope,
        governance,
        VALIDATION_TIME,
        POLICY_LIFETIME_SECONDS,
    )
    validate_contract(
        report,
        project_root / "specs" / "range-corpus-report.schema.json",
        "generated range corpus report",
    )
    require_condition(report["status"] == "compatible_no_execution", "Canonical local corpus did not pass.")
    blocked_preflight = preflight_document(envelope, report, VALIDATION_TIME - timedelta(seconds=30), "unproven")
    blocked_result = evaluate(blocked_preflight, policy, envelope, governance, report, VALIDATION_TIME)
    validate_contract(
        blocked_preflight,
        project_root / "specs" / "disposable-range-preflight.schema.json",
        "generated blocked disposable-range preflight",
    )
    validate_contract(
        blocked_result,
        project_root / "specs" / "disposable-range-preflight-result.schema.json",
        "generated blocked disposable-range preflight result",
    )
    require_condition(blocked_result["status"] == "blocked", "Unproven controls did not block the gate.")
    proven_preflight = preflight_document(envelope, report, VALIDATION_TIME - timedelta(seconds=30), "proven")
    proven_result = evaluate(proven_preflight, policy, envelope, governance, report, VALIDATION_TIME)
    validate_contract(
        proven_result,
        project_root / "specs" / "disposable-range-preflight-result.schema.json",
        "generated contract-only proven preflight result",
    )
    require_condition(
        proven_result["status"] == "ready_for_separately_authorized_range_connection"
        and proven_result["connection_gate_satisfied"] is True,
        "Contract-only proven controls did not satisfy the separate connection gate.",
    )
    require_condition(
        proven_result["tool_installation_authorized"] is False
        and proven_result["range_connection_authorized"] is False
        and proven_result["execution_authorized"] is False,
        "Preflight result granted authority.",
    )

    adversarial_count = 0
    signature_tamper = copy.deepcopy(envelope)
    signatures = cast(list[JsonObject], signature_tamper["signatures"])
    original_signature = cast(str, signatures[0]["signature_base64"])
    signatures[0]["signature_base64"] = ("A" if original_signature[0] != "A" else "B") + original_signature[1:]
    expect_error(RangePolicySignatureError, lambda: verify_range_adapter_policy_envelope(signature_tamper, policy, governance, VALIDATION_TIME, POLICY_LIFETIME_SECONDS), "signature tamper")
    adversarial_count += 1
    one_signature = copy.deepcopy(envelope)
    one_signature["signatures"] = cast(list[JsonObject], one_signature["signatures"])[:1]
    expect_error(RangePolicySignatureError, lambda: verify_range_adapter_policy_envelope(one_signature, policy, governance, VALIDATION_TIME, POLICY_LIFETIME_SECONDS), "threshold underflow")
    adversarial_count += 1
    duplicate_signer = copy.deepcopy(envelope)
    duplicate_signatures = cast(list[JsonObject], duplicate_signer["signatures"])
    duplicate_signatures[1]["signer_id"] = duplicate_signatures[0]["signer_id"]
    expect_error(RangePolicySignatureError, lambda: verify_range_adapter_policy_envelope(duplicate_signer, policy, governance, VALIDATION_TIME, POLICY_LIFETIME_SECONDS), "duplicate signer")
    adversarial_count += 1
    unknown_signer = copy.deepcopy(envelope)
    cast(list[JsonObject], unknown_signer["signatures"])[0]["signer_id"] = "key:unknown"
    expect_error(RangePolicySignatureError, lambda: verify_range_adapter_policy_envelope(unknown_signer, policy, governance, VALIDATION_TIME, POLICY_LIFETIME_SECONDS), "unknown signer")
    adversarial_count += 1
    policy_digest_substitution = copy.deepcopy(envelope)
    policy_digest_substitution["policy_digest"] = "sha256:" + "0" * 64
    expect_error(RangePolicySignatureError, lambda: verify_range_adapter_policy_envelope(policy_digest_substitution, policy, governance, VALIDATION_TIME, POLICY_LIFETIME_SECONDS), "policy digest substitution")
    adversarial_count += 1
    governance_digest_substitution = copy.deepcopy(envelope)
    governance_digest_substitution["governance_state_digest"] = "sha256:" + "0" * 64
    expect_error(RangePolicySignatureError, lambda: verify_range_adapter_policy_envelope(governance_digest_substitution, policy, governance, VALIDATION_TIME, POLICY_LIFETIME_SECONDS), "governance digest substitution")
    adversarial_count += 1
    expired = signed_policy_envelope(policy, governance, connectors, VALIDATION_TIME - timedelta(seconds=500), VALIDATION_TIME - timedelta(seconds=500), VALIDATION_TIME - timedelta(seconds=1))
    expect_error(RangePolicySignatureError, lambda: verify_range_adapter_policy_envelope(expired, policy, governance, VALIDATION_TIME, POLICY_LIFETIME_SECONDS), "expired policy")
    adversarial_count += 1
    future = signed_policy_envelope(policy, governance, connectors, VALIDATION_TIME, VALIDATION_TIME + timedelta(seconds=1), VALIDATION_TIME + timedelta(seconds=100))
    expect_error(RangePolicySignatureError, lambda: verify_range_adapter_policy_envelope(future, policy, governance, VALIDATION_TIME, POLICY_LIFETIME_SECONDS), "future policy")
    adversarial_count += 1
    overlong = signed_policy_envelope(policy, governance, connectors, VALIDATION_TIME - timedelta(seconds=1), VALIDATION_TIME - timedelta(seconds=1), VALIDATION_TIME + timedelta(seconds=601))
    expect_error(RangePolicySignatureError, lambda: verify_range_adapter_policy_envelope(overlong, policy, governance, VALIDATION_TIME, POLICY_LIFETIME_SECONDS), "overlong policy")
    adversarial_count += 1
    envelope_authority = copy.deepcopy(envelope)
    cast(JsonObject, envelope_authority["authority"])["can_connect"] = True
    expect_error(RangePolicySignatureError, lambda: verify_range_adapter_policy_envelope(envelope_authority, policy, governance, VALIDATION_TIME, POLICY_LIFETIME_SECONDS), "envelope authority")
    adversarial_count += 1
    policy_authority = copy.deepcopy(policy)
    cast(JsonObject, policy_authority["authority"])["can_execute"] = True
    expect_error(RangePolicySignatureError, lambda: verify_range_adapter_policy_envelope(envelope, policy_authority, governance, VALIDATION_TIME, POLICY_LIFETIME_SECONDS), "policy authority")
    adversarial_count += 1
    policy_stage = copy.deepcopy(policy)
    policy_stage["stage"] = "live"
    expect_error(RangePolicySignatureError, lambda: verify_range_adapter_policy_envelope(envelope, policy_stage, governance, VALIDATION_TIME, POLICY_LIFETIME_SECONDS), "policy stage widening")
    adversarial_count += 1

    manifest_authority = copy.deepcopy(manifest)
    cast(JsonObject, manifest_authority["authority"])["can_fetch"] = True
    expect_error(RangeCorpusError, lambda: scan_range_corpus(fixture_root, manifest_authority, policy, envelope, governance, VALIDATION_TIME, POLICY_LIFETIME_SECONDS), "manifest authority")
    adversarial_count += 1
    duplicate_entry = copy.deepcopy(manifest)
    duplicate_entries = cast(list[JsonObject], duplicate_entry["entries"])
    duplicate_entries[1]["entry_id"] = duplicate_entries[0]["entry_id"]
    duplicate_entry = update_snapshot_digest(duplicate_entry)
    expect_error(RangeCorpusError, lambda: scan_range_corpus(fixture_root, duplicate_entry, policy, envelope, governance, VALIDATION_TIME, POLICY_LIFETIME_SECONDS), "duplicate corpus entry")
    adversarial_count += 1
    duplicate_path = copy.deepcopy(manifest)
    duplicate_paths = cast(list[JsonObject], duplicate_path["entries"])
    duplicate_paths[1]["relative_path"] = duplicate_paths[0]["relative_path"]
    duplicate_path = update_snapshot_digest(duplicate_path)
    expect_error(RangeCorpusError, lambda: scan_range_corpus(fixture_root, duplicate_path, policy, envelope, governance, VALIDATION_TIME, POLICY_LIFETIME_SECONDS), "duplicate corpus path")
    adversarial_count += 1
    snapshot_substitution = copy.deepcopy(manifest)
    snapshot_substitution["snapshot_digest"] = "sha256:" + "0" * 64
    expect_error(RangeCorpusError, lambda: scan_range_corpus(fixture_root, snapshot_substitution, policy, envelope, governance, VALIDATION_TIME, POLICY_LIFETIME_SECONDS), "corpus snapshot substitution")
    adversarial_count += 1
    with tempfile.TemporaryDirectory(prefix="nimrod-range-corpus-") as temporary:
        temporary_root = Path(temporary)
        shutil.copytree(fixture_root, temporary_root / "missing")
        (temporary_root / "missing" / "atomic.valid.yaml").unlink()
        missing_report = scan_range_corpus(temporary_root / "missing", manifest, policy, envelope, governance, VALIDATION_TIME, POLICY_LIFETIME_SECONDS)
        require_condition(missing_report["status"] == "blocked" and missing_report["missing_files"], "Missing corpus file was not blocked.")
        adversarial_count += 1
        shutil.copytree(fixture_root, temporary_root / "unexpected")
        (temporary_root / "unexpected" / "unexpected.yaml").write_text(
            "fixture: true\n", encoding="utf-8", newline="\n"
        )
        unexpected_report = scan_range_corpus(temporary_root / "unexpected", manifest, policy, envelope, governance, VALIDATION_TIME, POLICY_LIFETIME_SECONDS)
        require_condition(unexpected_report["status"] == "blocked" and unexpected_report["unexpected_files"], "Unexpected corpus file was not blocked.")
        adversarial_count += 1
    artifact_substitution = copy.deepcopy(manifest)
    cast(list[JsonObject], artifact_substitution["entries"])[0]["expected_artifact_digest"] = "sha256:" + "0" * 64
    artifact_substitution = update_snapshot_digest(artifact_substitution)
    artifact_report = scan_range_corpus(fixture_root, artifact_substitution, policy, envelope, governance, VALIDATION_TIME, POLICY_LIFETIME_SECONDS)
    require_condition(artifact_report["status"] == "blocked", "Corpus artifact substitution was not blocked.")
    adversarial_count += 1
    object_substitution = copy.deepcopy(manifest)
    cast(list[JsonObject], object_substitution["entries"])[0]["source_object_id"] = "00000000-0000-4000-8000-000000000000"
    object_substitution = update_snapshot_digest(object_substitution)
    object_report = scan_range_corpus(fixture_root, object_substitution, policy, envelope, governance, VALIDATION_TIME, POLICY_LIFETIME_SECONDS)
    require_condition(object_report["status"] == "blocked", "Corpus object substitution was not blocked.")
    adversarial_count += 1

    wrong_policy_digest = copy.deepcopy(blocked_preflight)
    wrong_policy_digest["policy_envelope_digest"] = "sha256:" + "0" * 64
    expect_error(RangePreflightError, lambda: evaluate(wrong_policy_digest, policy, envelope, governance, report, VALIDATION_TIME), "preflight policy substitution")
    adversarial_count += 1
    wrong_report_digest = copy.deepcopy(blocked_preflight)
    wrong_report_digest["corpus_report_digest"] = "sha256:" + "0" * 64
    expect_error(RangePreflightError, lambda: evaluate(wrong_report_digest, policy, envelope, governance, report, VALIDATION_TIME), "preflight corpus substitution")
    adversarial_count += 1
    duplicate_control = copy.deepcopy(blocked_preflight)
    duplicate_controls = cast(list[JsonObject], duplicate_control["controls"])
    duplicate_controls[1]["control_id"] = duplicate_controls[0]["control_id"]
    expect_error(RangePreflightError, lambda: evaluate(duplicate_control, policy, envelope, governance, report, VALIDATION_TIME), "duplicate preflight control")
    adversarial_count += 1
    missing_control = copy.deepcopy(blocked_preflight)
    missing_control["controls"] = cast(list[JsonObject], missing_control["controls"])[:-1]
    expect_error(RangePreflightError, lambda: evaluate(missing_control, policy, envelope, governance, report, VALIDATION_TIME), "missing preflight control")
    adversarial_count += 1
    evidence_missing = copy.deepcopy(proven_preflight)
    cast(list[JsonObject], evidence_missing["controls"])[0]["evidence"] = []
    expect_error(RangePreflightError, lambda: evaluate(evidence_missing, policy, envelope, governance, report, VALIDATION_TIME), "proven control without evidence")
    adversarial_count += 1
    preflight_authority = copy.deepcopy(blocked_preflight)
    cast(JsonObject, preflight_authority["authority"])["can_connect"] = True
    expect_error(RangePreflightError, lambda: evaluate(preflight_authority, policy, envelope, governance, report, VALIDATION_TIME), "preflight authority")
    adversarial_count += 1
    stale = preflight_document(envelope, report, VALIDATION_TIME - timedelta(seconds=PREFLIGHT_AGE_SECONDS + 1), "unproven")
    expect_error(RangePreflightError, lambda: evaluate(stale, policy, envelope, governance, report, VALIDATION_TIME), "stale preflight")
    adversarial_count += 1
    future_preflight = preflight_document(envelope, report, VALIDATION_TIME + timedelta(seconds=1), "unproven")
    expect_error(RangePreflightError, lambda: evaluate(future_preflight, policy, envelope, governance, report, VALIDATION_TIME), "future preflight")
    adversarial_count += 1
    report_authority = copy.deepcopy(report)
    cast(JsonObject, report_authority["authority"])["can_connect"] = True
    report_authority_preflight = preflight_document(envelope, report_authority, VALIDATION_TIME, "unproven")
    expect_error(RangePreflightError, lambda: evaluate(report_authority_preflight, policy, envelope, governance, report_authority, VALIDATION_TIME), "corpus report authority")
    adversarial_count += 1
    active_report = copy.deepcopy(report)
    active_report["network_access_performed"] = True
    active_report_preflight = preflight_document(envelope, active_report, VALIDATION_TIME, "unproven")
    expect_error(RangePreflightError, lambda: evaluate(active_report_preflight, policy, envelope, governance, active_report, VALIDATION_TIME), "corpus report activity")
    adversarial_count += 1
    invalid_status = copy.deepcopy(blocked_preflight)
    cast(list[JsonObject], invalid_status["controls"])[0]["status"] = "unknown"
    expect_error(RangePreflightError, lambda: evaluate(invalid_status, policy, envelope, governance, report, VALIDATION_TIME), "unsupported preflight status")
    adversarial_count += 1

    return {
        "status": "RANGE_READINESS_GATES_VALID_CONNECTION_BLOCKED",
        "origin": "simulated",
        "signed_policy_threshold": 2,
        "signed_policy_verified_signer_count": len(cast(list[object], verification["verified_signer_ids"])),
        "signed_policy_role_count": len(cast(list[object], verification["verified_roles"])),
        "corpus_declared_entry_count": report["declared_entry_count"],
        "corpus_compatible_entry_count": report["compatible_entry_count"],
        "corpus_blocked_entry_count": report["blocked_entry_count"],
        "preflight_required_control_count": len(REQUIRED_CONTROLS),
        "current_preflight_status": blocked_result["status"],
        "contract_only_all_proven_gate_status": proven_result["status"],
        "adversarial_case_count": adversarial_count,
        "policy_envelope_digest_binding": True,
        "corpus_snapshot_digest_binding": True,
        "corpus_complete_file_set_required": True,
        "preflight_freshness_enforced": True,
        "compilation_performed": False,
        "source_tool_contacted": False,
        "network_access_performed": False,
        "offensive_tools_installed_or_launched": False,
        "range_connection_authorized": False,
        "live_execution_performed": False,
        "execution_authorized": False,
        "can_connect": False,
        "can_execute": False,
    }


def main() -> None:
    project_root = Path(__file__).resolve().parent.parent
    result = validate_range_readiness(project_root)
    report_path = project_root / "reports" / "RANGE_READINESS_VALIDATION.json"
    report_path.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n"
    )
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
