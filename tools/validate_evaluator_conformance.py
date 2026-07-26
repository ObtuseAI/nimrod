"""Differentially validate the independent TypeScript evaluator-assurance verifier."""

from __future__ import annotations

import copy
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

from nimrod_simulator.evaluator_observation import evaluation_input_digest
from nimrod_simulator.jsonio import sha256_digest
from nimrod_simulator.model import JsonObject
from validate_evolution_assurance import (
    MAXIMUM_LIFETIME_SECONDS,
    VALIDATION_TIME,
    candidate_document,
    capability_report,
    constitution,
    evaluation_claims,
    evaluator_connectors,
    evaluator_envelopes,
    evaluator_policy,
    governance_connectors,
    governance_state,
    isolation_attestations,
    resource_ledger,
)


def require_condition(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def validate_contract(value: JsonObject, schema_path: Path, label: str) -> None:
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors = sorted(validator.iter_errors(value), key=lambda item: list(item.absolute_path))
    if errors:
        rendered = "; ".join(error.message for error in errors)
        raise RuntimeError(f"{label} failed schema validation: {rendered}")


def build_bundle(project_root: Path) -> JsonObject:
    governance_signers = governance_connectors()
    evaluator_signers = evaluator_connectors()
    governance = governance_state(governance_signers, "simulated")
    signed_constitution = constitution(governance, governance_signers)
    candidate = candidate_document(project_root, signed_constitution)
    report = capability_report(candidate, signed_constitution)
    hard_gates, floors, metrics = evaluation_claims()
    policy = evaluator_policy(signed_constitution, governance, governance_signers, evaluator_signers)
    attestations = isolation_attestations(policy, governance, governance_signers, "fixture")
    ledger = resource_ledger(candidate, signed_constitution, governance, governance_signers, 4)
    envelopes = evaluator_envelopes(
        candidate,
        signed_constitution,
        report,
        policy,
        attestations,
        ledger,
        hard_gates,
        floors,
        metrics,
        evaluator_signers,
    )
    return {
        "bundle_version": "0.1.0",
        "origin": "simulated",
        "verification_time": VALIDATION_TIME.isoformat().replace("+00:00", "Z"),
        "maximum_lifetime_seconds": MAXIMUM_LIFETIME_SECONDS,
        "constitution": signed_constitution,
        "governance_state": governance,
        "evaluator_policy": policy,
        "isolation_attestations": attestations,
        "resource_ledger": ledger,
        "evaluator_envelopes": envelopes,
        "expected_bindings": {
            "candidate_digest": sha256_digest(candidate),
            "constitution_digest": sha256_digest(signed_constitution),
            "capability_report_digest": sha256_digest(report),
            "evaluation_input_digest": evaluation_input_digest(report, hard_gates, floors, metrics),
            "resource_ledger_digest": sha256_digest(ledger),
        },
        "authority": {"can_authorize": False, "can_execute": False, "can_promote": False},
    }


def run_typescript_verifier(
    node_path: str,
    verifier_path: Path,
    bundle: JsonObject,
    temporary_root: Path,
    label: str,
) -> tuple[int, JsonObject]:
    bundle_path = temporary_root / f"{label}.json"
    bundle_path.write_text(json.dumps(bundle, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    completed = subprocess.run(
        [node_path, str(verifier_path), "--input", str(bundle_path)],
        capture_output=True,
        check=False,
        text=True,
        timeout=30,
        encoding="utf-8",
        errors="strict",
    )
    output = completed.stdout if completed.returncode == 0 else completed.stderr
    try:
        parsed = json.loads(output)
    except json.JSONDecodeError as error:
        raise RuntimeError(
            f"TypeScript verifier returned non-JSON output for '{label}': returncode={completed.returncode}, "
            f"stdout={completed.stdout!r}, stderr={completed.stderr!r}."
        ) from error
    if not isinstance(parsed, dict):
        raise RuntimeError(f"TypeScript verifier output for '{label}' is not an object.")
    return completed.returncode, parsed


def expect_rejection(
    node_path: str,
    verifier_path: Path,
    bundle: JsonObject,
    temporary_root: Path,
    label: str,
    expected_code: str,
) -> None:
    return_code, result = run_typescript_verifier(node_path, verifier_path, bundle, temporary_root, label)
    require_condition(return_code != 0, f"TypeScript verifier accepted adversarial case '{label}'.")
    require_condition(
        result.get("status") == "TYPESCRIPT_EVALUATOR_CONFORMANCE_REJECTED",
        f"TypeScript verifier did not emit a rejection receipt for '{label}'.",
    )
    require_condition(
        result.get("code") == expected_code,
        f"TypeScript verifier returned code '{result.get('code')}' instead of '{expected_code}' for '{label}'.",
    )


def validate_evaluator_conformance(project_root: Path) -> JsonObject:
    node_path = shutil.which("node")
    if node_path is None:
        raise RuntimeError("Node.js is required for the independent evaluator conformance implementation.")
    implementation_root = project_root / "conformance" / "typescript-evaluator"
    verifier_path = implementation_root / "dist" / "index.js"
    if not verifier_path.is_file():
        raise RuntimeError(
            "TypeScript evaluator build output is missing. Run 'npm ci' and 'npm run build' in "
            "conformance/typescript-evaluator before validation."
        )
    bundle = build_bundle(project_root)
    validate_contract(
        bundle,
        project_root / "specs" / "evaluator-conformance-bundle.schema.json",
        "generated evaluator conformance bundle",
    )
    with tempfile.TemporaryDirectory(prefix="nimrod-typescript-conformance-") as temporary_directory:
        temporary_root = Path(temporary_directory)
        return_code, positive = run_typescript_verifier(
            node_path,
            verifier_path,
            bundle,
            temporary_root,
            "positive",
        )
        require_condition(return_code == 0, f"TypeScript evaluator rejected the valid Python-generated bundle: {positive}.")
        require_condition(positive.get("status") == "TYPESCRIPT_EVALUATOR_CONFORMANCE_VALID", "Independent verifier status mismatch.")
        require_condition(positive.get("shared_python_verification_logic") is False, "Independent verifier claimed shared Python logic.")
        require_condition(positive.get("live_os_enforcement_verified") is False, "Fixture evidence claimed live OS enforcement.")

        adversarial_count = 0
        signature_tamper = copy.deepcopy(bundle)
        signature_tamper["evaluator_envelopes"][0]["signature"]["signature_base64"] = "A" * 86 + "=="
        expect_rejection(node_path, verifier_path, signature_tamper, temporary_root, "signature-tamper", "SIGNATURE_INVALID")
        adversarial_count += 1

        role_collapse = copy.deepcopy(bundle)
        role_collapse["evaluator_policy"]["evaluators"][1]["role"] = "public_regression"
        expect_rejection(node_path, verifier_path, role_collapse, temporary_root, "role-collapse", "EVALUATOR_IDENTITY_COLLAPSE")
        adversarial_count += 1

        expired = copy.deepcopy(bundle)
        expired["verification_time"] = "2026-07-13T04:41:00Z"
        expect_rejection(node_path, verifier_path, expired, temporary_root, "expired-policy", "TIME_WINDOW")
        adversarial_count += 1

        candidate_substitution = copy.deepcopy(bundle)
        candidate_substitution["expected_bindings"]["candidate_digest"] = "sha256:" + "0" * 64
        expect_rejection(node_path, verifier_path, candidate_substitution, temporary_root, "candidate-substitution", "OBSERVATION_BINDING")
        adversarial_count += 1

        missing_control = copy.deepcopy(bundle)
        missing_control["isolation_attestations"][0]["controls"].pop()
        expect_rejection(node_path, verifier_path, missing_control, temporary_root, "missing-control", "ISOLATION_CONTROL_SET")
        adversarial_count += 1

        ledger_total_tamper = copy.deepcopy(bundle)
        ledger_total_tamper["resource_ledger"]["totals"]["total_compute_units"] = 5
        expect_rejection(node_path, verifier_path, ledger_total_tamper, temporary_root, "ledger-total-tamper", "LEDGER_TOTALS")
        adversarial_count += 1

        authority_widening = copy.deepcopy(bundle)
        authority_widening["authority"]["can_execute"] = True
        expect_rejection(node_path, verifier_path, authority_widening, temporary_root, "authority-widening", "AUTHORITY_WIDENED")
        adversarial_count += 1

        insufficient_threshold = copy.deepcopy(bundle)
        insufficient_threshold["evaluator_policy"]["signatures"].pop()
        expect_rejection(node_path, verifier_path, insufficient_threshold, temporary_root, "insufficient-threshold", "SIGNATURE_THRESHOLD")
        adversarial_count += 1

    return {
        "status": "INDEPENDENT_TYPESCRIPT_EVALUATOR_CONFORMANCE_VALID",
        "origin": "simulated",
        "implementation_language": "typescript",
        "runtime_cryptography": "node_crypto_ed25519",
        "shared_python_verification_logic": False,
        "canonical_json_implemented_independently": True,
        "threshold_signature_verification_implemented_independently": True,
        "evaluator_policy_semantics_implemented_independently": True,
        "isolation_semantics_implemented_independently": True,
        "resource_chain_semantics_implemented_independently": True,
        "evaluator_count": positive["evaluator_count"],
        "isolation_attestation_count": positive["isolation_attestation_count"],
        "resource_ledger_entry_count": positive["resource_ledger_entry_count"],
        "adversarial_case_count": adversarial_count,
        "candidate_executed": False,
        "live_os_enforcement_verified": False,
        "production_promotion_authorized": False,
    }


def main() -> None:
    project_root = Path(__file__).resolve().parent.parent
    result = validate_evaluator_conformance(project_root)
    report_path = project_root / "reports" / "EVALUATOR_CONFORMANCE_VALIDATION.json"
    report_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
