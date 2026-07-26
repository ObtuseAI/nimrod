from __future__ import annotations

import copy
import json
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import cast

from nimrod_simulator.compiler import PROHIBITED_EXECUTION_KEYS
from nimrod_simulator.errors import (
    ExecutionDirectiveError,
    RangeAdapterCompilationError,
    RangeAdapterImportError,
    RangeAdapterPolicyError,
    SimulatorError,
)
from nimrod_simulator.jsonio import read_json_object, validate_contract
from nimrod_simulator.model import JsonObject, JsonValue
from nimrod_simulator.range_adapter import (
    compile_range_import,
    import_atomic_definition,
    import_caldera_ability,
)


ATOMIC_ID = "3f3a9f2c-8c2f-4e91-9d45-8ec2a8805274"
CALDERA_ID = "89326aa2-7717-4c57-a2e0-3d6a03a74d58"
LEASE_ID = "44444444-4444-4444-8444-444444444444"
PROFILE_ID = "profile:windows-range-host"


def require_condition(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def expect_error(expected: type[SimulatorError], operation: Callable[[], object], label: str) -> None:
    try:
        operation()
    except expected:
        return
    raise AssertionError(f"Expected {expected.__name__} for {label}.")


def write_text(root: Path, name: str, value: str) -> Path:
    path = root / name
    path.write_text(value, encoding="utf-8", newline="\n")
    return path


def assert_no_execution_keys(value: JsonValue, path: str) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = key.casefold().replace("-", "_")
            require_condition(
                normalized not in PROHIBITED_EXECUTION_KEYS,
                f"Compiled range artifact contains prohibited key '{key}' at '{path}'.",
            )
            assert_no_execution_keys(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            assert_no_execution_keys(child, f"{path}[{index}]")


def blocked_atomic(
    root: Path,
    source_text: str,
    name: str,
    replacement: tuple[str, str],
) -> JsonObject:
    path = write_text(root, name, source_text.replace(replacement[0], replacement[1]))
    return import_atomic_definition(path, ATOMIC_ID)


def validate_range_adapter(project_root: Path) -> JsonObject:
    fixture_root = project_root / "tests" / "fixtures" / "range_adapter"
    atomic_path = fixture_root / "atomic.valid.yaml"
    caldera_path = fixture_root / "caldera.valid.yml"
    atomic = import_atomic_definition(atomic_path, ATOMIC_ID)
    caldera = import_caldera_ability(caldera_path, CALDERA_ID, "windows", "psh")
    policy = read_json_object(project_root / "specs" / "examples" / "range-adapter-policy.example.json")
    campaign_atomic, receipt_atomic = compile_range_import(atomic, policy, LEASE_ID, PROFILE_ID, 1)
    campaign_caldera, receipt_caldera = compile_range_import(caldera, policy, LEASE_ID, PROFILE_ID, 2)
    generated = (
        (atomic, "range-source-import.schema.json", "generated Atomic import"),
        (caldera, "range-source-import.schema.json", "generated Caldera import"),
        (campaign_atomic, "validation-campaign.schema.json", "generated Atomic campaign"),
        (campaign_caldera, "validation-campaign.schema.json", "generated Caldera campaign"),
        (receipt_atomic, "range-compilation-receipt.schema.json", "generated Atomic compilation receipt"),
        (receipt_caldera, "range-compilation-receipt.schema.json", "generated Caldera compilation receipt"),
    )
    for value, schema_name, label in generated:
        validate_contract(value, project_root / "specs" / schema_name, label)
    canonical_import = read_json_object(
        project_root / "specs" / "examples" / "range-source-import.example.json"
    )
    canonical_receipt = read_json_object(
        project_root / "specs" / "examples" / "range-compilation-receipt.example.json"
    )
    require_condition(atomic == canonical_import, "Generated Atomic import differs from its canonical example.")
    require_condition(
        receipt_atomic == canonical_receipt,
        "Generated Atomic compilation receipt differs from its canonical example.",
    )
    for value in (atomic, caldera, campaign_atomic, campaign_caldera, receipt_atomic, receipt_caldera):
        assert_no_execution_keys(value, "range_artifact")
    serialized = json.dumps(
        [campaign_atomic, campaign_caldera, receipt_atomic, receipt_caldera],
        sort_keys=True,
    )
    require_condition("fixture marker" not in serialized, "Raw fixture command text leaked into compiled artifacts.")
    require_condition(
        receipt_atomic.get("live_execution_performed") is False
        and receipt_caldera.get("source_tool_contacted") is False
        and receipt_caldera.get("target_discovery_performed") is False,
        "Compilation receipt does not preserve the no-execution boundary.",
    )
    negative_count = 0
    source_text = atomic_path.read_text(encoding="utf-8")
    with tempfile.TemporaryDirectory(prefix="nimrod-range-adapter-") as temporary:
        root = Path(temporary)
        tag_path = write_text(root, "tag.yaml", "value: !!python/object/apply:os.system ['whoami']\n")
        expect_error(
            RangeAdapterImportError,
            lambda: import_atomic_definition(tag_path, ATOMIC_ID),
            "unsafe YAML tag",
        )
        negative_count += 1
        alias_path = write_text(root, "alias.yaml", "value: &x fixture\ncopy: *x\n")
        expect_error(
            RangeAdapterImportError,
            lambda: import_atomic_definition(alias_path, ATOMIC_ID),
            "YAML alias",
        )
        negative_count += 1
        duplicate_path = write_text(root, "duplicate.yaml", "attack_technique: T1007\nattack_technique: T1082\n")
        expect_error(
            RangeAdapterImportError,
            lambda: import_atomic_definition(duplicate_path, ATOMIC_ID),
            "duplicate YAML key",
        )
        negative_count += 1
        oversized_path = write_text(root, "oversized.yaml", "x" * 65537)
        expect_error(
            RangeAdapterImportError,
            lambda: import_atomic_definition(oversized_path, ATOMIC_ID),
            "oversized YAML",
        )
        negative_count += 1
        expect_error(
            RangeAdapterImportError,
            lambda: import_atomic_definition(atomic_path, "00000000-0000-4000-8000-000000000000"),
            "unknown Atomic GUID",
        )
        negative_count += 1
        missing_cleanup = blocked_atomic(
            root,
            source_text,
            "missing-cleanup.yaml",
            ("      cleanup_command: Write-Output 'nimrod atomic fixture cleanup marker'\n", ""),
        )
        require_condition(
            "CLEANUP_MISSING" in cast(list[object], missing_cleanup.get("findings")),
            "Missing cleanup was not quarantined.",
        )
        expect_error(
            RangeAdapterCompilationError,
            lambda: compile_range_import(missing_cleanup, policy, LEASE_ID, PROFILE_ID, 1),
            "missing cleanup compilation",
        )
        negative_count += 1
        elevated = blocked_atomic(
            root,
            source_text,
            "elevated.yaml",
            ("elevation_required: false", "elevation_required: true"),
        )
        expect_error(
            RangeAdapterCompilationError,
            lambda: compile_range_import(elevated, policy, LEASE_ID, PROFILE_ID, 1),
            "elevated source",
        )
        negative_count += 1
        networked = blocked_atomic(
            root,
            source_text,
            "networked.yaml",
            ("Write-Output 'nimrod atomic fixture marker'", "Write-Output 'https://example.invalid/beacon'"),
        )
        expect_error(
            RangeAdapterCompilationError,
            lambda: compile_range_import(networked, policy, LEASE_ID, PROFILE_ID, 1),
            "network destination source",
        )
        negative_count += 1
        prohibited = blocked_atomic(
            root,
            source_text,
            "prohibited.yaml",
            ("Write-Output 'nimrod atomic fixture marker'", "Remove-Item C:\\fixture -Force"),
        )
        expect_error(
            RangeAdapterCompilationError,
            lambda: compile_range_import(prohibited, policy, LEASE_ID, PROFILE_ID, 1),
            "prohibited command semantics",
        )
        negative_count += 1
        variable = blocked_atomic(
            root,
            source_text,
            "variable.yaml",
            ("Write-Output 'nimrod atomic fixture marker'", "Write-Output '#{target.host}'"),
        )
        expect_error(
            RangeAdapterCompilationError,
            lambda: compile_range_import(variable, policy, LEASE_ID, PROFILE_ID, 1),
            "unresolved source variable",
        )
        negative_count += 1
        payload_text = caldera_path.read_text(encoding="utf-8").replace(
            "  platforms:\n",
            "  payloads:\n    - fixture.bin\n  platforms:\n",
        )
        payload_path = write_text(root, "payload.yml", payload_text)
        payload_import = import_caldera_ability(payload_path, CALDERA_ID, "windows", "psh")
        expect_error(
            RangeAdapterCompilationError,
            lambda: compile_range_import(payload_import, policy, LEASE_ID, PROFILE_ID, 1),
            "payload-bearing source",
        )
        negative_count += 1
        changed_source = blocked_atomic(
            root,
            source_text,
            "changed-source.yaml",
            ("fixture marker", "changed fixture marker"),
        )
        expect_error(
            RangeAdapterPolicyError,
            lambda: compile_range_import(changed_source, policy, LEASE_ID, PROFILE_ID, 1),
            "unpinned source digest",
        )
        negative_count += 1
    wrong_digest_policy = copy.deepcopy(policy)
    wrong_mappings = cast(list[JsonObject], wrong_digest_policy["source_mappings"])
    wrong_mappings[0]["source_artifact_digest"] = "sha256:" + "0" * 64
    expect_error(
        RangeAdapterPolicyError,
        lambda: compile_range_import(atomic, wrong_digest_policy, LEASE_ID, PROFILE_ID, 1),
        "policy source digest substitution",
    )
    negative_count += 1
    technique_substitution = copy.deepcopy(atomic)
    technique_substitution["technique_id"] = "T1082"
    expect_error(
        RangeAdapterPolicyError,
        lambda: compile_range_import(technique_substitution, policy, LEASE_ID, PROFILE_ID, 1),
        "technique substitution",
    )
    negative_count += 1
    platform_widening = copy.deepcopy(atomic)
    platform_widening["platforms"] = ["windows", "linux"]
    expect_error(
        RangeAdapterPolicyError,
        lambda: compile_range_import(platform_widening, policy, LEASE_ID, PROFILE_ID, 1),
        "platform widening",
    )
    negative_count += 1
    executor_widening = copy.deepcopy(atomic)
    executor_widening["executors"] = ["powershell", "cmd"]
    expect_error(
        RangeAdapterPolicyError,
        lambda: compile_range_import(executor_widening, policy, LEASE_ID, PROFILE_ID, 1),
        "executor widening",
    )
    negative_count += 1
    authority_policy = copy.deepcopy(policy)
    policy_authority = cast(JsonObject, authority_policy["authority"])
    policy_authority["can_connect"] = True
    expect_error(
        RangeAdapterPolicyError,
        lambda: compile_range_import(atomic, authority_policy, LEASE_ID, PROFILE_ID, 1),
        "policy connection authority",
    )
    negative_count += 1
    connector_widening = copy.deepcopy(policy)
    output = cast(JsonObject, connector_widening["output_template"])
    output["connector_id"] = "connector.caldera.live"
    expect_error(
        RangeAdapterPolicyError,
        lambda: compile_range_import(atomic, connector_widening, LEASE_ID, PROFILE_ID, 1),
        "connector widening",
    )
    negative_count += 1
    retained = copy.deepcopy(atomic)
    retained["raw_execution_material_retained"] = True
    expect_error(
        RangeAdapterCompilationError,
        lambda: compile_range_import(retained, policy, LEASE_ID, PROFILE_ID, 1),
        "raw execution retention",
    )
    negative_count += 1
    import_authority = copy.deepcopy(atomic)
    authority = cast(JsonObject, import_authority["authority"])
    authority["can_discover_targets"] = True
    expect_error(
        RangeAdapterCompilationError,
        lambda: compile_range_import(import_authority, policy, LEASE_ID, PROFILE_ID, 1),
        "import target-discovery authority",
    )
    negative_count += 1
    command_injection = copy.deepcopy(atomic)
    command_injection["command"] = "whoami"
    expect_error(
        ExecutionDirectiveError,
        lambda: compile_range_import(command_injection, policy, LEASE_ID, PROFILE_ID, 1),
        "normalized command injection",
    )
    negative_count += 1
    expect_error(
        RangeAdapterCompilationError,
        lambda: compile_range_import(atomic, policy, LEASE_ID, PROFILE_ID, 0),
        "non-positive sequence",
    )
    negative_count += 1
    expect_error(
        RangeAdapterCompilationError,
        lambda: compile_range_import(atomic, policy, "not-a-uuid", PROFILE_ID, 1),
        "invalid authorization lease ID",
    )
    negative_count += 1
    return {
        "status": "RANGE_ADAPTER_FIXTURE_COMPILATION_VALID",
        "origin": "simulated",
        "source_kind_count": 2,
        "normalized_import_count": 2,
        "compiled_campaign_count": 2,
        "compilation_receipt_count": 2,
        "adversarial_case_count": negative_count,
        "exact_source_digest_binding": True,
        "raw_execution_material_retained": False,
        "raw_execution_material_forwarded": False,
        "source_tool_contacted": False,
        "target_discovery_performed": False,
        "live_execution_performed": False,
        "offensive_tools_installed_or_launched": False,
        "maximum_capability": "range.test.simulate",
        "maximum_connector": "connector.simulated.atomic",
        "can_connect": False,
        "can_execute": False,
    }


def main() -> None:
    project_root = Path(__file__).resolve().parent.parent
    result = validate_range_adapter(project_root)
    report_path = project_root / "reports" / "RANGE_ADAPTER_VALIDATION.json"
    report_path.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n"
    )
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
