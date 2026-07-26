"""Quarantined Atomic/Caldera import and exact-digest no-execution compilation."""

from __future__ import annotations

import hashlib
import re
import uuid
from pathlib import Path

import yaml
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode
from yaml.tokens import AliasToken, AnchorToken, TagToken

from nimrod_simulator.compiler import reject_execution_directives
from nimrod_simulator.errors import (
    RangeAdapterCompilationError,
    RangeAdapterImportError,
    RangeAdapterPolicyError,
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
from nimrod_simulator.model import JsonObject, JsonValue


MAXIMUM_SOURCE_BYTES = 65536
MAXIMUM_COMMAND_CHARACTERS = 4096
NO_EXECUTION_CONNECTOR_ID = "connector.simulated.atomic"
NO_EXECUTION_CAPABILITY = "range.test.simulate"
VARIABLE_PATTERN = re.compile(r"#\{([A-Za-z0-9_.-]+)\}")
URL_PATTERN = re.compile(r"\b(?:https?|ftp)://", re.IGNORECASE)
FORBIDDEN_COMMAND_FRAGMENTS = (
    "add-mppreference",
    "bcdedit",
    "certutil",
    "chmod ",
    "chown ",
    "curl ",
    "del ",
    "diskpart",
    "downloadfile",
    "format ",
    "invoke-expression",
    "invoke-webrequest",
    "net user",
    "reg add",
    "remove-item",
    "rm ",
    "sc create",
    "schtasks",
    "shutdown",
    "sudo ",
    "vssadmin",
    "wevtutil cl",
    "wget ",
)


def raw_sha256_digest(payload: bytes) -> str:
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def _json_value(value: object, path: str) -> JsonValue:
    if value is None or isinstance(value, str | int | float | bool):
        return value
    if isinstance(value, list):
        return [_json_value(item, f"{path}[{index}]") for index, item in enumerate(value)]
    if isinstance(value, dict):
        result: JsonObject = {}
        for key, child in value.items():
            if not isinstance(key, str) or not key:
                raise RangeAdapterImportError(f"YAML mapping key at '{path}' must be a non-empty string.")
            result[key] = _json_value(child, f"{path}.{key}")
        return result
    raise RangeAdapterImportError(
        f"YAML value at '{path}' has unsupported type '{type(value).__name__}'."
    )


def _reject_duplicate_keys(node: Node | None, path: str) -> None:
    if node is None:
        return
    if isinstance(node, MappingNode):
        keys: set[str] = set()
        for key_node, value_node in node.value:
            if not isinstance(key_node, ScalarNode) or not isinstance(key_node.value, str) or not key_node.value:
                raise RangeAdapterImportError(f"YAML mapping key at '{path}' must be a non-empty scalar string.")
            if key_node.value in keys:
                raise RangeAdapterImportError(f"YAML mapping at '{path}' repeats key '{key_node.value}'.")
            keys.add(key_node.value)
            _reject_duplicate_keys(value_node, f"{path}.{key_node.value}")
        return
    if isinstance(node, SequenceNode):
        for index, child in enumerate(node.value):
            _reject_duplicate_keys(child, f"{path}[{index}]")


def read_quarantined_yaml(path: Path) -> tuple[JsonValue, str]:
    try:
        payload = path.read_bytes()
    except OSError as error:
        raise RangeAdapterImportError(f"Unable to read range definition '{path}': {error}.") from error
    if not payload or len(payload) > MAXIMUM_SOURCE_BYTES:
        raise RangeAdapterImportError(
            f"Range definition '{path}' must contain 1..{MAXIMUM_SOURCE_BYTES} bytes; received {len(payload)}."
        )
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise RangeAdapterImportError(f"Range definition '{path}' is not UTF-8: {error}.") from error
    try:
        for token in yaml.scan(text):
            if isinstance(token, AliasToken | AnchorToken | TagToken):
                raise RangeAdapterImportError(
                    f"Range definition '{path}' contains prohibited YAML alias, anchor, or tag syntax."
                )
        _reject_duplicate_keys(yaml.compose(text, Loader=yaml.SafeLoader), path.name)
        parsed: object = yaml.safe_load(text)
    except yaml.YAMLError as error:
        raise RangeAdapterImportError(f"Range definition '{path}' is invalid safe YAML: {error}.") from error
    return _json_value(parsed, path.name), raw_sha256_digest(payload)


def _command_findings(
    command: str,
    cleanup: str,
    elevation_required: bool,
    dynamic_reference_count: int,
    variable_names: list[str],
) -> list[str]:
    findings: list[str] = []
    combined = f"{command}\n{cleanup}".casefold()
    if len(command) > MAXIMUM_COMMAND_CHARACTERS or len(cleanup) > MAXIMUM_COMMAND_CHARACTERS:
        findings.append("COMMAND_SIZE_EXCEEDED")
    if elevation_required:
        findings.append("ELEVATION_REQUIRED")
    if dynamic_reference_count > 0:
        findings.append("DYNAMIC_INPUT_OR_PAYLOAD_PRESENT")
    if variable_names:
        findings.append("UNRESOLVED_VARIABLE_PRESENT")
    if not cleanup.strip():
        findings.append("CLEANUP_MISSING")
    if URL_PATTERN.search(combined) is not None:
        findings.append("NETWORK_DESTINATION_PRESENT")
    if any(fragment in combined for fragment in FORBIDDEN_COMMAND_FRAGMENTS):
        findings.append("PROHIBITED_COMMAND_SEMANTICS")
    return sorted(set(findings))


def _import_receipt(
    source_kind: str,
    source_artifact_digest: str,
    source_object_id: str,
    technique_id: str,
    name: str,
    platforms: list[str],
    executors: list[str],
    command: str,
    cleanup: str,
    elevation_required: bool,
    dynamic_reference_count: int,
) -> JsonObject:
    variable_names = sorted(set(VARIABLE_PATTERN.findall(f"{command}\n{cleanup}")))
    findings = _command_findings(
        command,
        cleanup,
        elevation_required,
        dynamic_reference_count,
        variable_names,
    )
    import_id = str(
        uuid.uuid5(
            uuid.UUID("8cc109a7-5b58-48c9-a55f-fba695aacaef"),
            f"{source_kind}:{source_artifact_digest}:{source_object_id}",
        )
    )
    return {
        "import_version": "0.1.0",
        "import_id": import_id,
        "origin": "simulated",
        "source_kind": source_kind,
        "source_artifact_digest": source_artifact_digest,
        "source_object_id": source_object_id,
        "technique_id": technique_id,
        "name": name,
        "platforms": sorted(platforms),
        "executors": sorted(executors),
        "raw_execution_fields_present": True,
        "raw_execution_material_retained": False,
        "command_digest": raw_sha256_digest(command.encode("utf-8")),
        "cleanup_digest": raw_sha256_digest(cleanup.encode("utf-8")),
        "elevation_required": elevation_required,
        "dynamic_input_or_payload_reference_count": dynamic_reference_count,
        "variable_names": variable_names,
        "findings": findings,
        "quarantine_status": "eligible_for_no_execution_mapping" if not findings else "blocked",
        "authority": {
            "can_connect": False,
            "can_execute": False,
            "can_discover_targets": False,
        },
    }


def import_atomic_definition(path: Path, test_guid: str) -> JsonObject:
    parsed, source_digest = read_quarantined_yaml(path)
    root = require_object(parsed, "atomic")
    technique_id = require_string(root.get("attack_technique"), "atomic.attack_technique")
    tests = require_list(root.get("atomic_tests"), "atomic.atomic_tests")
    matches: list[JsonObject] = []
    for index, value in enumerate(tests):
        test = require_object(value, f"atomic.atomic_tests[{index}]")
        if test.get("auto_generated_guid") == test_guid:
            matches.append(test)
    if len(matches) != 1:
        raise RangeAdapterImportError(
            f"Atomic source must contain exactly one test GUID '{test_guid}'; received {len(matches)}."
        )
    test = matches[0]
    executor = require_object(test.get("executor"), "atomic.executor")
    command = require_string(executor.get("command"), "atomic.executor.command")
    cleanup_value = executor.get("cleanup_command")
    cleanup = cleanup_value if isinstance(cleanup_value, str) else ""
    input_arguments = test.get("input_arguments")
    variable_count = len(input_arguments) if isinstance(input_arguments, dict) else 0
    payloads = test.get("dependency_executor_name")
    payload_count = variable_count + (1 if payloads is not None else 0)
    return _import_receipt(
        "atomic_red_team",
        source_digest,
        test_guid,
        technique_id,
        require_string(test.get("name"), "atomic.name"),
        require_string_list(test.get("supported_platforms"), "atomic.supported_platforms"),
        [require_string(executor.get("name"), "atomic.executor.name")],
        command,
        cleanup,
        require_boolean(executor.get("elevation_required"), "atomic.executor.elevation_required"),
        payload_count,
    )


def import_caldera_ability(path: Path, ability_id: str, platform: str, executor_name: str) -> JsonObject:
    parsed, source_digest = read_quarantined_yaml(path)
    abilities = require_list(parsed, "caldera")
    matches: list[JsonObject] = []
    for index, value in enumerate(abilities):
        ability = require_object(value, f"caldera[{index}]")
        if ability.get("id") == ability_id:
            matches.append(ability)
    if len(matches) != 1:
        raise RangeAdapterImportError(
            f"Caldera source must contain exactly one ability ID '{ability_id}'; received {len(matches)}."
        )
    ability = matches[0]
    platforms = require_object(ability.get("platforms"), "caldera.platforms")
    platform_value = require_object(platforms.get(platform), f"caldera.platforms.{platform}")
    executor = require_object(platform_value.get(executor_name), f"caldera.platforms.{platform}.{executor_name}")
    technique = require_object(ability.get("technique"), "caldera.technique")
    command = require_string(executor.get("command"), "caldera.executor.command")
    cleanup_value = executor.get("cleanup")
    cleanup = cleanup_value if isinstance(cleanup_value, str) else ""
    payload_values = ability.get("payloads")
    payload_count = len(payload_values) if isinstance(payload_values, list) else 0
    return _import_receipt(
        "caldera_ability",
        source_digest,
        ability_id,
        require_string(technique.get("attack_id"), "caldera.technique.attack_id"),
        require_string(ability.get("name"), "caldera.name"),
        [platform],
        [executor_name],
        command,
        cleanup,
        False,
        payload_count,
    )


def require_exact_source_mapping(import_receipt: JsonObject, policy: JsonObject) -> JsonObject:
    if require_string(policy.get("policy_version"), "policy.policy_version") != "0.1.0":
        raise RangeAdapterPolicyError("Range-adapter policy_version must be '0.1.0'.")
    if policy.get("origin") != "simulated" or policy.get("stage") != "no_execution_fixture_only":
        raise RangeAdapterPolicyError("Range-adapter policy must remain simulated and fixture-only.")
    authority = require_object(policy.get("authority"), "policy.authority")
    for field in ("can_connect", "can_execute", "can_discover_targets"):
        if require_boolean(authority.get(field), f"policy.authority.{field}"):
            raise RangeAdapterPolicyError(f"Range-adapter policy cannot grant '{field}'.")
    mappings = require_list(policy.get("source_mappings"), "policy.source_mappings")
    matches: list[JsonObject] = []
    for index, value in enumerate(mappings):
        mapping = require_object(value, f"policy.source_mappings[{index}]")
        if (
            mapping.get("source_kind") == import_receipt.get("source_kind")
            and mapping.get("source_object_id") == import_receipt.get("source_object_id")
            and mapping.get("source_artifact_digest") == import_receipt.get("source_artifact_digest")
        ):
            matches.append(mapping)
    if len(matches) != 1:
        raise RangeAdapterPolicyError(
            f"Range-adapter policy must bind exactly one source mapping; received {len(matches)}."
        )
    return matches[0]


def compile_range_import(
    import_receipt: JsonObject,
    policy: JsonObject,
    authorization_lease_id: str,
    protection_profile_id: str,
    sequence: int,
) -> tuple[JsonObject, JsonObject]:
    try:
        uuid.UUID(authorization_lease_id)
    except ValueError as error:
        raise RangeAdapterCompilationError(
            f"Authorization lease ID '{authorization_lease_id}' is not a UUID."
        ) from error
    if not protection_profile_id:
        raise RangeAdapterCompilationError("Protection profile ID cannot be empty.")
    if sequence < 1:
        raise RangeAdapterCompilationError(f"Range compilation sequence must be positive; received {sequence}.")
    if import_receipt.get("quarantine_status") != "eligible_for_no_execution_mapping":
        raise RangeAdapterCompilationError("Blocked range import cannot compile.")
    if require_list(import_receipt.get("findings"), "import.findings"):
        raise RangeAdapterCompilationError("Range import with safety findings cannot compile.")
    if import_receipt.get("raw_execution_material_retained") is not False:
        raise RangeAdapterCompilationError("Range import retained raw execution material.")
    import_authority = require_object(import_receipt.get("authority"), "import.authority")
    if any(
        require_boolean(import_authority.get(field), f"import.authority.{field}")
        for field in ("can_connect", "can_execute", "can_discover_targets")
    ):
        raise RangeAdapterCompilationError("Range import exposes connection, execution, or discovery authority.")
    reject_execution_directives(import_receipt, "range_import")
    mapping = require_exact_source_mapping(import_receipt, policy)
    technique_id = require_string(import_receipt.get("technique_id"), "import.technique_id")
    if mapping.get("technique_id") != technique_id:
        raise RangeAdapterPolicyError("Range-adapter mapping technique does not match the imported source.")
    platforms = set(require_string_list(import_receipt.get("platforms"), "import.platforms"))
    allowed_platforms = set(require_string_list(mapping.get("allowed_platforms"), "mapping.allowed_platforms"))
    executors = set(require_string_list(import_receipt.get("executors"), "import.executors"))
    allowed_executors = set(require_string_list(mapping.get("allowed_executors"), "mapping.allowed_executors"))
    if not platforms or not platforms.issubset(allowed_platforms):
        raise RangeAdapterPolicyError("Imported platforms exceed the exact source mapping.")
    if not executors or not executors.issubset(allowed_executors):
        raise RangeAdapterPolicyError("Imported executors exceed the exact source mapping.")
    output = require_object(policy.get("output_template"), "policy.output_template")
    connector_id = require_string(output.get("connector_id"), "output.connector_id")
    capability = require_string(output.get("capability"), "output.capability")
    if connector_id != NO_EXECUTION_CONNECTOR_ID or capability != NO_EXECUTION_CAPABILITY:
        raise RangeAdapterPolicyError("Range-adapter output must use the fixed no-execution connector and capability.")
    source_digest = require_string(import_receipt.get("source_artifact_digest"), "import.source_artifact_digest")
    policy_digest = sha256_digest(policy)
    campaign_id = str(
        uuid.uuid5(
            uuid.UUID("56e9124a-e10c-4b68-ac48-29008f46bb5f"),
            f"{source_digest}:{policy_digest}:{sequence}",
        )
    )
    source_object_id = require_string(import_receipt.get("source_object_id"), "import.source_object_id")
    step_id = f"step:imported-{source_object_id}"
    target_id = require_string(output.get("target_id"), "output.target_id")
    cleanup_step_id = require_string(output.get("cleanup_step_id"), "output.cleanup_step_id")
    campaign: JsonObject = {
        "campaign_version": "0.1.0",
        "campaign_id": campaign_id,
        "authorization_lease_id": authorization_lease_id,
        "objective": "Compile one pinned external definition into a simulated typed step without execution",
        "protection_profile_ids": [protection_profile_id],
        "standards_mappings": {"attack": [technique_id], "atlas": [], "d3fend": ["simulation-only"]},
        "steps": [
            {
                "step_id": step_id,
                "sequence": sequence,
                "connector_id": connector_id,
                "capability": capability,
                "target_id": target_id,
                "effect_class": "reversible_local",
                "preconditions": [
                    "The exact source artifact digest matches the fixture-only policy",
                    "No raw execution material is retained or forwarded",
                    "The fixed mapped target must separately match the authorization lease",
                ],
                "expected_state_delta": {
                    "simulation_state": "compiled_no_execution",
                    "source_artifact_digest": source_digest,
                },
                "cleanup_step_id": cleanup_step_id,
                "verification_oracles": [
                    {"id": "verifier:range-import-no-execution", "digest": source_digest}
                ],
            }
        ],
        "negative_controls": [
            "A changed source digest, command-bearing normalized field, or different target must fail compilation"
        ],
        "expected_evidence": [
            {
                "step_id": step_id,
                "source_id": "sensor:simulated-range-import",
                "ocsf_class": "simulation_event",
                "maximum_latency_seconds": 0,
                "required_fields": ["campaign_id", "step_id", "source_artifact_digest", "origin"],
            }
        ],
        "cleanup_plan": ["No target state was created; verify no-op connector and Witness receipts"],
        "success_contract": ["The typed campaign validates and contains no executable source material"],
        "failure_contract": ["Any ambiguity, substitution, authority, or raw command field remains blocked"],
    }
    reject_execution_directives(campaign, "compiled_campaign")
    compilation_receipt: JsonObject = {
        "compilation_version": "0.1.0",
        "origin": "simulated",
        "status": "compiled_no_execution",
        "source_kind": import_receipt["source_kind"],
        "source_object_id": source_object_id,
        "source_artifact_digest": source_digest,
        "import_receipt_digest": sha256_digest(import_receipt),
        "mapping_policy_digest": policy_digest,
        "campaign_id": campaign_id,
        "campaign_digest": sha256_digest(campaign),
        "connector_id": connector_id,
        "capability": capability,
        "raw_execution_material_forwarded": False,
        "source_tool_contacted": False,
        "target_discovery_performed": False,
        "live_execution_performed": False,
        "authority": {
            "can_connect": False,
            "can_execute": False,
            "can_discover_targets": False,
        },
    }
    return campaign, compilation_receipt
