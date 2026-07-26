"""Validate the runnable unprivileged Edge replay-to-proof slice."""

from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import TypeVar, cast

from nimrod_edge.runtime import RESULT_STATUS, run_edge_preview
from nimrod_edge.verifier import verify_edge_proposal
from nimrod_simulator.errors import (
    ContractValidationError,
    EdgeVerificationError,
    WitnessIntegrityError,
)
from nimrod_simulator.jsonio import read_json_object, sha256_digest, validate_contract
from nimrod_simulator.model import JsonObject
from nimrod_simulator.witness import verify_witness_store


TError = TypeVar("TError", bound=Exception)
PROJECT_ROOT = Path(__file__).resolve().parents[1]
EVALUATED_AT = datetime(2026, 7, 15, 16, 1, 0, tzinfo=timezone.utc)


def expect_error(error_type: type[TError], operation: Callable[[], object], label: str) -> None:
    try:
        operation()
    except error_type:
        return
    except Exception as error:
        raise AssertionError(
            f"{label} raised {type(error).__name__}; expected {error_type.__name__}: {error}"
        ) from error
    raise AssertionError(f"Expected {error_type.__name__} for {label}.")


def artifact_for_reference(output_root: Path, reference: JsonObject) -> JsonObject:
    digest = str(reference["digest"]).removeprefix("sha256:")
    return read_json_object(output_root / "artifacts" / "sha256" / f"{digest}.json")


def normalized_example(result: JsonObject) -> JsonObject:
    normalized = copy.deepcopy(result)
    verification = cast(JsonObject, normalized["independent_verification"])
    verification["verifier_process_id"] = 4242
    references = cast(JsonObject, normalized["references"])
    verification_reference = cast(JsonObject, references["verification"])
    verification_reference["digest"] = sha256_digest(verification)
    witness = cast(JsonObject, normalized["witness"])
    witness["journal"] = "validation://edge-preview/witness.jsonl"
    return normalized


def validate_edge_preview(project_root: Path) -> JsonObject:
    scenario_path = project_root / "specs" / "examples" / "edge-preview-scenario.example.json"
    result_example_path = project_root / "specs" / "examples" / "edge-preview-result.example.json"
    scenario = read_json_object(scenario_path)
    expected_result = read_json_object(result_example_path)
    ui_html = (project_root / "ui" / "index.html").read_text(encoding="utf-8")
    ui_javascript = (project_root / "ui" / "app.js").read_text(encoding="utf-8")
    for required_token in ("data-view=\"edge\"", "id=\"edge-summary\"", "id=\"edge-references\""):
        if required_token not in ui_html:
            raise AssertionError(f"Edge control board is missing required HTML token: {required_token}")
    for required_token in ("edgeStateUrl", "renderEdgePreview", "renderEdgeAuthorityDeck"):
        if required_token not in ui_javascript:
            raise AssertionError(f"Edge control board is missing required JavaScript token: {required_token}")
    negative_count = 0

    with TemporaryDirectory(prefix="nimrod-edge-preview-") as temporary:
        temporary_root = Path(temporary)
        api_output = temporary_root / "api"
        result = cast(JsonObject, run_edge_preview(project_root, scenario, api_output, EVALUATED_AT))
        if result.get("status") != RESULT_STATUS:
            raise AssertionError("Edge preview did not preserve its explicit replay-only status.")
        if result.get("authority") != {
            "can_authorize": False,
            "can_execute": False,
            "target_state_changed": False,
            "recovery_verified": False,
        }:
            raise AssertionError("Edge preview result widened authority or outcome claims.")
        if verify_witness_store(api_output) != 4:
            raise AssertionError("Edge preview Witness did not retain exactly four verified entries.")
        verification = cast(JsonObject, result["independent_verification"])
        if verification.get("verifier_process_id") == os.getpid():
            raise AssertionError("Edge preview verification did not execute in a distinct process.")
        if verification.get("verified_outcome") is not False:
            raise AssertionError("Structural verification incorrectly claimed a verified endpoint outcome.")

        references = cast(JsonObject, result["references"])
        action = artifact_for_reference(api_output, cast(JsonObject, references["action_proposal"]))
        serialized_action = json.dumps(action, sort_keys=True)
        for prohibited_field in ('"command"', '"shell"', '"payload"', '"script"'):
            if prohibited_field in serialized_action:
                raise AssertionError(f"Edge action proposal exposes prohibited field {prohibited_field}.")

        normalized = normalized_example(result)
        if normalized != expected_result:
            raise AssertionError("Canonical Edge preview result drifted from deterministic regeneration.")

        cli_output = temporary_root / "cli"
        cli = subprocess.run(
            [
                sys.executable,
                "-m",
                "nimrod_edge.cli",
                "--project-root",
                str(project_root),
                "--scenario",
                str(scenario_path),
                "--output",
                str(cli_output),
                "--now",
                "2026-07-15T16:01:00Z",
            ],
            cwd=project_root,
            capture_output=True,
            text=True,
            check=False,
        )
        if cli.returncode != 0:
            raise AssertionError(f"Edge preview CLI failed: stdout={cli.stdout!r}; stderr={cli.stderr!r}")
        cli_result: object = json.loads(cli.stdout)
        if not isinstance(cli_result, dict) or cli_result.get("status") != RESULT_STATUS:
            raise AssertionError("Edge preview CLI did not return the expected result.")

        live_origin = copy.deepcopy(scenario)
        live_origin["origin"] = "live"
        expect_error(
            ContractValidationError,
            lambda: run_edge_preview(project_root, live_origin, temporary_root / "live", EVALUATED_AT),
            "live origin laundering",
        )
        negative_count += 1

        widened_budget = copy.deepcopy(scenario)
        cast(JsonObject, widened_budget["policy"])["autonomy_budget"] = 2
        expect_error(
            ContractValidationError,
            lambda: run_edge_preview(project_root, widened_budget, temporary_root / "budget", EVALUATED_AT),
            "autonomy budget widening",
        )
        negative_count += 1

        execution_authority = copy.deepcopy(scenario)
        cast(JsonObject, execution_authority["authority"])["can_execute"] = True
        expect_error(
            ContractValidationError,
            lambda: run_edge_preview(project_root, execution_authority, temporary_root / "authority", EVALUATED_AT),
            "execution authority widening",
        )
        negative_count += 1

        hostile_content = copy.deepcopy(scenario)
        cast(JsonObject, hostile_content["observation"])["command"] = "powershell"
        expect_error(
            ContractValidationError,
            lambda: run_edge_preview(project_root, hostile_content, temporary_root / "hostile", EVALUATED_AT),
            "hostile observation field",
        )
        negative_count += 1

        tampered_action = copy.deepcopy(action)
        cast(JsonObject, tampered_action["authorization"])["policy_decision"] = "allow"
        expect_error(
            EdgeVerificationError,
            lambda: verify_edge_proposal(project_root, scenario, tampered_action, EVALUATED_AT),
            "allow decision substitution",
        )
        negative_count += 1

        directive_action = copy.deepcopy(action)
        cast(JsonObject, directive_action["execution_contract"])["command"] = "whoami"
        expect_error(
            ContractValidationError,
            lambda: verify_edge_proposal(project_root, scenario, directive_action, EVALUATED_AT),
            "execution directive insertion",
        )
        negative_count += 1

        expect_error(
            WitnessIntegrityError,
            lambda: run_edge_preview(project_root, scenario, api_output, EVALUATED_AT),
            "Witness output reuse",
        )
        negative_count += 1

        verification_reference = cast(JsonObject, references["verification"])
        if verification_reference.get("digest") != sha256_digest(verification):
            raise AssertionError("Edge verification reference does not bind the independent verifier result.")

        validate_contract(
            expected_result,
            project_root / "specs" / "edge-preview-result.schema.json",
            "canonical Edge preview result",
        )

    return {
        "status": "EDGE_PREVIEW_REPLAY_VERTICAL_SLICE_VALID",
        "origin": "replayed",
        "positive_api_flow_count": 1,
        "positive_cli_flow_count": 1,
        "independent_verifier_process_count": 1,
        "witness_entry_count": 4,
        "negative_fail_closed_case_count": negative_count,
        "autonomy_budget": 1,
        "execution_authorized": False,
        "execution_performed": False,
        "target_state_changed": False,
        "post_state_observed": False,
        "recovery_verified": False,
        "live_endpoint_observation_performed": False,
    }


def main() -> None:
    result = validate_edge_preview(PROJECT_ROOT)
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
