"""JSON-lines process boundary for the supervised read-only verifier service."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import cast

from nimrod_simulator.errors import SimulatorError, VerifierServiceError
from nimrod_simulator.jsonio import read_json_object, require_string, validate_contract
from nimrod_simulator.model import JsonObject, JsonValue
from nimrod_simulator.verifier_service import (
    build_health,
    handle_verify_request,
    require_clean_environment,
    validate_service_policy,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nimrod-verifier-service",
        description="Run the supervised read-only verifier JSON-lines service.",
    )
    parser.add_argument("--project-root", type=Path, required=True)
    parser.add_argument("--service-policy", type=Path, required=True)
    return parser


def parse_request(raw_line: str) -> JsonObject:
    try:
        parsed: JsonValue = cast(JsonValue, json.loads(raw_line))
    except json.JSONDecodeError as error:
        raise VerifierServiceError(f"Verifier request is invalid JSON: {error.msg}.") from error
    if not isinstance(parsed, dict):
        raise VerifierServiceError("Verifier request must be a JSON object.")
    return parsed


def emit(value: JsonObject) -> None:
    print(json.dumps(value, separators=(",", ":"), sort_keys=True), flush=True)


def main() -> None:
    arguments = build_parser().parse_args()
    try:
        policy = read_json_object(arguments.service_policy)
        validate_contract(
            policy,
            arguments.project_root / "specs" / "verifier-service-policy.schema.json",
            "verifier service policy",
        )
        validate_service_policy(policy)
        require_clean_environment(policy, os.environ)
    except SimulatorError as error:
        emit(
            {
                "response_version": "0.1.0",
                "status": "service_startup_failed",
                "error_type": type(error).__name__,
                "message": str(error),
            }
        )
        raise SystemExit(2) from error
    for raw_line in sys.stdin:
        if not raw_line.strip():
            continue
        try:
            request = parse_request(raw_line)
            request_type = require_string(request.get("request_type"), "request_type")
            request_id = require_string(request.get("request_id"), "request_id")
            if request_type == "health":
                response = build_health(policy, request_id, os.environ)
                validate_contract(
                    response,
                    arguments.project_root / "specs" / "verifier-health.schema.json",
                    "verifier health",
                )
            elif request_type == "verify":
                response = handle_verify_request(arguments.project_root, policy, request, os.environ)
                validate_contract(
                    response,
                    arguments.project_root / "specs" / "verifier-observation.schema.json",
                    "verifier observation",
                )
            elif request_type == "shutdown":
                response = {
                    "response_version": "0.1.0",
                    "request_id": request_id,
                    "service_id": policy["service_id"],
                    "process_id": os.getpid(),
                    "status": "shutdown_complete",
                }
                emit(response)
                return
            else:
                raise VerifierServiceError(f"Unsupported verifier request_type '{request_type}'.")
            emit(response)
        except SimulatorError as error:
            emit(
                {
                    "response_version": "0.1.0",
                    "status": "request_failed",
                    "error_type": type(error).__name__,
                    "message": str(error),
                }
            )
    raise VerifierServiceError("Verifier service input closed without an explicit shutdown request.")


if __name__ == "__main__":
    main()
