"""Read-only supervised verifier service and fail-closed observation reconciliation."""

from __future__ import annotations

import getpass
import hashlib
import os
import uuid
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path

from nimrod_simulator.authorization import parse_timestamp
from nimrod_simulator.errors import (
    SimulatorError,
    VerifierCredentialExposureError,
    VerifierDisagreementError,
    VerifierReadOnlyViolationError,
    VerifierServiceError,
)
from nimrod_simulator.jsonio import read_json_object, require_boolean, require_integer, require_list, require_string, sha256_digest, validate_contract
from nimrod_simulator.model import JsonObject
from nimrod_simulator.witness_checkpoint import verify_external_anchor_store


ALLOWED_CAPABILITIES = ["health.report", "witness.verify", "anchor.verify"]
PROHIBITED_CAPABILITIES = ["plan", "authorize", "execute", "sign", "write_evidence", "read_credentials"]
OBSERVATION_NAMESPACE = uuid.UUID("cccccccc-dddd-4eee-8fff-000000000001")
CONSENSUS_NAMESPACE = uuid.UUID("cccccccc-dddd-4eee-8fff-000000000002")


def validate_service_policy(policy: JsonObject) -> None:
    if require_string(policy.get("policy_version"), "policy_version") != "0.1.0":
        raise VerifierServiceError("Verifier service policy_version must be '0.1.0'.")
    if require_list(policy.get("allowed_capabilities"), "allowed_capabilities") != ALLOWED_CAPABILITIES:
        raise VerifierServiceError("Verifier service capabilities cannot include planning, authorization, or execution.")
    if require_list(policy.get("prohibited_capabilities"), "prohibited_capabilities") != PROHIBITED_CAPABILITIES:
        raise VerifierServiceError("Verifier service prohibited-capability list is incomplete or reordered.")
    if not require_boolean(policy.get("process_boundary_required"), "process_boundary_required"):
        raise VerifierServiceError("Verifier service requires a separate process boundary.")
    if not require_boolean(policy.get("read_only_inputs_required"), "read_only_inputs_required"):
        raise VerifierServiceError("Verifier service inputs must be read only.")
    if not require_boolean(
        policy.get("production_distinct_os_account_required"), "production_distinct_os_account_required"
    ):
        raise VerifierServiceError("Production verifier service requires a distinct OS account.")
    timeout_ms = require_integer(policy.get("request_timeout_ms"), "request_timeout_ms")
    if timeout_ms < 100 or timeout_ms > 60000:
        raise VerifierServiceError(f"Verifier request timeout {timeout_ms}ms is outside 100..60000ms.")
    origin = require_string(policy.get("origin"), "origin")
    boundary_status = require_string(policy.get("os_account_boundary_status"), "os_account_boundary_status")
    expected_account = policy.get("expected_os_account_identifier")
    if origin == "live" and (not isinstance(expected_account, str) or boundary_status != "verified"):
        raise VerifierServiceError("Live verifier policy requires a verified expected OS account identifier.")


def environment_findings(policy: JsonObject, environment: Mapping[str, str]) -> tuple[list[str], list[str]]:
    allowlist = {
        require_string(value, f"environment_allowlist[{index}]")
        for index, value in enumerate(require_list(policy.get("environment_allowlist"), "environment_allowlist"))
    }
    denied_prefixes = [
        require_string(value, f"denied_environment_prefixes[{index}]")
        for index, value in enumerate(
            require_list(policy.get("denied_environment_prefixes"), "denied_environment_prefixes")
        )
    ]
    environment_keys = set(environment.keys())
    unexpected = sorted(environment_keys - allowlist)
    credential_like = sorted(
        key
        for key in environment_keys
        if any(key.upper().startswith(prefix.upper()) for prefix in denied_prefixes)
    )
    return unexpected, credential_like


def require_clean_environment(policy: JsonObject, environment: Mapping[str, str]) -> None:
    unexpected, credential_like = environment_findings(policy, environment)
    if credential_like:
        raise VerifierCredentialExposureError(
            f"Verifier environment contains denied credential-like variables: {', '.join(credential_like)}."
        )
    if unexpected:
        raise VerifierCredentialExposureError(
            f"Verifier environment contains non-allowlisted variables: {', '.join(unexpected)}."
        )


def os_account_identifier() -> str:
    account = getpass.getuser()
    if not account:
        raise VerifierServiceError("Verifier cannot determine its OS account identifier.")
    domain = os.environ.get("USERDOMAIN")
    if domain:
        return f"{domain}\\{account}"
    return account


def os_account_boundary_verified(policy: JsonObject, actual_account: str) -> bool:
    expected = policy.get("expected_os_account_identifier")
    status = policy.get("os_account_boundary_status")
    return isinstance(expected, str) and expected.casefold() == actual_account.casefold() and status == "verified"


def build_health(policy: JsonObject, request_id: str, environment: Mapping[str, str]) -> JsonObject:
    require_clean_environment(policy, environment)
    actual_account = os_account_identifier()
    account_verified = os_account_boundary_verified(policy, actual_account)
    expected = policy.get("expected_os_account_identifier")
    status = "healthy_reference_boundary"
    if isinstance(expected, str) and not account_verified:
        status = "blocked_identity_mismatch"
    return {
        "health_version": "0.1.0",
        "request_id": request_id,
        "origin": policy["origin"],
        "service_id": policy["service_id"],
        "logical_principal": policy["logical_principal"],
        "process_id": os.getpid(),
        "os_account_identifier": actual_account,
        "status": status,
        "read_only_inputs_required": True,
        "filesystem_write_capability_exposed": False,
        "credential_environment_variable_count": 0,
        "unexpected_environment_variable_count": 0,
        "os_account_boundary_verified": account_verified,
        "production_ready": account_verified and status == "healthy_reference_boundary",
        "allowed_capabilities": ALLOWED_CAPABILITIES,
        "prohibited_capabilities": PROHIBITED_CAPABILITIES,
    }


def raw_file_digest(path: Path) -> str:
    try:
        payload = path.read_bytes()
    except OSError as error:
        raise VerifierServiceError(f"Verifier cannot read required input '{path}': {error}.") from error
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def read_only_snapshot(paths: list[Path]) -> str:
    snapshot: JsonObject = {}
    for root_index, root in enumerate(paths):
        resolved = root.resolve()
        label = f"input-{root_index}:{resolved}"
        if resolved.is_file():
            snapshot[label] = raw_file_digest(resolved)
            continue
        if not resolved.is_dir():
            raise VerifierServiceError(f"Verifier input path is missing: '{resolved}'.")
        files = sorted(path for path in resolved.rglob("*") if path.is_file())
        if not files:
            raise VerifierServiceError(f"Verifier input directory contains no files: '{resolved}'.")
        for path in files:
            relative = path.relative_to(resolved).as_posix()
            snapshot[f"{label}/{relative}"] = raw_file_digest(path)
    return sha256_digest(snapshot)


def observation_id(service_id: str, request_id: str, status: str, subject_digest: str | None) -> str:
    material = f"{service_id}:{request_id}:{status}:{subject_digest or 'none'}"
    return str(uuid.uuid5(OBSERVATION_NAMESPACE, material))


def build_observation(
    policy: JsonObject,
    request_id: str,
    observed_at: str,
    status: str,
    subject_digest: str | None,
    error_type: str | None,
    message: str | None,
    read_only_verified: bool,
    process_id: int | None,
    actual_account: str | None,
) -> JsonObject:
    account_verified = False
    if actual_account is not None:
        account_verified = os_account_boundary_verified(policy, actual_account)
    return {
        "observation_version": "0.1.0",
        "observation_id": observation_id(
            require_string(policy.get("service_id"), "service_id"), request_id, status, subject_digest
        ),
        "origin": policy["origin"],
        "service_id": policy["service_id"],
        "logical_principal": policy["logical_principal"],
        "process_id": process_id,
        "os_account_identifier": actual_account,
        "observed_at": observed_at,
        "status": status,
        "subject_digest": subject_digest,
        "read_only_behavior_verified": read_only_verified,
        "os_account_boundary_verified": account_verified,
        "credential_environment_variable_count": 0,
        "details": {"error_type": error_type, "message": message},
    }


def verify_request_paths(request: JsonObject) -> list[Path]:
    return [
        Path(require_string(request.get("witness_root"), "request.witness_root")),
        Path(require_string(request.get("anchor_root"), "request.anchor_root")),
        Path(require_string(request.get("governance_state"), "request.governance_state")),
        Path(require_string(request.get("anchor_policy"), "request.anchor_policy")),
        Path(require_string(request.get("pinned_head"), "request.pinned_head")),
    ]


def handle_verify_request(
    project_root: Path,
    policy: JsonObject,
    request: JsonObject,
    environment: Mapping[str, str],
) -> JsonObject:
    require_clean_environment(policy, environment)
    request_id = require_string(request.get("request_id"), "request.request_id")
    observed_at = require_string(request.get("now"), "request.now")
    expected_origin = require_string(request.get("expected_origin"), "request.expected_origin")
    paths = verify_request_paths(request)
    before_digest = read_only_snapshot(paths)
    actual_account = os_account_identifier()
    status = "valid"
    error_type: str | None = None
    message: str | None = None
    try:
        if isinstance(policy.get("expected_os_account_identifier"), str) and not os_account_boundary_verified(
            policy, actual_account
        ):
            raise VerifierServiceError(
                f"Verifier OS account '{actual_account}' does not match the required account identifier."
            )
        governance_state = read_json_object(paths[2])
        anchor_policy = read_json_object(paths[3])
        pinned_head = read_json_object(paths[4])
        specs = project_root / "specs"
        validate_contract(governance_state, specs / "key-governance-state.schema.json", "governance state")
        validate_contract(anchor_policy, specs / "witness-anchor-policy.schema.json", "anchor policy")
        validate_contract(pinned_head, specs / "witness-anchor-head.schema.json", "pinned head")
        if (
            governance_state.get("origin") != expected_origin
            or anchor_policy.get("origin") != expected_origin
            or pinned_head.get("origin") != expected_origin
        ):
            raise VerifierServiceError(
                f"Verifier request origin '{expected_origin}' does not match all supplied trust documents."
            )
        verify_external_anchor_store(
            paths[0],
            paths[1],
            governance_state,
            anchor_policy,
            pinned_head,
            parse_timestamp(observed_at, "request.now"),
        )
    except SimulatorError as error:
        status = "invalid"
        error_type = type(error).__name__
        message = str(error)
    after_digest = read_only_snapshot(paths)
    if after_digest != before_digest:
        raise VerifierReadOnlyViolationError(
            f"Verifier input snapshot changed during request '{request_id}': before={before_digest}, after={after_digest}."
        )
    return build_observation(
        policy,
        request_id,
        observed_at,
        status,
        before_digest,
        error_type,
        message,
        True,
        os.getpid(),
        actual_account,
    )


def reconcile_observations(primary: JsonObject, secondary: JsonObject, observed_at: str) -> JsonObject:
    primary_service = require_string(primary.get("service_id"), "primary.service_id")
    secondary_service = require_string(secondary.get("service_id"), "secondary.service_id")
    if primary_service == secondary_service:
        raise VerifierDisagreementError("Verifier consensus requires two distinct service identities.")
    primary_principal = require_string(primary.get("logical_principal"), "primary.logical_principal")
    secondary_principal = require_string(secondary.get("logical_principal"), "secondary.logical_principal")
    if primary_principal == secondary_principal:
        raise VerifierDisagreementError("Verifier consensus requires two distinct logical principals.")
    origin = require_string(primary.get("origin"), "primary.origin")
    if secondary.get("origin") != origin:
        raise VerifierDisagreementError("Verifier observations have different origins.")
    primary_status = require_string(primary.get("status"), "primary.status")
    secondary_status = require_string(secondary.get("status"), "secondary.status")
    allowed_statuses = {"valid", "invalid", "timeout", "unavailable"}
    if primary_status not in allowed_statuses or secondary_status not in allowed_statuses:
        raise VerifierDisagreementError(
            f"Verifier observation status is unsupported: primary='{primary_status}', secondary='{secondary_status}'."
        )
    for label, observation, status in (
        ("primary", primary, primary_status),
        ("secondary", secondary, secondary_status),
    ):
        if status == "valid" and (
            observation.get("subject_digest") is None
            or observation.get("read_only_behavior_verified") is not True
            or observation.get("credential_environment_variable_count") != 0
        ):
            raise VerifierDisagreementError(
                f"{label.capitalize()} valid observation lacks subject, read-only, or credential-isolation evidence."
            )
    primary_pid = primary.get("process_id")
    secondary_pid = secondary.get("process_id")
    if isinstance(primary_pid, int) and isinstance(secondary_pid, int) and primary_pid == secondary_pid:
        raise VerifierDisagreementError("Verifier consensus requires distinct process IDs.")
    primary_subject = primary.get("subject_digest")
    secondary_subject = secondary.get("subject_digest")
    statuses = {primary_status, secondary_status}
    state = "disagreement"
    reason = "Verifier states or subject digests disagree"
    accepted = False
    if "unavailable" in statuses:
        state = "verifier_unavailable"
        reason = "At least one required verifier process was unavailable"
    elif "timeout" in statuses:
        state = "verifier_timeout"
        reason = "At least one required verifier process exceeded its deadline"
    elif primary_status == secondary_status == "valid" and primary_subject == secondary_subject:
        isolated = (
            primary.get("os_account_boundary_verified") is True
            and secondary.get("os_account_boundary_verified") is True
        )
        if isolated:
            state = "agreed_valid"
            reason = "Two OS-account-isolated verifier services agreed on a valid subject digest"
            accepted = True
        else:
            state = "agreed_valid_boundary_unproven"
            reason = "Verifier services agreed, but dedicated OS-account isolation is unproven"
    elif primary_status == secondary_status == "invalid" and primary_subject == secondary_subject:
        state = "agreed_invalid"
        reason = "Two verifier services agreed that the same subject is invalid"
    consensus_material = f"{sha256_digest(primary)}:{sha256_digest(secondary)}:{state}:{observed_at}"
    return {
        "consensus_version": "0.1.0",
        "consensus_id": str(uuid.uuid5(CONSENSUS_NAMESPACE, consensus_material)),
        "origin": origin,
        "observed_at": observed_at,
        "primary_observation_digest": sha256_digest(primary),
        "secondary_observation_digest": sha256_digest(secondary),
        "state": state,
        "verification_accepted": accepted,
        "reason": reason,
    }
