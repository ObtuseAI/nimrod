"""Threshold-signed adapter-policy envelope construction and verification."""

from __future__ import annotations

from datetime import datetime

from nimrod_simulator.authorization import parse_timestamp
from nimrod_simulator.errors import ControlStateValidationError, RangePolicySignatureError
from nimrod_simulator.jsonio import (
    require_boolean,
    require_object,
    require_string,
    sha256_digest,
)
from nimrod_simulator.key_governance import (
    SigningConnector,
    validate_governance_state,
)
from nimrod_simulator.model import JsonObject
from nimrod_simulator.threshold_signing import sign_threshold_document, threshold_message, verify_threshold_signatures


RANGE_POLICY_DOMAIN = b"nimrod.range-adapter-policy-envelope.v0.1\x00"


def range_policy_message(envelope: JsonObject) -> bytes:
    return threshold_message(envelope, RANGE_POLICY_DOMAIN)


def sign_range_adapter_policy_envelope(
    unsigned_envelope: JsonObject, connectors: list[SigningConnector]
) -> JsonObject:
    return sign_threshold_document(
        unsigned_envelope,
        connectors,
        RANGE_POLICY_DOMAIN,
        "range policy envelope",
        RangePolicySignatureError,
    )


def _timestamp(value: object, field: str) -> datetime:
    try:
        return parse_timestamp(value, field)
    except ControlStateValidationError as error:
        raise RangePolicySignatureError(f"Range policy timestamp '{field}' is invalid: {error}.") from error


def verify_range_adapter_policy_envelope(
    envelope: JsonObject,
    policy: JsonObject,
    governance_state: JsonObject,
    now: datetime,
    maximum_lifetime_seconds: int,
) -> JsonObject:
    if maximum_lifetime_seconds <= 0:
        raise RangePolicySignatureError("Range policy maximum lifetime must be positive.")
    if now.utcoffset() is None:
        raise RangePolicySignatureError("Range policy verification time must be timezone-aware.")
    validate_governance_state(governance_state)
    if require_string(envelope.get("envelope_version"), "envelope.envelope_version") != "0.1.0":
        raise RangePolicySignatureError("Range policy envelope_version must be '0.1.0'.")
    if envelope.get("origin") != "simulated" or policy.get("origin") != "simulated" or governance_state.get("origin") != "simulated":
        raise RangePolicySignatureError("Range policy envelope, policy, and governance must remain simulated.")
    if policy.get("policy_version") != "0.1.0" or policy.get("stage") != "no_execution_fixture_only":
        raise RangePolicySignatureError(
            "Range adapter policy must be version 0.1.0 at the no_execution_fixture_only stage."
        )
    policy_authority = require_object(policy.get("authority"), "policy.authority")
    for field in ("can_connect", "can_execute", "can_discover_targets"):
        if require_boolean(policy_authority.get(field), f"policy.authority.{field}"):
            raise RangePolicySignatureError(f"Range adapter policy cannot grant '{field}'.")
    if envelope.get("policy_id") != policy.get("policy_id"):
        raise RangePolicySignatureError("Range policy envelope policy identity mismatch.")
    policy_digest = sha256_digest(policy)
    governance_digest = sha256_digest(governance_state)
    if envelope.get("policy_digest") != policy_digest:
        raise RangePolicySignatureError("Range policy envelope policy digest mismatch.")
    if envelope.get("governance_state_digest") != governance_digest:
        raise RangePolicySignatureError("Range policy envelope governance digest mismatch.")
    authority = require_object(envelope.get("authority"), "envelope.authority")
    for field in ("can_connect", "can_execute", "can_discover_targets"):
        if require_boolean(authority.get(field), f"envelope.authority.{field}"):
            raise RangePolicySignatureError(f"Range policy envelope cannot grant '{field}'.")
    issued_at = _timestamp(envelope.get("issued_at"), "issued_at")
    not_before = _timestamp(envelope.get("not_before"), "not_before")
    expires_at = _timestamp(envelope.get("expires_at"), "expires_at")
    if issued_at > not_before or not_before >= expires_at:
        raise RangePolicySignatureError("Range policy envelope requires issued_at <= not_before < expires_at.")
    lifetime = int((expires_at - issued_at).total_seconds())
    if lifetime > maximum_lifetime_seconds:
        raise RangePolicySignatureError(
            f"Range policy lifetime {lifetime}s exceeds {maximum_lifetime_seconds}s."
        )
    if now < not_before or now >= expires_at:
        raise RangePolicySignatureError("Range policy envelope is inactive or expired.")
    verified, roles = verify_threshold_signatures(
        envelope,
        governance_state,
        issued_at,
        RANGE_POLICY_DOMAIN,
        "range policy envelope",
        RangePolicySignatureError,
    )
    return {
        "verification_version": "0.1.0-internal",
        "status": "verified_simulated_policy",
        "envelope_digest": sha256_digest(envelope),
        "policy_digest": policy_digest,
        "governance_state_digest": governance_digest,
        "verified_signer_ids": verified,
        "verified_roles": roles,
        "expires_at": envelope["expires_at"],
        "authority": {"can_connect": False, "can_execute": False, "can_discover_targets": False},
    }
