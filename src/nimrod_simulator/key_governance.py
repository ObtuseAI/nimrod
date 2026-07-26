"""Threshold key governance and non-exportable signing connector contracts."""

from __future__ import annotations

import base64
import binascii
from datetime import datetime
from typing import Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from nimrod_simulator.authorization import parse_timestamp
from nimrod_simulator.errors import KeyCustodyError, KeyGovernanceError, KeyTransitionError
from nimrod_simulator.jsonio import (
    canonical_json_bytes,
    require_boolean,
    require_integer,
    require_list,
    require_object,
    require_string,
    sha256_digest,
)
from nimrod_simulator.model import JsonObject


KEY_TRANSITION_DOMAIN = b"nimrod.key-governance-transition.v0.1\x00"
ACTIVE_KEY_STATUS = "active"
TERMINAL_KEY_STATUSES = {"retired", "revoked", "lost", "compromised"}
SUPPORTED_CUSTODY_KINDS = {"pkcs11", "aws_kms", "azure_key_vault", "gcp_cloud_kms", "test_ephemeral"}


class SigningConnector(Protocol):
    """Boundary for HSM, KMS, PKCS#11, or validation-only signing custody."""

    @property
    def key_id(self) -> str:
        """Return the stable public key identifier."""

    @property
    def role(self) -> str:
        """Return the separation-of-duties role bound to the key."""

    @property
    def public_key_base64(self) -> str:
        """Return the raw Ed25519 public key; private key export is forbidden."""

    def sign(self, message: bytes) -> bytes:
        """Sign one domain-separated message without exporting private material."""


class EphemeralEd25519SigningConnector:
    """Validation-only in-memory connector; never used as production custody evidence."""

    def __init__(self, key_id: str, role: str, private_key: Ed25519PrivateKey) -> None:
        if not key_id or not role:
            raise KeyCustodyError("Ephemeral signing connector requires non-empty key ID and role.")
        self._key_id = key_id
        self._role = role
        self._private_key = private_key

    @property
    def key_id(self) -> str:
        return self._key_id

    @property
    def role(self) -> str:
        return self._role

    @property
    def public_key_base64(self) -> str:
        public_bytes = self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return base64.b64encode(public_bytes).decode("ascii")

    def sign(self, message: bytes) -> bytes:
        if not message:
            raise KeyCustodyError(f"Signing connector '{self._key_id}' refuses an empty message.")
        return self._private_key.sign(message)


def decode_public_key(value: str, key_id: str) -> bytes:
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as error:
        raise KeyGovernanceError(f"Key '{key_id}' public key is not canonical base64.") from error
    if len(decoded) != 32:
        raise KeyGovernanceError(
            f"Key '{key_id}' Ed25519 public key must be 32 bytes; received {len(decoded)}."
        )
    return decoded


def decode_signature(value: str, signer_id: str) -> bytes:
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as error:
        raise KeyTransitionError(f"Signature for '{signer_id}' is not canonical base64.") from error
    if len(decoded) != 64:
        raise KeyTransitionError(
            f"Signature for '{signer_id}' must be 64 bytes; received {len(decoded)}."
        )
    return decoded


def governance_key(
    connector: SigningConnector,
    status: str,
    valid_from: str,
    valid_until: str | None,
    connector_kind: str,
    connector_id: str,
    key_reference: str,
    hardware_backed: bool,
    attestation_digest: str | None,
) -> JsonObject:
    if connector_kind not in SUPPORTED_CUSTODY_KINDS:
        raise KeyCustodyError(f"Unsupported custody connector kind '{connector_kind}'.")
    if connector_kind != "test_ephemeral" and not hardware_backed:
        raise KeyCustodyError(
            f"Production-shaped custody connector '{connector_kind}' must declare hardware-backed custody."
        )
    return {
        "key_id": connector.key_id,
        "role": connector.role,
        "algorithm": "Ed25519",
        "public_key_base64": connector.public_key_base64,
        "status": status,
        "valid_from": valid_from,
        "valid_until": valid_until,
        "custody": {
            "connector_kind": connector_kind,
            "connector_id": connector_id,
            "key_reference": key_reference,
            "private_key_exportable": False,
            "hardware_backed": hardware_backed,
            "allowed_operations": ["sign"],
            "attestation_digest": attestation_digest,
        },
    }


def key_index(state: JsonObject) -> dict[str, JsonObject]:
    values = require_list(state.get("keys"), "keys")
    result: dict[str, JsonObject] = {}
    public_keys: set[str] = set()
    for index, value in enumerate(values):
        key = require_object(value, f"keys[{index}]")
        key_id = require_string(key.get("key_id"), f"keys[{index}].key_id")
        if key_id in result:
            raise KeyGovernanceError(f"Key governance state repeats key ID '{key_id}'.")
        public_key = require_string(key.get("public_key_base64"), f"keys[{index}].public_key_base64")
        decode_public_key(public_key, key_id)
        if public_key in public_keys:
            raise KeyGovernanceError(f"Key governance state reuses public key material for '{key_id}'.")
        public_keys.add(public_key)
        result[key_id] = key
    return result


def validate_custody(key: JsonObject) -> None:
    key_id = require_string(key.get("key_id"), "key.key_id")
    custody = require_object(key.get("custody"), f"{key_id}.custody")
    kind = require_string(custody.get("connector_kind"), f"{key_id}.custody.connector_kind")
    if kind not in SUPPORTED_CUSTODY_KINDS:
        raise KeyGovernanceError(f"Key '{key_id}' uses unsupported custody connector '{kind}'.")
    if require_boolean(custody.get("private_key_exportable"), f"{key_id}.private_key_exportable"):
        raise KeyGovernanceError(f"Key '{key_id}' custody cannot export private key material.")
    operations = require_list(custody.get("allowed_operations"), f"{key_id}.allowed_operations")
    if operations != ["sign"]:
        raise KeyGovernanceError(f"Key '{key_id}' custody must allow exactly the sign operation.")
    require_string(custody.get("connector_id"), f"{key_id}.custody.connector_id")
    require_string(custody.get("key_reference"), f"{key_id}.custody.key_reference")
    hardware_backed = require_boolean(custody.get("hardware_backed"), f"{key_id}.hardware_backed")
    if kind != "test_ephemeral" and not hardware_backed:
        raise KeyGovernanceError(
            f"Key '{key_id}' production custody kind '{kind}' must be hardware backed."
        )
    if kind != "test_ephemeral" and custody.get("attestation_digest") is None:
        raise KeyGovernanceError(
            f"Key '{key_id}' production custody kind '{kind}' requires an attestation digest."
        )


def validate_governance_state(state: JsonObject) -> None:
    if require_string(state.get("state_version"), "state_version") != "0.1.0":
        raise KeyGovernanceError("Key governance state_version must be '0.1.0'.")
    threshold = require_integer(state.get("threshold"), "threshold")
    ceremony_count = require_integer(state.get("ceremony_key_count"), "ceremony_key_count")
    minimum_roles = require_integer(state.get("minimum_distinct_roles"), "minimum_distinct_roles")
    if threshold != 2 or ceremony_count != 3 or minimum_roles != 2:
        raise KeyGovernanceError("Key governance must preserve a 2-of-3 threshold with two distinct roles.")
    keys = key_index(state)
    state_issued_at = parse_timestamp(state.get("issued_at"), "state.issued_at")
    active = [key for key in keys.values() if key.get("status") == ACTIVE_KEY_STATUS]
    if len(active) != ceremony_count:
        raise KeyGovernanceError(
            f"Key governance epoch must contain exactly {ceremony_count} active keys; received {len(active)}."
        )
    active_roles = {require_string(key.get("role"), "key.role") for key in active}
    if len(active_roles) < minimum_roles:
        raise KeyGovernanceError(
            f"Active key role diversity {len(active_roles)} is below required {minimum_roles}."
        )
    for key in keys.values():
        algorithm = require_string(key.get("algorithm"), "key.algorithm")
        if algorithm != "Ed25519":
            raise KeyGovernanceError(f"Key '{key.get('key_id')}' uses unsupported algorithm '{algorithm}'.")
        status = require_string(key.get("status"), "key.status")
        if status not in {ACTIVE_KEY_STATUS, *TERMINAL_KEY_STATUSES}:
            raise KeyGovernanceError(f"Key '{key.get('key_id')}' has invalid status '{status}'.")
        valid_from = parse_timestamp(key.get("valid_from"), "key.valid_from")
        valid_until_value = key.get("valid_until")
        if valid_from > state_issued_at:
            raise KeyGovernanceError(f"Key '{key.get('key_id')}' begins after its governance state epoch.")
        if status in TERMINAL_KEY_STATUSES and valid_until_value is None:
            raise KeyGovernanceError(f"Terminal key '{key.get('key_id')}' requires valid_until evidence.")
        if valid_until_value is not None:
            valid_until = parse_timestamp(valid_until_value, "key.valid_until")
            if valid_until < valid_from:
                raise KeyGovernanceError(f"Key '{key.get('key_id')}' valid_until precedes valid_from.")
            if status == ACTIVE_KEY_STATUS and valid_until <= state_issued_at:
                raise KeyGovernanceError(f"Active key '{key.get('key_id')}' is already expired.")
        validate_custody(key)


def transition_message(transition: JsonObject) -> bytes:
    unsigned: JsonObject = {key: value for key, value in transition.items() if key != "signatures"}
    return KEY_TRANSITION_DOMAIN + canonical_json_bytes(unsigned)


def sign_transition(unsigned_transition: JsonObject, connectors: list[SigningConnector]) -> JsonObject:
    if "signatures" in unsigned_transition:
        raise KeyTransitionError("Unsigned key transition must not contain a signatures field.")
    message = KEY_TRANSITION_DOMAIN + canonical_json_bytes(unsigned_transition)
    signatures: list[JsonObject] = []
    seen: set[str] = set()
    for connector in connectors:
        if connector.key_id in seen:
            raise KeyTransitionError(f"Signing ceremony repeats connector key '{connector.key_id}'.")
        seen.add(connector.key_id)
        signatures.append(
            {
                "signer_id": connector.key_id,
                "algorithm": "Ed25519",
                "signature_base64": base64.b64encode(connector.sign(message)).decode("ascii"),
            }
        )
    return {**unsigned_transition, "signatures": signatures}


def require_key_active_at(key: JsonObject, when: datetime) -> None:
    key_id = require_string(key.get("key_id"), "key.key_id")
    if require_string(key.get("status"), f"{key_id}.status") != ACTIVE_KEY_STATUS:
        raise KeyTransitionError(f"Key '{key_id}' is not active and cannot authorize a transition.")
    valid_from = parse_timestamp(key.get("valid_from"), f"{key_id}.valid_from")
    valid_until_value = key.get("valid_until")
    if when < valid_from:
        raise KeyTransitionError(f"Key '{key_id}' is not valid until {valid_from.isoformat()}.")
    if valid_until_value is not None:
        valid_until = parse_timestamp(valid_until_value, f"{key_id}.valid_until")
        if when >= valid_until:
            raise KeyTransitionError(f"Key '{key_id}' expired at {valid_until.isoformat()}.")


def verify_transition_signatures(current_state: JsonObject, transition: JsonObject) -> tuple[list[str], list[str]]:
    keys = key_index(current_state)
    issued_at = parse_timestamp(transition.get("issued_at"), "transition.issued_at")
    message = transition_message(transition)
    signatures = require_list(transition.get("signatures"), "transition.signatures")
    seen: set[str] = set()
    roles: set[str] = set()
    verified: list[str] = []
    for index, value in enumerate(signatures):
        signature = require_object(value, f"signatures[{index}]")
        signer_id = require_string(signature.get("signer_id"), f"signatures[{index}].signer_id")
        if signer_id in seen:
            raise KeyTransitionError(f"Key transition repeats signer '{signer_id}'.")
        seen.add(signer_id)
        key = keys.get(signer_id)
        if key is None:
            raise KeyTransitionError(f"Key transition contains unknown signer '{signer_id}'.")
        require_key_active_at(key, issued_at)
        algorithm = require_string(signature.get("algorithm"), f"signatures[{index}].algorithm")
        if algorithm != "Ed25519":
            raise KeyTransitionError(f"Key transition signer '{signer_id}' uses '{algorithm}'.")
        public_key = decode_public_key(
            require_string(key.get("public_key_base64"), f"{signer_id}.public_key_base64"), signer_id
        )
        signature_bytes = decode_signature(
            require_string(signature.get("signature_base64"), f"signatures[{index}].signature_base64"),
            signer_id,
        )
        try:
            Ed25519PublicKey.from_public_bytes(public_key).verify(signature_bytes, message)
        except (InvalidSignature, ValueError) as error:
            raise KeyTransitionError(f"Key transition signature verification failed for '{signer_id}'.") from error
        verified.append(signer_id)
        roles.add(require_string(key.get("role"), f"{signer_id}.role"))
    threshold = require_integer(current_state.get("threshold"), "threshold")
    minimum_roles = require_integer(current_state.get("minimum_distinct_roles"), "minimum_distinct_roles")
    if len(verified) < threshold:
        raise KeyTransitionError(
            f"Key transition threshold not met: verified {len(verified)}, required {threshold}."
        )
    if len(roles) < minimum_roles:
        raise KeyTransitionError(
            f"Key transition role diversity not met: verified {len(roles)}, required {minimum_roles}."
        )
    return sorted(verified), sorted(roles)


def changed_key_ids(current_keys: dict[str, JsonObject], next_keys: dict[str, JsonObject]) -> set[str]:
    changed: set[str] = set(next_keys.keys() - current_keys.keys())
    for key_id in current_keys.keys() & next_keys.keys():
        current = current_keys[key_id]
        following = next_keys[key_id]
        for immutable_field in ("role", "algorithm", "public_key_base64", "custody", "valid_from"):
            if current.get(immutable_field) != following.get(immutable_field):
                raise KeyTransitionError(
                    f"Key transition mutates immutable field '{immutable_field}' for '{key_id}'."
                )
        current_status = require_string(current.get("status"), f"{key_id}.status")
        next_status = require_string(following.get("status"), f"{key_id}.next_status")
        if current_status in TERMINAL_KEY_STATUSES and next_status != current_status:
            raise KeyTransitionError(
                f"Terminal key '{key_id}' cannot move from '{current_status}' to '{next_status}'."
            )
        if current_status == next_status and current.get("valid_until") != following.get("valid_until"):
            raise KeyTransitionError(f"Unchanged key '{key_id}' cannot alter valid_until.")
        if current_status != next_status:
            changed.add(key_id)
    missing = sorted(current_keys.keys() - next_keys.keys())
    if missing:
        raise KeyTransitionError(f"Key transition erases historical keys: {', '.join(missing)}.")
    return changed


def require_transition_kind(
    kind: str,
    current_keys: dict[str, JsonObject],
    next_keys: dict[str, JsonObject],
    issued_at: datetime,
) -> None:
    added = next_keys.keys() - current_keys.keys()
    status_by_kind = {
        "rotation": "retired",
        "revocation": "revoked",
        "lost_key_recovery": "lost",
        "compromise_recovery": "compromised",
    }
    required_status = status_by_kind.get(kind)
    if required_status is None:
        raise KeyTransitionError(f"Unsupported key transition kind '{kind}'.")
    changed_to_status = {
        key_id
        for key_id in current_keys.keys() & next_keys.keys()
        if next_keys[key_id].get("status") == required_status and current_keys[key_id].get("status") != required_status
    }
    if not added or not changed_to_status:
        raise KeyTransitionError(
            f"Transition kind '{kind}' requires a replacement key and a key moved to '{required_status}'."
        )
    other_status_changes = {
        key_id
        for key_id in current_keys.keys() & next_keys.keys()
        if current_keys[key_id].get("status") != next_keys[key_id].get("status")
        and next_keys[key_id].get("status") != required_status
    }
    if other_status_changes:
        raise KeyTransitionError(
            f"Transition kind '{kind}' contains unrelated status changes: {sorted(other_status_changes)}."
        )
    for key_id in changed_to_status:
        valid_until = parse_timestamp(next_keys[key_id].get("valid_until"), f"{key_id}.valid_until")
        if valid_until != issued_at:
            raise KeyTransitionError(
                f"Departing key '{key_id}' valid_until must equal transition issued_at."
            )
    for key_id in added:
        if next_keys[key_id].get("status") != ACTIVE_KEY_STATUS:
            raise KeyTransitionError(f"Replacement key '{key_id}' must enter as active.")
        valid_from = parse_timestamp(next_keys[key_id].get("valid_from"), f"{key_id}.valid_from")
        if valid_from != issued_at:
            raise KeyTransitionError(
                f"Replacement key '{key_id}' valid_from must equal transition issued_at."
            )


def verify_key_transition(
    current_state: JsonObject,
    transition: JsonObject,
    next_state: JsonObject,
    now: datetime,
) -> JsonObject:
    validate_governance_state(current_state)
    validate_governance_state(next_state)
    governance_id = require_string(current_state.get("governance_id"), "governance_id")
    if require_string(transition.get("governance_id"), "transition.governance_id") != governance_id:
        raise KeyTransitionError("Key transition governance ID does not match current state.")
    if require_string(next_state.get("governance_id"), "next.governance_id") != governance_id:
        raise KeyTransitionError("Next key state changes the governance ID.")
    origin = require_string(current_state.get("origin"), "origin")
    if transition.get("origin") != origin or next_state.get("origin") != origin:
        raise KeyTransitionError("Key transition and states must preserve origin.")
    current_epoch = require_integer(current_state.get("epoch"), "epoch")
    next_epoch = require_integer(next_state.get("epoch"), "next.epoch")
    from_epoch = require_integer(transition.get("from_epoch"), "transition.from_epoch")
    to_epoch = require_integer(transition.get("to_epoch"), "transition.to_epoch")
    if from_epoch != current_epoch or to_epoch != next_epoch or next_epoch != current_epoch + 1:
        raise KeyTransitionError(
            f"Key transition epochs must advance exactly once: current={current_epoch}, from={from_epoch}, "
            f"to={to_epoch}, next={next_epoch}."
        )
    current_digest = sha256_digest(current_state)
    next_digest = sha256_digest(next_state)
    if transition.get("previous_state_digest") != current_digest:
        raise KeyTransitionError("Key transition previous_state_digest does not match current state.")
    if transition.get("next_state_digest") != next_digest:
        raise KeyTransitionError("Key transition next_state_digest does not match next state.")
    if next_state.get("previous_state_digest") != current_digest:
        raise KeyTransitionError("Next key state does not chain to the current state digest.")
    issued_at = parse_timestamp(transition.get("issued_at"), "transition.issued_at")
    if now.tzinfo is None or issued_at > now:
        raise KeyTransitionError("Key transition time is in the future or verification time lacks an offset.")
    current_issued_at = parse_timestamp(current_state.get("issued_at"), "current.issued_at")
    next_issued_at = parse_timestamp(next_state.get("issued_at"), "next.issued_at")
    if issued_at <= current_issued_at or issued_at != next_issued_at:
        raise KeyTransitionError(
            "Key transition issued_at must advance beyond the current state and equal the next state issued_at."
        )
    current_keys = key_index(current_state)
    next_keys = key_index(next_state)
    changed = changed_key_ids(current_keys, next_keys)
    affected = {
        require_string(value, f"affected_key_ids[{index}]")
        for index, value in enumerate(require_list(transition.get("affected_key_ids"), "affected_key_ids"))
    }
    if affected != changed:
        raise KeyTransitionError(
            f"Key transition affected_key_ids mismatch: expected {sorted(changed)}, received {sorted(affected)}."
        )
    kind = require_string(transition.get("kind"), "transition.kind")
    require_transition_kind(kind, current_keys, next_keys, issued_at)
    verified_signers, verified_roles = verify_transition_signatures(current_state, transition)
    return {
        "status": "KEY_GOVERNANCE_TRANSITION_VALID",
        "governance_id": governance_id,
        "from_epoch": current_epoch,
        "to_epoch": next_epoch,
        "kind": kind,
        "previous_state_digest": current_digest,
        "next_state_digest": next_digest,
        "verified_signer_ids": verified_signers,
        "verified_roles": verified_roles,
        "private_key_material_exported": False,
    }
