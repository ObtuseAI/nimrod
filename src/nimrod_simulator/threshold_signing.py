"""Reusable domain-separated threshold signing for governed JSON documents."""

from __future__ import annotations

import base64
import binascii
from datetime import datetime

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from nimrod_simulator.errors import KeyTransitionError, ThresholdSignatureError
from nimrod_simulator.jsonio import canonical_json_bytes, require_integer, require_list, require_object, require_string
from nimrod_simulator.key_governance import SigningConnector, decode_public_key, key_index, require_key_active_at
from nimrod_simulator.model import JsonObject


def threshold_message(document: JsonObject, domain: bytes) -> bytes:
    unsigned: JsonObject = {key: value for key, value in document.items() if key != "signatures"}
    return domain + canonical_json_bytes(unsigned)


def sign_threshold_document(
    unsigned_document: JsonObject,
    connectors: list[SigningConnector],
    domain: bytes,
    label: str,
    error_type: type[ThresholdSignatureError],
) -> JsonObject:
    if "signatures" in unsigned_document:
        raise error_type(f"Unsigned {label} contains signatures.")
    message = domain + canonical_json_bytes(unsigned_document)
    signatures: list[JsonObject] = []
    seen: set[str] = set()
    for connector in connectors:
        if connector.key_id in seen:
            raise error_type(f"{label.capitalize()} repeats signing connector '{connector.key_id}'.")
        seen.add(connector.key_id)
        signatures.append(
            {
                "signer_id": connector.key_id,
                "algorithm": "Ed25519",
                "signature_base64": base64.b64encode(connector.sign(message)).decode("ascii"),
            }
        )
    return {**unsigned_document, "signatures": signatures}


def _decode_signature(
    value: str,
    signer_id: str,
    label: str,
    error_type: type[ThresholdSignatureError],
) -> bytes:
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as error:
        raise error_type(f"{label.capitalize()} signature for '{signer_id}' is not canonical base64.") from error
    if len(decoded) != 64:
        raise error_type(
            f"{label.capitalize()} signature for '{signer_id}' must be 64 bytes; received {len(decoded)}."
        )
    return decoded


def verify_threshold_signatures(
    document: JsonObject,
    governance_state: JsonObject,
    issued_at: datetime,
    domain: bytes,
    label: str,
    error_type: type[ThresholdSignatureError],
) -> tuple[list[str], list[str]]:
    keys = key_index(governance_state)
    signatures = require_list(document.get("signatures"), f"{label}.signatures")
    message = threshold_message(document, domain)
    seen: set[str] = set()
    roles: set[str] = set()
    verified: list[str] = []
    for index, value in enumerate(signatures):
        signature = require_object(value, f"{label}.signatures[{index}]")
        signer_id = require_string(signature.get("signer_id"), f"{label}.signatures[{index}].signer_id")
        if signer_id in seen:
            raise error_type(f"{label.capitalize()} repeats signer '{signer_id}'.")
        seen.add(signer_id)
        key = keys.get(signer_id)
        if key is None:
            raise error_type(f"{label.capitalize()} contains unknown signer '{signer_id}'.")
        try:
            require_key_active_at(key, issued_at)
        except KeyTransitionError as error:
            raise error_type(f"{label.capitalize()} signer '{signer_id}' is not active at issuance.") from error
        if require_string(signature.get("algorithm"), f"{label}.signatures[{index}].algorithm") != "Ed25519":
            raise error_type(f"{label.capitalize()} signer '{signer_id}' does not use Ed25519.")
        public_key = decode_public_key(
            require_string(key.get("public_key_base64"), f"{signer_id}.public_key_base64"), signer_id
        )
        signature_bytes = _decode_signature(
            require_string(signature.get("signature_base64"), f"{label}.signatures[{index}].signature_base64"),
            signer_id,
            label,
            error_type,
        )
        try:
            Ed25519PublicKey.from_public_bytes(public_key).verify(signature_bytes, message)
        except (InvalidSignature, ValueError) as error:
            raise error_type(f"{label.capitalize()} signature verification failed for '{signer_id}'.") from error
        verified.append(signer_id)
        roles.add(require_string(key.get("role"), f"{signer_id}.role"))
    threshold = require_integer(governance_state.get("threshold"), "governance.threshold")
    minimum_roles = require_integer(
        governance_state.get("minimum_distinct_roles"), "governance.minimum_distinct_roles"
    )
    if len(verified) < threshold:
        raise error_type(
            f"{label.capitalize()} threshold not met: verified {len(verified)}, required {threshold}."
        )
    if len(roles) < minimum_roles:
        raise error_type(
            f"{label.capitalize()} role diversity not met: verified {len(roles)}, required {minimum_roles}."
        )
    return sorted(verified), sorted(roles)
