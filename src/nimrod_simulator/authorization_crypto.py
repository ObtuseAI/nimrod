"""Threshold Ed25519 verification for canonical authorization leases."""

from __future__ import annotations

import base64
import binascii
from datetime import datetime

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from nimrod_simulator.authorization import parse_timestamp
from nimrod_simulator.errors import (
    AuthorizationProofError,
    AuthorizationSignatureError,
    AuthorizationThresholdError,
    TrustPolicyError,
)
from nimrod_simulator.jsonio import (
    canonical_json_bytes,
    require_integer,
    require_list,
    require_object,
    require_string,
    require_string_list,
    sha256_digest,
)
from nimrod_simulator.model import AuthorizationVerification, JsonObject


AUTHORIZATION_DOMAIN = b"nimrod.authorization-lease.v0.1\x00"
PROOF_HEADER_FIELDS = (
    "bundle_version",
    "bundle_id",
    "origin",
    "lease_id",
    "lease_digest",
    "trust_policy_digest",
    "signed_at",
)


def authorization_message(lease: JsonObject, proof_bundle: JsonObject) -> bytes:
    proof_header: JsonObject = {}
    for field in PROOF_HEADER_FIELDS:
        if field not in proof_bundle:
            raise AuthorizationProofError(
                f"Authorization proof is missing signed header field '{field}'."
            )
        proof_header[field] = proof_bundle[field]
    signed_content: JsonObject = {
        "lease": lease,
        "proof_header": proof_header,
    }
    return AUTHORIZATION_DOMAIN + canonical_json_bytes(signed_content)


def decode_base64(value: str, field: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as error:
        raise AuthorizationSignatureError(f"Field '{field}' is not valid canonical base64.") from error


def trusted_signer_index(trust_policy: JsonObject) -> dict[str, tuple[str, bytes]]:
    signer_values = require_list(trust_policy.get("trusted_signers"), "trusted_signers")
    result: dict[str, tuple[str, bytes]] = {}
    for index, signer_value in enumerate(signer_values):
        signer = require_object(signer_value, f"trusted_signers[{index}]")
        signer_id = require_string(signer.get("signer_id"), f"trusted_signers[{index}].signer_id")
        role = require_string(signer.get("role"), f"trusted_signers[{index}].role")
        algorithm = require_string(signer.get("algorithm"), f"trusted_signers[{index}].algorithm")
        if algorithm != "Ed25519":
            raise TrustPolicyError(f"Trusted signer '{signer_id}' uses unsupported algorithm '{algorithm}'.")
        if signer_id in result:
            raise TrustPolicyError(f"Trust policy contains duplicate signer_id '{signer_id}'.")
        key_bytes = decode_base64(
            require_string(signer.get("public_key_base64"), f"trusted_signers[{index}].public_key_base64"),
            f"trusted_signers[{index}].public_key_base64",
        )
        if len(key_bytes) != 32:
            raise AuthorizationSignatureError(
                f"Trusted signer '{signer_id}' Ed25519 public key must be 32 bytes; received {len(key_bytes)}."
            )
        result[signer_id] = (role, key_bytes)
    return result


def require_trust_window(trust_policy: JsonObject, now: datetime) -> None:
    not_before = parse_timestamp(trust_policy.get("not_before"), "trust_policy.not_before")
    expires_at = parse_timestamp(trust_policy.get("expires_at"), "trust_policy.expires_at")
    if now.tzinfo is None:
        raise TrustPolicyError("Authorization verification time must include a UTC offset.")
    if now < not_before:
        raise TrustPolicyError(
            f"Trust policy is not active until {not_before.isoformat()}; evaluated at {now.isoformat()}."
        )
    if now >= expires_at:
        raise TrustPolicyError(
            f"Trust policy expired at {expires_at.isoformat()}; evaluated at {now.isoformat()}."
        )


def verify_authorization(
    lease: JsonObject,
    proof_bundle: JsonObject,
    trust_policy: JsonObject,
    now: datetime,
) -> AuthorizationVerification:
    require_trust_window(trust_policy, now)
    lease_id = require_string(lease.get("lease_id"), "lease_id")
    proof_lease_id = require_string(proof_bundle.get("lease_id"), "proof_bundle.lease_id")
    if proof_lease_id != lease_id:
        raise AuthorizationProofError(
            f"Authorization proof references lease '{proof_lease_id}', but supplied lease is '{lease_id}'."
        )
    lease_digest = sha256_digest(lease)
    proof_lease_digest = require_string(proof_bundle.get("lease_digest"), "proof_bundle.lease_digest")
    if proof_lease_digest != lease_digest:
        raise AuthorizationProofError(
            f"Authorization proof lease digest mismatch: expected '{lease_digest}', received '{proof_lease_digest}'."
        )
    trust_policy_digest = sha256_digest(trust_policy)
    proof_trust_digest = require_string(
        proof_bundle.get("trust_policy_digest"), "proof_bundle.trust_policy_digest"
    )
    if proof_trust_digest != trust_policy_digest:
        raise AuthorizationProofError(
            "Authorization proof is not bound to the supplied trust policy digest."
        )
    proof_origin = require_string(proof_bundle.get("origin"), "proof_bundle.origin")
    policy_origin = require_string(trust_policy.get("origin"), "trust_policy.origin")
    if proof_origin != policy_origin:
        raise AuthorizationProofError(
            f"Proof origin '{proof_origin}' does not match trust-policy origin '{policy_origin}'."
        )
    signed_at = parse_timestamp(proof_bundle.get("signed_at"), "proof_bundle.signed_at")
    policy_not_before = parse_timestamp(trust_policy.get("not_before"), "trust_policy.not_before")
    policy_expires_at = parse_timestamp(trust_policy.get("expires_at"), "trust_policy.expires_at")
    lease_issued_at = parse_timestamp(lease.get("issued_at"), "lease.issued_at")
    lease_expires_at = parse_timestamp(lease.get("expires_at"), "lease.expires_at")
    if signed_at < policy_not_before or signed_at >= policy_expires_at:
        raise AuthorizationProofError(
            f"Authorization proof signed_at {signed_at.isoformat()} is outside the trust-policy window."
        )
    if signed_at < lease_issued_at or signed_at >= lease_expires_at:
        raise AuthorizationProofError(
            f"Authorization proof signed_at {signed_at.isoformat()} is outside the lease issuance window."
        )
    if signed_at > now:
        raise AuthorizationProofError(
            f"Authorization proof signed_at {signed_at.isoformat()} is in the future relative to {now.isoformat()}."
        )
    threshold = require_integer(trust_policy.get("threshold"), "trust_policy.threshold")
    required_roles = set(require_string_list(trust_policy.get("required_roles"), "trust_policy.required_roles"))
    trusted = trusted_signer_index(trust_policy)
    if threshold > len(trusted):
        raise TrustPolicyError(
            f"Trust threshold {threshold} exceeds distinct trusted signer count {len(trusted)}."
        )
    trusted_roles = {role for role, _ in trusted.values()}
    missing_trusted_roles = sorted(required_roles - trusted_roles)
    if missing_trusted_roles:
        raise TrustPolicyError(
            f"Trust policy cannot satisfy required roles: {', '.join(missing_trusted_roles)}."
        )
    message = authorization_message(lease, proof_bundle)
    signature_values = require_list(proof_bundle.get("signatures"), "proof_bundle.signatures")
    verified_signers: list[str] = []
    verified_roles: list[str] = []
    seen_signers: set[str] = set()
    for index, signature_value in enumerate(signature_values):
        signature = require_object(signature_value, f"signatures[{index}]")
        signer_id = require_string(signature.get("signer_id"), f"signatures[{index}].signer_id")
        if signer_id in seen_signers:
            raise AuthorizationThresholdError(f"Authorization proof repeats signer_id '{signer_id}'.")
        seen_signers.add(signer_id)
        trusted_entry = trusted.get(signer_id)
        if trusted_entry is None:
            raise AuthorizationSignatureError(f"Authorization proof contains untrusted signer '{signer_id}'.")
        role, public_key_bytes = trusted_entry
        algorithm = require_string(signature.get("algorithm"), f"signatures[{index}].algorithm")
        if algorithm != "Ed25519":
            raise AuthorizationSignatureError(
                f"Authorization signature for '{signer_id}' uses unsupported algorithm '{algorithm}'."
            )
        signature_bytes = decode_base64(
            require_string(signature.get("signature_base64"), f"signatures[{index}].signature_base64"),
            f"signatures[{index}].signature_base64",
        )
        if len(signature_bytes) != 64:
            raise AuthorizationSignatureError(
                f"Authorization signature for '{signer_id}' must be 64 bytes; received {len(signature_bytes)}."
            )
        try:
            Ed25519PublicKey.from_public_bytes(public_key_bytes).verify(signature_bytes, message)
        except (InvalidSignature, ValueError) as error:
            raise AuthorizationSignatureError(
                f"Ed25519 verification failed for trusted signer '{signer_id}'."
            ) from error
        verified_signers.append(signer_id)
        verified_roles.append(role)
    if len(verified_signers) < threshold:
        raise AuthorizationThresholdError(
            f"Authorization threshold not met: verified {len(verified_signers)}, required {threshold}."
        )
    missing_verified_roles = sorted(required_roles - set(verified_roles))
    if missing_verified_roles:
        raise AuthorizationThresholdError(
            f"Authorization proof lacks required verified roles: {', '.join(missing_verified_roles)}."
        )
    return {
        "cryptographic_authorization_verified": True,
        "lease_digest": lease_digest,
        "trust_policy_digest": trust_policy_digest,
        "threshold": threshold,
        "verified_signer_ids": sorted(verified_signers),
        "verified_roles": sorted(set(verified_roles)),
    }
