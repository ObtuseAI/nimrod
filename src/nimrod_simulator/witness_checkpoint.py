"""Threshold-signed Witness checkpoints and independently pinned external anchors."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import uuid
from datetime import datetime
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from nimrod_simulator.authorization import parse_timestamp
from nimrod_simulator.errors import (
    AnchorIntegrityError,
    AnchorRollbackError,
    JsonDocumentError,
    KeyGovernanceError,
    KeyTransitionError,
    WitnessCheckpointError,
    WitnessIntegrityError,
)
from nimrod_simulator.jsonio import (
    canonical_json_bytes,
    read_json_object,
    require_integer,
    require_list,
    require_object,
    require_string,
    sha256_digest,
)
from nimrod_simulator.key_governance import (
    SigningConnector,
    decode_public_key,
    decode_signature,
    key_index,
    require_key_active_at,
    validate_governance_state,
)
from nimrod_simulator.model import JsonObject
from nimrod_simulator.witness import read_json_object_from_value, verify_witness_store


CHECKPOINT_DOMAIN = b"nimrod.witness-checkpoint.v0.1\x00"
ANCHOR_RECEIPT_DOMAIN = b"nimrod.witness-anchor-receipt.v0.1\x00"
ANCHOR_HEAD_DOMAIN = b"nimrod.witness-anchor-head.v0.1\x00"


def sha256_bytes(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def merkle_tree_hash(entries: list[JsonObject]) -> str:
    if not entries:
        raise WitnessCheckpointError("Witness checkpoint Merkle tree requires at least one entry.")

    def tree_hash(values: list[JsonObject]) -> bytes:
        if len(values) == 1:
            return hashlib.sha256(b"\x00" + canonical_json_bytes(values[0])).digest()
        split = 1 << ((len(values) - 1).bit_length() - 1)
        left = tree_hash(values[:split])
        right = tree_hash(values[split:])
        return hashlib.sha256(b"\x01" + left + right).digest()

    return f"sha256:{tree_hash(entries).hex()}"


def read_witness_entries(root: Path) -> list[JsonObject]:
    verify_witness_store(root)
    journal_path = root / "witness.jsonl"
    entries: list[JsonObject] = []
    for line_number, raw_line in enumerate(journal_path.read_text(encoding="utf-8").splitlines(), start=1):
        try:
            parsed = json.loads(raw_line)
        except json.JSONDecodeError as error:
            raise WitnessIntegrityError(
                f"Witness journal line {line_number} is invalid JSON: {error.msg}."
            ) from error
        entries.append(read_json_object_from_value(parsed, line_number))
    return entries


def journal_prefix_bytes(entries: list[JsonObject]) -> bytes:
    return b"".join(canonical_json_bytes(entry) + b"\n" for entry in entries)


def checkpoint_message(checkpoint: JsonObject) -> bytes:
    unsigned: JsonObject = {key: value for key, value in checkpoint.items() if key != "signatures"}
    return CHECKPOINT_DOMAIN + canonical_json_bytes(unsigned)


def build_witness_checkpoint(
    witness_root: Path,
    witness_id: str,
    checkpoint_id: str,
    created_at: str,
    previous_checkpoint_digest: str | None,
    governance_state: JsonObject,
    signers: list[SigningConnector],
) -> JsonObject:
    validate_governance_state(governance_state)
    entries = read_witness_entries(witness_root)
    unsigned: JsonObject = {
        "checkpoint_version": "0.1.0",
        "checkpoint_id": checkpoint_id,
        "origin": require_string(governance_state.get("origin"), "governance.origin"),
        "witness_id": witness_id,
        "created_at": created_at,
        "tree_size": len(entries),
        "merkle_root_sha256": merkle_tree_hash(entries),
        "journal_prefix_digest": sha256_bytes(journal_prefix_bytes(entries)),
        "latest_entry_digest": sha256_digest(entries[-1]),
        "previous_checkpoint_digest": previous_checkpoint_digest,
        "governance_id": require_string(governance_state.get("governance_id"), "governance_id"),
        "governance_epoch": require_integer(governance_state.get("epoch"), "governance.epoch"),
        "governance_state_digest": sha256_digest(governance_state),
    }
    message = CHECKPOINT_DOMAIN + canonical_json_bytes(unsigned)
    signatures: list[JsonObject] = []
    seen: set[str] = set()
    state_keys = key_index(governance_state)
    for signer in signers:
        if signer.key_id in seen:
            raise WitnessCheckpointError(f"Witness checkpoint repeats signer '{signer.key_id}'.")
        seen.add(signer.key_id)
        state_key = state_keys.get(signer.key_id)
        if state_key is None or state_key.get("public_key_base64") != signer.public_key_base64:
            raise WitnessCheckpointError(
                f"Checkpoint signing connector '{signer.key_id}' is not bound to the governance state."
            )
        signatures.append(
            {
                "signer_id": signer.key_id,
                "algorithm": "Ed25519",
                "signature_base64": base64.b64encode(signer.sign(message)).decode("ascii"),
            }
        )
    checkpoint: JsonObject = {**unsigned, "signatures": signatures}
    verify_witness_checkpoint(witness_root, checkpoint, governance_state)
    return checkpoint


def verify_checkpoint_signatures(checkpoint: JsonObject, governance_state: JsonObject) -> tuple[list[str], list[str]]:
    try:
        state_keys = key_index(governance_state)
    except KeyGovernanceError as error:
        raise WitnessCheckpointError(f"Checkpoint governance state is invalid: {error}") from error
    created_at = parse_timestamp(checkpoint.get("created_at"), "checkpoint.created_at")
    message = checkpoint_message(checkpoint)
    signatures = require_list(checkpoint.get("signatures"), "checkpoint.signatures")
    seen: set[str] = set()
    roles: set[str] = set()
    verified: list[str] = []
    for index, value in enumerate(signatures):
        signature = require_object(value, f"checkpoint.signatures[{index}]")
        signer_id = require_string(signature.get("signer_id"), f"checkpoint.signatures[{index}].signer_id")
        if signer_id in seen:
            raise WitnessCheckpointError(f"Witness checkpoint repeats signer '{signer_id}'.")
        seen.add(signer_id)
        key = state_keys.get(signer_id)
        if key is None:
            raise WitnessCheckpointError(f"Witness checkpoint uses unknown signer '{signer_id}'.")
        try:
            require_key_active_at(key, created_at)
            public_key = decode_public_key(
                require_string(key.get("public_key_base64"), f"{signer_id}.public_key_base64"), signer_id
            )
            signature_bytes = decode_signature(
                require_string(signature.get("signature_base64"), f"checkpoint.signatures[{index}].signature"),
                signer_id,
            )
        except (KeyGovernanceError, KeyTransitionError) as error:
            raise WitnessCheckpointError(f"Checkpoint signer '{signer_id}' is invalid: {error}") from error
        try:
            Ed25519PublicKey.from_public_bytes(public_key).verify(signature_bytes, message)
        except (InvalidSignature, ValueError) as error:
            raise WitnessCheckpointError(
                f"Witness checkpoint signature verification failed for '{signer_id}'."
            ) from error
        verified.append(signer_id)
        roles.add(require_string(key.get("role"), f"{signer_id}.role"))
    threshold = require_integer(governance_state.get("threshold"), "governance.threshold")
    minimum_roles = require_integer(
        governance_state.get("minimum_distinct_roles"), "governance.minimum_distinct_roles"
    )
    if len(verified) < threshold or len(roles) < minimum_roles:
        raise WitnessCheckpointError(
            f"Witness checkpoint quorum failed: signers={len(verified)}/{threshold}, roles={len(roles)}/{minimum_roles}."
        )
    return sorted(verified), sorted(roles)


def verify_witness_checkpoint(
    witness_root: Path,
    checkpoint: JsonObject,
    governance_state: JsonObject,
) -> JsonObject:
    try:
        validate_governance_state(governance_state)
    except KeyGovernanceError as error:
        raise WitnessCheckpointError(f"Checkpoint governance state is invalid: {error}") from error
    if checkpoint.get("governance_state_digest") != sha256_digest(governance_state):
        raise WitnessCheckpointError("Witness checkpoint governance state digest mismatch.")
    if checkpoint.get("governance_id") != governance_state.get("governance_id"):
        raise WitnessCheckpointError("Witness checkpoint governance ID mismatch.")
    if checkpoint.get("governance_epoch") != governance_state.get("epoch"):
        raise WitnessCheckpointError("Witness checkpoint governance epoch mismatch.")
    entries = read_witness_entries(witness_root)
    tree_size = require_integer(checkpoint.get("tree_size"), "checkpoint.tree_size")
    if tree_size < 1 or tree_size > len(entries):
        raise WitnessCheckpointError(
            f"Witness checkpoint tree size {tree_size} exceeds current verified journal size {len(entries)}."
        )
    prefix = entries[:tree_size]
    checkpoint_created_at = parse_timestamp(checkpoint.get("created_at"), "checkpoint.created_at")
    latest_observed_at = parse_timestamp(prefix[-1].get("observed_at"), "journal.latest.observed_at")
    if checkpoint_created_at < latest_observed_at:
        raise WitnessCheckpointError("Witness checkpoint predates its latest committed journal entry.")
    if checkpoint.get("merkle_root_sha256") != merkle_tree_hash(prefix):
        raise WitnessCheckpointError("Witness checkpoint Merkle root does not match the journal prefix.")
    if checkpoint.get("journal_prefix_digest") != sha256_bytes(journal_prefix_bytes(prefix)):
        raise WitnessCheckpointError("Witness checkpoint journal prefix digest mismatch.")
    if checkpoint.get("latest_entry_digest") != sha256_digest(prefix[-1]):
        raise WitnessCheckpointError("Witness checkpoint latest entry digest mismatch.")
    verified_signers, verified_roles = verify_checkpoint_signatures(checkpoint, governance_state)
    return {
        "status": "WITNESS_CHECKPOINT_VALID",
        "checkpoint_digest": sha256_digest(checkpoint),
        "tree_size": tree_size,
        "verified_signer_ids": verified_signers,
        "verified_roles": verified_roles,
    }


def require_separate_roots(paths: list[Path]) -> None:
    resolved = [path.resolve() for path in paths]
    for index, path in enumerate(resolved):
        for other_index, other in enumerate(resolved):
            if index == other_index:
                continue
            if path == other or path in other.parents or other in path.parents:
                raise AnchorIntegrityError(
                    f"Witness, anchor, and pin roots must be separate non-nested paths: '{path}' and '{other}'."
                )


def anchor_key(policy: JsonObject) -> tuple[str, bytes]:
    key = require_object(policy.get("anchor_key"), "anchor_policy.anchor_key")
    key_id = require_string(key.get("key_id"), "anchor_policy.anchor_key.key_id")
    algorithm = require_string(key.get("algorithm"), "anchor_policy.anchor_key.algorithm")
    if algorithm != "Ed25519":
        raise AnchorIntegrityError(f"Anchor key '{key_id}' uses unsupported algorithm '{algorithm}'.")
    encoded = require_string(key.get("public_key_base64"), "anchor_policy.anchor_key.public_key_base64")
    try:
        decoded = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as error:
        raise AnchorIntegrityError(f"Anchor key '{key_id}' public key is invalid base64.") from error
    if len(decoded) != 32:
        raise AnchorIntegrityError(f"Anchor key '{key_id}' must be 32 bytes; received {len(decoded)}.")
    return key_id, decoded


def require_anchor_policy(policy: JsonObject, now: datetime) -> None:
    not_before = parse_timestamp(policy.get("not_before"), "anchor_policy.not_before")
    expires_at = parse_timestamp(policy.get("expires_at"), "anchor_policy.expires_at")
    if now.tzinfo is None or now < not_before or now >= expires_at:
        raise AnchorIntegrityError(
            f"Anchor policy is not active at '{now.isoformat()}'; window is {not_before.isoformat()} to {expires_at.isoformat()}."
        )
    anchor_key(policy)


def signed_anchor_document(unsigned: JsonObject, domain: bytes, connector: SigningConnector) -> JsonObject:
    message = domain + canonical_json_bytes(unsigned)
    return {
        **unsigned,
        "signature_base64": base64.b64encode(connector.sign(message)).decode("ascii"),
    }


def verify_anchor_signature(document: JsonObject, domain: bytes, policy: JsonObject, label: str) -> None:
    key_id, public_key = anchor_key(policy)
    if document.get("anchor_key_id") != key_id:
        raise AnchorIntegrityError(f"{label} anchor key ID does not match policy key '{key_id}'.")
    unsigned: JsonObject = {key: value for key, value in document.items() if key != "signature_base64"}
    signature_value = require_string(document.get("signature_base64"), f"{label}.signature_base64")
    try:
        signature = base64.b64decode(signature_value, validate=True)
    except (binascii.Error, ValueError) as error:
        raise AnchorIntegrityError(f"{label} signature is not canonical base64.") from error
    if len(signature) != 64:
        raise AnchorIntegrityError(f"{label} signature must be 64 bytes; received {len(signature)}.")
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            signature, domain + canonical_json_bytes(unsigned)
        )
    except (InvalidSignature, ValueError) as error:
        raise AnchorIntegrityError(f"{label} Ed25519 signature verification failed.") from error


def write_new_durable(path: Path, value: JsonObject) -> None:
    try:
        with path.open("xb") as handle:
            handle.write(canonical_json_bytes(value) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
    except FileExistsError as error:
        raise AnchorIntegrityError(f"External anchor path already exists: '{path}'.") from error


class FileExternalAnchorStore:
    """Independent filesystem connector for signed checkpoint receipts and heads."""

    def __init__(
        self,
        root: Path,
        witness_root: Path,
        pin_root: Path,
        policy: JsonObject,
        signing_connector: SigningConnector,
    ) -> None:
        require_separate_roots([root, witness_root, pin_root])
        if root.exists() and any(root.iterdir()):
            raise AnchorIntegrityError(f"External anchor root must be new or empty: '{root}'.")
        key_id, public_key = anchor_key(policy)
        connector_public = base64.b64decode(signing_connector.public_key_base64, validate=True)
        if signing_connector.key_id != key_id or connector_public != public_key:
            raise AnchorIntegrityError("External anchor connector does not match the anchor policy key.")
        self._root = root
        self._witness_root = witness_root
        self._policy = policy
        self._connector = signing_connector
        self._checkpoint_root = root / "checkpoints" / "sha256"
        self._receipt_root = root / "receipts"
        self._head_root = root / "heads"
        self._checkpoint_root.mkdir(parents=True)
        self._receipt_root.mkdir(parents=True)
        self._head_root.mkdir(parents=True)
        self._sequence = 0
        self._previous_receipt_digest: str | None = None
        self._previous_checkpoint_digest: str | None = None
        self._previous_anchored_at: datetime | None = None

    def anchor(
        self,
        checkpoint: JsonObject,
        governance_state: JsonObject,
        anchored_at: str,
    ) -> tuple[JsonObject, JsonObject]:
        now = parse_timestamp(anchored_at, "anchored_at")
        require_anchor_policy(self._policy, now)
        if self._previous_anchored_at is not None and now <= self._previous_anchored_at:
            raise AnchorIntegrityError("External anchor timestamps must increase monotonically.")
        checkpoint_created_at = parse_timestamp(checkpoint.get("created_at"), "checkpoint.created_at")
        if checkpoint_created_at > now:
            raise AnchorIntegrityError("External anchor cannot predate its Witness checkpoint.")
        witness_id = require_string(checkpoint.get("witness_id"), "checkpoint.witness_id")
        allowed = require_list(self._policy.get("allowed_witness_ids"), "anchor_policy.allowed_witness_ids")
        if witness_id not in allowed:
            raise AnchorIntegrityError(f"Witness '{witness_id}' is not allowed by the anchor policy.")
        verify_witness_checkpoint(self._witness_root, checkpoint, governance_state)
        if checkpoint.get("previous_checkpoint_digest") != self._previous_checkpoint_digest:
            raise AnchorIntegrityError("Witness checkpoint does not chain to the previous anchored checkpoint.")
        checkpoint_digest = sha256_digest(checkpoint)
        checkpoint_path = self._checkpoint_root / f"{checkpoint_digest.removeprefix('sha256:')}.json"
        write_new_durable(checkpoint_path, checkpoint)
        sequence = self._sequence + 1
        receipt_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"{self._policy['anchor_store_id']}:{sequence}:{checkpoint_digest}"))
        receipt_unsigned: JsonObject = {
            "receipt_version": "0.1.0",
            "receipt_id": receipt_id,
            "origin": self._policy["origin"],
            "anchor_store_id": self._policy["anchor_store_id"],
            "anchor_policy_digest": sha256_digest(self._policy),
            "sequence": sequence,
            "anchored_at": anchored_at,
            "checkpoint_digest": checkpoint_digest,
            "checkpoint_id": checkpoint["checkpoint_id"],
            "tree_size": checkpoint["tree_size"],
            "previous_receipt_digest": self._previous_receipt_digest,
            "anchor_key_id": self._connector.key_id,
        }
        receipt = signed_anchor_document(receipt_unsigned, ANCHOR_RECEIPT_DOMAIN, self._connector)
        receipt_path = self._receipt_root / f"{sequence:08d}.json"
        write_new_durable(receipt_path, receipt)
        receipt_digest = sha256_digest(receipt)
        head_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"{self._policy['anchor_store_id']}:head:{sequence}"))
        head_unsigned: JsonObject = {
            "head_version": "0.1.0",
            "head_id": head_id,
            "origin": self._policy["origin"],
            "anchor_store_id": self._policy["anchor_store_id"],
            "anchor_policy_digest": sha256_digest(self._policy),
            "sequence": sequence,
            "latest_receipt_digest": receipt_digest,
            "latest_checkpoint_digest": checkpoint_digest,
            "tree_size": checkpoint["tree_size"],
            "issued_at": anchored_at,
            "anchor_key_id": self._connector.key_id,
        }
        head = signed_anchor_document(head_unsigned, ANCHOR_HEAD_DOMAIN, self._connector)
        head_path = self._head_root / f"{sequence:08d}.json"
        write_new_durable(head_path, head)
        temporary_head = self._root / f".anchor-head.{uuid.uuid4().hex}.tmp"
        write_new_durable(temporary_head, head)
        os.replace(temporary_head, self._root / "anchor-head.json")
        self._sequence = sequence
        self._previous_receipt_digest = receipt_digest
        self._previous_checkpoint_digest = checkpoint_digest
        self._previous_anchored_at = now
        return receipt, head


class FileAnchorPinStore:
    """Separate trusted-input boundary for the latest externally observed anchor head."""

    def __init__(self, root: Path, witness_root: Path, anchor_root: Path) -> None:
        require_separate_roots([root, witness_root, anchor_root])
        self._root = root
        self._root.mkdir(parents=True, exist_ok=True)
        self._path = root / "pinned-anchor-head.json"

    def pin(self, head: JsonObject, policy: JsonObject) -> Path:
        verify_anchor_signature(head, ANCHOR_HEAD_DOMAIN, policy, "anchor head")
        if self._path.is_file():
            current = read_json_object(self._path)
            current_sequence = require_integer(current.get("sequence"), "pinned.sequence")
            next_sequence = require_integer(head.get("sequence"), "head.sequence")
            if next_sequence <= current_sequence:
                raise AnchorRollbackError(
                    f"Pinned anchor head cannot move from sequence {current_sequence} to {next_sequence}."
                )
        temporary = self._root / f".pinned-head.{uuid.uuid4().hex}.tmp"
        write_new_durable(temporary, head)
        os.replace(temporary, self._path)
        return self._path


def verify_anchor_receipt(receipt: JsonObject, policy: JsonObject) -> None:
    verify_anchor_signature(receipt, ANCHOR_RECEIPT_DOMAIN, policy, "anchor receipt")
    if receipt.get("anchor_store_id") != policy.get("anchor_store_id"):
        raise AnchorIntegrityError("Anchor receipt store ID does not match policy.")
    if receipt.get("anchor_policy_digest") != sha256_digest(policy):
        raise AnchorIntegrityError("Anchor receipt does not bind the supplied anchor policy digest.")


def verify_anchor_head(head: JsonObject, policy: JsonObject) -> None:
    verify_anchor_signature(head, ANCHOR_HEAD_DOMAIN, policy, "anchor head")
    if head.get("anchor_store_id") != policy.get("anchor_store_id"):
        raise AnchorIntegrityError("Anchor head store ID does not match policy.")
    if head.get("anchor_policy_digest") != sha256_digest(policy):
        raise AnchorIntegrityError("Anchor head does not bind the supplied anchor policy digest.")


def verify_external_anchor_store(
    witness_root: Path,
    anchor_root: Path,
    governance_state: JsonObject,
    policy: JsonObject,
    pinned_head: JsonObject,
    now: datetime,
) -> JsonObject:
    require_separate_roots([witness_root, anchor_root])
    require_anchor_policy(policy, now)
    verify_anchor_head(pinned_head, policy)
    receipt_paths = sorted((anchor_root / "receipts").glob("*.json"))
    if not receipt_paths:
        raise AnchorIntegrityError(f"External anchor has no receipts: '{anchor_root}'.")
    previous_receipt_digest: str | None = None
    previous_checkpoint_digest: str | None = None
    previous_tree_size = 0
    previous_anchored_at: datetime | None = None
    receipts: list[JsonObject] = []
    heads: list[JsonObject] = []
    for expected_sequence, path in enumerate(receipt_paths, start=1):
        receipt = read_json_object(path)
        verify_anchor_receipt(receipt, policy)
        sequence = require_integer(receipt.get("sequence"), "receipt.sequence")
        if sequence != expected_sequence:
            raise AnchorIntegrityError(
                f"Anchor receipt sequence mismatch: expected {expected_sequence}, received {sequence}."
            )
        if receipt.get("previous_receipt_digest") != previous_receipt_digest:
            raise AnchorIntegrityError(f"Anchor receipt chain mismatch at sequence {sequence}.")
        anchored_at = parse_timestamp(receipt.get("anchored_at"), "receipt.anchored_at")
        require_anchor_policy(policy, anchored_at)
        if previous_anchored_at is not None and anchored_at <= previous_anchored_at:
            raise AnchorIntegrityError(f"Anchor receipt timestamp does not increase at sequence {sequence}.")
        checkpoint_digest = require_string(receipt.get("checkpoint_digest"), "receipt.checkpoint_digest")
        checkpoint_path = anchor_root / "checkpoints" / "sha256" / f"{checkpoint_digest.removeprefix('sha256:')}.json"
        try:
            checkpoint = read_json_object(checkpoint_path)
        except JsonDocumentError as error:
            raise AnchorIntegrityError(
                f"Anchored checkpoint is missing or malformed at sequence {sequence}: '{checkpoint_path}'."
            ) from error
        if sha256_digest(checkpoint) != checkpoint_digest:
            raise AnchorIntegrityError(f"Anchored checkpoint digest mismatch at sequence {sequence}.")
        if checkpoint.get("previous_checkpoint_digest") != previous_checkpoint_digest:
            raise AnchorIntegrityError(f"Anchored checkpoint chain mismatch at sequence {sequence}.")
        checkpoint_result = verify_witness_checkpoint(witness_root, checkpoint, governance_state)
        checkpoint_created_at = parse_timestamp(checkpoint.get("created_at"), "checkpoint.created_at")
        if checkpoint_created_at > anchored_at:
            raise AnchorIntegrityError(f"Anchor receipt predates checkpoint at sequence {sequence}.")
        tree_size = require_integer(checkpoint.get("tree_size"), "checkpoint.tree_size")
        if tree_size <= previous_tree_size:
            raise AnchorIntegrityError(
                f"Anchored checkpoint tree size must increase: previous {previous_tree_size}, current {tree_size}."
            )
        if receipt.get("tree_size") != tree_size or receipt.get("checkpoint_id") != checkpoint.get("checkpoint_id"):
            raise AnchorIntegrityError(f"Anchor receipt does not bind checkpoint metadata at sequence {sequence}.")
        previous_receipt_digest = sha256_digest(receipt)
        previous_checkpoint_digest = str(checkpoint_result["checkpoint_digest"])
        previous_tree_size = tree_size
        previous_anchored_at = anchored_at
        receipts.append(receipt)
        historical_head_path = anchor_root / "heads" / f"{sequence:08d}.json"
        try:
            historical_head = read_json_object(historical_head_path)
        except JsonDocumentError as error:
            raise AnchorIntegrityError(
                f"Anchor head history is missing or malformed at sequence {sequence}: '{historical_head_path}'."
            ) from error
        verify_anchor_head(historical_head, policy)
        if historical_head.get("sequence") != sequence:
            raise AnchorIntegrityError(f"Historical anchor head sequence mismatch at {sequence}.")
        if historical_head.get("latest_receipt_digest") != previous_receipt_digest:
            raise AnchorIntegrityError(f"Historical anchor head receipt digest mismatch at {sequence}.")
        if historical_head.get("latest_checkpoint_digest") != previous_checkpoint_digest:
            raise AnchorIntegrityError(f"Historical anchor head checkpoint digest mismatch at {sequence}.")
        if historical_head.get("tree_size") != tree_size or historical_head.get("issued_at") != receipt.get("anchored_at"):
            raise AnchorIntegrityError(f"Historical anchor head metadata mismatch at {sequence}.")
        heads.append(historical_head)
    current_head_path = anchor_root / "anchor-head.json"
    try:
        current_head = read_json_object(current_head_path)
    except JsonDocumentError as error:
        raise AnchorIntegrityError(
            f"External anchor current head is missing or malformed: '{current_head_path}'."
        ) from error
    verify_anchor_head(current_head, policy)
    if sha256_digest(current_head) != sha256_digest(heads[-1]):
        raise AnchorIntegrityError("External anchor current head does not equal the latest signed historical head.")
    current_sequence = require_integer(current_head.get("sequence"), "anchor_head.sequence")
    if current_sequence != len(receipts):
        raise AnchorIntegrityError(
            f"Anchor head sequence {current_sequence} does not match receipt count {len(receipts)}."
        )
    if current_head.get("latest_receipt_digest") != previous_receipt_digest:
        raise AnchorIntegrityError("Anchor head latest receipt digest mismatch.")
    if current_head.get("latest_checkpoint_digest") != previous_checkpoint_digest:
        raise AnchorIntegrityError("Anchor head latest checkpoint digest mismatch.")
    if current_head.get("tree_size") != previous_tree_size:
        raise AnchorIntegrityError("Anchor head tree size mismatch.")
    pinned_sequence = require_integer(pinned_head.get("sequence"), "pinned_head.sequence")
    if current_sequence < pinned_sequence:
        raise AnchorRollbackError(
            f"Anchor rolled back from pinned sequence {pinned_sequence} to {current_sequence}."
        )
    pinned_store_head_path = anchor_root / "heads" / f"{pinned_sequence:08d}.json"
    try:
        pinned_store_head = read_json_object(pinned_store_head_path)
    except JsonDocumentError as error:
        raise AnchorRollbackError(
            f"Anchor lacks the independently pinned head at sequence {pinned_sequence}."
        ) from error
    if sha256_digest(pinned_store_head) != sha256_digest(pinned_head):
        raise AnchorRollbackError(
            f"Anchor head at sequence {pinned_sequence} disagrees with the independent pin."
        )
    minimum_sequence = require_integer(policy.get("minimum_head_sequence"), "policy.minimum_head_sequence")
    if current_sequence < minimum_sequence:
        raise AnchorRollbackError(
            f"Anchor sequence {current_sequence} is below policy minimum {minimum_sequence}."
        )
    return {
        "status": "EXTERNAL_WITNESS_ANCHOR_VALID",
        "receipt_count": len(receipts),
        "latest_sequence": current_sequence,
        "latest_tree_size": previous_tree_size,
        "latest_checkpoint_digest": previous_checkpoint_digest,
        "pinned_head_verified": True,
        "merkle_construction": "rfc9162_sha256_domain_separated",
    }
