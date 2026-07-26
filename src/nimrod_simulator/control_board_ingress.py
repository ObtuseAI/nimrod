"""Signed, freshness-bound, crash-recoverable control-board snapshot ingress."""

from __future__ import annotations

import base64
import binascii
import os
import time
import uuid
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import TypedDict

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from nimrod_simulator.authorization import parse_timestamp
from nimrod_simulator.errors import (
    ControlBoardIngressIntegrityError,
    ControlBoardIngressPathExistsError,
    ControlBoardIngressReplayError,
    ControlBoardIngressRollbackError,
    ControlStateValidationError,
    ControlBoardSnapshotError,
    ControlBoardSnapshotSignatureError,
    JsonDocumentError,
    KeyTransitionError,
)
from nimrod_simulator.jsonio import (
    canonical_json_bytes,
    read_json_object,
    require_boolean,
    require_integer,
    require_list,
    require_object,
    require_string,
    sha256_digest,
)
from nimrod_simulator.key_governance import (
    SigningConnector,
    decode_public_key,
    key_index,
    require_key_active_at,
    validate_governance_state,
)
from nimrod_simulator.model import JsonObject


SNAPSHOT_DOMAIN = b"nimrod.control-board-snapshot.v0.1\x00"
SNAPSHOT_AUDIENCE = "nimrod-control-board"
DURABLE_READ_ATTEMPTS = 16
DURABLE_READ_DELAY_SECONDS = 0.01
FailureInjector = Callable[[str], None]


class VerifiedSnapshot(TypedDict):
    snapshot_digest: str
    projection_digest: str
    issuer_service_id: str
    sequence: int
    freshness_seconds: int
    verified_signer_ids: list[str]
    verified_roles: list[str]


class IngressStateReport(TypedDict):
    state_version: str
    accepted_sequence: int
    accepted_snapshot_digest: str | None
    record_count: int
    owner_count: int
    orphan_preparation_count: int


def no_ingress_failure(phase: str) -> None:
    """Production hook that deliberately injects no ingress failure."""
    if not phase:
        raise ControlBoardIngressIntegrityError("Control-board ingress failure phase cannot be empty.")


def snapshot_message(snapshot: JsonObject) -> bytes:
    unsigned: JsonObject = {key: value for key, value in snapshot.items() if key != "signatures"}
    return SNAPSHOT_DOMAIN + canonical_json_bytes(unsigned)


def sign_control_board_snapshot(
    unsigned_snapshot: JsonObject, connectors: list[SigningConnector]
) -> JsonObject:
    if "signatures" in unsigned_snapshot:
        raise ControlBoardSnapshotSignatureError("Unsigned control-board snapshot contains signatures.")
    signatures: list[JsonObject] = []
    seen: set[str] = set()
    message = SNAPSHOT_DOMAIN + canonical_json_bytes(unsigned_snapshot)
    for connector in connectors:
        if connector.key_id in seen:
            raise ControlBoardSnapshotSignatureError(
                f"Control-board snapshot repeats signing connector '{connector.key_id}'."
            )
        seen.add(connector.key_id)
        signatures.append(
            {
                "signer_id": connector.key_id,
                "algorithm": "Ed25519",
                "signature_base64": base64.b64encode(connector.sign(message)).decode("ascii"),
            }
        )
    return {**unsigned_snapshot, "signatures": signatures}


def _decode_snapshot_signature(value: str, signer_id: str) -> bytes:
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as error:
        raise ControlBoardSnapshotSignatureError(
            f"Control-board snapshot signature for '{signer_id}' is not canonical base64."
        ) from error
    if len(decoded) != 64:
        raise ControlBoardSnapshotSignatureError(
            f"Control-board snapshot signature for '{signer_id}' must be 64 bytes; received {len(decoded)}."
        )
    return decoded


def _verify_snapshot_signatures(
    snapshot: JsonObject, governance_state: JsonObject, issued_at: datetime
) -> tuple[list[str], list[str]]:
    keys = key_index(governance_state)
    signatures = require_list(snapshot.get("signatures"), "snapshot.signatures")
    message = snapshot_message(snapshot)
    seen: set[str] = set()
    roles: set[str] = set()
    verified: list[str] = []
    for index, value in enumerate(signatures):
        signature = require_object(value, f"snapshot.signatures[{index}]")
        signer_id = require_string(signature.get("signer_id"), f"snapshot.signatures[{index}].signer_id")
        if signer_id in seen:
            raise ControlBoardSnapshotSignatureError(
                f"Control-board snapshot repeats signer '{signer_id}'."
            )
        seen.add(signer_id)
        key = keys.get(signer_id)
        if key is None:
            raise ControlBoardSnapshotSignatureError(
                f"Control-board snapshot contains unknown signer '{signer_id}'."
            )
        try:
            require_key_active_at(key, issued_at)
        except KeyTransitionError as error:
            raise ControlBoardSnapshotSignatureError(
                f"Control-board snapshot signer '{signer_id}' is not active at issuance."
            ) from error
        if require_string(signature.get("algorithm"), f"snapshot.signatures[{index}].algorithm") != "Ed25519":
            raise ControlBoardSnapshotSignatureError(
                f"Control-board snapshot signer '{signer_id}' does not use Ed25519."
            )
        public_key = decode_public_key(
            require_string(key.get("public_key_base64"), f"{signer_id}.public_key_base64"), signer_id
        )
        signature_bytes = _decode_snapshot_signature(
            require_string(signature.get("signature_base64"), f"snapshot.signatures[{index}].signature_base64"),
            signer_id,
        )
        try:
            Ed25519PublicKey.from_public_bytes(public_key).verify(signature_bytes, message)
        except (InvalidSignature, ValueError) as error:
            raise ControlBoardSnapshotSignatureError(
                f"Control-board snapshot signature verification failed for '{signer_id}'."
            ) from error
        verified.append(signer_id)
        roles.add(require_string(key.get("role"), f"{signer_id}.role"))
    threshold = require_integer(governance_state.get("threshold"), "governance.threshold")
    minimum_roles = require_integer(
        governance_state.get("minimum_distinct_roles"), "governance.minimum_distinct_roles"
    )
    if len(verified) < threshold:
        raise ControlBoardSnapshotSignatureError(
            f"Control-board snapshot threshold not met: verified {len(verified)}, required {threshold}."
        )
    if len(roles) < minimum_roles:
        raise ControlBoardSnapshotSignatureError(
            f"Control-board snapshot role diversity not met: verified {len(roles)}, required {minimum_roles}."
        )
    return sorted(verified), sorted(roles)


def _aware_timestamp(value: object, field: str) -> datetime:
    try:
        parsed = parse_timestamp(value, field)
    except ControlStateValidationError as error:
        raise ControlBoardSnapshotError(
            f"Control-board timestamp '{field}' is invalid: {error}."
        ) from error
    if parsed.utcoffset() is None:
        raise ControlBoardSnapshotError(f"Control-board timestamp '{field}' must include a UTC offset.")
    return parsed


def verify_control_board_snapshot(
    snapshot: JsonObject,
    projection: JsonObject,
    governance_state: JsonObject,
    required_issuer_service_id: str,
    now: datetime,
    maximum_lifetime_seconds: int,
    maximum_future_skew_seconds: int,
) -> VerifiedSnapshot:
    if maximum_lifetime_seconds <= 0:
        raise ControlBoardSnapshotError("Maximum control-board snapshot lifetime must be positive.")
    if maximum_future_skew_seconds < 0:
        raise ControlBoardSnapshotError("Maximum control-board future skew cannot be negative.")
    validate_governance_state(governance_state)
    if require_string(snapshot.get("snapshot_version"), "snapshot.snapshot_version") != "0.1.0":
        raise ControlBoardSnapshotError("Control-board snapshot_version must be '0.1.0'.")
    if require_string(snapshot.get("snapshot_kind"), "snapshot.snapshot_kind") != "verifier_projection":
        raise ControlBoardSnapshotError("Control-board snapshot kind must be 'verifier_projection'.")
    issuer = require_string(snapshot.get("issuer_service_id"), "snapshot.issuer_service_id")
    if issuer != required_issuer_service_id:
        raise ControlBoardSnapshotError(
            f"Control-board snapshot issuer '{issuer}' does not match required issuer '{required_issuer_service_id}'."
        )
    if require_string(snapshot.get("audience"), "snapshot.audience") != SNAPSHOT_AUDIENCE:
        raise ControlBoardSnapshotError(
            f"Control-board snapshot audience must be '{SNAPSHOT_AUDIENCE}'."
        )
    origin = require_string(snapshot.get("origin"), "snapshot.origin")
    if projection.get("origin") != origin or governance_state.get("origin") != origin:
        raise ControlBoardSnapshotError("Snapshot, projection, and governance origins must match.")
    expected_governance_digest = sha256_digest(governance_state)
    if snapshot.get("governance_state_digest") != expected_governance_digest:
        raise ControlBoardSnapshotError("Control-board snapshot governance-state digest mismatch.")
    expected_projection_digest = sha256_digest(projection)
    if snapshot.get("projection_digest") != expected_projection_digest:
        raise ControlBoardSnapshotError("Control-board snapshot projection digest mismatch.")
    projection_authority = require_object(projection.get("authority"), "projection.authority")
    if require_boolean(projection_authority.get("can_authorize"), "projection.authority.can_authorize"):
        raise ControlBoardSnapshotError("Signed verifier projection cannot authorize.")
    if require_boolean(projection_authority.get("can_execute"), "projection.authority.can_execute"):
        raise ControlBoardSnapshotError("Signed verifier projection cannot execute.")
    authority = require_object(snapshot.get("authority"), "snapshot.authority")
    if require_boolean(authority.get("can_authorize"), "snapshot.authority.can_authorize"):
        raise ControlBoardSnapshotError("Control-board snapshot transport cannot authorize.")
    if require_boolean(authority.get("can_execute"), "snapshot.authority.can_execute"):
        raise ControlBoardSnapshotError("Control-board snapshot transport cannot execute.")
    issued_at = _aware_timestamp(snapshot.get("issued_at"), "snapshot.issued_at")
    not_before = _aware_timestamp(snapshot.get("not_before"), "snapshot.not_before")
    expires_at = _aware_timestamp(snapshot.get("expires_at"), "snapshot.expires_at")
    if issued_at > not_before or not_before >= expires_at:
        raise ControlBoardSnapshotError(
            "Control-board snapshot requires issued_at <= not_before < expires_at."
        )
    lifetime_seconds = int((expires_at - issued_at).total_seconds())
    if lifetime_seconds > maximum_lifetime_seconds:
        raise ControlBoardSnapshotError(
            f"Control-board snapshot lifetime {lifetime_seconds}s exceeds {maximum_lifetime_seconds}s."
        )
    future_seconds = int((issued_at - now).total_seconds())
    if future_seconds > maximum_future_skew_seconds:
        raise ControlBoardSnapshotError(
            f"Control-board snapshot issuance is {future_seconds}s in the future; allowed skew is {maximum_future_skew_seconds}s."
        )
    if now < not_before:
        raise ControlBoardSnapshotError("Control-board snapshot is not yet active.")
    if now >= expires_at:
        raise ControlBoardSnapshotError("Control-board snapshot is stale and expired.")
    captured_at = _aware_timestamp(projection.get("captured_at"), "projection.captured_at")
    if captured_at > issued_at:
        raise ControlBoardSnapshotError("Control-board projection capture time is after snapshot issuance.")
    verified_signers, verified_roles = _verify_snapshot_signatures(snapshot, governance_state, issued_at)
    return {
        "snapshot_digest": sha256_digest(snapshot),
        "projection_digest": expected_projection_digest,
        "issuer_service_id": issuer,
        "sequence": require_integer(snapshot.get("sequence"), "snapshot.sequence"),
        "freshness_seconds": max(0, int((now - issued_at).total_seconds())),
        "verified_signer_ids": verified_signers,
        "verified_roles": verified_roles,
    }


class FileControlBoardIngressStore:
    """Filesystem boundary for crash-recoverable, monotonic snapshot acceptance."""

    def __init__(self, root: Path, issuer_service_id: str, failure_injector: FailureInjector) -> None:
        if not issuer_service_id:
            raise ControlBoardIngressIntegrityError("Control-board ingress requires a non-empty issuer service ID.")
        self._issuer = issuer_service_id
        self._root = root / "control-board-ingress" / "v1" / issuer_service_id
        self._prepared_root = self._root / "prepared"
        self._owner_root = self._root / "owners"
        self._record_root = self._root / "records"
        self._head_path = self._root / "head.json"
        self._failure_injector = failure_injector
        self._prepared_root.mkdir(parents=True, exist_ok=True)
        self._owner_root.mkdir(parents=True, exist_ok=True)
        self._record_root.mkdir(parents=True, exist_ok=True)
        self.recover()

    def accept(
        self,
        snapshot: JsonObject,
        projection: JsonObject,
        governance_state: JsonObject,
        accepted_at: datetime,
        maximum_lifetime_seconds: int,
        maximum_future_skew_seconds: int,
    ) -> JsonObject:
        verified = verify_control_board_snapshot(
            snapshot,
            projection,
            governance_state,
            self._issuer,
            accepted_at,
            maximum_lifetime_seconds,
            maximum_future_skew_seconds,
        )
        sequence = verified["sequence"]
        current = self.inspect()
        expected_sequence = current["accepted_sequence"] + 1
        if sequence < expected_sequence:
            raise ControlBoardIngressReplayError(
                f"Control-board snapshot sequence {sequence} was already accepted; next is {expected_sequence}."
            )
        if sequence > expected_sequence:
            raise ControlBoardIngressRollbackError(
                f"Control-board snapshot sequence gap: received {sequence}, expected {expected_sequence}."
            )
        previous_digest = snapshot.get("previous_snapshot_digest")
        if previous_digest != current["accepted_snapshot_digest"]:
            raise ControlBoardIngressRollbackError(
                "Control-board snapshot previous digest does not match the durable accepted head."
            )
        prepared: JsonObject = {
            "prepared_version": "0.1.0",
            "issuer_service_id": self._issuer,
            "sequence": sequence,
            "snapshot_digest": verified["snapshot_digest"],
            "projection_digest": verified["projection_digest"],
            "snapshot": snapshot,
        }
        prepared_path = self._prepared_root / f"{sequence:020d}.{uuid.uuid4().hex}.json"
        self._write_new_durable(prepared_path, prepared)
        self._failure_injector("prepared_durable")
        owner: JsonObject = {
            "owner_version": "0.1.0",
            "issuer_service_id": self._issuer,
            "sequence": sequence,
            "prepared_name": prepared_path.name,
            "prepared_digest": sha256_digest(prepared),
        }
        owner_path = self._owner_path(sequence)
        try:
            self._write_new_durable(owner_path, owner)
        except ControlBoardIngressIntegrityError as error:
            self.recover()
            raise ControlBoardIngressReplayError(
                f"Control-board snapshot sequence {sequence} already has a durable owner."
            ) from error
        self._failure_injector("owner_durable")
        record = self._publish_record(owner, prepared)
        self._failure_injector("record_durable")
        self._publish_head(record)
        self._failure_injector("head_published")
        return {
            "ingress_version": "0.1.0",
            "origin": snapshot["origin"],
            "status": "accepted",
            "issuer_service_id": self._issuer,
            "audience": SNAPSHOT_AUDIENCE,
            "sequence": sequence,
            "snapshot_id": snapshot["snapshot_id"],
            "snapshot_digest": verified["snapshot_digest"],
            "projection_digest": verified["projection_digest"],
            "accepted_at": accepted_at.isoformat().replace("+00:00", "Z"),
            "freshness_seconds": verified["freshness_seconds"],
            "verified_signer_ids": verified["verified_signer_ids"],
            "verified_roles": verified["verified_roles"],
            "durable_replay_guard": True,
            "stale_state_guard": True,
            "authority": {"can_authorize": False, "can_execute": False},
        }

    def recover(self) -> IngressStateReport:
        for owner_path in sorted(self._owner_root.glob("*.json")):
            owner = self._read(owner_path, "ingress owner")
            sequence = require_integer(owner.get("sequence"), "owner.sequence")
            record_path = self._record_path(sequence)
            if record_path.is_file():
                self._verify_record(self._read(record_path, "ingress record"), sequence)
                continue
            prepared_name = require_string(owner.get("prepared_name"), "owner.prepared_name")
            prepared_path = self._prepared_root / prepared_name
            prepared = self._read(prepared_path, "ingress preparation")
            if sha256_digest(prepared) != owner.get("prepared_digest"):
                raise ControlBoardIngressIntegrityError(
                    f"Ingress owner sequence {sequence} does not bind its preparation."
                )
            self._publish_record(owner, prepared)
        records = self._ordered_records()
        previous_digest: str | None = None
        for expected_sequence, record in enumerate(records, start=1):
            self._verify_record(record, expected_sequence)
            snapshot = require_object(record.get("snapshot"), f"records[{expected_sequence}].snapshot")
            if snapshot.get("previous_snapshot_digest") != previous_digest:
                raise ControlBoardIngressIntegrityError(
                    f"Ingress record sequence {expected_sequence} breaks the snapshot digest chain."
                )
            previous_digest = require_string(record.get("snapshot_digest"), "record.snapshot_digest")
        if records:
            self._verify_existing_head(records)
            self._publish_head(records[-1])
        elif self._head_path.exists():
            raise ControlBoardIngressIntegrityError("Ingress head exists without immutable acceptance records.")
        return self._state_report(records)

    def _verify_existing_head(self, records: list[JsonObject]) -> None:
        if not self._head_path.is_file():
            return
        head = self._read(self._head_path, "ingress head")
        sequence = require_integer(head.get("sequence"), "head.sequence")
        if sequence < 1 or sequence > len(records):
            raise ControlBoardIngressIntegrityError(
                f"Ingress head sequence {sequence} is outside the immutable record chain."
            )
        record = records[sequence - 1]
        expected: JsonObject = {
            "head_version": "0.1.0",
            "issuer_service_id": self._issuer,
            "sequence": sequence,
            "snapshot_digest": require_string(record.get("snapshot_digest"), "record.snapshot_digest"),
            "record_digest": sha256_digest(record),
        }
        if head != expected:
            raise ControlBoardIngressIntegrityError(
                f"Ingress head sequence {sequence} does not bind its immutable record."
            )

    def inspect(self) -> IngressStateReport:
        return self.recover()

    def _state_report(self, records: list[JsonObject]) -> IngressStateReport:
        owner_count = len(list(self._owner_root.glob("*.json")))
        owned_preparations: set[str] = set()
        for owner_path in self._owner_root.glob("*.json"):
            owner = self._read(owner_path, "ingress owner")
            owned_preparations.add(require_string(owner.get("prepared_name"), "owner.prepared_name"))
        orphan_count = sum(
            1 for path in self._prepared_root.glob("*.json") if path.name not in owned_preparations
        )
        if not records:
            return {
                "state_version": "0.1.0",
                "accepted_sequence": 0,
                "accepted_snapshot_digest": None,
                "record_count": 0,
                "owner_count": owner_count,
                "orphan_preparation_count": orphan_count,
            }
        latest = records[-1]
        sequence = require_integer(latest.get("sequence"), "record.sequence")
        snapshot_digest = require_string(latest.get("snapshot_digest"), "record.snapshot_digest")
        self._verify_head(sequence, snapshot_digest, sha256_digest(latest))
        return {
            "state_version": "0.1.0",
            "accepted_sequence": sequence,
            "accepted_snapshot_digest": snapshot_digest,
            "record_count": len(records),
            "owner_count": owner_count,
            "orphan_preparation_count": orphan_count,
        }

    def _publish_record(self, owner: JsonObject, prepared: JsonObject) -> JsonObject:
        sequence = require_integer(owner.get("sequence"), "owner.sequence")
        snapshot = require_object(prepared.get("snapshot"), "prepared.snapshot")
        record: JsonObject = {
            "record_version": "0.1.0",
            "issuer_service_id": self._issuer,
            "sequence": sequence,
            "snapshot_digest": require_string(prepared.get("snapshot_digest"), "prepared.snapshot_digest"),
            "projection_digest": require_string(prepared.get("projection_digest"), "prepared.projection_digest"),
            "prepared_digest": sha256_digest(prepared),
            "snapshot": snapshot,
        }
        record_path = self._record_path(sequence)
        if record_path.is_file():
            existing = self._read(record_path, "ingress record")
            if sha256_digest(existing) != sha256_digest(record):
                raise ControlBoardIngressIntegrityError(
                    f"Ingress sequence {sequence} has conflicting immutable records."
                )
            return existing
        try:
            self._write_new_durable(record_path, record)
            return record
        except ControlBoardIngressPathExistsError:
            existing = self._read(record_path, "ingress record")
            if sha256_digest(existing) != sha256_digest(record):
                raise ControlBoardIngressIntegrityError(
                    f"Ingress sequence {sequence} has conflicting immutable records."
                )
            return existing

    def _publish_head(self, record: JsonObject) -> None:
        sequence = require_integer(record.get("sequence"), "record.sequence")
        head: JsonObject = {
            "head_version": "0.1.0",
            "issuer_service_id": self._issuer,
            "sequence": sequence,
            "snapshot_digest": require_string(record.get("snapshot_digest"), "record.snapshot_digest"),
            "record_digest": sha256_digest(record),
        }
        if self._head_matches(head):
            return
        temporary_path = self._root / f".head.{uuid.uuid4().hex}.tmp"
        self._write_new_durable(temporary_path, head)
        last_error: PermissionError | None = None
        for _ in range(8):
            try:
                os.replace(temporary_path, self._head_path)
                return
            except PermissionError as error:
                last_error = error
                if self._head_matches(head):
                    temporary_path.unlink(missing_ok=True)
                    return
                time.sleep(0.01)
        temporary_path.unlink(missing_ok=True)
        raise ControlBoardIngressIntegrityError(
            f"Ingress head publication remained blocked after bounded retries: {last_error}."
        )

    def _head_matches(self, expected: JsonObject) -> bool:
        if not self._head_path.is_file():
            return False
        current = self._read(self._head_path, "ingress head")
        return current == expected

    def _verify_head(self, sequence: int, snapshot_digest: str, record_digest: str) -> None:
        if not self._head_path.is_file():
            raise ControlBoardIngressIntegrityError("Ingress records exist without a durable head.")
        head = self._read(self._head_path, "ingress head")
        if (
            head.get("issuer_service_id") != self._issuer
            or head.get("sequence") != sequence
            or head.get("snapshot_digest") != snapshot_digest
            or head.get("record_digest") != record_digest
        ):
            raise ControlBoardIngressIntegrityError("Ingress head does not bind the latest immutable record.")

    def _verify_record(self, record: JsonObject, expected_sequence: int) -> None:
        if record.get("issuer_service_id") != self._issuer or record.get("sequence") != expected_sequence:
            raise ControlBoardIngressIntegrityError(
                f"Ingress record order mismatch at expected sequence {expected_sequence}."
            )
        snapshot = require_object(record.get("snapshot"), "record.snapshot")
        if sha256_digest(snapshot) != record.get("snapshot_digest"):
            raise ControlBoardIngressIntegrityError(
                f"Ingress record sequence {expected_sequence} snapshot digest mismatch."
            )
        if snapshot.get("projection_digest") != record.get("projection_digest"):
            raise ControlBoardIngressIntegrityError(
                f"Ingress record sequence {expected_sequence} projection digest mismatch."
            )

    def _ordered_records(self) -> list[JsonObject]:
        return [self._read(path, "ingress record") for path in sorted(self._record_root.glob("*.json"))]

    def _write_new_durable(self, path: Path, value: JsonObject) -> None:
        temporary_path = path.parent / f".{path.name}.{uuid.uuid4().hex}.tmp"
        try:
            with temporary_path.open("xb") as handle:
                handle.write(canonical_json_bytes(value) + b"\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.link(temporary_path, path)
        except FileExistsError as error:
            raise ControlBoardIngressPathExistsError(
                f"Control-board ingress path unexpectedly exists: '{path}'."
            ) from error
        except OSError as error:
            raise ControlBoardIngressIntegrityError(
                f"Control-board ingress cannot durably write '{path}': {error}."
            ) from error
        finally:
            temporary_path.unlink(missing_ok=True)

    def _read(self, path: Path, label: str) -> JsonObject:
        last_error: JsonDocumentError | None = None
        for attempt in range(DURABLE_READ_ATTEMPTS):
            try:
                return read_json_object(path)
            except JsonDocumentError as error:
                if not isinstance(error.__cause__, PermissionError):
                    raise ControlBoardIngressIntegrityError(
                        f"Unable to read {label} at '{path}'."
                    ) from error
                last_error = error
                if attempt + 1 < DURABLE_READ_ATTEMPTS:
                    time.sleep(DURABLE_READ_DELAY_SECONDS)
        raise ControlBoardIngressIntegrityError(
            f"Unable to read {label} at '{path}' after {DURABLE_READ_ATTEMPTS} bounded retries."
        ) from last_error

    def _owner_path(self, sequence: int) -> Path:
        return self._owner_root / f"{sequence:020d}.json"

    def _record_path(self, sequence: int) -> Path:
        return self._record_root / f"{sequence:020d}.json"
