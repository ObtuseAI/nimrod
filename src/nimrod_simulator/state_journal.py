"""Crash-recoverable filesystem connector for single-use authorization state."""

from __future__ import annotations

import logging
import os
import time
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Literal, TypedDict

from nimrod_simulator.errors import AuthorizationStateIntegrityError, JsonDocumentError, LeaseReplayError
from nimrod_simulator.jsonio import canonical_json_bytes, read_json_object, require_string, sha256_digest
from nimrod_simulator.model import JsonObject


FailureInjector = Callable[[str], None]
ReplaceOperation = Callable[[Path, Path], None]
JsonReadOperation = Callable[[Path], JsonObject]
SleepOperation = Callable[[float], None]
RecoveryStatus = Literal["direct", "recovered_from_owner", "consumed_ambiguous"]
WINDOWS_PUBLICATION_ATTEMPTS = 8
WINDOWS_PUBLICATION_DELAY_SECONDS = 0.01
WINDOWS_READ_ATTEMPTS = 16
WINDOWS_READ_DELAY_SECONDS = 0.01
LOGGER = logging.getLogger(__name__)


class AuthorizationStateReport(TypedDict):
    state_version: str
    owner_count: int
    committed_count: int
    recovered_count: int
    ambiguous_count: int
    orphan_preparation_count: int


def no_state_failure(phase: str) -> None:
    """Production hook that deliberately injects no authorization-state failure."""
    if not phase:
        raise AuthorizationStateIntegrityError("Authorization-state failure phase cannot be empty.")


def claim_key_for(lease_id: str, nonce: str) -> str:
    if not lease_id or not nonce:
        raise AuthorizationStateIntegrityError("Lease ID and nonce must be non-empty before state can be claimed.")
    return sha256_digest({"lease_id": lease_id, "nonce": nonce}).removeprefix("sha256:")


def publish_file_with_windows_retry(
    temporary_path: Path,
    published_path: Path,
    attempts: int,
    delay_seconds: float,
    replace_operation: ReplaceOperation,
    sleep_operation: SleepOperation,
) -> None:
    """Publish one file while retrying only transient Windows access-denied races."""
    if attempts <= 0:
        raise AuthorizationStateIntegrityError("Authorization-state publication attempts must be positive.")
    if delay_seconds < 0:
        raise AuthorizationStateIntegrityError("Authorization-state publication delay cannot be negative.")
    last_error: PermissionError | None = None
    for attempt in range(1, attempts + 1):
        try:
            replace_operation(temporary_path, published_path)
            return
        except PermissionError as error:
            if getattr(error, "winerror", None) != 5:
                raise AuthorizationStateIntegrityError(
                    "Authorization-state publication failed with a non-retryable permission error: "
                    f"source='{temporary_path}', destination='{published_path}', error='{error}'."
                ) from error
            last_error = error
            if attempt == attempts:
                break
            LOGGER.warning(
                "Authorization-state publication encountered transient Windows access denial.",
                extra={
                    "source_path": str(temporary_path),
                    "destination_path": str(published_path),
                    "attempt": attempt,
                    "maximum_attempts": attempts,
                    "winerror": 5,
                },
            )
            sleep_operation(delay_seconds)
    raise AuthorizationStateIntegrityError(
        "Authorization-state publication remained blocked after bounded Windows retries: "
        f"source='{temporary_path}', destination='{published_path}', attempts={attempts}, error='{last_error}'."
    ) from last_error


def read_json_object_with_windows_retry(
    path: Path,
    attempts: int,
    delay_seconds: float,
    read_operation: JsonReadOperation,
    sleep_operation: SleepOperation,
) -> JsonObject:
    """Read one published object while bounding only Windows access-denied retries."""
    if attempts <= 0:
        raise AuthorizationStateIntegrityError("Authorization-state read attempts must be positive.")
    if delay_seconds < 0:
        raise AuthorizationStateIntegrityError("Authorization-state read delay cannot be negative.")
    last_error: JsonDocumentError | None = None
    for attempt in range(1, attempts + 1):
        try:
            return read_operation(path)
        except JsonDocumentError as error:
            cause = error.__cause__
            if not isinstance(cause, PermissionError) or getattr(cause, "winerror", None) != 5:
                raise
            last_error = error
            if attempt == attempts:
                break
            LOGGER.warning(
                "Authorization-state read encountered transient Windows access denial.",
                extra={
                    "path": str(path),
                    "attempt": attempt,
                    "maximum_attempts": attempts,
                    "winerror": 5,
                },
            )
            sleep_operation(delay_seconds)
    raise AuthorizationStateIntegrityError(
        "Authorization-state read remained blocked after bounded Windows retries: "
        f"path='{path}', attempts={attempts}, error='{last_error}'."
    ) from last_error


def require_claim_key(value: JsonObject, expected: str, label: str) -> None:
    actual = require_string(value.get("claim_key"), f"{label}.claim_key")
    if actual != expected:
        raise AuthorizationStateIntegrityError(
            f"Authorization-state {label} claim key mismatch: expected '{expected}', received '{actual}'."
        )


class FileLeaseStateStore:
    """External filesystem boundary for process-crash-safe single-use nonce claims."""

    def __init__(self, root: Path, failure_injector: FailureInjector) -> None:
        self._root = root / "authorization-state" / "v1"
        self._prepared_root = self._root / "prepared"
        self._owner_root = self._root / "owners"
        self._committed_root = self._root / "committed"
        self._failure_injector = failure_injector
        self._prepared_root.mkdir(parents=True, exist_ok=True)
        self._owner_root.mkdir(parents=True, exist_ok=True)
        self._committed_root.mkdir(parents=True, exist_ok=True)
        self.recover()

    def claim(self, lease_id: str, nonce: str, claimed_at: str) -> Path:
        claim_key = claim_key_for(lease_id, nonce)
        attempt_id = uuid.uuid4().hex
        prepared: JsonObject = {
            "state_version": "0.1.0",
            "record_type": "prepared_claim",
            "claim_key": claim_key,
            "attempt_id": attempt_id,
            "lease_id": lease_id,
            "nonce_digest": sha256_digest({"nonce": nonce}),
            "claimed_at": claimed_at,
            "purpose": "single-use no-execution simulator lease",
        }
        prepared_path = self._prepared_path(claim_key, attempt_id)
        prepared_temporary_path = self._prepared_root / f".{claim_key}.{attempt_id}.tmp"
        self._write_new_durable(prepared_temporary_path, prepared)
        try:
            os.link(prepared_temporary_path, prepared_path)
        except FileExistsError as error:
            prepared_temporary_path.unlink()
            raise AuthorizationStateIntegrityError(
                f"Authorization-state prepared record unexpectedly exists: '{prepared_path}'."
            ) from error
        except OSError as error:
            prepared_temporary_path.unlink()
            raise AuthorizationStateIntegrityError(
                f"Filesystem cannot atomically publish prepared authorization state '{prepared_path}': {error}."
            ) from error
        prepared_temporary_path.unlink()
        self._failure_injector("prepared_durable")
        owner: JsonObject = {
            "state_version": "0.1.0",
            "record_type": "claim_owner",
            "claim_key": claim_key,
            "attempt_id": attempt_id,
            "prepared_digest": sha256_digest(prepared),
        }
        owner_path = self._owner_path(claim_key)
        owner_temporary_path = self._owner_root / f".{claim_key}.{attempt_id}.tmp"
        self._write_new_durable(owner_temporary_path, owner)
        try:
            os.link(owner_temporary_path, owner_path)
        except FileExistsError as error:
            owner_temporary_path.unlink()
            self._recover_claim(claim_key)
            raise LeaseReplayError(
                f"Lease '{lease_id}' nonce has already been atomically owned at '{owner_path}'."
            ) from error
        except OSError as error:
            raise AuthorizationStateIntegrityError(
                f"Filesystem cannot atomically publish authorization owner '{owner_path}': {error}."
            ) from error
        self._failure_injector("owner_created")
        owner_temporary_path.unlink()
        self._failure_injector("owner_durable")
        committed_path = self._publish_commit(prepared, "direct")
        return committed_path

    def recover(self) -> AuthorizationStateReport:
        for owner_path in sorted(self._owner_root.glob("*.owner")):
            self._recover_claim(owner_path.stem)
        return self.inspect()

    def inspect(self) -> AuthorizationStateReport:
        owner_keys = {path.stem for path in self._owner_root.glob("*.owner")}
        committed_records = [self._read_committed(path) for path in sorted(self._committed_root.glob("*.json"))]
        committed_keys = {
            require_string(record.get("claim_key"), "committed.claim_key") for record in committed_records
        }
        missing_owner = sorted(committed_keys - owner_keys)
        if missing_owner:
            raise AuthorizationStateIntegrityError(
                f"Committed authorization state lacks owner markers for claim keys: {', '.join(missing_owner)}."
            )
        for claim_key in sorted(owner_keys):
            if claim_key not in committed_keys:
                raise AuthorizationStateIntegrityError(
                    f"Authorization owner '{claim_key}' lacks a recovered committed record."
                )
            self._verify_committed_claim(claim_key, self._read_committed(self._committed_path(claim_key)))
        recovered_count = sum(
            1
            for record in committed_records
            if require_string(record.get("recovery_status"), "committed.recovery_status") != "direct"
        )
        ambiguous_count = sum(
            1
            for record in committed_records
            if require_string(record.get("recovery_status"), "committed.recovery_status") == "consumed_ambiguous"
        )
        orphan_count = 0
        for prepared_path in self._prepared_root.glob("*.json"):
            prepared = self._read_prepared(prepared_path)
            key = require_string(prepared.get("claim_key"), "prepared.claim_key")
            if key not in owner_keys:
                orphan_count += 1
        return {
            "state_version": "0.1.0",
            "owner_count": len(owner_keys),
            "committed_count": len(committed_records),
            "recovered_count": recovered_count,
            "ambiguous_count": ambiguous_count,
            "orphan_preparation_count": orphan_count,
        }

    def _recover_claim(self, claim_key: str) -> Path:
        committed_path = self._committed_path(claim_key)
        if committed_path.is_file():
            committed = self._read_committed(committed_path)
            self._verify_committed_claim(claim_key, committed)
            return committed_path
        owner_path = self._owner_path(claim_key)
        if not owner_path.is_file():
            raise AuthorizationStateIntegrityError(
                f"Authorization-state recovery cannot find owner marker '{owner_path}'."
            )
        try:
            owner = read_json_object(owner_path)
            require_claim_key(owner, claim_key, "owner")
            attempt_id = require_string(owner.get("attempt_id"), "owner.attempt_id")
            prepared = self._read_prepared(self._prepared_path(claim_key, attempt_id))
            expected_digest = require_string(owner.get("prepared_digest"), "owner.prepared_digest")
            if sha256_digest(prepared) != expected_digest:
                raise AuthorizationStateIntegrityError(
                    f"Owner marker '{owner_path}' does not match its durable prepared record."
                )
            return self._publish_commit(prepared, "recovered_from_owner")
        except JsonDocumentError:
            return self._publish_ambiguous_commit(claim_key)

    def _publish_commit(self, prepared: JsonObject, recovery_status: RecoveryStatus) -> Path:
        claim_key = require_string(prepared.get("claim_key"), "prepared.claim_key")
        committed_path = self._committed_path(claim_key)
        if committed_path.is_file():
            existing = self._read_committed(committed_path)
            self._verify_committed_claim(claim_key, existing)
            return committed_path
        committed: JsonObject = {
            "state_version": "0.1.0",
            "record_type": "consumed_nonce",
            "claim_key": claim_key,
            "lease_id": require_string(prepared.get("lease_id"), "prepared.lease_id"),
            "nonce_digest": require_string(prepared.get("nonce_digest"), "prepared.nonce_digest"),
            "claimed_at": require_string(prepared.get("claimed_at"), "prepared.claimed_at"),
            "prepared_digest": sha256_digest(prepared),
            "recovery_status": recovery_status,
        }
        temporary_path = self._committed_root / f".{claim_key}.{uuid.uuid4().hex}.tmp"
        self._write_new_durable(temporary_path, committed)
        self._failure_injector("commit_prepared")
        publish_file_with_windows_retry(
            temporary_path,
            committed_path,
            WINDOWS_PUBLICATION_ATTEMPTS,
            WINDOWS_PUBLICATION_DELAY_SECONDS,
            os.replace,
            time.sleep,
        )
        self._failure_injector("commit_published")
        return committed_path

    def _verify_committed_claim(self, claim_key: str, committed: JsonObject) -> None:
        require_claim_key(committed, claim_key, "committed")
        owner_path = self._owner_path(claim_key)
        if committed.get("record_type") == "consumed_nonce_tombstone":
            try:
                read_json_object(owner_path)
            except JsonDocumentError:
                return
            raise AuthorizationStateIntegrityError(
                f"Authorization-state tombstone '{claim_key}' contradicts a readable owner record."
            )
        try:
            owner = read_json_object(owner_path)
        except JsonDocumentError as error:
            raise AuthorizationStateIntegrityError(
                f"Committed authorization claim '{claim_key}' has an unreadable owner marker."
            ) from error
        require_claim_key(owner, claim_key, "owner")
        attempt_id = require_string(owner.get("attempt_id"), "owner.attempt_id")
        prepared = self._read_prepared(self._prepared_path(claim_key, attempt_id))
        owner_digest = require_string(owner.get("prepared_digest"), "owner.prepared_digest")
        prepared_digest = sha256_digest(prepared)
        committed_digest = require_string(committed.get("prepared_digest"), "committed.prepared_digest")
        if owner_digest != prepared_digest or committed_digest != prepared_digest:
            raise AuthorizationStateIntegrityError(
                f"Authorization claim '{claim_key}' owner, preparation, and commit digests disagree."
            )
        for field in ("lease_id", "nonce_digest", "claimed_at"):
            prepared_value = require_string(prepared.get(field), f"prepared.{field}")
            committed_value = require_string(committed.get(field), f"committed.{field}")
            if prepared_value != committed_value:
                raise AuthorizationStateIntegrityError(
                    f"Authorization claim '{claim_key}' field '{field}' differs between preparation and commit."
                )

    def _publish_ambiguous_commit(self, claim_key: str) -> Path:
        committed: JsonObject = {
            "state_version": "0.1.0",
            "record_type": "consumed_nonce_tombstone",
            "claim_key": claim_key,
            "recovery_status": "consumed_ambiguous",
            "reason": "owner marker exists but no valid prepared identity record remains",
        }
        committed_path = self._committed_path(claim_key)
        temporary_path = self._committed_root / f".{claim_key}.{uuid.uuid4().hex}.tmp"
        self._write_new_durable(temporary_path, committed)
        self._failure_injector("commit_prepared")
        publish_file_with_windows_retry(
            temporary_path,
            committed_path,
            WINDOWS_PUBLICATION_ATTEMPTS,
            WINDOWS_PUBLICATION_DELAY_SECONDS,
            os.replace,
            time.sleep,
        )
        self._failure_injector("commit_published")
        return committed_path

    def _write_new_durable(self, path: Path, value: JsonObject) -> None:
        try:
            with path.open("xb") as handle:
                handle.write(canonical_json_bytes(value) + b"\n")
                handle.flush()
                os.fsync(handle.fileno())
        except FileExistsError as error:
            raise AuthorizationStateIntegrityError(
                f"Authorization-state attempt path unexpectedly exists: '{path}'."
            ) from error

    def _read_prepared(self, path: Path) -> JsonObject:
        try:
            prepared = read_json_object(path)
        except JsonDocumentError as error:
            raise AuthorizationStateIntegrityError(
                f"Prepared authorization-state record is missing or malformed: '{path}'."
            ) from error
        if prepared.get("record_type") != "prepared_claim":
            raise AuthorizationStateIntegrityError(
                f"Prepared authorization-state record has the wrong type: '{path}'."
            )
        return prepared

    def _read_committed(self, path: Path) -> JsonObject:
        try:
            committed = read_json_object_with_windows_retry(
                path,
                WINDOWS_READ_ATTEMPTS,
                WINDOWS_READ_DELAY_SECONDS,
                read_json_object,
                time.sleep,
            )
        except JsonDocumentError as error:
            raise AuthorizationStateIntegrityError(
                f"Committed authorization-state record is missing or malformed: '{path}'."
            ) from error
        if committed.get("record_type") not in {"consumed_nonce", "consumed_nonce_tombstone"}:
            raise AuthorizationStateIntegrityError(
                f"Committed authorization-state record has the wrong type: '{path}'."
            )
        return committed

    def _prepared_path(self, claim_key: str, attempt_id: str) -> Path:
        return self._prepared_root / f"{claim_key}.{attempt_id}.json"

    def _owner_path(self, claim_key: str) -> Path:
        return self._owner_root / f"{claim_key}.owner"

    def _committed_path(self, claim_key: str) -> Path:
        return self._committed_root / f"{claim_key}.json"
