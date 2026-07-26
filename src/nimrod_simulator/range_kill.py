"""Threshold-authorized one-way out-of-band kill state for a range generation."""

from __future__ import annotations

import os
import uuid
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

from nimrod_simulator.authorization import parse_timestamp
from nimrod_simulator.errors import (
    ControlStateValidationError,
    JsonDocumentError,
    RangeKillConflictError,
    RangeKillReplayError,
    RangeKillSignatureError,
    RangeKillStateError,
)
from nimrod_simulator.jsonio import canonical_json_bytes, read_json_object, require_integer, require_object, require_string, sha256_digest
from nimrod_simulator.key_governance import SigningConnector, validate_governance_state
from nimrod_simulator.model import JsonObject
from nimrod_simulator.range_topology import validate_range_topology
from nimrod_simulator.threshold_signing import sign_threshold_document, threshold_message, verify_threshold_signatures


RANGE_KILL_DOMAIN = b"nimrod.range-kill-command.v0.1\x00"
RangeKillFailureInjector = Callable[[str], None]


def no_range_kill_failure(phase: str) -> None:
    if not phase:
        raise RangeKillStateError("Range-kill failure phase cannot be empty.")


def range_kill_message(command: JsonObject) -> bytes:
    return threshold_message(command, RANGE_KILL_DOMAIN)


def sign_range_kill_command(
    unsigned_command: JsonObject, connectors: list[SigningConnector]
) -> JsonObject:
    return sign_threshold_document(
        unsigned_command,
        connectors,
        RANGE_KILL_DOMAIN,
        "range kill command",
        RangeKillSignatureError,
    )


def _timestamp(value: object, field: str) -> datetime:
    try:
        return parse_timestamp(value, field)
    except ControlStateValidationError as error:
        raise RangeKillSignatureError(f"Range kill timestamp '{field}' is invalid: {error}.") from error


def verify_range_kill_command(
    command: JsonObject,
    topology: JsonObject,
    governance_state: JsonObject,
    now: datetime,
    maximum_lifetime_seconds: int,
) -> JsonObject:
    if now.utcoffset() is None:
        raise RangeKillSignatureError("Range kill verification time must be timezone-aware.")
    if maximum_lifetime_seconds <= 0:
        raise RangeKillSignatureError("Range kill maximum lifetime must be positive.")
    validate_governance_state(governance_state)
    topology_verdict = validate_range_topology(topology)
    if command.get("command_version") != "0.1.0" or command.get("origin") != "simulated":
        raise RangeKillSignatureError("Range kill command must be version 0.1.0 and simulated.")
    if command.get("command") != "engage":
        raise RangeKillSignatureError("Range kill command supports only the irreversible 'engage' transition.")
    if command.get("topology_id") != topology.get("topology_id"):
        raise RangeKillSignatureError("Range kill command topology identity mismatch.")
    if command.get("topology_digest") != topology_verdict.get("topology_digest"):
        raise RangeKillSignatureError("Range kill command topology digest mismatch.")
    generation = require_integer(command.get("generation"), "command.generation")
    if generation != topology.get("generation"):
        raise RangeKillSignatureError("Range kill command generation mismatch.")
    if require_integer(command.get("sequence"), "command.sequence") != generation:
        raise RangeKillSignatureError("Range kill command sequence must equal the immutable topology generation.")
    if command.get("governance_state_digest") != sha256_digest(governance_state):
        raise RangeKillSignatureError("Range kill command governance-state digest mismatch.")
    authority = require_object(command.get("authority"), "command.authority")
    if authority != {"can_disengage": False, "can_connect": False, "can_execute": False}:
        raise RangeKillSignatureError("Range kill command cannot disengage, connect, or execute.")
    issued_at = _timestamp(command.get("issued_at"), "command.issued_at")
    not_before = _timestamp(command.get("not_before"), "command.not_before")
    expires_at = _timestamp(command.get("expires_at"), "command.expires_at")
    if issued_at > not_before or not_before >= expires_at:
        raise RangeKillSignatureError("Range kill command requires issued_at <= not_before < expires_at.")
    lifetime = int((expires_at - issued_at).total_seconds())
    if lifetime > maximum_lifetime_seconds:
        raise RangeKillSignatureError(
            f"Range kill command lifetime {lifetime}s exceeds {maximum_lifetime_seconds}s."
        )
    if now < not_before or now >= expires_at:
        raise RangeKillSignatureError("Range kill command is inactive or expired.")
    verified_signers, verified_roles = verify_threshold_signatures(
        command,
        governance_state,
        issued_at,
        RANGE_KILL_DOMAIN,
        "range kill command",
        RangeKillSignatureError,
    )
    return {
        "command_digest": sha256_digest(command),
        "topology_digest": topology_verdict["topology_digest"],
        "generation": generation,
        "verified_signer_ids": verified_signers,
        "verified_roles": verified_roles,
    }


def _utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _state_key(topology_id: str, generation: int) -> str:
    return sha256_digest({"topology_id": topology_id, "generation": generation}).removeprefix("sha256:")


class RangeKillStateStore:
    """Filesystem connector for an irreversible, atomically published kill state."""

    def __init__(self, root: Path, failure_injector: RangeKillFailureInjector) -> None:
        self._root = root / "range-kill" / "v1"
        self._state_root = self._root / "states"
        self._temporary_root = self._root / "temporary"
        self._failure_injector = failure_injector
        self._state_root.mkdir(parents=True, exist_ok=True)
        self._temporary_root.mkdir(parents=True, exist_ok=True)

    def engage(
        self,
        command: JsonObject,
        topology: JsonObject,
        governance_state: JsonObject,
        now: datetime,
        maximum_lifetime_seconds: int,
    ) -> JsonObject:
        verified = verify_range_kill_command(
            command,
            topology,
            governance_state,
            now,
            maximum_lifetime_seconds,
        )
        topology_id = require_string(topology.get("topology_id"), "topology.topology_id")
        generation = require_integer(topology.get("generation"), "topology.generation")
        state: JsonObject = {
            "state_version": "0.1.0",
            "origin": "simulated",
            "topology_id": topology_id,
            "topology_digest": verified["topology_digest"],
            "generation": generation,
            "sequence": generation,
            "state": "engaged",
            "engaged_at": _utc(now),
            "command_id": command["command_id"],
            "command_digest": verified["command_digest"],
            "governance_state_digest": command["governance_state_digest"],
            "verified_signer_ids": verified["verified_signer_ids"],
            "verified_roles": verified["verified_roles"],
            "previous_state_digest": None,
            "cleanup_required": True,
            "kill_remains_engaged": True,
            "authority": {"can_disengage": False, "can_connect": False, "can_execute": False},
        }
        state_path = self._state_path(topology_id, generation)
        temporary_path = self._temporary_root / f".{state_path.stem}.{uuid.uuid4().hex}.tmp"
        self._write_new_durable(temporary_path, state)
        self._failure_injector("temporary_durable")
        try:
            os.link(temporary_path, state_path)
        except FileExistsError as error:
            temporary_path.unlink()
            existing = self.inspect(topology_id, generation)
            if existing is not None and existing.get("command_digest") == verified["command_digest"]:
                raise RangeKillReplayError(
                    f"Range generation '{topology_id}:{generation}' already consumed this kill command."
                ) from error
            raise RangeKillConflictError(
                f"Range generation '{topology_id}:{generation}' is already engaged by a different command."
            ) from error
        except OSError as error:
            temporary_path.unlink()
            raise RangeKillStateError(
                f"Filesystem cannot atomically publish range-kill state '{state_path}': {error}."
            ) from error
        temporary_path.unlink()
        self._failure_injector("state_published")
        return state

    def inspect(self, topology_id: str, generation: int) -> JsonObject | None:
        state_path = self._state_path(topology_id, generation)
        if not state_path.is_file():
            return None
        try:
            state = read_json_object(state_path)
        except JsonDocumentError as error:
            raise RangeKillStateError(f"Range-kill state is malformed: '{state_path}'.") from error
        if state.get("state") != "engaged" or state.get("kill_remains_engaged") is not True:
            raise RangeKillStateError(f"Range-kill state is not irreversibly engaged: '{state_path}'.")
        if state.get("topology_id") != topology_id or state.get("generation") != generation:
            raise RangeKillStateError(f"Range-kill state identity mismatch: '{state_path}'.")
        authority = require_object(state.get("authority"), "state.authority")
        if authority != {"can_disengage": False, "can_connect": False, "can_execute": False}:
            raise RangeKillStateError(f"Range-kill state contains authority: '{state_path}'.")
        return state

    def orphan_temporary_count(self) -> int:
        return len(tuple(self._temporary_root.glob("*.tmp")))

    def _write_new_durable(self, path: Path, value: JsonObject) -> None:
        try:
            with path.open("xb") as handle:
                handle.write(canonical_json_bytes(value) + b"\n")
                handle.flush()
                os.fsync(handle.fileno())
        except FileExistsError as error:
            raise RangeKillStateError(f"Range-kill temporary path unexpectedly exists: '{path}'.") from error

    def _state_path(self, topology_id: str, generation: int) -> Path:
        if not topology_id or generation <= 0:
            raise RangeKillStateError("Range-kill state identity requires a non-empty topology ID and generation.")
        return self._state_root / f"{_state_key(topology_id, generation)}.json"
