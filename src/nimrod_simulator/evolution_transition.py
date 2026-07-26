"""Threshold-authorized shadow registration, demotion, and rollback receipts."""

from __future__ import annotations

import os
import uuid
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

from nimrod_simulator.authorization import parse_timestamp
from nimrod_simulator.errors import (
    ControlStateValidationError,
    EvolutionTransitionConflictError,
    EvolutionTransitionError,
    EvolutionTransitionReplayError,
    JsonDocumentError,
)
from nimrod_simulator.evolution_constitution import verify_evolution_constitution
from nimrod_simulator.evolution_foundry import CANDIDATE_AUTHORITY
from nimrod_simulator.jsonio import canonical_json_bytes, read_json_object, require_integer, require_object, require_string, sha256_digest
from nimrod_simulator.key_governance import SigningConnector
from nimrod_simulator.model import JsonObject
from nimrod_simulator.threshold_signing import sign_threshold_document, threshold_message, verify_threshold_signatures


EVOLUTION_TRANSITION_DOMAIN = b"nimrod.evolution-transition-envelope.v0.1\x00"
TransitionFailureInjector = Callable[[str], None]


def no_transition_failure(phase: str) -> None:
    if not phase:
        raise EvolutionTransitionError("Evolution transition failure phase cannot be empty.")


def evolution_transition_message(envelope: JsonObject) -> bytes:
    return threshold_message(envelope, EVOLUTION_TRANSITION_DOMAIN)


def sign_evolution_transition(
    unsigned_envelope: JsonObject, connectors: list[SigningConnector]
) -> JsonObject:
    return sign_threshold_document(
        unsigned_envelope,
        connectors,
        EVOLUTION_TRANSITION_DOMAIN,
        "evolution transition envelope",
        EvolutionTransitionError,
    )


def _timestamp(value: object, field: str) -> datetime:
    try:
        return parse_timestamp(value, field)
    except ControlStateValidationError as error:
        raise EvolutionTransitionError(f"Evolution transition timestamp '{field}' is invalid: {error}.") from error


def verify_evolution_transition(
    envelope: JsonObject,
    candidate: JsonObject,
    evaluation: JsonObject,
    capability_report: JsonObject,
    constitution: JsonObject,
    governance_state: JsonObject,
    now: datetime,
    maximum_constitution_lifetime_seconds: int,
    maximum_transition_lifetime_seconds: int,
) -> JsonObject:
    if now.utcoffset() is None:
        raise EvolutionTransitionError("Evolution transition verification time must be timezone-aware.")
    if maximum_transition_lifetime_seconds <= 0:
        raise EvolutionTransitionError("Evolution transition maximum lifetime must be positive.")
    constitution_verification = verify_evolution_constitution(
        constitution,
        governance_state,
        now,
        maximum_constitution_lifetime_seconds,
    )
    if envelope.get("envelope_version") != "0.1.0" or envelope.get("origin") != "simulated":
        raise EvolutionTransitionError("Evolution transition envelope must be version 0.1.0 and simulated.")
    candidate_digest = sha256_digest(candidate)
    evaluation_digest = sha256_digest(evaluation)
    capability_digest = sha256_digest(capability_report)
    if candidate.get("authority") != CANDIDATE_AUTHORITY:
        raise EvolutionTransitionError("Evolution transition candidate authority was widened.")
    if envelope.get("candidate_digest") != candidate_digest:
        raise EvolutionTransitionError("Evolution transition candidate digest mismatch.")
    if envelope.get("evaluation_digest") != evaluation_digest:
        raise EvolutionTransitionError("Evolution transition evaluation digest mismatch.")
    if envelope.get("capability_report_digest") != capability_digest:
        raise EvolutionTransitionError("Evolution transition capability-report digest mismatch.")
    if envelope.get("constitution_digest") != constitution_verification.get("constitution_digest"):
        raise EvolutionTransitionError("Evolution transition constitution digest mismatch.")
    if envelope.get("active_baseline_digest") != candidate.get("active_baseline_digest"):
        raise EvolutionTransitionError("Evolution transition active-baseline digest mismatch.")
    authority = require_object(envelope.get("authority"), "envelope.authority")
    required_authority = {
        "can_modify_active_baseline": False,
        "can_execute_candidate": False,
        "can_promote_to_production": False,
        "can_expand_authority": False,
    }
    if authority != required_authority:
        raise EvolutionTransitionError("Evolution transition envelope authority must remain false.")
    action = require_string(envelope.get("action"), "envelope.action")
    sequence = require_integer(envelope.get("sequence"), "envelope.sequence")
    previous_receipt_digest = envelope.get("previous_receipt_digest")
    destination = require_string(envelope.get("destination"), "envelope.destination")
    if action == "register_shadow":
        if sequence != 1 or previous_receipt_digest is not None or destination != "shadow":
            raise EvolutionTransitionError("Shadow registration must be sequence 1 with no predecessor and shadow destination.")
        if candidate.get("authority_tier") not in {"A", "B"}:
            raise EvolutionTransitionError("Only Tier A or B candidates may register in the shadow lane.")
        if evaluation.get("status") != "eligible_for_shadow" or evaluation.get("candidate_digest") != candidate_digest:
            raise EvolutionTransitionError("Shadow registration requires an eligible evaluation bound to the candidate.")
        if capability_report.get("status") != "clear" or capability_report.get("candidate_digest") != candidate_digest:
            raise EvolutionTransitionError("Shadow registration requires a clear capability report bound to the candidate.")
    elif action in {"demote", "rollback"}:
        expected_destination = "quarantine" if action == "demote" else "rolled_back"
        if sequence != 2 or not isinstance(previous_receipt_digest, str) or destination != expected_destination:
            raise EvolutionTransitionError(
                f"Evolution transition '{action}' must be sequence 2, predecessor-bound, and target '{expected_destination}'."
            )
    else:
        raise EvolutionTransitionError(f"Unsupported evolution transition action '{action}'.")
    issued_at = _timestamp(envelope.get("issued_at"), "envelope.issued_at")
    not_before = _timestamp(envelope.get("not_before"), "envelope.not_before")
    expires_at = _timestamp(envelope.get("expires_at"), "envelope.expires_at")
    if issued_at > not_before or not_before >= expires_at:
        raise EvolutionTransitionError("Evolution transition requires issued_at <= not_before < expires_at.")
    if int((expires_at - issued_at).total_seconds()) > maximum_transition_lifetime_seconds:
        raise EvolutionTransitionError("Evolution transition lifetime exceeds the configured maximum.")
    if now < not_before or now >= expires_at:
        raise EvolutionTransitionError("Evolution transition envelope is inactive or expired.")
    signers, roles = verify_threshold_signatures(
        envelope,
        governance_state,
        issued_at,
        EVOLUTION_TRANSITION_DOMAIN,
        "evolution transition envelope",
        EvolutionTransitionError,
    )
    return {
        "envelope_digest": sha256_digest(envelope),
        "candidate_digest": candidate_digest,
        "evaluation_digest": evaluation_digest,
        "capability_report_digest": capability_digest,
        "constitution_digest": constitution_verification["constitution_digest"],
        "action": action,
        "sequence": sequence,
        "destination": destination,
        "previous_receipt_digest": previous_receipt_digest,
        "verified_signer_ids": signers,
        "verified_roles": roles,
    }


def _utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _lineage_key(candidate_id: str) -> str:
    return sha256_digest({"candidate_id": candidate_id}).removeprefix("sha256:")


class EvolutionTransitionStore:
    """External filesystem boundary for immutable shadow and terminal transition receipts."""

    def __init__(self, root: Path, failure_injector: TransitionFailureInjector) -> None:
        self._root = root / "evolution-foundry" / "v1" / "transitions"
        self._shadow_root = self._root / "shadow"
        self._terminal_root = self._root / "terminal"
        self._temporary_root = self._root / "temporary"
        self._failure_injector = failure_injector
        self._shadow_root.mkdir(parents=True, exist_ok=True)
        self._terminal_root.mkdir(parents=True, exist_ok=True)
        self._temporary_root.mkdir(parents=True, exist_ok=True)

    def apply(
        self,
        envelope: JsonObject,
        candidate: JsonObject,
        evaluation: JsonObject,
        capability_report: JsonObject,
        constitution: JsonObject,
        governance_state: JsonObject,
        now: datetime,
        maximum_constitution_lifetime_seconds: int,
        maximum_transition_lifetime_seconds: int,
    ) -> JsonObject:
        verified = verify_evolution_transition(
            envelope,
            candidate,
            evaluation,
            capability_report,
            constitution,
            governance_state,
            now,
            maximum_constitution_lifetime_seconds,
            maximum_transition_lifetime_seconds,
        )
        candidate_id = require_string(candidate.get("candidate_id"), "candidate.candidate_id")
        action = require_string(verified.get("action"), "verified.action")
        if action == "register_shadow":
            path = self._shadow_path(candidate_id)
        else:
            shadow = self.inspect_shadow(candidate_id)
            if shadow is None:
                raise EvolutionTransitionError(f"Terminal transition '{action}' requires a durable shadow receipt.")
            if verified.get("previous_receipt_digest") != sha256_digest(shadow):
                raise EvolutionTransitionError(f"Terminal transition '{action}' predecessor digest mismatch.")
            path = self._terminal_path(candidate_id)
        receipt: JsonObject = {
            "receipt_version": "0.1.0",
            "receipt_id": str(uuid.uuid5(uuid.UUID("c0d71424-57ec-4b03-b3b7-76f61e906b1e"), f"{verified['envelope_digest']}:{_utc(now)}")),
            "origin": "simulated",
            "candidate_id": candidate_id,
            "candidate_digest": verified["candidate_digest"],
            "active_baseline_digest": candidate["active_baseline_digest"],
            "constitution_digest": verified["constitution_digest"],
            "action": action,
            "sequence": verified["sequence"],
            "previous_receipt_digest": verified["previous_receipt_digest"],
            "envelope_digest": verified["envelope_digest"],
            "recorded_at": _utc(now),
            "status": {
                "register_shadow": "shadow_candidate_registered",
                "demote": "candidate_demoted",
                "rollback": "candidate_rolled_back",
            }[action],
            "destination": verified["destination"],
            "verified_signer_ids": verified["verified_signer_ids"],
            "verified_roles": verified["verified_roles"],
            "active_baseline_modified": False,
            "candidate_executed": False,
            "production_promotion_authorized": False,
            "authority": {
                "can_modify_active_baseline": False,
                "can_execute_candidate": False,
                "can_promote_to_production": False,
            },
        }
        self._publish(path, receipt, verified["envelope_digest"])
        return receipt

    def inspect_shadow(self, candidate_id: str) -> JsonObject | None:
        return self._read_optional(self._shadow_path(candidate_id), "shadow")

    def inspect_terminal(self, candidate_id: str) -> JsonObject | None:
        return self._read_optional(self._terminal_path(candidate_id), "terminal")

    def _publish(self, path: Path, receipt: JsonObject, envelope_digest: object) -> None:
        temporary = self._temporary_root / f".{path.stem}.{uuid.uuid4().hex}.tmp"
        try:
            with temporary.open("xb") as handle:
                handle.write(canonical_json_bytes(receipt) + b"\n")
                handle.flush()
                os.fsync(handle.fileno())
            self._failure_injector("temporary_durable")
            os.link(temporary, path)
        except FileExistsError as error:
            existing = self._read_optional(path, "existing")
            if existing is not None and existing.get("envelope_digest") == envelope_digest:
                raise EvolutionTransitionReplayError(f"Evolution transition already exists at '{path}'.") from error
            raise EvolutionTransitionConflictError(f"Evolution transition conflicts at '{path}'.") from error
        except OSError as error:
            raise EvolutionTransitionError(f"Evolution transition publication failed at '{path}': {error}.") from error
        finally:
            if temporary.exists():
                temporary.unlink()
        self._failure_injector("state_published")

    def _read_optional(self, path: Path, label: str) -> JsonObject | None:
        if not path.is_file():
            return None
        try:
            receipt = read_json_object(path)
        except JsonDocumentError as error:
            raise EvolutionTransitionError(f"Evolution {label} receipt is malformed: '{path}'.") from error
        authority = require_object(receipt.get("authority"), "receipt.authority")
        if authority != {
            "can_modify_active_baseline": False,
            "can_execute_candidate": False,
            "can_promote_to_production": False,
        }:
            raise EvolutionTransitionError(f"Evolution {label} receipt contains authority: '{path}'.")
        return receipt

    def _shadow_path(self, candidate_id: str) -> Path:
        return self._shadow_root / f"{_lineage_key(candidate_id)}.json"

    def _terminal_path(self, candidate_id: str) -> Path:
        return self._terminal_root / f"{_lineage_key(candidate_id)}.json"
