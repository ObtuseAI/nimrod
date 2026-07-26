from __future__ import annotations

import copy
import json
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from uuid import NAMESPACE_URL, uuid5

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from nimrod_simulator.errors import KeyGovernanceError, KeyTransitionError, SimulatorError
from nimrod_simulator.jsonio import sha256_digest, validate_contract
from nimrod_simulator.key_governance import (
    EphemeralEd25519SigningConnector,
    SigningConnector,
    governance_key,
    sign_transition,
    validate_governance_state,
    verify_key_transition,
)
from nimrod_simulator.model import JsonObject


GOVERNANCE_ID = "11111111-2222-4333-8444-555555555555"
ORIGIN = "simulated"


def require_condition(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def expect_error(expected: type[SimulatorError], operation: Callable[[], object], label: str) -> None:
    try:
        operation()
    except expected:
        return
    except SimulatorError as error:
        raise AssertionError(
            f"{label} raised {type(error).__name__}; expected {expected.__name__}: {error}"
        ) from error
    raise AssertionError(f"{label} did not fail closed with {expected.__name__}.")


def connector(key_id: str, role: str) -> EphemeralEd25519SigningConnector:
    return EphemeralEd25519SigningConnector(key_id, role, Ed25519PrivateKey.generate())


def key_document(signing_connector: SigningConnector, status: str, valid_from: str) -> JsonObject:
    return governance_key(
        signing_connector,
        status,
        valid_from,
        None,
        "test_ephemeral",
        f"connector:custody:{signing_connector.key_id}",
        f"memory:{signing_connector.key_id}",
        False,
        None,
    )


def initial_state(connectors: list[SigningConnector], issued_at: str) -> JsonObject:
    return {
        "state_version": "0.1.0",
        "governance_id": GOVERNANCE_ID,
        "origin": ORIGIN,
        "epoch": 1,
        "issued_at": issued_at,
        "previous_state_digest": None,
        "threshold": 2,
        "ceremony_key_count": 3,
        "minimum_distinct_roles": 2,
        "keys": [key_document(item, "active", issued_at) for item in connectors],
    }


def next_state(
    current: JsonObject,
    departing_key_id: str,
    departing_status: str,
    replacement: SigningConnector,
    issued_at: str,
) -> JsonObject:
    following = copy.deepcopy(current)
    following["epoch"] = int(str(current["epoch"])) + 1
    following["issued_at"] = issued_at
    following["previous_state_digest"] = sha256_digest(current)
    keys = following.get("keys")
    if not isinstance(keys, list):
        raise TypeError("Key governance state keys must be a list.")
    departing_found = False
    for value in keys:
        if isinstance(value, dict) and value.get("key_id") == departing_key_id:
            value["status"] = departing_status
            value["valid_until"] = issued_at
            departing_found = True
    if not departing_found:
        raise ValueError(f"Departing key '{departing_key_id}' is absent.")
    keys.append(key_document(replacement, "active", issued_at))
    return following


def unsigned_transition(
    current: JsonObject,
    following: JsonObject,
    kind: str,
    issued_at: str,
    affected_key_ids: list[str],
) -> JsonObject:
    transition_id = str(uuid5(NAMESPACE_URL, f"{GOVERNANCE_ID}:{current['epoch']}:{following['epoch']}:{kind}"))
    return {
        "transition_version": "0.1.0",
        "transition_id": transition_id,
        "origin": ORIGIN,
        "governance_id": GOVERNANCE_ID,
        "from_epoch": current["epoch"],
        "to_epoch": following["epoch"],
        "kind": kind,
        "issued_at": issued_at,
        "previous_state_digest": sha256_digest(current),
        "next_state_digest": sha256_digest(following),
        "affected_key_ids": affected_key_ids,
        "reason": f"Simulated {kind} ceremony",
    }


def signed_transition(
    current: JsonObject,
    following: JsonObject,
    kind: str,
    issued_at: str,
    affected_key_ids: list[str],
    signers: list[SigningConnector],
) -> JsonObject:
    return sign_transition(
        unsigned_transition(current, following, kind, issued_at, affected_key_ids),
        signers,
    )


def mutate_and_resign(
    current: JsonObject,
    following: JsonObject,
    transition: JsonObject,
    signers: list[SigningConnector],
) -> JsonObject:
    unsigned = {key: value for key, value in transition.items() if key != "signatures"}
    unsigned["next_state_digest"] = sha256_digest(following)
    return sign_transition(unsigned, signers)


def validate_key_governance(project_root: Path) -> JsonObject:
    specs = project_root / "specs"
    a = connector("key:customer-a", "customer_authority")
    b = connector("key:safety-b", "safety_officer")
    c = connector("key:recovery-c", "recovery_officer")
    d = connector("key:customer-d", "customer_authority")
    e = connector("key:safety-e", "safety_officer")
    f = connector("key:recovery-f", "recovery_officer")
    g = connector("key:customer-g", "customer_authority")
    state_1 = initial_state([a, b, c], "2026-07-12T21:00:00Z")
    state_2 = next_state(state_1, a.key_id, "retired", d, "2026-07-12T21:05:00Z")
    transition_1 = signed_transition(
        state_1, state_2, "rotation", "2026-07-12T21:05:00Z", [a.key_id, d.key_id], [a, b]
    )
    state_3 = next_state(state_2, b.key_id, "lost", e, "2026-07-12T21:10:00Z")
    transition_2 = signed_transition(
        state_2, state_3, "lost_key_recovery", "2026-07-12T21:10:00Z", [b.key_id, e.key_id], [c, d]
    )
    state_4 = next_state(state_3, c.key_id, "compromised", f, "2026-07-12T21:15:00Z")
    transition_3 = signed_transition(
        state_3,
        state_4,
        "compromise_recovery",
        "2026-07-12T21:15:00Z",
        [c.key_id, f.key_id],
        [d, e],
    )
    state_5 = next_state(state_4, d.key_id, "revoked", g, "2026-07-12T21:20:00Z")
    transition_4 = signed_transition(
        state_4, state_5, "revocation", "2026-07-12T21:20:00Z", [d.key_id, g.key_id], [e, f]
    )
    states = [state_1, state_2, state_3, state_4, state_5]
    transitions = [transition_1, transition_2, transition_3, transition_4]
    for state in states:
        validate_contract(state, specs / "key-governance-state.schema.json", "generated key governance state")
        validate_governance_state(state)
    transition_kinds: list[str] = []
    for index, transition in enumerate(transitions):
        validate_contract(
            transition,
            specs / "key-governance-transition.schema.json",
            "generated key governance transition",
        )
        result = verify_key_transition(
            states[index],
            transition,
            states[index + 1],
            datetime.fromisoformat("2026-07-12T21:30:00+00:00"),
        )
        transition_kinds.append(str(result["kind"]))
        require_condition(len(result["verified_signer_ids"]) == 2, "Transition did not verify exactly two signers.")

    negative_count = 0
    insufficient = copy.deepcopy(transition_1)
    signatures = insufficient.get("signatures")
    if not isinstance(signatures, list):
        raise TypeError("Transition signatures must be a list.")
    insufficient["signatures"] = signatures[:1]
    expect_error(
        KeyTransitionError,
        lambda: verify_key_transition(state_1, insufficient, state_2, datetime.fromisoformat("2026-07-12T21:30:00+00:00")),
        "one-of-three threshold",
    )
    negative_count += 1

    duplicate = copy.deepcopy(transition_1)
    duplicate_signatures = duplicate.get("signatures")
    if not isinstance(duplicate_signatures, list):
        raise TypeError("Transition signatures must be a list.")
    duplicate_signatures[1] = copy.deepcopy(duplicate_signatures[0])
    expect_error(
        KeyTransitionError,
        lambda: verify_key_transition(state_1, duplicate, state_2, datetime.fromisoformat("2026-07-12T21:30:00+00:00")),
        "duplicate transition signer",
    )
    negative_count += 1

    terminal_signer = signed_transition(
        state_3,
        state_4,
        "compromise_recovery",
        "2026-07-12T21:15:00Z",
        [c.key_id, f.key_id],
        [b, d],
    )
    expect_error(
        KeyTransitionError,
        lambda: verify_key_transition(state_3, terminal_signer, state_4, datetime.fromisoformat("2026-07-12T21:30:00+00:00")),
        "lost signer authorization",
    )
    negative_count += 1

    compromised_signer = signed_transition(
        state_4, state_5, "revocation", "2026-07-12T21:20:00Z", [d.key_id, g.key_id], [c, e]
    )
    expect_error(
        KeyTransitionError,
        lambda: verify_key_transition(state_4, compromised_signer, state_5, datetime.fromisoformat("2026-07-12T21:30:00+00:00")),
        "compromised signer authorization",
    )
    negative_count += 1

    threshold_downgrade = copy.deepcopy(state_2)
    threshold_downgrade["threshold"] = 1
    expect_error(
        KeyGovernanceError,
        lambda: validate_governance_state(threshold_downgrade),
        "threshold downgrade",
    )
    negative_count += 1

    exportable = copy.deepcopy(state_2)
    export_keys = exportable.get("keys")
    if not isinstance(export_keys, list) or not isinstance(export_keys[-1], dict):
        raise TypeError("Exportable state keys are invalid.")
    export_custody = export_keys[-1].get("custody")
    if not isinstance(export_custody, dict):
        raise TypeError("Exportable state custody is invalid.")
    export_custody["private_key_exportable"] = True
    expect_error(KeyGovernanceError, lambda: validate_governance_state(exportable), "exportable private key")
    negative_count += 1

    multi_operation = copy.deepcopy(state_2)
    operation_keys = multi_operation.get("keys")
    if not isinstance(operation_keys, list) or not isinstance(operation_keys[-1], dict):
        raise TypeError("Multi-operation state keys are invalid.")
    operation_custody = operation_keys[-1].get("custody")
    if not isinstance(operation_custody, dict):
        raise TypeError("Multi-operation state custody is invalid.")
    operation_custody["allowed_operations"] = ["sign", "decrypt"]
    expect_error(KeyGovernanceError, lambda: validate_governance_state(multi_operation), "custody operation widening")
    negative_count += 1

    unattested_hardware = copy.deepcopy(state_2)
    hardware_keys = unattested_hardware.get("keys")
    if not isinstance(hardware_keys, list) or not isinstance(hardware_keys[-1], dict):
        raise TypeError("Unattested hardware state keys are invalid.")
    hardware_custody = hardware_keys[-1].get("custody")
    if not isinstance(hardware_custody, dict):
        raise TypeError("Unattested hardware custody is invalid.")
    hardware_custody["connector_kind"] = "pkcs11"
    hardware_custody["hardware_backed"] = True
    hardware_custody["attestation_digest"] = None
    expect_error(
        KeyGovernanceError,
        lambda: validate_governance_state(unattested_hardware),
        "production custody without attestation",
    )
    negative_count += 1

    missing_replacement = copy.deepcopy(state_1)
    missing_keys = missing_replacement.get("keys")
    if not isinstance(missing_keys, list) or not isinstance(missing_keys[0], dict):
        raise TypeError("Missing replacement state keys are invalid.")
    missing_keys[0]["status"] = "revoked"
    expect_error(KeyGovernanceError, lambda: validate_governance_state(missing_replacement), "missing replacement")
    negative_count += 1

    mismatch_digest = copy.deepcopy(transition_1)
    mismatch_digest["next_state_digest"] = "sha256:" + ("0" * 64)
    expect_error(
        KeyTransitionError,
        lambda: verify_key_transition(state_1, mismatch_digest, state_2, datetime.fromisoformat("2026-07-12T21:30:00+00:00")),
        "next state digest substitution",
    )
    negative_count += 1

    affected_mismatch = copy.deepcopy(transition_1)
    affected_mismatch["affected_key_ids"] = [a.key_id]
    affected_mismatch = sign_transition(
        {key: value for key, value in affected_mismatch.items() if key != "signatures"}, [a, b]
    )
    expect_error(
        KeyTransitionError,
        lambda: verify_key_transition(state_1, affected_mismatch, state_2, datetime.fromisoformat("2026-07-12T21:30:00+00:00")),
        "affected key omission",
    )
    negative_count += 1

    reactivated = copy.deepcopy(state_3)
    reactivated["epoch"] = 4
    reactivated["issued_at"] = "2026-07-12T21:15:00Z"
    reactivated["previous_state_digest"] = sha256_digest(state_3)
    reactivated_keys = reactivated.get("keys")
    if not isinstance(reactivated_keys, list):
        raise TypeError("Reactivated state keys are invalid.")
    for value in reactivated_keys:
        if isinstance(value, dict) and value.get("key_id") == b.key_id:
            value["status"] = "active"
            value["valid_until"] = None
        if isinstance(value, dict) and value.get("key_id") == c.key_id:
            value["status"] = "retired"
            value["valid_until"] = "2026-07-12T21:15:00Z"
    reactivation_transition = signed_transition(
        state_3,
        reactivated,
        "rotation",
        "2026-07-12T21:15:00Z",
        [b.key_id, c.key_id],
        [d, e],
    )
    expect_error(
        KeyTransitionError,
        lambda: verify_key_transition(state_3, reactivation_transition, reactivated, datetime.fromisoformat("2026-07-12T21:30:00+00:00")),
        "terminal key reactivation",
    )
    negative_count += 1

    reused_material = copy.deepcopy(state_2)
    reused_keys = reused_material.get("keys")
    if not isinstance(reused_keys, list) or not isinstance(reused_keys[-1], dict):
        raise TypeError("Reused material state keys are invalid.")
    reused_keys[-1]["public_key_base64"] = a.public_key_base64
    expect_error(KeyGovernanceError, lambda: validate_governance_state(reused_material), "public key reuse")
    negative_count += 1

    future_transition = signed_transition(
        state_1, state_2, "rotation", "2026-07-12T21:05:00Z", [a.key_id, d.key_id], [a, b]
    )
    expect_error(
        KeyTransitionError,
        lambda: verify_key_transition(state_1, future_transition, state_2, datetime.fromisoformat("2026-07-12T21:04:59+00:00")),
        "future transition",
    )
    negative_count += 1

    rollback_state = copy.deepcopy(state_2)
    rollback_state["epoch"] = 1
    rollback_transition = mutate_and_resign(state_1, rollback_state, transition_1, [a, b])
    rollback_transition["to_epoch"] = 1
    rollback_transition = sign_transition(
        {key: value for key, value in rollback_transition.items() if key != "signatures"}, [a, b]
    )
    expect_error(
        KeyTransitionError,
        lambda: verify_key_transition(state_1, rollback_transition, rollback_state, datetime.fromisoformat("2026-07-12T21:30:00+00:00")),
        "epoch rollback",
    )
    negative_count += 1

    return {
        "status": "KEY_GOVERNANCE_VALID",
        "origin": ORIGIN,
        "threshold": 2,
        "ceremony_key_count": 3,
        "valid_transition_count": len(transitions),
        "transition_kinds": transition_kinds,
        "negative_fail_closed_case_count": negative_count,
        "custody_interface_kinds": ["pkcs11", "aws_kms", "azure_key_vault", "gcp_cloud_kms"],
        "external_custody_provider_calls": 0,
        "private_key_material_exported": False,
        "ephemeral_private_keys_persisted": False,
        "live_execution_performed": False,
    }


def main() -> None:
    project_root = Path(__file__).resolve().parent.parent
    result = validate_key_governance(project_root)
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
