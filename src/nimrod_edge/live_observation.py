"""Caller-scoped, read-only Windows process observation for the Edge preview."""

from __future__ import annotations

import hashlib
import os
from datetime import datetime

from nimrod_platform_assurance.windows_isolation_collector import collect_process_identity
from nimrod_simulator.compiler import deterministic_uuid, format_timestamp
from nimrod_simulator.errors import EdgeLiveObservationError
from nimrod_simulator.model import JsonObject


LIVE_OBSERVATION_STATUS = "EDGE_LIVE_PROCESS_OBSERVED_POLICY_INPUT_INCOMPLETE"
COLLECTION_INTERFACES = [
    "OpenProcess",
    "QueryFullProcessImageNameW",
    "OpenProcessToken",
    "GetTokenInformation",
    "LookupAccountSidW",
    "ConvertSidToStringSidW",
]
MISSING_POLICY_FACTS = [
    "destination_observation",
    "parent_process_observation",
    "publisher_verification",
    "user_writable_classification",
]
LIVE_OBSERVATION_BLOCKERS = [
    "DESTINATION_OBSERVATION_MISSING",
    "PARENT_PROCESS_OBSERVATION_MISSING",
    "PUBLISHER_VERIFICATION_MISSING",
    "USER_WRITABLE_CLASSIFICATION_MISSING",
]
LIVE_OBSERVATION_AUTHORITY = {
    "can_propose": False,
    "can_authorize": False,
    "can_execute": False,
    "can_modify_process": False,
    "can_modify_network": False,
    "can_change_policy": False,
}


def _string_digest(value: str) -> str:
    return f"sha256:{hashlib.sha256(value.encode('utf-8')).hexdigest()}"


def validate_live_process_observation(observation: JsonObject) -> None:
    if observation.get("origin") != "live" or observation.get("status") != LIVE_OBSERVATION_STATUS:
        raise EdgeLiveObservationError("Live Edge observation must preserve its literal live incomplete status.")
    if observation.get("authority") != LIVE_OBSERVATION_AUTHORITY:
        raise EdgeLiveObservationError("Live Edge observation exposes prohibited authority.")
    if observation.get("blockers") != LIVE_OBSERVATION_BLOCKERS:
        raise EdgeLiveObservationError("Live Edge observation blocker set is incomplete or reordered.")
    scope = observation.get("scope")
    process = observation.get("process")
    collector = observation.get("collector")
    policy_input = observation.get("policy_input")
    if not all(isinstance(value, dict) for value in (scope, process, collector, policy_input)):
        raise EdgeLiveObservationError("Live Edge observation is missing scope, process, collector, or policy input.")
    if scope.get("kind") != "requested_process_only" or scope.get("requested_process_id") != process.get("process_id"):
        raise EdgeLiveObservationError("Live Edge observation escaped its requested process scope.")
    if collector.get("requested_process_only") is not True:
        raise EdgeLiveObservationError("Live Edge collector did not preserve requested-process-only scope.")
    if collector.get("interfaces") != COLLECTION_INTERFACES:
        raise EdgeLiveObservationError("Live Edge collector interface declaration is incomplete or widened.")
    prohibited_collector_truths = (
        "active_network_probe_performed",
        "raw_executable_path_retained",
        "raw_account_sid_retained",
        "writes_performed",
    )
    if any(collector.get(field) is not False for field in prohibited_collector_truths):
        raise EdgeLiveObservationError("Live Edge collector claims prohibited probing, retention, or writes.")
    if policy_input.get("ready_for_egress_policy") is not False:
        raise EdgeLiveObservationError("Process identity alone cannot become an egress policy input.")
    if policy_input.get("observed_facts") != [] or policy_input.get("missing_facts") != MISSING_POLICY_FACTS:
        raise EdgeLiveObservationError("Live Edge observation launders missing facts into observed policy evidence.")


def collect_live_process_observation(process_id: int, collected_at: datetime) -> JsonObject:
    if process_id <= 0:
        raise EdgeLiveObservationError(
            f"Live Edge observation requires a positive process_id; received {process_id}."
        )
    identity = collect_process_identity(process_id)
    account_sid = identity.get("os_account_sid")
    if not isinstance(account_sid, str) or not account_sid:
        raise EdgeLiveObservationError("Live Edge process identity did not contain an account SID.")
    executable_digest = identity.get("executable_digest")
    path_digest = identity.get("executable_path_digest")
    account_identifier = identity.get("os_account_identifier")
    if not all(isinstance(value, str) and value for value in (executable_digest, path_digest, account_identifier)):
        raise EdgeLiveObservationError("Live Edge process identity contains an invalid digest or account identifier.")
    collected_at_text = format_timestamp(collected_at)
    observation: JsonObject = {
        "observation_version": "0.1.0",
        "observation_id": deterministic_uuid(
            str(process_id),
            f"{executable_digest}:{collected_at_text}",
            "edge-live-process-observation",
        ),
        "origin": "live",
        "status": LIVE_OBSERVATION_STATUS,
        "collected_at": collected_at_text,
        "platform": "windows",
        "scope": {
            "kind": "requested_process_only",
            "requested_process_id": process_id,
        },
        "process": {
            "process_id": process_id,
            "executable_digest": executable_digest,
            "executable_path_digest": path_digest,
            "os_account_identifier": account_identifier,
            "os_account_sid_digest": _string_digest(account_sid.casefold()),
        },
        "collector": {
            "process_id": os.getpid(),
            "independent_process": os.getpid() != process_id,
            "interfaces": list(COLLECTION_INTERFACES),
            "requested_process_only": True,
            "active_network_probe_performed": False,
            "raw_executable_path_retained": False,
            "raw_account_sid_retained": False,
            "writes_performed": False,
        },
        "policy_input": {
            "ready_for_egress_policy": False,
            "observed_facts": [],
            "missing_facts": list(MISSING_POLICY_FACTS),
        },
        "blockers": list(LIVE_OBSERVATION_BLOCKERS),
        "authority": dict(LIVE_OBSERVATION_AUTHORITY),
    }
    validate_live_process_observation(observation)
    return observation
