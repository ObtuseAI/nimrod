"""Deterministic CACIS world-model replay and immutable generation storage."""

from __future__ import annotations

import json
import os
import uuid
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import cast

from nimrod_simulator.errors import WorldModelError
from nimrod_simulator.jsonio import canonical_json_bytes, sha256_digest
from nimrod_simulator.model import JsonObject, JsonValue


DOMAINS: tuple[str, ...] = ("identity", "endpoint", "network", "cloud", "threat", "recovery")
OBSERVATION_AUTHORITY: Mapping[str, bool] = {
    "can_authorize": False,
    "can_execute": False,
    "can_change_policy": False,
    "can_claim_truth": False,
}
GENERATION_AUTHORITY: Mapping[str, bool] = {
    "can_authorize": False,
    "can_execute": False,
    "can_change_policy": False,
    "can_contact_targets": False,
    "policy_input_ready": False,
    "production_truth_claimed": False,
}
SECURITY_CLAIM = (
    "Deterministic replay derived world state; no live sensing, policy readiness, execution, "
    "containment, recovery, or production truth established"
)
GENERATION_NAMESPACE = uuid.UUID("da4f5826-c6a5-5b3e-979a-328f42a0c613")


def require_object(value: object, label: str) -> JsonObject:
    if not isinstance(value, dict):
        raise WorldModelError(f"CACIS world model {label} must be an object.")
    return cast(JsonObject, value)


def require_object_list(value: object, label: str) -> tuple[JsonObject, ...]:
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise WorldModelError(f"CACIS world model {label} must be a list of objects.")
    return tuple(cast(JsonObject, item) for item in value)


def require_string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise WorldModelError(f"CACIS world model {label} must be a non-empty string.")
    return value


def parse_timestamp(value: object, label: str) -> datetime:
    text = require_string(value, label)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as error:
        raise WorldModelError(f"CACIS world model {label} is not a valid timestamp: value={text!r}.") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise WorldModelError(f"CACIS world model {label} must include an offset: value={text!r}.")
    return parsed.astimezone(timezone.utc)


def observation_key(observation: JsonObject) -> tuple[str, str, str, str]:
    subject = require_object(observation.get("subject"), "observation.subject")
    return (
        require_string(observation.get("domain"), "observation.domain"),
        require_string(subject.get("subject_id"), "observation.subject.subject_id"),
        require_string(subject.get("subject_type"), "observation.subject.subject_type"),
        require_string(observation.get("fact_key"), "observation.fact_key"),
    )


def validate_observation(observation: JsonObject) -> None:
    authority = require_object(observation.get("authority"), "observation.authority")
    if authority != OBSERVATION_AUTHORITY:
        raise WorldModelError(
            "CACIS observations are non-authorizing data and cannot claim truth or change policy: "
            f"received={authority!r}."
        )
    if observation.get("origin") != "replayed":
        raise WorldModelError(f"CACIS W1 accepts replayed observations only: origin={observation.get('origin')!r}.")
    domain, _, _, _ = observation_key(observation)
    if domain not in DOMAINS:
        raise WorldModelError(f"CACIS observation domain is unknown: domain={domain!r}.")
    assertion = require_object(observation.get("assertion"), "observation.assertion")
    posture = assertion.get("posture")
    value = assertion.get("value")
    confidence = observation.get("confidence")
    if not isinstance(confidence, int | float) or isinstance(confidence, bool):
        raise WorldModelError("CACIS observation confidence must be numeric.")
    if posture == "unknown" and (value is not None or float(confidence) != 0.0):
        raise WorldModelError("CACIS unknown observations require null value and zero confidence.")
    if posture == "observed" and (not isinstance(value, str) or not value):
        raise WorldModelError("CACIS observed assertions require a non-empty string value.")
    observed_at = parse_timestamp(observation.get("observed_at"), "observation.observed_at")
    collected_at = parse_timestamp(observation.get("collected_at"), "observation.collected_at")
    valid_until = parse_timestamp(observation.get("valid_until"), "observation.valid_until")
    if observed_at > collected_at:
        raise WorldModelError("CACIS observation cannot be collected before it was observed.")
    if valid_until <= observed_at:
        raise WorldModelError("CACIS observation validity must end after observation time.")


def requirement_key(requirement: JsonObject) -> tuple[str, str, str, str]:
    return (
        require_string(requirement.get("domain"), "requirement.domain"),
        require_string(requirement.get("subject_id"), "requirement.subject_id"),
        require_string(requirement.get("subject_type"), "requirement.subject_type"),
        require_string(requirement.get("fact_key"), "requirement.fact_key"),
    )


def validate_replay_scenario(scenario: JsonObject) -> None:
    expected_fields = {
        "scenario_version",
        "scenario_id",
        "origin",
        "title",
        "generated_at",
        "previous_generation_digest",
        "requirements",
        "observations",
    }
    if set(scenario) != expected_fields:
        raise WorldModelError(
            "CACIS replay scenario fields must match the W1 contract exactly: "
            f"missing={sorted(expected_fields - set(scenario))!r}, extra={sorted(set(scenario) - expected_fields)!r}."
        )
    if scenario.get("scenario_version") != "0.1.0" or scenario.get("origin") != "replayed":
        raise WorldModelError("CACIS W1 scenario version and origin must be 0.1.0 and replayed.")
    previous_generation_digest = scenario.get("previous_generation_digest")
    if previous_generation_digest is not None:
        digest_filename(require_string(previous_generation_digest, "scenario.previous_generation_digest"))
    generated_at = parse_timestamp(scenario.get("generated_at"), "scenario.generated_at")
    requirements = require_object_list(scenario.get("requirements"), "scenario.requirements")
    observations = require_object_list(scenario.get("observations"), "scenario.observations")
    keys = tuple(requirement_key(item) for item in requirements)
    if len(keys) != len(set(keys)):
        raise WorldModelError("CACIS world-model requirements must be unique.")
    if {key[0] for key in keys} != set(DOMAINS):
        raise WorldModelError("CACIS W1 requirements must cover all six world-model domains.")
    observation_ids: list[str] = []
    sequences: list[int] = []
    for observation in observations:
        validate_observation(observation)
        observation_ids.append(require_string(observation.get("observation_id"), "observation.observation_id"))
        sequence = observation.get("replay_sequence")
        if not isinstance(sequence, int) or isinstance(sequence, bool):
            raise WorldModelError("CACIS replay_sequence must be an integer.")
        sequences.append(sequence)
        if observation_key(observation) not in set(keys):
            raise WorldModelError(
                "CACIS W1 observation is outside the declared requirement set: "
                f"key={observation_key(observation)!r}."
            )
        if parse_timestamp(observation.get("collected_at"), "observation.collected_at") > generated_at:
            raise WorldModelError("CACIS generation cannot include an observation collected in its future.")
    if len(observation_ids) != len(set(observation_ids)):
        raise WorldModelError("CACIS replay observation identifiers must be unique.")
    if sequences != list(range(1, len(observations) + 1)):
        raise WorldModelError(
            "CACIS replay sequences must be ordered, unique, and contiguous from one: "
            f"received={sequences!r}."
        )


def build_candidate(observation: JsonObject) -> JsonObject:
    assertion = require_object(observation["assertion"], "observation.assertion")
    source = require_object(observation["source"], "observation.source")
    evidence_refs = observation["evidence_refs"]
    if not isinstance(evidence_refs, list):
        raise WorldModelError("CACIS observation evidence_refs must be a list.")
    return {
        "posture": assertion["posture"],
        "value": assertion["value"],
        "confidence": observation["confidence"],
        "observed_at": observation["observed_at"],
        "valid_until": observation["valid_until"],
        "source_ids": [source["source_id"]],
        "evidence_refs": sorted(cast(list[str], evidence_refs)),
    }


def derive_fact_state(observations: Sequence[JsonObject], generated_at: datetime) -> str:
    assertions = [require_object(item["assertion"], "observation.assertion") for item in observations]
    observed_values = {str(item["value"]) for item in assertions if item["posture"] == "observed"}
    if len(observed_values) > 1:
        return "contradictory"
    if not observed_values:
        return "unknown"
    if all(parse_timestamp(item["valid_until"], "observation.valid_until") < generated_at for item in observations):
        return "stale"
    return "known"


def derive_fact(requirement: JsonObject, observations: Sequence[JsonObject], generated_at: datetime) -> JsonObject:
    sorted_observations = sorted(observations, key=lambda item: int(cast(int, item["replay_sequence"])))
    return {
        "subject_id": requirement["subject_id"],
        "subject_type": requirement["subject_type"],
        "fact_key": requirement["fact_key"],
        "state": derive_fact_state(sorted_observations, generated_at),
        "candidates": [build_candidate(item) for item in sorted_observations],
        "derived_from_observation_digests": [sha256_digest(item) for item in sorted_observations],
    }


def derive_domain_state(domain: str, facts: Sequence[JsonObject], missing: Sequence[str]) -> str:
    states = {str(item["state"]) for item in facts}
    if "contradictory" in states:
        return "contradictory"
    if not facts or states == {"unknown"}:
        return "unknown"
    if not missing and states == {"known"}:
        return "known"
    return "partially_known"


def build_generation_body(scenario: JsonObject) -> JsonObject:
    validate_replay_scenario(scenario)
    generated_at = parse_timestamp(scenario["generated_at"], "scenario.generated_at")
    requirements = require_object_list(scenario["requirements"], "scenario.requirements")
    observations = require_object_list(scenario["observations"], "scenario.observations")
    indexed: dict[tuple[str, str, str, str], list[JsonObject]] = {}
    for observation in observations:
        indexed.setdefault(observation_key(observation), []).append(observation)
    domains: list[JsonObject] = []
    fact_states: list[str] = []
    for domain in DOMAINS:
        domain_requirements = [item for item in requirements if item["domain"] == domain]
        facts: list[JsonObject] = []
        missing: list[str] = []
        for requirement in domain_requirements:
            matching = indexed.get(requirement_key(requirement), [])
            if not matching:
                missing.append(f"{requirement['subject_id']}::{requirement['fact_key']}")
                continue
            fact = derive_fact(requirement, matching, generated_at)
            facts.append(fact)
            fact_states.append(str(fact["state"]))
        domains.append(
            {
                "domain": domain,
                "knowledge_state": derive_domain_state(domain, facts, missing),
                "facts": facts,
                "missing_requirements": sorted(missing),
            }
        )
    domain_states = [str(item["knowledge_state"]) for item in domains]
    observation_digests = [sha256_digest(item) for item in observations]
    scenario_id = require_string(scenario["scenario_id"], "scenario.scenario_id")
    generation_identity: JsonObject = {"scenario_id": scenario_id, "observations": observation_digests}
    previous_generation_digest = scenario.get("previous_generation_digest")
    if previous_generation_digest is not None:
        generation_identity["previous_generation_digest"] = previous_generation_digest
    generation_name = sha256_digest(cast(JsonValue, generation_identity))
    return {
        "generation_id": str(uuid.uuid5(GENERATION_NAMESPACE, generation_name)),
        "origin": "replayed",
        "scenario_id": scenario_id,
        "scenario_digest": sha256_digest(scenario),
        "previous_generation_digest": previous_generation_digest,
        "generated_at": scenario["generated_at"],
        "observation_set_digest": sha256_digest(cast(JsonValue, observation_digests)),
        "observation_digests": observation_digests,
        "domains": domains,
        "summary": {
            "known_domain_count": domain_states.count("known"),
            "partially_known_domain_count": domain_states.count("partially_known"),
            "unknown_domain_count": domain_states.count("unknown"),
            "contradictory_domain_count": domain_states.count("contradictory"),
            "known_fact_count": fact_states.count("known"),
            "unknown_fact_count": fact_states.count("unknown"),
            "stale_fact_count": fact_states.count("stale"),
            "contradictory_fact_count": fact_states.count("contradictory"),
        },
        "replay": {
            "observation_count": len(observations),
            "first_sequence": 1,
            "last_sequence": len(observations),
            "duplicate_count": 0,
            "out_of_order_count": 0,
            "deterministic": True,
        },
        "authority": dict(GENERATION_AUTHORITY),
        "security_claim": SECURITY_CLAIM,
    }


def build_world_model_generation(scenario: JsonObject) -> JsonObject:
    generation = build_generation_body(scenario)
    return {
        "generation_version": "0.1.0",
        "generation_digest": sha256_digest(generation),
        "generation": generation,
    }


def validate_world_model_generation(document: JsonObject) -> None:
    generation = require_object(document.get("generation"), "generation")
    if document.get("generation_digest") != sha256_digest(generation):
        raise WorldModelError("CACIS world-model generation digest does not match canonical generation content.")
    domains = require_object_list(generation.get("domains"), "generation.domains")
    if tuple(str(item.get("domain")) for item in domains) != DOMAINS:
        raise WorldModelError("CACIS world-model generation must preserve canonical six-domain order.")
    authority = require_object(generation.get("authority"), "generation.authority")
    if authority != GENERATION_AUTHORITY:
        raise WorldModelError("CACIS world-model generation cannot authorize, execute, contact targets, or claim production truth.")
    if generation.get("security_claim") != SECURITY_CLAIM:
        raise WorldModelError("CACIS world-model generation security claim was widened.")
    previous_generation_digest = generation.get("previous_generation_digest")
    if previous_generation_digest is not None:
        digest_filename(require_string(previous_generation_digest, "generation.previous_generation_digest"))
    summary = require_object(generation.get("summary"), "generation.summary")
    domain_states = [str(item.get("knowledge_state")) for item in domains]
    expected_domain_counts = {
        "known_domain_count": domain_states.count("known"),
        "partially_known_domain_count": domain_states.count("partially_known"),
        "unknown_domain_count": domain_states.count("unknown"),
        "contradictory_domain_count": domain_states.count("contradictory"),
    }
    for field, expected in expected_domain_counts.items():
        if summary.get(field) != expected:
            raise WorldModelError(f"CACIS world-model summary is inconsistent: field={field!r}, expected={expected!r}.")
    fact_states = [
        str(fact.get("state"))
        for domain in domains
        for fact in require_object_list(domain.get("facts"), f"generation.domains.{domain.get('domain')}.facts")
    ]
    expected_fact_counts = {
        "known_fact_count": fact_states.count("known"),
        "unknown_fact_count": fact_states.count("unknown"),
        "stale_fact_count": fact_states.count("stale"),
        "contradictory_fact_count": fact_states.count("contradictory"),
    }
    for field, expected in expected_fact_counts.items():
        if summary.get(field) != expected:
            raise WorldModelError(f"CACIS world-model fact summary is inconsistent: field={field!r}, expected={expected!r}.")


def read_json_document(path: Path, label: str) -> JsonObject:
    try:
        value: object = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise WorldModelError(f"Unable to read CACIS {label}: path={path}; error={error}.") from error
    return require_object(value, label)


def digest_filename(digest: str) -> str:
    hex_digest = digest.removeprefix("sha256:")
    if not digest.startswith("sha256:") or len(hex_digest) != 64 or any(character not in "0123456789abcdef" for character in hex_digest):
        raise WorldModelError(f"CACIS content digest is invalid: digest={digest!r}.")
    return hex_digest + ".json"


def write_immutable_json(path: Path, value: JsonObject) -> None:
    payload = canonical_json_bytes(value) + b"\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("xb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError:
        if path.read_bytes() != payload:
            raise WorldModelError(f"CACIS immutable artifact conflicts with existing bytes: path={path}.")


def prepare_world_model_store(store_root: Path, scenario: JsonObject, document: JsonObject) -> JsonObject:
    validate_replay_scenario(scenario)
    validate_world_model_generation(document)
    observations = require_object_list(scenario["observations"], "scenario.observations")
    for observation in observations:
        digest = sha256_digest(observation)
        write_immutable_json(store_root / "observations" / digest_filename(digest), observation)
    generation_digest = require_string(document["generation_digest"], "generation_digest")
    generation_path = store_root / "generations" / digest_filename(generation_digest)
    write_immutable_json(generation_path, document)
    prepared_head = {
        "head_version": "0.1.0",
        "generation_digest": generation_digest,
        "generation_path": generation_path.relative_to(store_root).as_posix(),
        "previous_generation_digest": require_object(document["generation"], "generation").get(
            "previous_generation_digest"
        ),
    }
    prepared_path = store_root / ("HEAD." + generation_digest.removeprefix("sha256:") + ".prepared")
    write_immutable_json(prepared_path, prepared_head)
    return prepared_head


def commit_world_model_store(store_root: Path, generation_digest: str) -> JsonObject:
    prepared_path = store_root / ("HEAD." + generation_digest.removeprefix("sha256:") + ".prepared")
    head_path = store_root / "HEAD.json"
    if not prepared_path.exists():
        if head_path.exists():
            existing = read_json_document(head_path, "active head")
            if existing.get("generation_digest") == generation_digest:
                return existing
        raise WorldModelError(f"CACIS prepared head is missing: path={prepared_path}.")
    prepared = read_json_document(prepared_path, "prepared head")
    generation_path = store_root / require_string(prepared.get("generation_path"), "prepared head.generation_path")
    expected_generation_path = store_root / "generations" / digest_filename(generation_digest)
    if generation_path.resolve() != expected_generation_path.resolve():
        raise WorldModelError("CACIS prepared head generation path is not the digest-derived artifact path.")
    document = read_json_document(generation_path, "prepared generation")
    validate_world_model_generation(document)
    if document.get("generation_digest") != generation_digest:
        raise WorldModelError("CACIS prepared head generation digest does not match the requested commit.")
    generation = require_object(document.get("generation"), "prepared generation.generation")
    previous_generation_digest = generation.get("previous_generation_digest")
    if prepared.get("previous_generation_digest") != previous_generation_digest:
        raise WorldModelError("CACIS prepared head previous-generation binding is invalid.")
    if head_path.exists():
        existing = read_json_document(head_path, "active head")
        existing_digest = require_string(existing.get("generation_digest"), "active head.generation_digest")
        if existing_digest == generation_digest:
            prepared_path.unlink()
            return existing
        if previous_generation_digest != existing_digest:
            raise WorldModelError(
                "CACIS successor generation does not extend the active head: "
                f"active={existing_digest!r}, previous={previous_generation_digest!r}."
            )
    elif previous_generation_digest is not None:
        raise WorldModelError("CACIS successor generation cannot be committed without its active predecessor.")
    os.replace(prepared_path, head_path)
    return read_json_document(head_path, "active head")


def recover_world_model_store(store_root: Path) -> JsonObject:
    generation_files = sorted((store_root / "generations").glob("*.json")) if (store_root / "generations").exists() else []
    observation_files = sorted((store_root / "observations").glob("*.json")) if (store_root / "observations").exists() else []
    for observation_path in observation_files:
        observation = read_json_document(observation_path, "immutable observation")
        validate_observation(observation)
        if observation_path.name != digest_filename(sha256_digest(observation)):
            raise WorldModelError(f"CACIS observation filename does not match its content digest: path={observation_path}.")
    for generation_path in generation_files:
        document = read_json_document(generation_path, "immutable generation")
        validate_world_model_generation(document)
        digest = require_string(document["generation_digest"], "generation_digest")
        if generation_path.name != digest_filename(digest):
            raise WorldModelError(f"CACIS generation filename does not match its content digest: path={generation_path}.")
    head_path = store_root / "HEAD.json"
    prepared_files = sorted(store_root.glob("HEAD.*.prepared")) if store_root.exists() else []
    if not head_path.exists():
        return {
            "status": "prepared_uncommitted" if prepared_files else "empty",
            "active_generation_digest": None,
            "observation_file_count": len(observation_files),
            "generation_file_count": len(generation_files),
            "prepared_head_count": len(prepared_files),
        }
    head = read_json_document(head_path, "active head")
    generation_digest = require_string(head.get("generation_digest"), "head.generation_digest")
    generation_path = store_root / require_string(head.get("generation_path"), "head.generation_path")
    expected_generation_path = store_root / "generations" / digest_filename(generation_digest)
    if generation_path.resolve() != expected_generation_path.resolve():
        raise WorldModelError("CACIS active head generation path is not the digest-derived artifact path.")
    if not generation_path.exists():
        raise WorldModelError(f"CACIS active generation artifact is missing: path={generation_path}.")
    document = read_json_document(generation_path, "active generation")
    validate_world_model_generation(document)
    if document.get("generation_digest") != generation_digest:
        raise WorldModelError("CACIS active head digest does not match its generation artifact.")
    return {
        "status": "active_replayed_generation",
        "active_generation_digest": generation_digest,
        "observation_file_count": len(observation_files),
        "generation_file_count": len(generation_files),
        "prepared_head_count": len(prepared_files),
    }
