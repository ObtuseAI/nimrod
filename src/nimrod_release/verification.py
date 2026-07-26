"""Offline release verification without installation or plugin execution authority."""

from __future__ import annotations

import base64
import copy
import hashlib
from datetime import datetime

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from nimrod_simulator.authorization import parse_timestamp
from nimrod_simulator.errors import PluginSandboxError, ReleaseVerificationError
from nimrod_simulator.jsonio import (
    canonical_json_bytes,
    require_boolean,
    require_integer,
    require_list,
    require_object,
    require_string,
    sha256_digest,
)
from nimrod_simulator.key_governance import (
    ACTIVE_KEY_STATUS,
    SigningConnector,
    decode_public_key,
    decode_signature,
    key_index,
    validate_governance_state,
)
from nimrod_simulator.model import JsonObject


RELEASE_SIGNATURE_DOMAIN = b"nimrod.edge-release-manifest.v0.1\x00"
PLUGIN_ALLOWED_CAPABILITIES = ["observe_process_metadata"]
PLUGIN_DENIED_CAPABILITIES = [
    "credential_access",
    "filesystem_write",
    "host_command",
    "network_access",
    "policy_write",
    "process_control",
    "signing",
]
PLUGIN_AUTHORITY = {
    "can_install": False,
    "can_load": False,
    "can_execute_host_command": False,
    "can_request_credentials": False,
    "can_change_policy": False,
}
RELEASE_AUTHORITY = {
    "can_install": False,
    "can_promote": False,
    "can_change_rollout": False,
    "can_change_policy": False,
}
RECEIPT_AUTHORITY = {
    "can_install": False,
    "can_promote": False,
    "can_execute_plugin": False,
    "can_change_trust": False,
}
RELEASE_BLOCKERS = [
    "INSTALLATION_GATE_MISSING",
    "PRODUCTION_CUSTODY_UNPROVEN",
    "STAGED_ROLLOUT_UNPERFORMED",
]


def artifact_digest(content: bytes) -> str:
    return f"sha256:{hashlib.sha256(content).hexdigest()}"


def release_signature_message(manifest: JsonObject) -> bytes:
    unsigned = {key: value for key, value in manifest.items() if key != "signatures"}
    return RELEASE_SIGNATURE_DOMAIN + canonical_json_bytes(unsigned)


def sign_release_manifest(
    unsigned_manifest: JsonObject,
    connectors: list[SigningConnector],
) -> JsonObject:
    if "signatures" in unsigned_manifest:
        raise ReleaseVerificationError("Unsigned release manifest must not contain signatures.")
    if not connectors:
        raise ReleaseVerificationError("Release signing requires at least one connector.")
    message = RELEASE_SIGNATURE_DOMAIN + canonical_json_bytes(unsigned_manifest)
    signatures: list[JsonObject] = []
    signer_ids: set[str] = set()
    for connector in connectors:
        if connector.key_id in signer_ids:
            raise ReleaseVerificationError(f"Release signing repeats signer '{connector.key_id}'.")
        signer_ids.add(connector.key_id)
        signatures.append(
            {
                "signer_id": connector.key_id,
                "role": connector.role,
                "algorithm": "Ed25519",
                "signature_base64": base64.b64encode(connector.sign(message)).decode("ascii"),
            }
        )
    signed = copy.deepcopy(unsigned_manifest)
    signed["signatures"] = signatures
    return signed


def verify_plugin_manifest(plugin: JsonObject) -> None:
    if plugin.get("manifest_version") != "0.1.0":
        raise PluginSandboxError("Plugin manifest_version must be '0.1.0'.")
    if plugin.get("authority") != PLUGIN_AUTHORITY:
        raise PluginSandboxError("Plugin manifest exposes prohibited lifecycle or host authority.")
    runtime = require_object(plugin.get("runtime"), "plugin.runtime")
    if runtime.get("kind") != "wasm_component" or runtime.get("abi") != "wasi_preview2":
        raise PluginSandboxError("Plugin runtime must remain a WASI Preview 2 component.")
    if require_boolean(runtime.get("threads"), "plugin.runtime.threads"):
        raise PluginSandboxError("Plugin sandbox cannot expose threads in the foundation profile.")
    if require_integer(runtime.get("maximum_memory_bytes"), "plugin.runtime.maximum_memory_bytes") > 67_108_864:
        raise PluginSandboxError("Plugin memory ceiling exceeds the 64 MiB foundation limit.")
    if require_integer(runtime.get("maximum_fuel"), "plugin.runtime.maximum_fuel") > 50_000_000:
        raise PluginSandboxError("Plugin fuel ceiling exceeds the foundation limit.")
    if require_integer(runtime.get("wall_clock_timeout_ms"), "plugin.runtime.wall_clock_timeout_ms") > 500:
        raise PluginSandboxError("Plugin wall-clock timeout exceeds the foundation limit.")
    capabilities = require_object(plugin.get("capabilities"), "plugin.capabilities")
    if capabilities.get("allow") != PLUGIN_ALLOWED_CAPABILITIES:
        raise PluginSandboxError("Plugin allowed capabilities are incomplete or widened.")
    if capabilities.get("deny") != PLUGIN_DENIED_CAPABILITIES:
        raise PluginSandboxError("Plugin denied capabilities are incomplete or reordered.")
    filesystem = require_object(plugin.get("filesystem"), "plugin.filesystem")
    network = require_object(plugin.get("network"), "plugin.network")
    lifecycle = require_object(plugin.get("lifecycle"), "plugin.lifecycle")
    if filesystem.get("read_paths") != [] or filesystem.get("write_paths") != []:
        raise PluginSandboxError("Plugin foundation manifest cannot expose filesystem paths.")
    if network.get("allowed_destinations") != [] or network.get("dns") is not False:
        raise PluginSandboxError("Plugin foundation manifest cannot expose network or DNS access.")
    if any(
        lifecycle.get(field) is not False
        for field in ("auto_start", "install_authorized", "load_authorized")
    ):
        raise PluginSandboxError("Plugin manifest cannot authorize installation, loading, or auto-start.")


def verify_release_signatures(
    manifest: JsonObject,
    governance_state: JsonObject,
    verification_time: datetime,
) -> tuple[list[str], list[str]]:
    validate_governance_state(governance_state)
    signatures = require_list(manifest.get("signatures"), "release.signatures")
    keys = key_index(governance_state)
    message = release_signature_message(manifest)
    verified_signers: list[str] = []
    verified_roles: list[str] = []
    for index, value in enumerate(signatures):
        signature = require_object(value, f"release.signatures[{index}]")
        signer_id = require_string(signature.get("signer_id"), f"release.signatures[{index}].signer_id")
        role = require_string(signature.get("role"), f"release.signatures[{index}].role")
        if signer_id in verified_signers:
            raise ReleaseVerificationError(f"Release signature repeats signer '{signer_id}'.")
        key = keys.get(signer_id)
        if key is None or key.get("status") != ACTIVE_KEY_STATUS:
            raise ReleaseVerificationError(f"Release signer '{signer_id}' is not active in the trusted epoch.")
        if key.get("role") != role:
            raise ReleaseVerificationError(f"Release signer '{signer_id}' role is not bound to governance.")
        if signature.get("algorithm") != "Ed25519":
            raise ReleaseVerificationError(f"Release signer '{signer_id}' uses an unsupported algorithm.")
        valid_from = parse_timestamp(key.get("valid_from"), f"governance key '{signer_id}' valid_from")
        valid_until_value = key.get("valid_until")
        if verification_time < valid_from:
            raise ReleaseVerificationError(f"Release signer '{signer_id}' is not yet valid.")
        if valid_until_value is not None and verification_time > parse_timestamp(
            valid_until_value,
            f"governance key '{signer_id}' valid_until",
        ):
            raise ReleaseVerificationError(f"Release signer '{signer_id}' is expired.")
        try:
            public_key = Ed25519PublicKey.from_public_bytes(
                decode_public_key(
                    require_string(key.get("public_key_base64"), f"governance key '{signer_id}' public key"),
                    signer_id,
                )
            )
            public_key.verify(
                decode_signature(
                    require_string(signature.get("signature_base64"), f"release signature '{signer_id}'"),
                    signer_id,
                ),
                message,
            )
        except (InvalidSignature, ValueError) as error:
            raise ReleaseVerificationError(f"Release signature for '{signer_id}' is invalid.") from error
        verified_signers.append(signer_id)
        verified_roles.append(role)
    threshold = require_integer(governance_state.get("threshold"), "governance.threshold")
    minimum_roles = require_integer(
        governance_state.get("minimum_distinct_roles"),
        "governance.minimum_distinct_roles",
    )
    if len(verified_signers) < threshold or len(set(verified_roles)) < minimum_roles:
        raise ReleaseVerificationError("Release signatures do not satisfy threshold and role diversity.")
    return sorted(verified_signers), sorted(set(verified_roles))


def verify_release_candidate(
    manifest: JsonObject,
    plugin_manifests: list[JsonObject],
    artifact_content: bytes,
    trusted_release_digest: str,
    trusted_release_sequence: int,
    governance_state: JsonObject,
    verification_time: datetime,
) -> JsonObject:
    if manifest.get("origin") != "simulated" or manifest.get("channel") != "candidate":
        raise ReleaseVerificationError("Foundation release verification accepts only simulated candidates.")
    if manifest.get("product") != "nimrod-edge" or manifest.get("authority") != RELEASE_AUTHORITY:
        raise ReleaseVerificationError("Release manifest product or authority boundary is invalid.")
    if manifest.get("governance_state_digest") != sha256_digest(governance_state):
        raise ReleaseVerificationError("Release manifest is not bound to the supplied governance state.")
    issued_at = parse_timestamp(manifest.get("issued_at"), "release.issued_at")
    expires_at = parse_timestamp(manifest.get("expires_at"), "release.expires_at")
    if verification_time < issued_at or verification_time > expires_at:
        raise ReleaseVerificationError("Release manifest is outside its validity window.")
    sequence = require_integer(manifest.get("release_sequence"), "release.release_sequence")
    if sequence != trusted_release_sequence + 1:
        raise ReleaseVerificationError("Release sequence does not advance the trusted baseline exactly once.")
    previous_release = require_object(manifest.get("previous_release"), "release.previous_release")
    if previous_release.get("manifest_digest") != trusted_release_digest:
        raise ReleaseVerificationError("Release manifest does not bind the trusted predecessor digest.")
    if previous_release.get("release_sequence") != trusted_release_sequence:
        raise ReleaseVerificationError("Release predecessor sequence does not match the trusted baseline.")
    artifact = require_object(manifest.get("artifact"), "release.artifact")
    measured_artifact_digest = artifact_digest(artifact_content)
    if artifact.get("digest") != measured_artifact_digest or artifact.get("size_bytes") != len(artifact_content):
        raise ReleaseVerificationError("Release artifact bytes do not match the signed digest and size.")
    require_string(artifact.get("provenance_digest"), "release.artifact.provenance_digest")
    require_string(artifact.get("sbom_digest"), "release.artifact.sbom_digest")
    rollback = require_object(manifest.get("rollback"), "release.rollback")
    if rollback.get("target_release_manifest_digest") != trusted_release_digest:
        raise ReleaseVerificationError("Rollback target is not the trusted predecessor release.")
    if any(
        rollback.get(field) is not True
        for field in ("offline_verified", "rollback_tested", "safe_uninstall_tested")
    ):
        raise ReleaseVerificationError("Release rollback and uninstall evidence is incomplete.")
    rollout = require_object(manifest.get("rollout"), "release.rollout")
    if rollout.get("percentage") != 0 or rollout.get("cohort") != [] or rollout.get("installation_authorized") is not False:
        raise ReleaseVerificationError("Candidate release cannot silently become a staged installation.")
    references = require_list(manifest.get("plugins"), "release.plugins")
    expected_plugins = sorted(
        (
            require_string(require_object(item, "release.plugin").get("plugin_id"), "release.plugin.plugin_id"),
            require_string(require_object(item, "release.plugin").get("manifest_digest"), "release.plugin.manifest_digest"),
        )
        for item in references
    )
    actual_plugins: list[tuple[str, str]] = []
    for plugin in plugin_manifests:
        verify_plugin_manifest(plugin)
        actual_plugins.append(
            (
                require_string(plugin.get("plugin_id"), "plugin.plugin_id"),
                sha256_digest(plugin),
            )
        )
    if sorted(actual_plugins) != expected_plugins:
        raise ReleaseVerificationError("Release plugin manifest set does not match the signed references.")
    verified_signers, verified_roles = verify_release_signatures(
        manifest,
        governance_state,
        verification_time,
    )
    return {
        "receipt_version": "0.1.0",
        "origin": "simulated",
        "status": "UPDATE_SIGNATURE_PROVENANCE_AND_ROLLBACK_VALID_INSTALLATION_BLOCKED",
        "verified_at": verification_time.isoformat().replace("+00:00", "Z"),
        "manifest_digest": sha256_digest(manifest),
        "artifact_digest": measured_artifact_digest,
        "governance_state_digest": sha256_digest(governance_state),
        "verified_signer_ids": verified_signers,
        "verified_roles": verified_roles,
        "anti_rollback_verified": True,
        "previous_release_bound": True,
        "artifact_verified": True,
        "provenance_present": True,
        "sbom_present": True,
        "rollback_contract_verified": True,
        "plugin_manifests_verified": True,
        "plugin_code_executed": False,
        "installation_authorized": False,
        "installation_performed": False,
        "rollback_performed": False,
        "network_access_performed": False,
        "blockers": list(RELEASE_BLOCKERS),
        "authority": dict(RECEIPT_AUTHORITY),
    }
