"""Benign hold-open process for external verifier identity and ACL observation."""

from __future__ import annotations

import argparse
import json
import os
import time
from pathlib import Path


CREDENTIAL_PREFIXES: tuple[str, ...] = (
    "ANTHROPIC_",
    "AWS_",
    "AZURE_",
    "DOCKER_",
    "GITHUB_",
    "GOOGLE_",
    "KUBECONFIG",
    "OPENAI_",
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--component-id", required=True)
    parser.add_argument("--ready-file", type=Path, required=True)
    parser.add_argument("--release-file", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=int, required=True)
    arguments = parser.parse_args()
    if arguments.timeout_seconds <= 0 or arguments.timeout_seconds > 30:
        raise ValueError("Verifier identity probe timeout must be between 1 and 30 seconds.")
    names = sorted(os.environ)
    credential_names = [name for name in names if any(name.upper().startswith(prefix) for prefix in CREDENTIAL_PREFIXES)]
    payload = {
        "component_id": arguments.component_id,
        "worker_process_id": os.getpid(),
        "environment_names": names,
        "credential_environment_names": credential_names,
        "credential_value_accessed": False,
        "network_access_performed": False,
    }
    arguments.ready_file.write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    deadline = time.monotonic() + arguments.timeout_seconds
    while time.monotonic() < deadline:
        if arguments.release_file.is_file():
            return
        time.sleep(0.02)
    raise TimeoutError(f"Verifier identity probe '{arguments.component_id}' timed out awaiting release.")


if __name__ == "__main__":
    main()
