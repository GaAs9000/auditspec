"""Standalone closed verifier worker used by the isolated execution runtime."""

from __future__ import annotations

import json
import os
import socket
import sys
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any

REQUEST_SCHEMA = "AuditSpec-isolated-verifier-worker-request-v1"
RESULT_SCHEMA = "AuditSpec-isolated-verifier-worker-result-v1"


def _read(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise TypeError("isolated verifier request must be an object")
    return value


def _write(path: Path, value: Mapping[str, Any]) -> None:
    with path.open("x", encoding="utf-8") as handle:
        json.dump(
            value, handle, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        )
        handle.write("\n")


def _network_interfaces() -> list[str]:
    lines = Path("/proc/net/dev").read_text(encoding="utf-8").splitlines()[2:]
    return sorted(line.split(":", 1)[0].strip() for line in lines if ":" in line)


def _closed_checks(payload: object, fuel: int) -> tuple[bool, int]:
    if type(payload) is not dict or set(payload) != {"checks"}:
        raise ValueError("isolated Boolean verifier input differs from closed schema")
    checks = payload["checks"]
    if type(checks) is not list or not checks:
        raise ValueError("isolated Boolean verifier requires a non-empty check list")
    if len(checks) > fuel:
        raise RuntimeError("isolated verifier fuel exhausted")
    if any(type(item) is not bool for item in checks):
        raise TypeError("isolated Boolean verifier checks must be Boolean")
    for item in checks:
        if not item:
            return False, len(checks)
    return True, len(checks)


def _namespace_probe() -> dict[str, Any]:
    interfaces = _network_interfaces()
    root_write_blocked = False
    try:
        Path("/auditspec-isolation-root-write-probe").write_text(
            "forbidden", encoding="utf-8"
        )
    except OSError:
        root_write_blocked = True
    scratch = Path("/tmp/auditspec-isolation-scratch")
    scratch.write_text("ok", encoding="utf-8")
    scratch_ok = scratch.read_text(encoding="utf-8") == "ok"
    scratch.unlink()
    sensitive_environment_names = sorted(
        name
        for name in os.environ
        if any(
            token in name.upper() for token in ("KEY", "TOKEN", "SECRET", "PASSWORD")
        )
    )
    return {
        "interfaces": interfaces,
        "network_isolated": interfaces == ["lo"],
        "root_write_blocked": root_write_blocked,
        "scratch_writable": scratch_ok,
        "pid": os.getpid(),
        "uid": os.getuid(),
        "gid": os.getgid(),
        "hostname": socket.gethostname(),
        "namespace_ids": {
            name: os.readlink(f"/proc/self/ns/{name}")
            for name in ("user", "mnt", "pid", "ipc", "uts", "net")
        },
        "environment_names": sorted(os.environ),
        "sensitive_environment_names": sensitive_environment_names,
    }


def execute(request: Mapping[str, Any]) -> dict[str, Any]:
    expected = {
        "schema",
        "request_id",
        "verifier_id",
        "verifier_version",
        "input_schema",
        "input_payload",
        "fuel",
    }
    if set(request) != expected or request.get("schema") != REQUEST_SCHEMA:
        raise ValueError("isolated verifier request fields/schema differ")
    request_id = request["request_id"]
    verifier_id = request["verifier_id"]
    verifier_version = request["verifier_version"]
    input_schema = request["input_schema"]
    fuel = request["fuel"]
    if any(
        not isinstance(value, str) or not value
        for value in (request_id, verifier_id, verifier_version, input_schema)
    ):
        raise ValueError("isolated verifier identifiers must be non-empty")
    if not isinstance(fuel, int) or isinstance(fuel, bool) or fuel < 0:
        raise ValueError("isolated verifier fuel is invalid")

    if verifier_id == "auditspec-all-boolean-checks-isolated-v1":
        answer, steps = _closed_checks(request["input_payload"], fuel)
        result: Any = {"answer": answer, "steps": steps}
    elif verifier_id == "auditspec-isolation-namespace-probe-v1":
        if request["input_payload"] != {"probe": True}:
            raise ValueError("namespace probe input differs from closed schema")
        result = _namespace_probe()
        answer, steps = True, 1
    elif verifier_id == "auditspec-isolation-sleep-test-v1":
        seconds = request["input_payload"].get("seconds")
        if not isinstance(seconds, int) or isinstance(seconds, bool) or seconds < 0:
            raise ValueError("sleep-test seconds are invalid")
        time.sleep(seconds)
        answer, steps, result = True, 1, {"slept": seconds}
    elif verifier_id == "auditspec-isolation-cpu-test-v1":
        value = 0
        while True:
            value = (value + 1) % 1_000_003
    elif verifier_id == "auditspec-isolation-memory-test-v1":
        chunks: list[bytes] = []
        while True:
            chunks.append(b"x" * (8 * 1024 * 1024))
    elif verifier_id == "auditspec-isolation-output-test-v1":
        size = request["input_payload"].get("bytes")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise ValueError("output-test bytes are invalid")
        answer, steps, result = True, 1, {"payload": "x" * size}
    elif verifier_id == "auditspec-isolation-nonzero-test-v1":
        raise SystemExit(17)
    elif verifier_id == "auditspec-isolation-invalid-json-test-v1":
        return {"__invalid_json_fixture__": True}
    else:
        raise ValueError("unregistered isolated verifier")

    return {
        "schema": RESULT_SCHEMA,
        "request_id": request_id,
        "verifier_id": verifier_id,
        "verifier_version": verifier_version,
        "answer": answer,
        "steps": steps,
        "result": result,
    }


def main() -> int:
    if len(sys.argv) != 3:
        raise SystemExit("usage: verifier_worker.py REQUEST_JSON OUTPUT_JSON")
    request_path = Path(sys.argv[1])
    output_path = Path(sys.argv[2])
    request = _read(request_path)
    if request.get("verifier_id") == "auditspec-isolation-invalid-json-test-v1":
        output_path.write_text("not-json\n", encoding="utf-8")
        return 0
    result = execute(request)
    _write(output_path, result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
