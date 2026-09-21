"""Send one fixed lab fixture through the internal Docker network.

The client records raw responses, socket outcomes, and input bytes. It makes
no vulnerability judgement and cannot select an arbitrary network target.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import socket
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from real_lab.cases import cases  # noqa: E402


_SAFE_NAME = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
TARGETS = {"edge": ("edge", 8080), "backend": ("backend", 80)}
READ_LIMIT = 131_072
READ_TIMEOUT_SECONDS = 6.0


def _safe_name(value: str) -> str:
    if not _SAFE_NAME.fullmatch(value):
        raise ValueError(f"unsafe run ID: {value!r}")
    return value


def _connect(host: str, port: int) -> tuple[socket.socket, int]:
    """Wait briefly for local containers to listen, without sending probes."""
    deadline = time.monotonic() + 8.0
    attempts = 0
    while True:
        attempts += 1
        try:
            return socket.create_connection((host, port), timeout=1.0), attempts
        except OSError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.25)


def main() -> int:
    fixture_map = cases()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", choices=tuple(fixture_map), required=True)
    parser.add_argument("--target", choices=tuple(TARGETS), default="edge")
    parser.add_argument("--run-id", default=os.environ.get("LAB_RUN_ID", "manual"))
    args = parser.parse_args()
    run_id = _safe_name(args.run_id)
    case = args.case
    data = fixture_map[case]
    target = args.target
    host, port = TARGETS[target]
    output_path = Path("/artifacts") / run_id / case / "client.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)

    observed: dict[str, object] = {
        "schema_version": 1,
        "case": case,
        "run_id": run_id,
        "target": target,
        "started_utc": datetime.now(timezone.utc).isoformat(),
        "endpoint": f"{host}:{port}",
        "input_length": len(data),
        "input_sha256": hashlib.sha256(data).hexdigest(),
        "input_hex": data.hex(),
        "response_hex": "",
        "response_length": 0,
        "response_chunks": [],
        "outcome": "not_started",
    }
    response = bytearray()
    started = time.monotonic()
    try:
        connection, attempts = _connect(host, port)
        observed["connect_attempts"] = attempts
        with connection:
            observed["client_local"] = str(connection.getsockname())
            connection.settimeout(READ_TIMEOUT_SECONDS)
            connection.sendall(data)
            observed["sent_complete"] = True
            while len(response) < READ_LIMIT:
                try:
                    chunk = connection.recv(min(65_536, READ_LIMIT - len(response)))
                except socket.timeout:
                    observed["outcome"] = "read_timeout"
                    break
                if not chunk:
                    observed["outcome"] = "eof"
                    break
                response.extend(chunk)
                observed["response_chunks"].append(
                    {"length": len(chunk), "elapsed_ms": round((time.monotonic() - started) * 1000, 3)}
                )
            else:
                observed["outcome"] = "read_limit"
    except OSError as exc:
        observed["outcome"] = "socket_error"
        observed["error"] = repr(exc)
    finally:
        observed["response_hex"] = response.hex()
        observed["response_length"] = len(response)
        observed["elapsed_ms"] = round((time.monotonic() - started) * 1000, 3)
        observed["finished_utc"] = datetime.now(timezone.utc).isoformat()
        output_path.write_text(json.dumps(observed, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(json.dumps({"case": case, "outcome": observed["outcome"], "response_length": len(response)}))
    return 1 if observed["outcome"] == "socket_error" else 0


if __name__ == "__main__":
    raise SystemExit(main())
