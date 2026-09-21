"""Run the fixed HTTP/1.1 study against isolated Docker containers.

Each case gets a fresh Compose project. The program stores observations and
configurations; it does not claim that a product is vulnerable.
"""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import os
import re
import secrets
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from real_lab.cases import cases  # noqa: E402


ROOT = Path(__file__).resolve().parents[1]
COMPOSE_FILES = {"nginx": ROOT / "compose.yaml", "haproxy": ROOT / "compose.haproxy.yaml"}
EDGE_CONFIGS = {"nginx": ROOT / "real_lab/nginx.conf", "haproxy": ROOT / "real_lab/haproxy.cfg"}
OUTPUT_ROOT = ROOT / "results" / "real"
CASE_NAMES = tuple(cases())
CONTROL_NAMES = ("get-single", "get-pipeline", "cl-normal", "chunked-normal")
SAFE_NAME = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
EDGE_IMAGES = {
    "nginx": "nginx:1.28-alpine@sha256:a8b39bd9cf0f83869a2162827a0caf6137ddf759d50a171451b335cecc87d236",
    "haproxy": "haproxy:3.2.23-alpine@sha256:5961c68bc8a81c5124d0a98ab20f81b74717d6afe596e805977d9cf84c126222",
}
COMMON_IMAGES = (
    "httpd:2.4-alpine@sha256:4e585da9d0125dec36d4500a9f5c5df7b2c0a01f67cb47865a91a4b05bdbec1b",
    "python:3.11-slim@sha256:9534e5a8e315485d4061ed659af0fd78a284c015f9b73661b41d6bab25604534",
)


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _invoke(command: list[str], env: dict[str, str], path: Path) -> int:
    completed = subprocess.run(
        command, cwd=ROOT, env=env, text=True, encoding="utf-8", errors="replace", capture_output=True, check=False
    )
    path.write_text(
        f"COMMAND: {json.dumps(command)}\nEXIT: {completed.returncode}\n"
        f"\nSTDOUT:\n{completed.stdout}\nSTDERR:\n{completed.stderr}",
        encoding="utf-8",
    )
    return completed.returncode


def _compose(compose_file: Path, project: str, *args: str) -> list[str]:
    return ["docker", "compose", "-f", str(compose_file), "-p", project, *args]


def _complete_response_statuses(raw: bytes) -> list[int] | None:
    """Frame fixed-control HTTP/1.1 responses; return None if incomplete."""
    statuses: list[int] = []
    position = 0
    while position < len(raw):
        header_end = raw.find(b"\r\n\r\n", position)
        if header_end < 0:
            return None
        lines = raw[position:header_end].split(b"\r\n")
        match = re.fullmatch(rb"HTTP/1\.1 ([0-9]{3}) [^\r\n]*", lines[0])
        if match is None:
            return None
        lengths = []
        for line in lines[1:]:
            if b":" not in line:
                return None
            name, value = line.split(b":", 1)
            if name.lower() == b"content-length":
                value = value.strip()
                if not value.isdigit():
                    return None
                lengths.append(int(value))
        if len(lengths) != 1:
            return None
        position = header_end + 4 + lengths[0]
        if position > len(raw):
            return None
        statuses.append(int(match.group(1)))
    return statuses


def _control_check(case_dir: Path, case: str, target: str = "edge") -> dict[str, object]:
    expected = {
        "get-single": ("GET /visible HTTP/1.1",),
        "get-pipeline": ("GET /visible HTTP/1.1", "GET /visible HTTP/1.1"),
        "cl-normal": ("POST /synthetic HTTP/1.1", "GET /visible HTTP/1.1"),
        "chunked-normal": ("POST /synthetic HTTP/1.1", "GET /visible HTTP/1.1"),
    }[case]
    reasons: list[str] = []
    client_path = case_dir / "client.json"
    relay_path = case_dir / "relay.jsonl"
    backend_path = case_dir / "backend.log"
    if not client_path.exists():
        reasons.append("client artifact missing")
    else:
        client = json.loads(client_path.read_text(encoding="utf-8"))
        response = bytes.fromhex(client.get("response_hex", ""))
        statuses = _complete_response_statuses(response)
        if statuses != [200] * len(expected):
            reasons.append(f"expected {len(expected)} complete HTTP/1.1 200 responses; saw {statuses}")
        if client.get("sent_complete") is not True:
            reasons.append("client did not finish sending input")
        if client.get("outcome") == "socket_error":
            reasons.append("client socket error")
    if target == "edge" and not relay_path.exists():
        reasons.append("relay artifact missing")
    elif target == "edge":
        records = [json.loads(line) for line in relay_path.read_text(encoding="utf-8").splitlines()]
        if not any(
            record.get("event") == "drained" and record.get("direction") == "edge_to_backend"
            for record in records
        ):
            reasons.append("no relay edge-to-backend bytes")
    backend = backend_path.read_text(encoding="utf-8") if backend_path.exists() else ""
    observed: list[str] = []
    for line in backend.splitlines():
        if "LAB_BACKEND " not in line:
            continue
        match = re.search(r'LAB_BACKEND .*\brequest="([^"]*)"', line)
        if match is None:
            reasons.append("malformed LAB_BACKEND access log line")
        else:
            observed.append(match.group(1))
    if Counter(observed) != Counter(expected):
        reasons.append(f"backend custom access log requests {observed!r} differ from {expected!r}")
    return {"passed": not reasons, "reasons": reasons}


def _image_metadata(run_dir: Path, references: tuple[str, ...]) -> None:
    metadata: list[dict[str, object]] = []
    for reference in references:
        completed = subprocess.run(
            ["docker", "image", "inspect", reference],
            cwd=ROOT, text=True, encoding="utf-8", errors="replace", capture_output=True, check=False
        )
        entry: dict[str, object] = {"reference": reference, "exit_code": completed.returncode}
        if completed.returncode == 0:
            inspected = json.loads(completed.stdout)[0]
            entry.update(id=inspected.get("Id"), repo_digests=inspected.get("RepoDigests"))
        else:
            entry["error"] = completed.stderr.strip()
        metadata.append(entry)
    (run_dir / "images.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", choices=("all", *CASE_NAMES), default="all")
    parser.add_argument("--edge", choices=tuple(COMPOSE_FILES), default="nginx")
    parser.add_argument("--target", choices=("edge", "backend"), default="edge")
    parser.add_argument("--run-id", help="optional safe output folder name")
    args = parser.parse_args()
    run_id = args.run_id or datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(3)
    if not SAFE_NAME.fullmatch(run_id):
        parser.error("run ID must match [a-z0-9][a-z0-9_-]{0,63}")
    run_dir = OUTPUT_ROOT / run_id
    run_dir.mkdir(parents=True, exist_ok=False)
    selected = CASE_NAMES if args.case == "all" else (args.case,)
    compose_file = COMPOSE_FILES[args.edge]
    config_files = (
        compose_file, EDGE_CONFIGS[args.edge], ROOT / "real_lab/backend.conf",
        ROOT / "real_lab/relay.py", ROOT / "real_lab/client.py", ROOT / "real_lab/cases.py",
    )
    manifest: dict[str, object] = {
        "schema_version": 1,
        "run_id": run_id,
        "started_utc": _utc(),
        "selected_cases": list(selected),
        "edge": args.edge,
        "target": args.target,
        "compose_file": str(compose_file.relative_to(ROOT)),
        "network": "Compose internal network; no host-published ports",
        "config_sha256": {
            str(path.relative_to(ROOT)): _sha256(path)
            for path in config_files
        },
        "cases": [],
    }
    _image_metadata(run_dir, COMMON_IMAGES + ((EDGE_IMAGES[args.edge],) if args.target == "edge" else ()))
    try:
        for case in selected:
            case_dir = run_dir / case
            case_dir.mkdir()
            project = f"desynclab-{run_id}-{args.edge}-{args.target}-{case}"
            env = os.environ.copy()
            env.update(LAB_RUN_ID=run_id, LAB_CASE_NAME=case)
            record: dict[str, object] = {"case": case, "edge": args.edge, "target": args.target, "project": project, "started_utc": _utc()}
            manifest["cases"].append(record)
            config_exit = _invoke(_compose(compose_file, project, "config"), env, case_dir / "compose-config.txt")
            record["config_exit"] = config_exit
            if config_exit != 0:
                record["error"] = "compose config failed"
                break
            try:
                up_services = ("backend", "relay", "edge") if args.target == "edge" else ("backend",)
                up_exit = _invoke(
                    _compose(compose_file, project, "up", "-d", "--pull", "never", *up_services),
                    env, case_dir / "compose-up.txt"
                )
                record["up_exit"] = up_exit
                if up_exit != 0:
                    record["error"] = "compose up failed"
                if up_exit == 0:
                    time.sleep(1.0)
                    record["client_exit"] = _invoke(
                        _compose(compose_file, project, "run", "--rm", "--no-deps", "-T", "client",
                                 "--case", case, "--target", args.target, "--run-id", run_id),
                        env, case_dir / "client-command.txt"
                    )
                    if record["client_exit"] != 0:
                        record["error"] = "client command failed"
                    time.sleep(0.25)
                log_services = ("edge", "relay", "backend") if args.target == "edge" else ("backend",)
                for service in log_services:
                    record[f"{service}_logs_exit"] = _invoke(
                        _compose(compose_file, project, "logs", "--no-color", "--timestamps", service),
                        env, case_dir / f"{service}.log"
                    )
                _invoke(_compose(compose_file, project, "ps", "--all"), env, case_dir / "compose-ps.txt")
            finally:
                record["down_exit"] = _invoke(
                    _compose(compose_file, project, "down", "--remove-orphans"),
                    env, case_dir / "compose-down.txt"
                )
            if case in CONTROL_NAMES:
                record["control_check"] = _control_check(case_dir, case, args.target)
                if not record["control_check"]["passed"]:
                    record["error"] = "normal control failed; remaining cases skipped"
                    break
            record["finished_utc"] = _utc()
    finally:
        manifest["finished_utc"] = _utc()
        (run_dir / "manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    print(run_dir)
    return 1 if any("error" in case for case in manifest["cases"]) else 0


if __name__ == "__main__":
    raise SystemExit(main())
