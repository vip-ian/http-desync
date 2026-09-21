"""Read-only, conservative summary of a recorded two-hop Docker study.

This reports what was observed at the client, relay, proxy log, and backend
log. It never labels a product vulnerable based on status codes or timeouts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any


_BACKEND = re.compile(
    r'LAB_BACKEND peer=(\S+) port=(\d+) pid=(\d+) keepalive=(\d+) '
    r'status=(\d+) connection=(\S+) request="([^"]*)"'
)
_DEFAULT_APACHE = re.compile(r'"(?:GET|POST) [^\"]+ HTTP/1\.1" \d{3} ')
_HAPROXY_ACCESS = re.compile(
    r'(?P<client>\S+:\d+)\s+\[[^\]]+\]\s+(?P<frontend>\S+)\s+'
    r'(?P<backend>\S+/\S+)\s+(?:-?\d+/){4}-?\d+\s+'
    r'(?P<status>\d{3})\s+(?P<bytes>\d+)\b.*"(?P<request>[^"]*)"\s*$'
)


def _response_status_lines(raw: bytes) -> tuple[list[str], bool]:
    """Read complete Content-Length framed HTTP/1.1 responses if possible."""
    lines: list[str] = []
    position = 0
    while position < len(raw):
        line_end = raw.find(b"\r\n", position)
        header_end = raw.find(b"\r\n\r\n", position)
        if line_end < 0 or header_end < 0 or line_end > header_end:
            return lines, False
        status_line = raw[position:line_end]
        if not re.fullmatch(rb"HTTP/1\.1 [0-9]{3} [^\r\n]*", status_line):
            return lines, False
        lines.append(status_line.decode("ascii", errors="replace"))
        lengths: list[int] = []
        for header in raw[line_end + 2 : header_end].split(b"\r\n"):
            if b":" not in header:
                return lines, False
            name, value = header.split(b":", 1)
            if name.lower() == b"content-length":
                value = value.strip()
                if not value.isdigit():
                    return lines, False
                lengths.append(int(value))
        if len(lengths) != 1:
            return lines, False
        position = header_end + 4 + lengths[0]
        if position > len(raw):
            return lines, False
    return lines, True


def _read_client(path: Path, issues: list[str]) -> dict[str, Any]:
    if not path.exists():
        issues.append("client.json missing")
        return {"present": False}
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
        response = bytes.fromhex(document.get("response_hex", ""))
    except (json.JSONDecodeError, ValueError) as exc:
        issues.append(f"client.json malformed: {exc}")
        return {"present": True, "malformed": True}
    status_lines, complete = _response_status_lines(response)
    if len(response) != document.get("response_length"):
        issues.append("client response length field disagrees with raw hex")
    return {
        "present": True,
        "target": document.get("target"),
        "outcome": document.get("outcome"),
        "sent_complete": document.get("sent_complete"),
        "response_length": len(response),
        "http_status_lines": status_lines,
        "http_responses_complete": complete,
        "input_length": document.get("input_length"),
        "input_sha256": document.get("input_sha256"),
    }


def _read_relay(path: Path, issues: list[str], required: bool = True) -> dict[str, Any]:
    if not path.exists():
        if required:
            issues.append("relay.jsonl missing; no-forwarding cannot be inferred")
        return {"capture_present": False, "connections": [], "upstream_length": None}

    connections: dict[int, dict[str, Any]] = defaultdict(
        lambda: {"backend_local": None, "streams": defaultdict(list), "sequences": defaultdict(list)}
    )
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        try:
            event = json.loads(line)
            connection_id = int(event["connection_id"])
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            issues.append(f"relay.jsonl line {number} malformed: {exc}")
            continue
        connection = connections[connection_id]
        if event.get("event") == "open":
            connection["backend_local"] = event.get("backend_local")
        elif event.get("event") == "drained":
            direction = event.get("direction")
            if direction not in ("edge_to_backend", "backend_to_edge"):
                issues.append(f"relay.jsonl line {number} has unknown direction")
                continue
            try:
                chunk = bytes.fromhex(event["hex"])
                sequence = int(event["sequence"])
            except (KeyError, TypeError, ValueError) as exc:
                issues.append(f"relay.jsonl line {number} has invalid byte record: {exc}")
                continue
            if len(chunk) != event.get("length") or hashlib.sha256(chunk).hexdigest() != event.get("sha256"):
                issues.append(f"relay.jsonl line {number} byte length or hash mismatch")
            connection["streams"][direction].append(chunk)
            connection["sequences"][direction].append(sequence)
        elif event.get("event") in ("pump_error", "connect_error"):
            issues.append(f"relay connection {connection_id} {event['event']}: {event.get('detail')}")

    records: list[dict[str, Any]] = []
    upstream_length = 0
    for connection_id in sorted(connections):
        connection = connections[connection_id]
        record: dict[str, Any] = {
            "connection_id": connection_id,
            "backend_local": connection["backend_local"],
        }
        for direction, prefix in (("edge_to_backend", "upstream"), ("backend_to_edge", "downstream")):
            sequences = connection["sequences"][direction]
            if sequences != list(range(1, len(sequences) + 1)):
                issues.append(f"relay connection {connection_id} {direction} sequence gap or duplicate")
            stream = b"".join(connection["streams"][direction])
            record[f"{prefix}_length"] = len(stream)
            record[f"{prefix}_sha256"] = hashlib.sha256(stream).hexdigest() if stream else None
            if prefix == "upstream":
                upstream_length += len(stream)
        records.append(record)
    return {"capture_present": True, "connections": records, "upstream_length": upstream_length}


def _read_backend(path: Path, relay: dict[str, Any], issues: list[str]) -> dict[str, Any]:
    if not path.exists():
        issues.append("backend.log missing")
        return {"present": False, "requests": []}
    text = path.read_text(encoding="utf-8", errors="replace")
    port_to_connection: dict[int, int] = {}
    for connection in relay["connections"]:
        address = connection.get("backend_local")
        if isinstance(address, str) and ":" in address:
            try:
                port_to_connection[int(address.rsplit(":", 1)[1])] = connection["connection_id"]
            except ValueError:
                issues.append(f"invalid relay backend_local address: {address}")
    requests: list[dict[str, Any]] = []
    default_access_lines = 0
    for line in text.splitlines():
        if "LAB_BACKEND " in line:
            match = _BACKEND.search(line)
            if match is None:
                issues.append("malformed LAB_BACKEND access log line")
                continue
            peer, port, pid, keepalive, status, connection_state, request = match.groups()
            requests.append({
                "request": request,
                "status": int(status),
                "peer": peer,
                "port": int(port),
                "relay_connection_id": port_to_connection.get(int(port)),
                "pid": int(pid),
                "keepalive": int(keepalive),
                "connection_state": connection_state,
            })
        elif _DEFAULT_APACHE.search(line):
            default_access_lines += 1
    return {
        "present": True,
        "requests": requests,
        "default_access_log_lines_ignored": default_access_lines,
    }


def _read_edge(path: Path, issues: list[str], edge_kind: str, required: bool = True) -> dict[str, Any]:
    if not path.exists():
        if required:
            issues.append("edge.log missing")
        return {"present": False, "kind": edge_kind, "access": []}
    access: list[dict[str, Any]] = []
    rejections: list[str] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if edge_kind == "nginx":
            marker = line.find('{"time":')
            if marker >= 0:
                try:
                    item = json.loads(line[marker:])
                except json.JSONDecodeError:
                    issues.append("malformed Nginx JSON access log line")
                    continue
                access.append({
                    "request": item.get("request"),
                    "status": item.get("status"),
                    "upstream_status": item.get("upstream_status"),
                    "upstream_addr": item.get("upstream_addr"),
                    "connection": item.get("connection"),
                    "connection_requests": item.get("connection_requests"),
                })
            elif "client sent " in line and " while reading client request headers" in line:
                rejections.append(line.split(" | ", 1)[-1])
        elif edge_kind == "haproxy":
            match = _HAPROXY_ACCESS.search(line)
            if match is not None:
                access.append({
                    "request": match.group("request"),
                    "status": match.group("status"),
                    "upstream_status": None,
                    "upstream_addr": match.group("backend"),
                    "connection": None,
                    "connection_requests": None,
                })
            elif "invalid" in line.lower() or "bad request" in line.lower():
                rejections.append(line.split(" | ", 1)[-1])
    if edge_kind not in ("nginx", "haproxy"):
        issues.append(f"unknown edge log format: {edge_kind}")
    return {"present": True, "kind": edge_kind, "access": access, "header_rejection_log": rejections}


def analyze_case(case_dir: Path, edge_kind: str = "nginx", target: str = "edge") -> dict[str, Any]:
    issues: list[str] = []
    client = _read_client(case_dir / "client.json", issues)
    effective_target = client.get("target") or target
    relay = _read_relay(case_dir / "relay.jsonl", issues, required=effective_target == "edge")
    backend = _read_backend(case_dir / "backend.log", relay, issues)
    edge = _read_edge(case_dir / "edge.log", issues, edge_kind, required=effective_target == "edge")

    bytes_forwarded = relay["upstream_length"]
    backend_count = len(backend["requests"])
    edge_statuses = [item["status"] for item in edge["access"]]
    if effective_target == "backend":
        observation = "direct_backend_requests_logged" if backend_count else "direct_backend_no_access_log"
    elif bytes_forwarded is None:
        observation = "capture_unavailable"
    elif bytes_forwarded == 0 and backend_count == 0 and any(str(code).startswith("4") for code in edge_statuses):
        observation = "edge_rejected_without_observed_forwarding"
    elif bytes_forwarded == 0 and backend_count == 0:
        observation = "no_forwarding_observed"
    elif bytes_forwarded == 0:
        observation = "inconsistent_relay_and_backend_records"
    elif backend_count == 0:
        observation = "forwarded_bytes_without_backend_access_log"
    else:
        observation = "forwarded_bytes_and_backend_requests_logged"
    if backend.get("default_access_log_lines_ignored", 0):
        issues.append("Apache default access log duplicates request text; only LAB_BACKEND rows count")
    return {
        "case": case_dir.name,
        "edge_kind": edge_kind,
        "target": effective_target,
        "observation": observation,
        "client": client,
        "relay": relay,
        "backend": backend,
        "edge": edge,
        "issues": issues,
        "vulnerability_verdict": None,
    }


def analyze_run(run_dir: Path) -> dict[str, Any]:
    if not run_dir.is_dir():
        raise FileNotFoundError(run_dir)
    manifest_path = run_dir / "manifest.json"
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        case_names = [item["case"] for item in manifest.get("cases", [])]
        run_id = manifest.get("run_id", run_dir.name)
        edge_kind = manifest.get("edge", "nginx")
        target = manifest.get("target", "edge")
    else:
        case_names = [path.name for path in sorted(run_dir.iterdir()) if path.is_dir()]
        run_id = run_dir.name
        edge_kind = "unknown"
        target = "edge"
    return {
        "schema_version": 1,
        "run_id": run_id,
        "source_directory": str(run_dir.resolve()),
        "edge_kind": edge_kind,
        "target": target,
        "cases": [analyze_case(run_dir / name, edge_kind, target) for name in case_names],
        "scope": "read-only observation summary; no vulnerability determination",
    }


def _print_text(document: dict[str, Any]) -> None:
    print(f"Run: {document['run_id']}")
    for case in document["cases"]:
        client = case["client"]
        relay = case["relay"]
        backend = case["backend"]
        edge = case["edge"]
        statuses = ",".join(client.get("http_status_lines", [])) or "none"
        edge_codes = ",".join(str(item["status"]) for item in edge["access"]) or "none"
        streams = ", ".join(
            f"#{item['connection_id']}:{item['upstream_length']}B:{item['upstream_sha256'] or '-'}"
            for item in relay["connections"]
        ) or "none"
        requests = ", ".join(
            f"{item['request']} [status={item['status']}, port={item['port']}, k={item['keepalive']}, relay={item['relay_connection_id']}]"
            for item in backend["requests"]
        ) or "none"
        print(f"{case['case']}: {case['observation']}")
        print(f"  client={client.get('outcome', 'missing')} [{statuses}] complete={client.get('http_responses_complete')}")
        if case["target"] == "backend":
            print("  direct backend (no proxy or relay)")
        else:
            print(f"  {case['edge_kind']}=[{edge_codes}] relay={relay['upstream_length']}B ({streams})")
        print(f"  apache={requests}")
        for issue in case["issues"]:
            print(f"  note: {issue}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_dir", type=Path, help="results/real/<run-id> directory")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    args = parser.parse_args()
    document = analyze_run(args.run_dir)
    if args.json:
        print(json.dumps(document, indent=2, sort_keys=True))
    else:
        _print_text(document)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
