"""Read-only verification of the five fixed Docker study archives.

This checks recorded process success, exact fixed inputs, normal controls,
proxy/backend observations, and repeatability. It is an archive consistency
check, not a claim that any product is vulnerable or that files are signed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from real_lab.analyze import analyze_run
from real_lab.cases import cases
from real_lab.run import _control_check


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RESULTS = ROOT / "results" / "real"
ARCHIVES = {
    "nginx_a1": ("nginx1283-httpd2468-a1", "nginx", "edge"),
    "nginx_a2": ("nginx1283-httpd2468-a2", "nginx", "edge"),
    "haproxy_a1": ("haproxy3223-httpd2468-a1", "haproxy", "edge"),
    "haproxy_a2": ("haproxy3223-httpd2468-a2", "haproxy", "edge"),
    "apache_direct": ("apache2468-direct-a1", "nginx", "backend"),
}
FIXTURES = cases()
CASE_ORDER = tuple(FIXTURES)
CONTROLS = CASE_ORDER[:4]
AMBIGUOUS = CASE_ORDER[4:]
NORMAL_REQUESTS = {
    "get-single": ["GET /visible HTTP/1.1"],
    "get-pipeline": ["GET /visible HTTP/1.1"] * 2,
    "cl-normal": ["POST /synthetic HTTP/1.1", "GET /visible HTTP/1.1"],
    "chunked-normal": ["POST /synthetic HTTP/1.1", "GET /visible HTTP/1.1"],
}


class Audit:
    def __init__(self) -> None:
        self.errors: list[str] = []
        self.notes: list[str] = []

    def require(self, condition: bool, label: str) -> None:
        if not condition:
            self.errors.append(label)


def _status_codes(lines: list[str]) -> list[int]:
    codes: list[int] = []
    for line in lines:
        match = re.match(r"HTTP/1\.1 ([0-9]{3}) ", line)
        if match is not None:
            codes.append(int(match.group(1)))
    return codes


def _edge_codes(case: dict[str, Any]) -> list[int]:
    return [int(item["status"]) for item in case["edge"]["access"] if str(item.get("status", "")).isdigit()]


def _backend_rows(case: dict[str, Any]) -> list[tuple[str, int]]:
    return [(item["request"], item["status"]) for item in case["backend"]["requests"]]


def _relay_upstream(case_dir: Path, audit: Audit, label: str) -> dict[int, bytes] | None:
    path = case_dir / "relay.jsonl"
    if not path.exists():
        audit.require(False, f"{label}: relay.jsonl missing")
        return None
    chunks: dict[int, list[tuple[int, bytes]]] = defaultdict(list)
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            record = json.loads(line)
            if record.get("event") == "drained" and record.get("direction") == "edge_to_backend":
                chunks[int(record["connection_id"])].append(
                    (int(record["sequence"]), bytes.fromhex(record["hex"]))
                )
    except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        audit.require(False, f"{label}: malformed relay bytes: {exc}")
        return None
    streams: dict[int, bytes] = {}
    for connection_id, items in chunks.items():
        ordered = sorted(items)
        audit.require(
            [sequence for sequence, _ in ordered] == list(range(1, len(ordered) + 1)),
            f"{label}: relay sequence gap or duplicate on connection {connection_id}",
        )
        streams[connection_id] = b"".join(chunk for _, chunk in ordered)
    return streams


def _check_manifest(path: Path, role: str, edge: str, target: str, audit: Audit) -> dict[str, Any] | None:
    manifest_path = path / "manifest.json"
    if not manifest_path.exists():
        audit.require(False, f"{role}: manifest.json missing")
        return None
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        audit.require(False, f"{role}: invalid manifest.json: {exc}")
        return None
    audit.require(manifest.get("selected_cases") == list(CASE_ORDER), f"{role}: selected cases/order differ")
    entries = manifest.get("cases", [])
    audit.require([entry.get("case") for entry in entries] == list(CASE_ORDER), f"{role}: seven completed case records missing or out of order")
    if role == "nginx_a1" and manifest.get("edge") is None and manifest.get("target") is None:
        audit.notes.append("nginx_a1 predates edge/target manifest fields; client records establish edge target")
    else:
        audit.require(manifest.get("edge") == edge, f"{role}: manifest edge differs")
        audit.require(manifest.get("target") == target, f"{role}: manifest target differs")
    for entry in entries:
        case_name = entry.get("case", "unknown")
        for field in ("config_exit", "up_exit", "client_exit", "down_exit", "backend_logs_exit"):
            audit.require(entry.get(field) == 0, f"{role}/{case_name}: {field} is not zero")
        if target == "edge":
            for field in ("edge_logs_exit", "relay_logs_exit"):
                audit.require(entry.get(field) == 0, f"{role}/{case_name}: {field} is not zero")
        audit.require("error" not in entry, f"{role}/{case_name}: manifest error recorded")
        if case_name in CONTROLS:
            stored = entry.get("control_check", {})
            audit.require(stored.get("passed") is True, f"{role}/{case_name}: stored control failed")
            recomputed = _control_check(path / case_name, case_name, target)
            audit.require(recomputed["passed"] is True, f"{role}/{case_name}: recomputed control failed: {recomputed['reasons']}")
    hashes = manifest.get("config_sha256", {})
    audit.require(bool(hashes) and all(re.fullmatch(r"[0-9a-f]{64}", value or "") for value in hashes.values()), f"{role}: config SHA-256 fields invalid")
    images_path = path / "images.json"
    if images_path.exists():
        try:
            images = json.loads(images_path.read_text(encoding="utf-8"))
            audit.require(bool(images) and all(image.get("exit_code") == 0 and image.get("id") for image in images), f"{role}: image inspection incomplete")
        except json.JSONDecodeError:
            audit.require(False, f"{role}: images.json malformed")
    else:
        audit.require(False, f"{role}: images.json missing")
    return manifest


def _check_inputs(path: Path, role: str, target: str, audit: Audit) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for case_name, expected in FIXTURES.items():
        file = path / case_name / "client.json"
        if not file.exists():
            audit.require(False, f"{role}/{case_name}: client.json missing")
            continue
        try:
            client = json.loads(file.read_text(encoding="utf-8"))
            raw = bytes.fromhex(client["input_hex"])
        except (json.JSONDecodeError, KeyError, ValueError) as exc:
            audit.require(False, f"{role}/{case_name}: invalid client input: {exc}")
            continue
        digest = hashlib.sha256(raw).hexdigest()
        hashes[case_name] = digest
        audit.require(raw == expected, f"{role}/{case_name}: input bytes differ from fixed fixture")
        audit.require(client.get("input_sha256") == digest and client.get("input_length") == len(raw), f"{role}/{case_name}: input digest/length mismatch")
        audit.require(client.get("target") == target and client.get("sent_complete") is True, f"{role}/{case_name}: client target or send completion differs")
    return hashes


def _check_cases(path: Path, role: str, edge: str, target: str, document: dict[str, Any], audit: Audit) -> dict[str, tuple[Any, ...]]:
    audit.require(len(document["cases"]) == 7, f"{role}: analyzer did not return seven cases")
    fingerprints: dict[str, tuple[Any, ...]] = {}
    for case in document["cases"]:
        name = case["case"]
        label = f"{role}/{name}"
        client = case["client"]
        relay = case["relay"]
        backend = case["backend"]["requests"]
        codes = _status_codes(client.get("http_status_lines", []))
        edge_codes = _edge_codes(case)
        raw_streams = _relay_upstream(path / name, audit, label) if target == "edge" else None
        upstream = tuple((cid, len(data), hashlib.sha256(data).hexdigest()) for cid, data in sorted((raw_streams or {}).items()))
        fingerprints[name] = (
            tuple(codes), tuple(edge_codes), client.get("outcome"),
            tuple((row["request"], row["status"], row["keepalive"]) for row in backend),
            upstream,
        )
        audit.require(client.get("http_responses_complete") is True, f"{label}: response framing incomplete")
        for issue in case["issues"]:
            if any(word in issue for word in ("malformed", "missing", "mismatch", "sequence gap", "invalid", "unknown")):
                audit.require(False, f"{label}: analyzer integrity issue: {issue}")
        if name in CONTROLS:
            expected = NORMAL_REQUESTS[name]
            audit.require(codes == [200] * len(expected), f"{label}: client 200 response count differs")
            audit.require(_backend_rows(case) == [(request, 200) for request in expected], f"{label}: backend request/status sequence differs")
            audit.require([row["keepalive"] for row in backend] == list(range(len(expected))), f"{label}: backend keepalive sequence differs")
            if target == "edge":
                audit.require(edge_codes == [200] * len(expected), f"{label}: edge 200 status count differs")
                audit.require(case["observation"] == "forwarded_bytes_and_backend_requests_logged", f"{label}: edge forwarding observation differs")
                audit.require(raw_streams is not None and len(raw_streams) == 1 and all(raw_streams.values()), f"{label}: expected one nonempty relay upstream stream")
                if raw_streams and len(raw_streams) == 1:
                    relay_id = next(iter(raw_streams))
                    audit.require(all(row["relay_connection_id"] == relay_id for row in backend), f"{label}: backend rows do not map to relay connection")
            else:
                audit.require(case["observation"] == "direct_backend_requests_logged", f"{label}: direct backend observation differs")
            continue

        if edge == "nginx" and target == "edge":
            audit.require(codes == [400] and client.get("outcome") == "eof", f"{label}: Nginx client rejection differs")
            audit.require(edge_codes == [400] and case["edge"].get("header_rejection_log"), f"{label}: Nginx access/error rejection evidence missing")
            audit.require(relay["capture_present"] is True and relay["upstream_length"] == 0 and raw_streams == {}, f"{label}: Nginx forwarded bytes observed")
            audit.require(not backend, f"{label}: unexpected backend request")
        elif edge == "haproxy" and target == "edge" and name in ("cl-te", "te-cl"):
            audit.require(codes == [200] and client.get("outcome") == "eof", f"{label}: HAProxy client outcome differs")
            audit.require(edge_codes == [200], f"{label}: HAProxy edge status differs")
            audit.require(_backend_rows(case) == [("POST /synthetic HTTP/1.1", 200)], f"{label}: backend request sequence differs")
            expected_length = {"cl-te": 84, "te-cl": 147}[name]
            audit.require(raw_streams is not None and len(raw_streams) == 1, f"{label}: expected one forwarded connection")
            if raw_streams and len(raw_streams) == 1:
                stream = next(iter(raw_streams.values()))
                header = stream.split(b"\r\n\r\n", 1)[0].lower()
                audit.require(len(stream) == expected_length, f"{label}: forwarded byte count differs")
                audit.require(b"transfer-encoding: chunked" in header, f"{label}: forwarded TE missing")
                audit.require(b"content-length:" not in header, f"{label}: forwarded CL was not removed")
                audit.require(b"GET /visible" not in stream, f"{label}: visible request unexpectedly forwarded")
            audit.require(all(row["request"] != "GET /synthetic-shadow HTTP/1.1" for row in backend), f"{label}: shadow request reached backend as separate request")
        elif edge == "haproxy" and target == "edge":
            audit.require(codes == [] and client.get("response_length") == 0 and client.get("outcome") == "eof", f"{label}: HAProxy duplicate-CL client outcome differs")
            audit.require(edge_codes == [400], f"{label}: HAProxy duplicate-CL access 400 missing")
            audit.require(relay["capture_present"] is True and relay["upstream_length"] == 0 and raw_streams == {}, f"{label}: HAProxy duplicate-CL forwarded bytes observed")
            audit.require(not backend, f"{label}: HAProxy duplicate-CL backend request observed")
        elif target == "backend" and name in ("cl-te", "te-cl"):
            audit.require(codes == [200] and client.get("outcome") == "eof", f"{label}: direct Apache CL/TE client outcome differs")
            audit.require(_backend_rows(case) == [("POST /synthetic HTTP/1.1", 200)], f"{label}: direct Apache CL/TE request sequence differs")
            audit.require(len(backend) == 1 and backend[0]["connection_state"] == "-", f"{label}: direct Apache connection close evidence missing")
        elif target == "backend":
            audit.require(codes == [400] and client.get("outcome") == "eof", f"{label}: direct Apache duplicate-CL client outcome differs")
            audit.require(_backend_rows(case) == [("POST /synthetic HTTP/1.1", 400)], f"{label}: direct Apache duplicate-CL rejection differs")
    return fingerprints


def verify(paths: dict[str, Path]) -> dict[str, Any]:
    audit = Audit()
    input_hashes: dict[str, dict[str, str]] = {}
    fingerprints: dict[str, dict[str, tuple[Any, ...]]] = {}
    manifests: dict[str, dict[str, Any]] = {}
    for role, (_, edge, target) in ARCHIVES.items():
        path = paths[role]
        if not path.is_dir():
            audit.require(False, f"{role}: archive directory missing: {path}")
            continue
        manifest = _check_manifest(path, role, edge, target, audit)
        if manifest is None:
            continue
        manifests[role] = manifest
        input_hashes[role] = _check_inputs(path, role, target, audit)
        try:
            document = analyze_run(path)
        except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
            audit.require(False, f"{role}: analyzer failed: {exc}")
            continue
        fingerprints[role] = _check_cases(path, role, edge, target, document, audit)

    for case_name in CASE_ORDER:
        observed = {hashes.get(case_name) for hashes in input_hashes.values()}
        audit.require(len(observed) == 1 and None not in observed, f"{case_name}: input SHA-256 differs across five archives")
    for first, second in (("nginx_a1", "nginx_a2"), ("haproxy_a1", "haproxy_a2")):
        if first in fingerprints and second in fingerprints:
            for case_name in CASE_ORDER:
                audit.require(fingerprints[first].get(case_name) == fingerprints[second].get(case_name), f"{first}/{second}/{case_name}: observable fingerprint differs")
            one = {key.replace("\\", "/"): value for key, value in manifests[first].get("config_sha256", {}).items()}
            two = {key.replace("\\", "/"): value for key, value in manifests[second].get("config_sha256", {}).items()}
            for key in (set(one) | set(two)) - {"real_lab/client.py"}:
                audit.require(one.get(key) == two.get(key), f"{first}/{second}: configuration hash differs for {key}")
            if one.get("real_lab/client.py") != two.get("real_lab/client.py"):
                audit.notes.append(f"{first}/{second}: client code SHA-256 differs; raw input bytes and observations match")
    if "haproxy_a1" in fingerprints and "haproxy_a2" in fingerprints:
        for role in ("haproxy_a1", "haproxy_a2"):
            case_dir = paths[role] / "cl-normal"
            streams = _relay_upstream(case_dir, audit, f"{role}/cl-normal")
            if streams and len(streams) == 1:
                header = next(iter(streams.values())).split(b"\r\n\r\n", 1)[0].lower()
                audit.require(b"content-length: 4" in header, f"{role}/cl-normal: normal CL was not forwarded")
    return {
        "passed": not audit.errors,
        "archives_checked": len(manifests),
        "cases_per_archive": len(CASE_ORDER),
        "errors": audit.errors,
        "notes": audit.notes,
        "summary": [
            "Nginx x2: normal controls forwarded; three ambiguous inputs rejected before observed relay forwarding",
            "HAProxy x2: normal controls forwarded; CL.TE and TE.CL forwarded after CL removal with one backend POST; duplicate CL rejected",
            "Apache direct x1: normal controls passed; CL.TE and TE.CL produced one POST then connection close; duplicate CL returned 400",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results-root", type=Path, default=DEFAULT_RESULTS)
    for role, (name, _, _) in ARCHIVES.items():
        parser.add_argument(f"--{role.replace('_', '-')}", type=Path, help=f"override path for {name}")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    paths = {
        role: getattr(args, role) or args.results_root / name
        for role, (name, _, _) in ARCHIVES.items()
    }
    result = verify(paths)
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(f"Archive verification: {'PASS' if result['passed'] else 'FAIL'} ({result['archives_checked']}/5 archives, 7 cases each)")
        for line in result["summary"]:
            print(f"  {line}")
        for note in result["notes"]:
            print(f"  note: {note}")
        for error in result["errors"]:
            print(f"  ERROR: {error}")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
