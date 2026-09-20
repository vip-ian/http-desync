"""Deterministic, offline HTTP/1.1 request-boundary comparison lab.

The parser policies here are deliberately small models, not implementations of
particular servers. All inputs are synthetic byte strings; this module neither
opens sockets nor sends requests to a target.
"""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass
from typing import Sequence


POLICIES = (
    "strict",
    "cl-first",
    "te-first",
    "duplicate-cl-first",
    "duplicate-cl-last",
)
MAX_HEADER_BYTES = 16_384
MAX_BODY_BYTES = 1_048_576
_TOKEN = re.compile(rb"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_HEX = re.compile(rb"^[0-9A-Fa-f]+$")


@dataclass(frozen=True)
class ParseIssue:
    code: str
    offset: int
    detail: str

    def to_dict(self) -> dict[str, object]:
        return {"code": self.code, "offset": self.offset, "detail": self.detail}


@dataclass(frozen=True)
class ParsedRequest:
    start: int
    end: int
    header_end: int
    framing: str
    method: str
    target: str

    def to_dict(self, source: bytes) -> dict[str, object]:
        return {
            "start": self.start,
            "end": self.end,
            "header_end": self.header_end,
            "framing": self.framing,
            "method": self.method,
            "target": self.target,
            "raw_hex": source[self.start : self.end].hex(),
        }


@dataclass(frozen=True)
class StreamResult:
    policy: str
    requests: tuple[ParsedRequest, ...]
    error: ParseIssue | None

    @property
    def boundaries(self) -> list[int]:
        """Exclusive, zero-based byte offsets of complete requests."""
        return [request.end for request in self.requests]

    def to_dict(self, source: bytes) -> dict[str, object]:
        return {
            "policy": self.policy,
            "boundaries": self.boundaries,
            "requests": [request.to_dict(source) for request in self.requests],
            "error": None if self.error is None else self.error.to_dict(),
        }


class _ParseFailure(Exception):
    def __init__(self, code: str, offset: int, detail: str):
        super().__init__(detail)
        self.issue = ParseIssue(code, offset, detail)


def _fail(code: str, offset: int, detail: str) -> None:
    raise _ParseFailure(code, offset, detail)


def _chunked_end(data: bytes, start: int) -> int:
    position = start
    decoded_size = 0
    while True:
        line_end = data.find(b"\r\n", position)
        if line_end < 0:
            _fail("incomplete_chunk_size", position, "chunk size line has no CRLF")
        size_token = data[position:line_end].split(b";", 1)[0]
        if not _HEX.fullmatch(size_token):
            _fail("invalid_chunk_size", position, "chunk size is not hexadecimal")
        size = int(size_token, 16)
        position = line_end + 2
        decoded_size += size
        if decoded_size > MAX_BODY_BYTES:
            _fail("body_too_large", position, "decoded chunk body exceeds lab limit")

        if size == 0:
            while True:
                trailer_end = data.find(b"\r\n", position)
                if trailer_end < 0:
                    _fail("incomplete_trailers", position, "chunk trailers have no closing CRLF")
                if trailer_end == position:
                    return position + 2
                trailer = data[position:trailer_end]
                if b":" not in trailer or not _TOKEN.fullmatch(trailer.split(b":", 1)[0]):
                    _fail("invalid_trailer", position, "trailer is not a header field")
                position = trailer_end + 2

        if position + size + 2 > len(data):
            _fail("incomplete_chunk_data", position, "chunk data or its CRLF is missing")
        if data[position + size : position + size + 2] != b"\r\n":
            _fail("invalid_chunk_terminator", position + size, "chunk data is not followed by CRLF")
        position += size + 2


def _one_request(data: bytes, start: int, policy: str) -> ParsedRequest:
    marker = data.find(b"\r\n\r\n", start)
    if marker < 0:
        if len(data) - start > MAX_HEADER_BYTES:
            _fail("header_too_large", start, "header exceeds lab limit")
        _fail("incomplete_headers", start, "request has no closing CRLF CRLF")
    header_end = marker + 4
    if header_end - start > MAX_HEADER_BYTES:
        _fail("header_too_large", start, "header exceeds lab limit")

    first_line_end = data.find(b"\r\n", start, marker + 2)
    if first_line_end < 0:
        _fail("invalid_request_line", start, "request line has no CRLF")
    request_line = data[start:first_line_end]
    parts = request_line.split(b" ")
    if len(parts) != 3 or not _TOKEN.fullmatch(parts[0]) or not parts[1]:
        _fail("invalid_request_line", start, "expected METHOD target HTTP/1.1")
    if parts[2] != b"HTTP/1.1":
        _fail("unsupported_version", start, "this lab accepts HTTP/1.1 only")
    if any(byte < 0x21 or byte > 0x7E for byte in parts[1]):
        _fail("invalid_target", start, "target must contain visible ASCII bytes")

    header_lines = data[first_line_end + 2 : marker].split(b"\r\n")
    if header_lines == [b""]:
        header_lines = []
    content_lengths: list[int] = []
    transfer_encodings: list[bytes] = []
    for line in header_lines:
        if b":" not in line:
            _fail("invalid_header", start, "header line lacks a colon")
        name, value = line.split(b":", 1)
        if not _TOKEN.fullmatch(name):
            _fail("invalid_header", start, "header name is not an HTTP token")
        value = value.strip(b" \t")
        if b"\r" in value or b"\n" in value:
            _fail("invalid_header", start, "bare line break in header value")
        if name.lower() == b"content-length":
            if not value.isdigit():
                _fail("invalid_content_length", start, "Content-Length must be decimal digits")
            # Bound conversion before int(): Python limits very long decimal strings.
            significant = value.lstrip(b"0") or b"0"
            maximum = str(MAX_BODY_BYTES).encode("ascii")
            if len(significant) > len(maximum) or (
                len(significant) == len(maximum) and significant > maximum
            ):
                _fail("body_too_large", start, "Content-Length exceeds lab limit")
            number = int(significant)
            content_lengths.append(number)
        elif name.lower() == b"transfer-encoding":
            transfer_encodings.extend(part.strip(b" \t").lower() for part in value.split(b","))

    has_cl = bool(content_lengths)
    has_te = bool(transfer_encodings)
    if has_te and transfer_encodings != [b"chunked"]:
        _fail("unsupported_transfer_encoding", start, "only a single chunked coding is modeled")
    if has_cl and len(set(content_lengths)) > 1:
        if policy == "duplicate-cl-first":
            content_length = content_lengths[0]
        elif policy == "duplicate-cl-last":
            content_length = content_lengths[-1]
        else:
            _fail("ambiguous_duplicate_cl", start, "Content-Length field values disagree")
    else:
        content_length = content_lengths[0] if has_cl else 0

    if has_cl and has_te:
        if policy in ("strict", "duplicate-cl-first", "duplicate-cl-last"):
            _fail("conflicting_framing", start, "both Transfer-Encoding and Content-Length are present")
        framing = "content-length" if policy == "cl-first" else "chunked"
    elif has_te:
        framing = "chunked"
    elif has_cl:
        framing = "content-length"
    else:
        framing = "none"

    if framing == "chunked":
        end = _chunked_end(data, header_end)
    elif framing == "content-length":
        end = header_end + content_length
        if end > len(data):
            _fail("incomplete_body", header_end, "Content-Length bytes are not all present")
    else:
        end = header_end

    return ParsedRequest(
        start=start,
        end=end,
        header_end=header_end,
        framing=framing,
        method=parts[0].decode("ascii"),
        target=parts[1].decode("ascii"),
    )


def parse_stream(data: bytes, policy: str = "strict") -> StreamResult:
    """Parse complete requests in *data*; offsets count raw bytes, not characters."""
    if policy not in POLICIES:
        raise ValueError(f"unknown policy: {policy}")
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    position = 0
    requests: list[ParsedRequest] = []
    while position < len(data):
        try:
            request = _one_request(data, position, policy)
        except _ParseFailure as exc:
            return StreamResult(policy, tuple(requests), exc.issue)
        requests.append(request)
        position = request.end
    return StreamResult(policy, tuple(requests), None)


def simulate(data: bytes, edge_policy: str, backend_policy: str) -> dict[str, object]:
    """Forward only edge-complete raw request slices, then parse the same bytes downstream."""
    edge = parse_stream(data, edge_policy)
    forwarded = b"".join(data[request.start : request.end] for request in edge.requests)
    backend = parse_stream(forwarded, backend_policy)
    first_mismatch = next(
        (
            index
            for index, (edge_end, backend_end) in enumerate(
                zip(edge.boundaries, backend.boundaries), start=1
            )
            if edge_end != backend_end
        ),
        None,
    )
    if first_mismatch is not None:
        classification = "confirmed_boundary_mismatch"
    elif edge.error is not None or backend.error is not None:
        classification = "parse_error_without_boundary_mismatch"
    else:
        classification = "no_mismatch"
    return {
        "input_hex": data.hex(),
        "input_length": len(data),
        "edge": edge.to_dict(data),
        "forwarding": {
            "forwarded_hex": forwarded.hex(),
            "forwarded_length": len(forwarded),
            "matches_input": forwarded == data,
        },
        "backend": backend.to_dict(forwarded),
        "divergence": {
            "classification": classification,
            "confirmed_boundary_mismatch": first_mismatch is not None,
            "at_request_index": first_mismatch,
        },
    }


def _get(target: str) -> bytes:
    return f"GET {target} HTTP/1.1\r\nHost: example.invalid\r\n\r\n".encode("ascii")


def _post(headers: Sequence[tuple[str, str]], body: bytes) -> bytes:
    lines = [b"POST /synthetic HTTP/1.1", b"Host: example.invalid"]
    lines.extend(f"{name}: {value}".encode("ascii") for name, value in headers)
    return b"\r\n".join(lines) + b"\r\n\r\n" + body


def fixtures() -> tuple[dict[str, object], ...]:
    """Return synthetic streams and policy pairs; no fixture names a live endpoint."""
    shadow = _get("/synthetic-shadow")
    visible = _get("/visible")
    cl_body = b"PING"
    chunk_body = b"4\r\nPING\r\n0\r\n\r\n"
    cl_te_body = b"0\r\n\r\n" + shadow
    te_cl_chunk_prefix = f"{len(shadow):02X}\r\n".encode("ascii")
    te_cl_body = te_cl_chunk_prefix + shadow + b"\r\n0\r\n\r\n"
    duplicate_body = b"HELLO" + shadow
    return (
        {
            "name": "cl-normal",
            "description": "Ordinary Content-Length control with a following request.",
            "data": _post([("Content-Length", str(len(cl_body)))], cl_body) + visible,
            "edge_policy": "strict",
            "backend_policy": "strict",
        },
        {
            "name": "chunked-normal",
            "description": "Ordinary chunked control with a following request.",
            "data": _post([("Transfer-Encoding", "chunked")], chunk_body) + visible,
            "edge_policy": "strict",
            "backend_policy": "strict",
        },
        {
            "name": "cl-te",
            "description": "CL-first edge consumes a synthetic request that TE-first backend sees separately.",
            "data": _post(
                [("Content-Length", str(len(cl_te_body))), ("Transfer-Encoding", "chunked")],
                cl_te_body,
            ) + visible,
            "edge_policy": "cl-first",
            "backend_policy": "te-first",
        },
        {
            "name": "te-cl",
            "description": "TE-first edge consumes a chunk that CL-first backend ends before synthetic data.",
            "data": _post(
                [("Content-Length", str(len(te_cl_chunk_prefix))), ("Transfer-Encoding", "chunked")],
                te_cl_body,
            ) + visible,
            "edge_policy": "te-first",
            "backend_policy": "cl-first",
        },
        {
            "name": "duplicate-cl",
            "description": "First versus last differing Content-Length values.",
            "data": _post(
                [
                    ("Content-Length", "5"),
                    ("Content-Length", str(len(duplicate_body))),
                ],
                duplicate_body,
            ) + visible,
            "edge_policy": "duplicate-cl-first",
            "backend_policy": "duplicate-cl-last",
        },
    )


def matrix() -> dict[str, object]:
    rows: list[dict[str, object]] = []
    for fixture in fixtures():
        row = simulate(
            fixture["data"],  # type: ignore[arg-type]
            fixture["edge_policy"],  # type: ignore[arg-type]
            fixture["backend_policy"],  # type: ignore[arg-type]
        )
        row.update(name=fixture["name"], description=fixture["description"])
        rows.append(row)
    return {"schema_version": 1, "offset_unit": "byte", "fixtures": rows}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["matrix"], help="print the deterministic fixture matrix as JSON")
    parser.add_argument("--pretty", action="store_true", help="indent JSON for reading")
    args = parser.parse_args(argv)
    if args.command == "matrix":
        print(json.dumps(matrix(), indent=2 if args.pretty else None, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
