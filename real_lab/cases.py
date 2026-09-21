"""Immutable, synthetic requests used by the Docker study."""

from __future__ import annotations

from desync_lab import fixtures


_GET = b"GET /visible HTTP/1.1\r\nHost: example.invalid\r\n\r\n"


def cases() -> dict[str, bytes]:
    ordered: dict[str, bytes] = {
        "get-single": _GET,
        "get-pipeline": _GET + _GET,
    }
    ordered.update({fixture["name"]: fixture["data"] for fixture in fixtures()})
    return ordered
