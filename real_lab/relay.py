"""Byte-blind TCP relay between the real proxy and real backend.

This program does not parse HTTP. It records each successful socket write and
the source port of its backend connection so Apache's access log can be joined
to the exact relayed stream. It is reachable only on the Compose internal net.
"""

from __future__ import annotations

import asyncio
import hashlib
import itertools
import json
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path


_SAFE_NAME = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
BACKEND_HOST = "backend"
BACKEND_PORT = 80
LISTEN_PORT = 9000


def _name(environment_key: str) -> str:
    value = os.environ.get(environment_key, "manual")
    if not _SAFE_NAME.fullmatch(value):
        raise ValueError(f"unsafe {environment_key}: {value!r}")
    return value


def _address(value: object) -> str:
    if isinstance(value, tuple) and len(value) >= 2:
        return f"{value[0]}:{value[1]}"
    return str(value)


class Recorder:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self._stream = path.open("a", encoding="utf-8", buffering=1)
        self._connection_ids = itertools.count(1)

    def next_connection(self) -> int:
        return next(self._connection_ids)

    def emit(self, connection_id: int, event: str, **fields: object) -> None:
        record = {
            "time_utc": datetime.now(timezone.utc).isoformat(),
            "monotonic_ns": time.monotonic_ns(),
            "connection_id": connection_id,
            "event": event,
            **fields,
        }
        self._stream.write(json.dumps(record, sort_keys=True) + "\n")


async def _pump(
    source: asyncio.StreamReader,
    destination: asyncio.StreamWriter,
    recorder: Recorder,
    connection_id: int,
    direction: str,
) -> None:
    sequence = 0
    try:
        while chunk := await source.read(65_536):
            destination.write(chunk)
            await destination.drain()
            sequence += 1
            recorder.emit(
                connection_id,
                "drained",
                direction=direction,
                sequence=sequence,
                length=len(chunk),
                sha256=hashlib.sha256(chunk).hexdigest(),
                hex=chunk.hex(),
            )
        recorder.emit(connection_id, "eof", direction=direction)
        if destination.can_write_eof():
            destination.write_eof()
            await destination.drain()
    except (ConnectionError, OSError) as exc:
        recorder.emit(connection_id, "pump_error", direction=direction, detail=repr(exc))


async def _handle(
    edge_reader: asyncio.StreamReader,
    edge_writer: asyncio.StreamWriter,
    recorder: Recorder,
) -> None:
    connection_id = recorder.next_connection()
    edge_peer = _address(edge_writer.get_extra_info("peername"))
    try:
        backend_reader, backend_writer = await asyncio.open_connection(
            BACKEND_HOST, BACKEND_PORT
        )
    except OSError as exc:
        recorder.emit(connection_id, "connect_error", edge_peer=edge_peer, detail=repr(exc))
        edge_writer.close()
        await edge_writer.wait_closed()
        return

    recorder.emit(
        connection_id,
        "open",
        edge_peer=edge_peer,
        backend_local=_address(backend_writer.get_extra_info("sockname")),
        backend_peer=_address(backend_writer.get_extra_info("peername")),
    )
    try:
        await asyncio.gather(
            _pump(edge_reader, backend_writer, recorder, connection_id, "edge_to_backend"),
            _pump(backend_reader, edge_writer, recorder, connection_id, "backend_to_edge"),
        )
    finally:
        backend_writer.close()
        edge_writer.close()
        await asyncio.gather(
            backend_writer.wait_closed(), edge_writer.wait_closed(), return_exceptions=True
        )
        recorder.emit(connection_id, "closed")


async def main() -> None:
    path = Path("/artifacts") / _name("LAB_RUN_ID") / _name("LAB_CASE_NAME") / "relay.jsonl"
    recorder = Recorder(path)
    server = await asyncio.start_server(
        lambda reader, writer: _handle(reader, writer, recorder),
        "0.0.0.0",
        LISTEN_PORT,
    )
    print(f"relay listening on {LISTEN_PORT}; recording to {path}", flush=True)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
