"""False-positive controls for the Docker study's normal-case gate."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from real_lab.run import _control_check


def _response(body: bytes = b"X") -> bytes:
    return b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body


class ControlGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.case_dir = Path(self.directory.name)

    def tearDown(self) -> None:
        self.directory.cleanup()

    def _write(self, response: bytes, custom_requests: list[str], default_requests: list[str] | None = None) -> None:
        (self.case_dir / "client.json").write_text(
            json.dumps({"response_hex": response.hex(), "sent_complete": True, "outcome": "read_timeout"}),
            encoding="utf-8",
        )
        (self.case_dir / "relay.jsonl").write_text(
            json.dumps({"event": "drained", "direction": "edge_to_backend", "hex": "58"}) + "\n",
            encoding="utf-8",
        )
        lines = [
            f'backend-1 | LAB_BACKEND peer=172.0.0.1 port=1 pid=1 keepalive={index} '
            f'status=200 connection=+ request="{request}"'
            for index, request in enumerate(custom_requests)
        ]
        lines.extend(f'backend-1 | "{request}" 200 1' for request in (default_requests or []))
        (self.case_dir / "backend.log").write_text("\n".join(lines), encoding="utf-8")

    def test_pipeline_passes_with_two_complete_responses_and_two_custom_logs(self) -> None:
        request = "GET /visible HTTP/1.1"
        self._write(_response() + _response(), [request, request], [request, request])
        self.assertTrue(_control_check(self.case_dir, "get-pipeline")["passed"])

    def test_default_access_log_cannot_substitute_for_second_backend_request(self) -> None:
        request = "GET /visible HTTP/1.1"
        self._write(_response() + _response(), [request], [request, request])
        self.assertFalse(_control_check(self.case_dir, "get-pipeline")["passed"])

    def test_fake_status_line_in_body_cannot_substitute_for_second_response(self) -> None:
        request = "GET /visible HTTP/1.1"
        self._write(_response(b"HTTP/1.1 200 OK\r\n"), [request, request])
        self.assertFalse(_control_check(self.case_dir, "get-pipeline")["passed"])

    def test_truncated_second_response_and_extra_backend_request_fail(self) -> None:
        request = "GET /visible HTTP/1.1"
        self._write(_response() + b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nX", [request, request, request])
        result = _control_check(self.case_dir, "get-pipeline")
        self.assertFalse(result["passed"])
        self.assertEqual(len(result["reasons"]), 2)


if __name__ == "__main__":
    unittest.main()
