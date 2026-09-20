"""Behavioral checks for the offline, byte-oriented comparison lab."""

import contextlib
import io
import json
import unittest

import desync_lab


class DesyncLabTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.by_name = {fixture["name"]: fixture for fixture in desync_lab.fixtures()}

    def test_normal_controls_agree_on_two_pipelined_requests(self):
        for name in ("cl-normal", "chunked-normal"):
            with self.subTest(name=name):
                fixture = self.by_name[name]
                result = desync_lab.simulate(
                    fixture["data"], fixture["edge_policy"], fixture["backend_policy"]
                )
                self.assertEqual(result["edge"]["boundaries"], result["backend"]["boundaries"])
                self.assertEqual(len(result["edge"]["requests"]), 2)
                self.assertIsNone(result["edge"]["error"])
                self.assertIsNone(result["backend"]["error"])
                self.assertEqual(result["divergence"]["classification"], "no_mismatch")
                self.assertTrue(result["forwarding"]["matches_input"])

    def test_cl_te_boundary_differs_and_strict_policy_rejects_conflict(self):
        fixture = self.by_name["cl-te"]
        result = desync_lab.simulate(
            fixture["data"], fixture["edge_policy"], fixture["backend_policy"]
        )
        self.assertGreater(result["edge"]["boundaries"][0], result["backend"]["boundaries"][0])
        self.assertEqual(result["divergence"]["at_request_index"], 1)
        self.assertEqual(result["divergence"]["classification"], "confirmed_boundary_mismatch")
        self.assertEqual([r["target"] for r in result["edge"]["requests"]], ["/synthetic", "/visible"])
        self.assertEqual(
            [r["target"] for r in result["backend"]["requests"]],
            ["/synthetic", "/synthetic-shadow", "/visible"],
        )
        strict = desync_lab.parse_stream(fixture["data"], "strict")
        self.assertEqual(strict.requests, ())
        self.assertEqual(strict.error.code, "conflicting_framing")

    def test_te_cl_boundary_differs_even_when_later_parse_fails(self):
        fixture = self.by_name["te-cl"]
        result = desync_lab.simulate(
            fixture["data"], fixture["edge_policy"], fixture["backend_policy"]
        )
        self.assertLess(result["backend"]["boundaries"][0], result["edge"]["boundaries"][0])
        self.assertEqual(result["divergence"]["classification"], "confirmed_boundary_mismatch")
        self.assertEqual(result["divergence"]["at_request_index"], 1)
        self.assertEqual(result["backend"]["requests"][1]["target"], "/synthetic-shadow")
        self.assertIsNotNone(result["backend"]["error"])
        self.assertTrue(result["forwarding"]["matches_input"])

    def test_duplicate_cl_first_and_last_diverge_while_strict_rejects(self):
        fixture = self.by_name["duplicate-cl"]
        result = desync_lab.simulate(
            fixture["data"], fixture["edge_policy"], fixture["backend_policy"]
        )
        self.assertLess(result["edge"]["boundaries"][0], result["backend"]["boundaries"][0])
        self.assertEqual(result["divergence"]["classification"], "confirmed_boundary_mismatch")
        self.assertEqual(len(result["edge"]["requests"]), 3)
        self.assertEqual(len(result["backend"]["requests"]), 2)
        strict = desync_lab.parse_stream(fixture["data"], "strict")
        self.assertEqual(strict.error.code, "ambiguous_duplicate_cl")

    def test_identical_duplicate_cl_is_unambiguous_control(self):
        stream = (
            b"POST /same HTTP/1.1\r\nContent-Length: 4\r\nContent-Length: 4\r\n\r\nDATA"
            b"GET /next HTTP/1.1\r\n\r\n"
        )
        parsed = desync_lab.parse_stream(stream, "strict")
        self.assertIsNone(parsed.error)
        self.assertEqual(len(parsed.requests), 2)
        self.assertEqual(parsed.boundaries[-1], len(stream))

    def test_very_long_numeric_content_length_returns_parse_issue(self):
        stream = b"POST /large HTTP/1.1\r\nContent-Length: " + b"9" * 5_000 + b"\r\n\r\n"
        parsed = desync_lab.parse_stream(stream, "strict")
        self.assertEqual(parsed.requests, ())
        self.assertEqual(parsed.error.code, "body_too_large")
        self.assertEqual(parsed.error.offset, 0)

    def test_offsets_measure_bytes_and_raw_slices_are_preserved(self):
        body = "é".encode("utf-8")
        stream = b"POST /bytes HTTP/1.1\r\nContent-Length: 2\r\n\r\n" + body
        result = desync_lab.simulate(stream, "strict", "strict")
        self.assertEqual(result["edge"]["boundaries"], [len(stream)])
        self.assertEqual(result["edge"]["requests"][0]["raw_hex"], stream.hex())
        self.assertEqual(result["forwarding"]["forwarded_hex"], stream.hex())
        self.assertEqual(result["backend"]["requests"][0]["raw_hex"], stream.hex())

    def test_parse_error_alone_is_not_boundary_mismatch(self):
        stream = b"GET /incomplete HTTP/1.1\r\nHost: example.invalid\r\n"
        result = desync_lab.simulate(stream, "strict", "strict")
        self.assertEqual(result["edge"]["error"]["code"], "incomplete_headers")
        self.assertEqual(result["edge"]["boundaries"], [])
        self.assertEqual(result["forwarding"]["forwarded_length"], 0)
        self.assertFalse(result["divergence"]["confirmed_boundary_mismatch"])
        self.assertEqual(
            result["divergence"]["classification"], "parse_error_without_boundary_mismatch"
        )

    def test_forwarding_stops_at_edge_error_without_changing_completed_bytes(self):
        complete = b"GET /complete HTTP/1.1\r\n\r\n"
        stream = complete + b"GET /truncated HTTP/1.1\r\n"
        result = desync_lab.simulate(stream, "strict", "strict")
        self.assertEqual(result["forwarding"]["forwarded_hex"], complete.hex())
        self.assertEqual(result["edge"]["boundaries"], [len(complete)])
        self.assertEqual(result["backend"]["boundaries"], [len(complete)])
        self.assertEqual(result["divergence"]["classification"], "parse_error_without_boundary_mismatch")

    def test_cli_matrix_is_machine_readable(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            exit_code = desync_lab.main(["matrix"])
        document = json.loads(output.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertEqual(document["schema_version"], 1)
        self.assertEqual(document["offset_unit"], "byte")
        self.assertEqual(set(row["name"] for row in document["fixtures"]), set(self.by_name))
        self.assertEqual(
            sum(row["divergence"]["confirmed_boundary_mismatch"] for row in document["fixtures"]),
            3,
        )


if __name__ == "__main__":
    unittest.main()
