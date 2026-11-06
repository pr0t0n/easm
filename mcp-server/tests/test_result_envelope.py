"""Tests for result_envelope v1 — stdlib unittest (no pytest required)."""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from result_envelope import (  # noqa: E402
    ENVELOPE_VERSION,
    build_envelope,
    compare_evidence,
)


class BuildEnvelopeTests(unittest.TestCase):
    def test_envelope_shape_and_version(self):
        env = build_envelope(tool="nuclei", target="http://x", status="done", return_code=0)
        self.assertEqual(env["envelope_version"], ENVELOPE_VERSION)
        for key in ("tool", "target", "status", "findings_raw", "quality_flags",
                    "evidence_refs", "normalized_at"):
            self.assertIn(key, env)

    def test_unknown_family_yields_no_findings(self):
        env = build_envelope(tool="nmap", target="http://x", status="done",
                             stdout="80/tcp open http\n")
        self.assertEqual(env["findings_raw"], [])

    def test_nuclei_extracts_template_findings(self):
        parsed = [
            {"template-id": "http/misconfig/x", "severity": "high",
             "host": "http://a", "matched-at": "http://a/p"},
            {"severity": "info"},  # sem template-id -> ignorado
        ]
        env = build_envelope(tool="nuclei", target="http://a", status="done", parsed=parsed)
        self.assertEqual(len(env["findings_raw"]), 1)
        self.assertEqual(env["findings_raw"][0]["id"], "http/misconfig/x")
        self.assertEqual(env["findings_raw"][0]["severity"], "high")

    def test_sqlmap_only_when_vulnerable(self):
        env = build_envelope(tool="sqlmap", target="http://a", status="done",
                             stdout="testing connection\nnothing found\n")
        self.assertEqual(env["findings_raw"], [])
        env = build_envelope(
            tool="sqlmap", target="http://a", status="done",
            stdout="Parameter: id\n    Type: boolean-based blind\nid is vulnerable\n")
        self.assertEqual(len(env["findings_raw"]), 1)
        self.assertEqual(env["findings_raw"][0]["host"], "id")

    def test_ffuf_skips_404(self):
        parsed = [
            {"url": "http://a/admin", "status": 200, "length": 1200},
            {"url": "http://a/nope", "status": 404, "length": 300},
        ]
        env = build_envelope(tool="ffuf", target="http://a", status="done", parsed=parsed)
        self.assertEqual(len(env["findings_raw"]), 1)
        self.assertEqual(env["findings_raw"][0]["host"], "http://a/admin")

    def test_quality_flags(self):
        env = build_envelope(tool="httpx", target="http://a", status="done",
                             return_code=0, stdout="")
        self.assertIn("empty_output", env["quality_flags"])
        env = build_envelope(tool="httpx", target="http://a", status="timeout",
                             return_code=None, stdout="x")
        self.assertIn("timeout", env["quality_flags"])
        env = build_envelope(tool="httpx", target="http://a", status="done",
                             return_code=2, stdout="ok", allowed_return_codes=[0, 1])
        self.assertIn("error_exit", env["quality_flags"])
        env = build_envelope(tool="httpx", target="http://a", status="done",
                             return_code=0, stdout="x" * 600_000)
        self.assertIn("high_noise", env["quality_flags"])


class CompareEvidenceTests(unittest.TestCase):
    def test_confirmed_when_all_signals_present(self):
        out = compare_evidence(evidence_expected=["is vulnerable", "Parameter: id"],
                               status="done", stdout="Parameter: id\nid is vulnerable\n")
        self.assertEqual(out["verdict"], "confirmed")
        self.assertEqual(out["missing"], [])

    def test_not_reproducible_when_no_signal(self):
        out = compare_evidence(evidence_expected=["is vulnerable"],
                               status="done", stdout="all clean")
        self.assertEqual(out["verdict"], "not_reproducible")

    def test_inconclusive_partial(self):
        out = compare_evidence(evidence_expected=["is vulnerable", "Parameter: id"],
                               status="done", stdout="Parameter: id only")
        self.assertEqual(out["verdict"], "inconclusive")
        self.assertEqual(out["matched"], ["Parameter: id"])

    def test_inconclusive_when_job_not_done(self):
        out = compare_evidence(evidence_expected=["x"], status="timeout", stdout="x")
        self.assertEqual(out["verdict"], "inconclusive")
        self.assertIn("timeout", out["reason"])

    def test_inconclusive_when_no_expected_signals(self):
        out = compare_evidence(evidence_expected=[], status="done", stdout="x")
        self.assertEqual(out["verdict"], "inconclusive")

    def test_matches_against_parsed_json(self):
        parsed = {"template-id": "http/x", "host": "http://a"}
        out = compare_evidence(evidence_expected=["http/x"], status="done",
                               stdout="", parsed=parsed)
        self.assertEqual(out["verdict"], "confirmed")


if __name__ == "__main__":
    unittest.main()
