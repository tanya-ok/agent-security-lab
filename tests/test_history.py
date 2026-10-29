# SPDX-FileCopyrightText: 2026 Tanya Babitskaya
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from agent_security_lab.history import diagnostic, runs


def report(run_id, state="passed", steps=None, **extra):
    return {
        "schema": 1,
        "run_id": run_id,
        "operation": "demo",
        "started_at": "2026-01-02T03:04:05+00:00",
        "finished_at": "2026-01-02T03:14:05+00:00",
        "state": state,
        "steps": steps if steps is not None else [{"name": "Start stack", "state": "passed"}],
        **extra,
    }


class HistoryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.data = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def save(self, run_id, value):
        folder = self.data / "runs" / run_id
        folder.mkdir(parents=True)
        (folder / "report.json").write_text(json.dumps(value), encoding="utf-8")
        return folder

    def test_runs_are_newest_first_bounded_and_summarized(self):
        ids = [f"2026010{n}T030405Z-abc12{n}" for n in range(1, 6)]
        for run_id in ids:
            self.save(run_id, report(run_id))
        failed = "20260109T030405Z-fff999"
        self.save(
            failed,
            report(
                failed,
                "failed",
                [
                    {"name": "Start stack", "state": "passed"},
                    {"name": "Run FHIR scenarios", "state": "failed"},
                ],
                error="raw failure text",
            ),
        )
        result = runs(self.data, limit=3)
        self.assertEqual([r["run_id"] for r in result], [failed, ids[4], ids[3]])
        self.assertEqual(result[0]["failed_step"], "Run FHIR scenarios")
        self.assertEqual((result[0]["steps_passed"], result[0]["steps_total"]), (1, 2))
        self.assertNotIn("error", result[0])

    def test_malformed_mismatched_and_symlinked_runs_are_skipped(self):
        self.save("20260101T000000Z-aaaaaa", report("20260101T000000Z-bbbbbb"))
        broken = self.data / "runs" / "20260102T000000Z-cccccc"
        broken.mkdir(parents=True)
        (broken / "report.json").write_text("{not json", encoding="utf-8")
        (self.data / "runs" / "not-a-run").mkdir()
        target = self.save("20260103T000000Z-dddddd", report("20260103T000000Z-dddddd"))
        (self.data / "runs" / "20260104T000000Z-eeeeee").symlink_to(target)
        self.assertEqual([r["run_id"] for r in runs(self.data)], ["20260103T000000Z-dddddd"])

    def test_missing_or_symlinked_history_folder_is_empty(self):
        self.assertEqual(runs(self.data), [])
        outside = tempfile.TemporaryDirectory()
        self.addCleanup(outside.cleanup)
        (self.data / "runs").symlink_to(outside.name)
        self.assertEqual(runs(self.data), [])

    def test_diagnostic_keeps_only_allowlisted_fields(self):
        secret = "/Users/someone/private/token-abc"
        latest = report(
            "20260105T000000Z-123abc",
            "failed",
            [
                {"name": "Start stack", "state": "passed", "duration_seconds": 3.5, "log": secret},
                {"name": secret + "\nexfil", "state": "failed", "output": secret},
            ],
            error=secret,
            artifacts={"security": {"path": secret}},
        )
        status = {
            "latest": latest,
            "runtimes": [{"name": "security-lab", "status": "Running", "dir": secret}],
            "ports": {"hub": True, "grc": False, "bogus": secret},
            "control": {"token": secret},
        }
        pins = {"it-grc": {"commit": "a" * 40, "local_source": secret}, "bad": {"commit": "x"}}
        value = diagnostic(self.data, status, pins)
        self.assertNotIn(secret, json.dumps(value))
        self.assertEqual(value["source_pins"], {"it-grc": "a" * 12})
        self.assertEqual(value["ports"], {"hub": True, "grc": False})
        self.assertEqual(value["runtimes"], [{"name": "security-lab", "status": "Running"}])
        self.assertEqual(value["latest"]["steps"][1]["name"], None)
        self.assertEqual(value["latest"]["steps"][0]["duration_seconds"], 3.5)
        self.assertTrue(value["synthetic_data_only"])

    def test_diagnostic_without_any_run(self):
        value = diagnostic(self.data, {"latest": None, "runtimes": [], "ports": {}}, {})
        self.assertIsNone(value["latest"])
        self.assertEqual(value["history"], [])


if __name__ == "__main__":
    unittest.main()
