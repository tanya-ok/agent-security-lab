# SPDX-License-Identifier: Apache-2.0
"""Regression tests for source, ownership, execution and evidence boundaries."""

from __future__ import annotations

import http.client
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from agent_security_lab.cli import (
    PROJECTS,
    Controls,
    Lab,
    LabError,
    handler,
    read,
    stamp,
    tool_path,
    validate_security_report,
    write,
)


class LauncherTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base = tempfile.TemporaryDirectory()
        cls.workspace = Path(cls.base.name)
        source = cls.workspace / "source"
        source.mkdir()
        subprocess.run(["git", "init", "-q", str(source)], check=True)
        (source / "source.txt").write_text("reviewed source\n", encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=source, check=True)
        subprocess.run(
            [
                "git",
                "-c",
                "user.name=Synthetic Fixture",
                "-c",
                "user.email=fixture@example.org",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "-qm",
                "Initial fixture",
            ],
            cwd=source,
            check=True,
        )
        cls.commit = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=source, text=True
        ).strip()
        for name in PROJECTS:
            shutil.copytree(source, cls.workspace / name)

    @classmethod
    def tearDownClass(cls):
        cls.base.cleanup()

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=self.workspace)
        self.root = Path(self.temporary.name)
        write(
            self.root / "lab.lock.json",
            {
                "schema": 1,
                "projects": {
                    name: {"commit": self.commit, "local_source": name} for name in PROJECTS
                },
            },
        )
        self.lab = Lab(self.root, self.workspace)

    def tearDown(self):
        self.temporary.cleanup()

    def test_only_committed_source_is_materialized(self):
        source = self.workspace / PROJECTS[0] / "source.txt"
        source.write_text("uncommitted user work", encoding="utf-8")
        try:
            self.lab.sync()
            self.assertEqual(
                (self.lab.repo(PROJECTS[0]) / "source.txt").read_text(), "reviewed source\n"
            )
            self.assertEqual(source.read_text(), "uncommitted user work")
        finally:
            source.write_text("reviewed source\n", encoding="utf-8")

    def test_source_and_metadata_rewrite_cannot_forge_git_pin(self):
        self.lab.sync()
        name = PROJECTS[0]
        (self.lab.repo(name) / "source.txt").write_text("modified", encoding="utf-8")
        metadata = self.lab.data / "snapshots" / (name + ".json")
        value = read(metadata)
        value["files"] = {}
        write(metadata, value)
        with self.assertRaisesRegex(LabError, "Source snapshot changed"):
            self.lab.verify(name)

    def test_symlink_source_replacement_is_refused(self):
        self.lab.sync()
        path = self.lab.repo(PROJECTS[0]) / "source.txt"
        path.unlink()
        path.symlink_to(self.workspace / PROJECTS[0] / "source.txt")
        with self.assertRaises(LabError):
            self.lab.verify(PROJECTS[0])

    def test_runtime_ownership_cannot_be_rebound(self):
        self.lab.owned()
        write(self.lab.data / "owner.json", {"root": "/another/checkout"})
        with self.assertRaisesRegex(LabError, "another launcher"):
            self.lab.env()

    def test_runtime_symlink_and_unowned_directory_are_refused(self):
        self.lab.data.symlink_to(self.workspace, target_is_directory=True)
        with self.assertRaises(LabError):
            self.lab.owned()
        self.lab.data.unlink()
        self.lab.data.mkdir()
        (self.lab.data / "unknown").touch()
        with self.assertRaises(LabError):
            self.lab.owned()

    def test_secret_environment_is_not_inherited(self):
        with patch.dict(
            os.environ,
            {
                "AWS_PROFILE": "private",
                "MOONSHOT_API_KEY": "test",
                "SSH_AUTH_SOCK": "/private/socket",
                "LIMA_HOME": "/another/runtime",
            },
        ):
            env = self.lab.env()
        for name in ("AWS_PROFILE", "MOONSHOT_API_KEY", "SSH_AUTH_SOCK"):
            self.assertNotIn(name, env)
        self.assertEqual(env["LIMA_HOME"], str(self.lab.data / "lima"))
        self.assertEqual(env["PLAYWRIGHT_SKIP_BROWSER_GC"], "1")
        self.assertEqual(self.lab.data.stat().st_mode & 0o777, 0o700)

    def test_desktop_path_finds_tools_without_system_directories(self):
        with patch.dict(os.environ, {"PATH": str(self.root)}):
            env = self.lab.env()
            # Exercise actual child lookup, not just the resulting string.
            process = subprocess.run(
                ["sh", "-c", "command -v ls"], env=env, capture_output=True, check=False
            )
            self.assertEqual(process.returncode, 0)
            self.assertIn("/opt/homebrew/bin", env["PATH"].split(os.pathsep))
            self.assertEqual(env["PATH"].split(os.pathsep)[0], str(self.root))

    def test_path_preserves_selected_tool_and_excludes_implicit_working_directory(self):
        tool = self.root / "lab-test-tool"
        tool.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        tool.chmod(0o700)
        with patch.dict(os.environ, {"PATH": f"{self.root}::.:relative:{self.root}"}):
            env = self.lab.env()
            self.assertEqual(shutil.which("lab-test-tool", path=env["PATH"]), str(tool))
            paths = env["PATH"].split(os.pathsep)
            self.assertEqual(paths.count(str(self.root)), 1)
            self.assertTrue(all(Path(path).is_absolute() for path in paths))
            self.assertEqual(env["PATH"], tool_path())

    def test_parallel_mutation_is_refused(self):
        with self.lab.exclusive(), self.assertRaisesRegex(LabError, "already running"):
            with self.lab.exclusive():
                pass

    def test_reused_pid_is_not_killed(self):
        self.lab.owned()
        write(self.lab.service_file("dashboard"), {"pid": 123, "fingerprint": "old process"})
        with (
            patch("agent_security_lab.cli.fingerprint", return_value="another process"),
            patch("agent_security_lab.cli.os.killpg") as kill,
        ):
            self.lab.stop_service("dashboard")
        kill.assert_not_called()

    def test_owned_process_identity_is_required_before_stop(self):
        self.lab.owned()
        identity = str(self.lab.root) + "/dashboard process at original start time"
        write(self.lab.service_file("dashboard"), {"pid": 123, "fingerprint": identity})
        with (
            patch("agent_security_lab.cli.fingerprint", return_value=identity),
            patch("agent_security_lab.cli.os.killpg") as kill,
        ):
            self.lab.stop_service("dashboard")
        kill.assert_called_once()

    def test_failed_command_stays_failed_in_report(self):
        self.lab.begin("demo")
        with self.assertRaises(LabError):
            self.lab.run("Expected denial fixture", [sys.executable, "-c", "raise SystemExit(7)"])
        self.lab.finish(False)
        report = read(self.lab.data / "latest.json")
        self.assertEqual(report["state"], "failed")
        self.assertEqual(report["steps"][0]["exit_code"], 7)

    def test_timeout_stops_its_child_and_preserves_failure(self):
        self.lab.begin("demo")
        with self.assertRaises(LabError):
            self.lab.run(
                "Timeout fixture",
                [sys.executable, "-c", "import time; time.sleep(10)"],
                timeout=0.05,
            )
        self.assertEqual(self.lab.report["steps"][0]["state"], "failed")

    def test_grc_gets_fresh_security_report_and_dashboard_is_synthetic(self):
        self.lab.begin("demo")
        report = self.lab.repo("mcp-svid-auth") / "deploy/.data/demo-report.json"
        write(
            report,
            {
                "passed": True,
                "timestamp": stamp(),
                "results": [{"scenario": n, "passed": True} for n in range(1, 19)],
            },
        )
        events = []

        def make(name, target, **kwargs):
            events.append((target, kwargs))

        with (
            patch.object(self.lab, "up", side_effect=lambda: events.append(("up", {}))),
            patch.object(self.lab, "verify", side_effect=self.lab.repo),
            patch.object(self.lab, "run", side_effect=lambda *a, **k: events.append((a[0], {}))),
            patch.object(self.lab, "make", side_effect=make),
            patch(
                "agent_security_lab.services.Services.restart",
                side_effect=lambda key: events.append(("restart:" + key, {})),
            ),
            patch.object(self.lab, "identity_demos"),
            patch.object(self.lab, "verify_access") as verify_access,
            patch.object(self.lab, "package_demos"),
            patch.object(self.lab, "artifact", return_value={"passed": [1, 2]}),
            patch(
                "agent_security_lab.cli.local_json",
                side_effect=[{"status": "ok"}, {"nodes": [1, 2]}],
            ),
        ):
            self.lab.demo()
        self.assertEqual([name for name, _ in events[:2]], ["up", "restart:fhir"])
        verify_access.assert_called_once_with()
        grc = next(value for name, value in events if name == "grc-demo")
        self.assertEqual(grc["extra"], ("REPORT=" + str(report),))
        self.assertLess(
            next(i for i, e in enumerate(events) if "18 real-stack" in e[0]),
            next(i for i, e in enumerate(events) if e[0] == "grc-demo"),
        )
        self.assertEqual(self.lab.report["dashboard"], {"fixture": True, "nodes": 2})

    def test_incomplete_security_evidence_stops_before_grc(self):
        self.lab.begin("demo")
        write(
            self.lab.repo("mcp-svid-auth") / "deploy/.data/demo-report.json",
            {"passed": False, "results": []},
        )
        with (
            patch.object(self.lab, "up"),
            patch("agent_security_lab.services.Services.restart"),
            patch.object(self.lab, "run"),
            patch.object(self.lab, "verify", side_effect=self.lab.repo),
            patch.object(self.lab, "make") as make,
            self.assertRaises(LabError),
        ):
            self.lab.demo()
        make.assert_not_called()

    def test_failed_fhir_rollout_stops_before_scenarios(self):
        self.lab.begin("demo")
        with (
            patch.object(self.lab, "up"),
            patch(
                "agent_security_lab.services.Services.restart",
                side_effect=LabError("Rollout failed"),
            ) as restart,
            patch.object(self.lab, "run") as run,
            patch.object(self.lab, "make") as make,
            self.assertRaises(LabError),
        ):
            self.lab.demo()
        restart.assert_called_once_with("fhir")
        run.assert_not_called()
        make.assert_not_called()

    def test_unavailable_browser_stops_before_identity_access(self):
        self.lab.begin("demo")
        with (
            patch("agent_security_lab.acceptance.owner_snapshot") as snapshot,
            patch.object(self.lab, "run", side_effect=LabError("Browser unavailable")),
            self.assertRaises(LabError),
        ):
            self.lab.identity_demos()
        snapshot.assert_not_called()

    def test_identity_failure_still_checks_preservation_and_never_imports_evidence(self):
        self.lab.begin("demo")

        def fail_stage(name, *args, **kwargs):
            if name != "Ensure pinned synthetic browser":
                raise LabError("Synthetic stage failed")

        with (
            patch(
                "agent_security_lab.acceptance.owner_snapshot",
                side_effect=[{"fixture": 1}, {"fixture": 2}],
            ) as snapshot,
            patch.object(self.lab, "verify", side_effect=self.lab.repo),
            patch.object(self.lab, "run", side_effect=fail_stage),
            patch.object(self.lab, "artifact") as artifact,
            self.assertRaises(LabError),
        ):
            self.lab.identity_demos()
        self.assertEqual(snapshot.call_count, 2)
        self.assertFalse(self.lab.report["owner_identity_preserved"])
        artifact.assert_not_called()

    def test_identity_acceptance_requires_fresh_complete_reports(self):
        self.lab.begin("demo")
        folder = self.lab.repo("mcp-svid-auth") / "deploy/.data/passkey"
        write(
            folder / "identity-demo-report.json",
            {"checked_at": stamp(), "passed": ["duplicate"] * 11},
        )
        with (
            patch("agent_security_lab.acceptance.owner_snapshot", return_value={"fixture": 1}),
            patch.object(self.lab, "verify", side_effect=self.lab.repo),
            patch.object(self.lab, "run"),
            patch.object(self.lab, "artifact") as artifact,
            self.assertRaises(LabError),
        ):
            self.lab.identity_demos()
        artifact.assert_not_called()
        self.assertNotIn("identity_checks", self.lab.report)

    def test_identity_acceptance_keeps_both_full_reports_and_owner_proof(self):
        self.lab.begin("demo")
        folder = self.lab.repo("mcp-svid-auth") / "deploy/.data/passkey"
        for filename, count in (("identity-demo-report.json", 11), ("google-setup-report.json", 4)):
            write(
                folder / filename, {"checked_at": stamp(), "passed": [str(n) for n in range(count)]}
            )
        with (
            patch("agent_security_lab.acceptance.owner_snapshot", return_value={"fixture": 1}),
            patch.object(self.lab, "verify", side_effect=self.lab.repo),
            patch.object(self.lab, "run"),
        ):
            self.lab.identity_demos()
        self.assertTrue(self.lab.report["owner_identity_preserved"])
        self.assertEqual(self.lab.report["identity_checks"], 11)
        self.assertEqual(self.lab.report["google_setup_checks"], 4)
        self.assertEqual(self.lab.report["synthetic_identity_profile"], "isolated")

    def test_security_report_refuses_stale_future_and_missing_scenarios(self):
        started = stamp()
        report = {
            "passed": True,
            "timestamp": stamp(),
            "results": [{"scenario": n, "passed": True} for n in range(1, 19)],
        }
        self.assertIs(validate_security_report(report, started), report)
        for invalid in ("2020-01-01T00:00:00+00:00", "2099-01-01T00:00:00+00:00"):
            with self.subTest(timestamp=invalid), self.assertRaises(LabError):
                validate_security_report({**report, "timestamp": invalid}, started)
        with self.assertRaises(LabError):
            validate_security_report({**report, "results": report["results"][:-1]}, started)
        report["results"][0]["passed"] = False
        with self.assertRaises(LabError):
            validate_security_report(report, started)

    def test_process_start_failure_is_recorded_without_exception_text(self):
        self.lab.begin("demo")
        with self.assertRaises(LabError):
            self.lab.run("Missing tool", ["/nonexistent/demo-tool"])
        self.assertEqual(self.lab.report["steps"][0]["state"], "failed")
        self.assertEqual(self.lab.report["steps"][0]["exit_code"], -2)

    def test_down_operation_does_not_replace_last_demo(self):
        self.lab.begin("demo")
        self.lab.finish(True)
        demo = read(self.lab.data / "demo-latest.json")
        self.lab.begin("down")
        self.lab.finish(True)
        self.assertEqual(read(self.lab.data / "demo-latest.json"), demo)
        self.assertEqual(read(self.lab.data / "latest.json")["operation"], "down")

    def test_down_removes_disposable_security_before_vm_stop(self):
        calls = []
        with (
            patch.object(self.lab, "owned"),
            patch.object(self.lab, "stop_service"),
            patch.object(
                self.lab,
                "inventory",
                return_value=[
                    {"name": "security-lab", "status": "Running"},
                    {"name": "it-grc", "status": "Running"},
                ],
            ),
            patch.object(
                self.lab, "make", side_effect=lambda project, target: calls.append(target)
            ),
        ):
            self.lab.down()
        self.assertEqual(calls, ["down", "runtime-stop", "grc-stop"])
        self.assertNotIn("grc-down", calls)
        self.assertNotIn("grc-destroy", calls)

    def test_only_owned_vm_home_is_inspected(self):
        self.lab.owned()
        result = subprocess.CompletedProcess(
            [], 0, json.dumps({"name": "security-lab", "status": "Stopped"}), ""
        )
        with patch("agent_security_lab.cli.subprocess.run", return_value=result) as call:
            self.assertEqual(self.lab.inventory()[0]["status"], "Stopped")
        self.assertEqual(call.call_args.kwargs["env"]["LIMA_HOME"], str(self.lab.data / "lima"))

    def test_browser_stop_preserves_hub_and_persistent_grc(self):
        stopped = []
        with (
            patch.object(self.lab, "inventory", return_value=[]),
            patch.object(self.lab, "stop_service", side_effect=stopped.append),
        ):
            self.lab.down(keep_hub=True)
        self.assertEqual(stopped, ["dashboard", "sso-tunnel"])

    def test_browser_start_is_async_and_serialized(self):
        controls = Controls(self.lab)
        started = threading.Event()
        release = threading.Event()

        def up(runner):
            started.set()
            release.wait(3)

        with patch.object(Lab, "up", up):
            controls.submit("start")
            self.assertTrue(started.wait(2))
            try:
                self.assertTrue(controls.status()["busy"])
                with self.assertRaisesRegex(LabError, "already running"):
                    controls.submit("demo")
                with self.assertRaises(LabError), self.lab.exclusive():
                    pass
            finally:
                release.set()
                controls.thread.join(3)
        self.assertFalse(controls.status()["busy"])
        self.assertEqual(read(self.lab.data / "latest.json")["state"], "passed")

    def test_browser_stop_cancels_child_then_runs_scoped_teardown(self):
        controls = Controls(self.lab)
        child_pid = self.lab.root / "child.pid"
        calls = []

        def up(runner):
            runner.run(
                "Cancellable child",
                [
                    sys.executable,
                    "-c",
                    "import os,time; from pathlib import Path; "
                    f"Path({str(child_pid)!r}).write_text(str(os.getpid())); time.sleep(30)",
                ],
            )

        def down(runner, keep_hub=False):
            pid = int(child_pid.read_text())
            with self.assertRaises(ProcessLookupError):
                os.kill(pid, 0)
            calls.append(keep_hub)

        with patch.object(Lab, "up", up), patch.object(Lab, "down", down):
            controls.submit("start")
            deadline = time.monotonic() + 3
            while not child_pid.exists() and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertTrue(child_pid.exists())
            controls.submit("stop")
            controls.thread.join(5)
        self.assertFalse(controls.thread.is_alive())
        self.assertEqual(calls, [True])
        reports = [read(p) for p in (self.lab.data / "runs").glob("*/report.json")]
        self.assertEqual(
            {x["operation"]: x["state"] for x in reports}, {"up": "failed", "down": "passed"}
        )
        self.assertFalse(controls.status()["busy"])

    def test_browser_will_not_cancel_an_external_cli_operation(self):
        controls = Controls(self.lab)
        with self.lab.exclusive():
            self.assertTrue(controls.status()["external"])
            with self.assertRaises(LabError):
                controls.submit("stop")
        self.assertIsNone(controls.active)

    def test_browser_failure_has_safe_message_and_releases_lock(self):
        controls = Controls(self.lab)
        with patch.object(Lab, "demo", side_effect=RuntimeError("secret exception")):
            controls.submit("demo")
            controls.thread.join(3)
        report = read(self.lab.data / "latest.json")
        self.assertEqual(report["state"], "failed")
        self.assertNotIn("secret", json.dumps(report))
        self.assertNotIn("secret", controls.status()["message"])
        with self.lab.exclusive():
            pass

    def test_cancel_handles_child_exiting_before_termination_signal(self):
        self.lab.begin("demo")
        process = unittest.mock.Mock(pid=123)
        process.wait.side_effect = [0]
        self.lab.cancel.set()
        # Let the operation reach the launch before cancellation is noticed.
        with (
            patch.object(
                self.lab, "check_cancelled", side_effect=[None, LabError("Operation cancelled")]
            ),
            patch("agent_security_lab.cli.subprocess.Popen", return_value=process),
            patch("agent_security_lab.cli.os.killpg", side_effect=ProcessLookupError),
            self.assertRaisesRegex(LabError, "cancelled"),
        ):
            self.lab.run("Child already exited", ["fixture"])
        self.assertEqual(self.lab.report["steps"][0]["state"], "failed")
        self.assertEqual(self.lab.report["steps"][0]["exit_code"], -1)

    def test_browser_rejects_arbitrary_commands(self):
        controls = Controls(self.lab)
        for action in ("prepare", "reset-security", "rm -rf /", "up"):
            with self.subTest(action=action), self.assertRaises(LabError):
                controls.submit(action)
        self.assertFalse((self.lab.data / "latest.json").exists())

    def http_fixture(self):
        controls = Controls(self.lab)
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler(self.lab, controls))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(thread.join, 2)
        self.addCleanup(server.shutdown)
        return controls, server.server_port

    def request(self, port, method="POST", path="/api/control", body=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=4)
        try:
            connection.request(method, path, body=body, headers=headers or {})
            response = connection.getresponse()
            return response.status, response.getheaders(), response.read()
        finally:
            connection.close()

    def browser_headers(self, controls):
        return {
            "Host": "127.0.0.1:18879",
            "Origin": "http://127.0.0.1:18879",
            "X-Lab-Token": controls.token,
            "Content-Type": "application/json",
        }

    def test_http_requires_exact_host_origin_and_session_token(self):
        controls, port = self.http_fixture()
        headers = self.browser_headers(controls)
        cases = [
            {**headers, "Host": "evil.example:18879"},
            {**headers, "Origin": "https://evil.example"},
            {**headers, "Origin": "null"},
            {**headers, "X-Lab-Token": "stale-token"},
            {k: v for k, v in headers.items() if k != "Origin"},
            {**headers, "Sec-Fetch-Site": "cross-site"},
        ]
        with patch.object(controls, "submit") as submit:
            for invalid in cases:
                with self.subTest(headers=list(invalid)):
                    self.assertEqual(
                        self.request(port, body='{"action":"stop"}', headers=invalid)[0], 403
                    )
        submit.assert_not_called()

    def test_http_malformed_or_oversized_actions_never_execute(self):
        controls, port = self.http_fixture()
        headers = self.browser_headers(controls)
        with patch.object(controls, "submit") as submit:
            for body in (
                "not json",
                "[]",
                '{"action":"demo","path":"/tmp"}',
                '{"action":["stop"]}',
                '{"action":"prepare"}',
                "[" * 1000,
                '{"action":"stop"}' + " " * 1100,
            ):
                self.assertEqual(self.request(port, body=body, headers=headers)[0], 400)
            self.assertEqual(
                self.request(
                    port,
                    body='{"action":"stop"}',
                    headers={**headers, "Content-Type": "text/plain"},
                )[0],
                400,
            )
        submit.assert_not_called()

    def test_http_accepts_only_explicit_action_and_reports_busy(self):
        controls, port = self.http_fixture()
        headers = self.browser_headers(controls)
        with patch.object(controls, "submit") as submit:
            code, _, raw = self.request(port, body='{"action":"demo"}', headers=headers)
            self.assertEqual(code, 202)
            self.assertTrue(json.loads(raw)["accepted"])
            submit.assert_called_once_with("demo")
        with patch.object(
            controls, "submit", side_effect=LabError("Another lab operation is already running")
        ):
            self.assertEqual(self.request(port, body='{"action":"start"}', headers=headers)[0], 409)

    def test_service_api_requires_session_and_fixed_targets(self):
        controls, port = self.http_fixture()
        headers = self.browser_headers(controls)
        with (
            patch(
                "agent_security_lab.services.Services.logs", return_value={"entries": []}
            ) as logs,
            patch.object(controls, "submit") as submit,
        ):
            self.assertEqual(
                self.request(
                    port,
                    path="/api/service",
                    body='{"action":"logs","service":"fhir"}',
                    headers={**headers, "Origin": "https://example.org"},
                )[0],
                403,
            )
            self.assertEqual(
                self.request(
                    port,
                    path="/api/service",
                    body='{"action":"logs","service":"../../keys"}',
                    headers=headers,
                )[0],
                400,
            )
            code, _, body = self.request(
                port,
                path="/api/service",
                body='{"action":"logs","service":"fhir"}',
                headers=headers,
            )
            self.assertEqual(code, 200)
            self.assertEqual(json.loads(body), {"entries": []})
            logs.assert_called_once_with("fhir")
            self.assertEqual(
                self.request(
                    port,
                    path="/api/service",
                    body='{"action":"restart","service":"fhir"}',
                    headers=headers,
                )[0],
                202,
            )
            submit.assert_called_once_with("restart:fhir")

    def test_protected_restart_is_refused_before_any_operation(self):
        controls = Controls(self.lab)
        for key in ("postgres", "zitadel", "spire-server", "spire-agent"):
            with self.assertRaisesRegex(LabError, "identity state"):
                controls.submit("restart:" + key)
        self.assertIsNone(controls.active)

    def test_runtime_api_uses_same_host_boundary_and_is_read_only(self):
        _, port = self.http_fixture()
        value = {"checked_at": stamp(), "services": [], "projects": [], "workloads": []}
        with patch("agent_security_lab.runtime.Monitor.snapshot", return_value=value) as snapshot:
            code, _, body = self.request(
                port, method="GET", path="/api/runtime", headers={"Host": "localhost:18879"}
            )
            self.assertEqual(code, 200)
            self.assertEqual({k: json.loads(body)[k] for k in value}, value)
            self.assertEqual(
                self.request(
                    port, method="GET", path="/api/runtime", headers={"Host": "evil.example:18879"}
                )[0],
                403,
            )
            snapshot.assert_called_once()

    def test_history_and_diagnostic_are_read_only_and_host_bound(self):
        _, port = self.http_fixture()
        run_id = "20260101T000000Z-abcdef"
        write(
            self.lab.data / "runs" / run_id / "report.json",
            {"run_id": run_id, "operation": "demo", "state": "passed", "steps": []},
        )
        host = {"Host": "localhost:18879"}
        code, _, body = self.request(port, method="GET", path="/api/runs", headers=host)
        self.assertEqual(code, 200)
        self.assertEqual([r["run_id"] for r in json.loads(body)["runs"]], [run_id])
        status = {"runtimes": [], "ports": {}, "latest": None, "demo": None}
        with patch.object(Lab, "status", return_value=status):
            code, headers, body = self.request(
                port, method="GET", path="/api/diagnostic", headers=host
            )
        self.assertEqual(code, 200)
        self.assertIn("attachment", dict(headers)["Content-Disposition"])
        self.assertEqual(json.loads(body)["kind"], "agent-security-lab-diagnostic")
        for path in ("/api/runs", "/api/diagnostic"):
            foreign = {"Host": "evil.example:18879"}
            self.assertEqual(self.request(port, method="GET", path=path, headers=foreign)[0], 403)
        self.assertFalse((self.lab.data / "latest.json").exists())

    def test_http_does_not_serve_logs_or_allow_foreign_hosts(self):
        controls, port = self.http_fixture()
        code, headers, raw = self.request(
            port, method="GET", path="/api/session", headers={"Host": "localhost:18879"}
        )
        self.assertEqual(code, 200)
        self.assertEqual(json.loads(raw)["token"], controls.token)
        self.assertNotIn("Access-Control-Allow-Origin", dict(headers))
        self.assertEqual(dict(headers)["Cache-Control"], "no-store")
        for path in ("/.data/latest.json", "/../lab.lock.json", "/api/command"):
            self.assertEqual(
                self.request(port, method="GET", path=path, headers={"Host": "localhost:18879"})[0],
                404,
            )
        self.assertEqual(self.request(port, method="GET", path="/api/session")[0], 403)


if __name__ == "__main__":
    unittest.main()
