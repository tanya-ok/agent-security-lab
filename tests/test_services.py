# SPDX-License-Identifier: Apache-2.0
"""Service actions must preserve ownership, state and log privacy."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from agent_security_lab.cli import LabError
from agent_security_lab.services import PROTECTED, Services, project_logs


def controller():
    return {
        "metadata": {
            "name": "fhir",
            "uid": "original-id",
            "resourceVersion": "42",
            "labels": {"app.kubernetes.io/part-of": "security-lab"},
        },
        "spec": {"template": {"metadata": {}, "spec": {"containers": [{"name": "fhir"}]}}},
    }


class ServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.lab = Mock()
        self.lab.data = Path(self.temp.name)
        self.lab.restart_check.return_value = "REUSE"
        self.services = Services(self.lab)

    def test_logs_project_only_safe_signals_never_arbitrary_content(self):
        secrets = [
            "token-example",
            "user@example.org",
            "Patient/123",
            "eyJhbGciOiJFUzI1NiJ9.private.signature",
            "-----BEGIN PRIVATE KEY-----",
            "api_key=abc123",
        ]
        raw = (
            "2026-10-15T11:00:00Z ERROR connection refused "
            + " ".join(secrets)
            + "\nINFO "
            + " ".join(secrets)
        )
        result = project_logs(raw)
        self.assertEqual(result["entries"][0]["summary"], "Connection failed")
        self.assertEqual(result["hidden_lines"], 1)
        unknown = project_logs("ERROR private custom detail")
        self.assertEqual(unknown["entries"][0]["summary"], "Application reported an error")
        self.assertNotIn("private", json.dumps(unknown))
        for secret in secrets:
            self.assertNotIn(secret, json.dumps(result))

    def test_log_sample_is_bounded_and_controls_are_not_reproduced(self):
        result = project_logs(("INFO server started \x1b[31m private\n") * 200)
        self.assertLessEqual(result["sampled_lines"], 100)
        self.assertNotIn("private", json.dumps(result))
        self.assertNotIn("\u001b", json.dumps(result))
        self.assertEqual(project_logs("unstructured private detail")["entries"], [])

    def test_stateful_services_are_protected_before_commands(self):
        for key in PROTECTED:
            with self.assertRaises(LabError):
                self.services.restart(key)
        self.lab.run.assert_not_called()

    def test_unrecognized_ids_and_paths_are_refused(self):
        for key in ("../../keys", "--all", "other-service", None, []):
            with self.assertRaises(LabError):
                Services.target(key)

    def test_foreign_namespace_refuses_logs_and_restart(self):
        self.services.query = Mock(return_value=b'{"metadata":{"labels":{}}}')
        with self.assertRaisesRegex(LabError, "namespace ownership"):
            self.services.logs("fhir")
        with self.assertRaisesRegex(LabError, "namespace ownership"):
            self.services.restart("fhir")
        self.lab.run.assert_not_called()

    def test_foreign_controller_refuses_mutation(self):
        obj = controller()
        obj["metadata"]["labels"] = {}
        self.services.query = Mock(
            side_effect=[
                b'{"metadata":{"labels":{"app.kubernetes.io/part-of":"security-lab"}}}',
                json.dumps(obj).encode(),
            ]
        )
        with self.assertRaisesRegex(LabError, "controller ownership"):
            self.services.restart("fhir")
        self.lab.run.assert_not_called()

    def test_restart_uses_uid_and_revision_preconditions_then_waits(self):
        obj = controller()
        obj["spec"]["template"]["metadata"]["annotations"] = {"private": "not copied"}
        self.services.controller = Mock(return_value=("deployment", obj))
        self.services.restart("fhir")
        calls = self.lab.run.call_args_list
        args = calls[0].args[1]
        patch_value = json.loads(args[args.index("-p") + 1])
        self.assertEqual(
            patch_value[0], {"op": "test", "path": "/metadata/uid", "value": "original-id"}
        )
        self.assertEqual(patch_value[1]["path"], "/metadata/resourceVersion")
        self.assertNotIn("not copied", json.dumps(patch_value))
        self.assertIn("rollout", calls[1].args[1])
        self.assertIn("deployment/fhir", calls[1].args[1])
        self.assertEqual(args[:3], ["limactl", "shell", "security-lab"])

    def test_restarting_pod_bound_login_reconnects_its_forwarders(self):
        obj = controller()
        obj["metadata"]["name"] = "zitadel-login"
        self.services.controller = Mock(return_value=("deployment", obj))
        self.services.restart("zitadel-login")
        self.assertEqual([call.args[1] for call in self.lab.make.call_args_list], ["ui-stop", "ui"])

    def test_viewer_reconnect_reuses_identity_without_provisioning(self):
        self.services.controller = Mock(return_value=("deployment", controller()))
        self.services.restart("viewer")
        self.lab.restart_check.assert_called_once_with("identity")
        self.assertEqual([call.args[1] for call in self.lab.make.call_args_list], ["ui-stop", "ui"])

    def test_viewer_reconnect_refuses_missing_or_invalid_identity(self):
        self.services.controller = Mock(return_value=("deployment", controller()))
        for state in ("NEW", "UNKNOWN", None):
            self.lab.restart_check.return_value = state
            with self.subTest(state=state), self.assertRaises(LabError):
                self.services.restart("viewer")
        self.lab.make.assert_not_called()
        self.lab.run.assert_not_called()

    def test_tls_restart_reconnects_only_owned_forward_after_successful_rollout(self):
        self.services.controller = Mock(return_value=("deployment", controller()))
        self.services.restart("grc-tls")
        calls = self.lab.run.call_args_list
        self.assertEqual(len(calls), 3)
        self.assertIn("rollout", calls[1].args[1])
        self.assertEqual(
            calls[2].args[1],
            [
                "limactl",
                "shell",
                "it-grc",
                "sudo",
                "systemctl",
                "restart",
                "it-grc-https.service",
            ],
        )

    def test_failed_tls_rollout_does_not_reconnect_or_report_success(self):
        self.services.controller = Mock(return_value=("deployment", controller()))
        self.lab.run.side_effect = [None, LabError("Rollout failed")]
        with self.assertRaises(LabError):
            self.services.restart("grc-tls")
        self.assertEqual(self.lab.run.call_count, 2)

    def test_patch_failure_does_not_report_rollout_success(self):
        self.services.controller = Mock(return_value=("deployment", controller()))
        self.lab.run.side_effect = LabError("Restart failed")
        with self.assertRaises(LabError):
            self.services.restart("fhir")
        self.assertEqual(self.lab.run.call_count, 1)

    def test_dashboard_waits_for_port_release_before_start(self):
        self.lab.repo.return_value = self.lab.data
        events = []
        self.lab.stop_service.side_effect = lambda role: events.append("stop")
        self.lab.start_service.side_effect = lambda *args: events.append("start")
        with (
            patch("agent_security_lab.services.listening", side_effect=[True, False]),
            patch(
                "agent_security_lab.services.time.sleep",
                side_effect=lambda seconds: events.append("wait"),
            ),
        ):
            self.services.restart("dashboard")
        self.assertEqual(events, ["stop", "wait", "start"])

    def test_logs_use_fixed_controller_container_and_bounded_options(self):
        obj = controller()
        obj["metadata"]["name"] = "unexpected-resource-name"
        self.services.controller = Mock(return_value=("deployment", obj))
        self.services.query = Mock(return_value=b"INFO server started")
        result = self.services.logs("fhir")
        args = self.services.query.call_args.args
        self.assertIn("deployment/fhir", args)
        self.assertIn("--limit-bytes=32768", args)
        self.assertIn("--tail=100", args)
        self.assertIn("--since=15m", args)
        self.assertEqual(result["entries"][0]["summary"], "Service started or listening")

    def test_host_log_cannot_be_replaced_by_symlink(self):
        private = self.lab.data / "private"
        private.write_text("private data", encoding="utf-8")
        (self.lab.data / "dashboard.log").symlink_to(private)
        with self.assertRaisesRegex(LabError, "No retained"):
            self.services.logs("dashboard")

    def test_host_log_reads_only_bounded_safe_sample(self):
        (self.lab.data / "dashboard.log").write_text(
            "private data\n" * 10000 + "INFO server started\n", encoding="utf-8"
        )
        result = self.services.logs("dashboard")
        self.assertNotIn("private", json.dumps(result))
        self.assertLessEqual(result["sampled_lines"], 100)


if __name__ == "__main__":
    unittest.main()
