# SPDX-License-Identifier: Apache-2.0
"""Health observations must be bounded, truthful and free of private payloads."""

import json
import ssl
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from agent_security_lab.cli import PROJECTS, LabError
from agent_security_lab.runtime import (
    ENDPOINTS,
    Monitor,
    access_diagnostics,
    image_versions,
    probe,
    source_info,
    summarize_pods,
    workload_health,
)


def pod(name="backend", ready=True, image="registry.example/app@sha256:" + "a" * 64):
    return {
        "metadata": {"name": "synthetic-pod", "namespace": "it-grc", "secret": "private"},
        "spec": {"containers": [{"name": name, "image": "declared:latest", "env": ["private"]}]},
        "status": {
            "phase": "Running",
            "conditions": [{"type": "Ready", "status": "True" if ready else "False"}],
            "containerStatuses": [
                {"name": name, "ready": ready, "imageID": image, "restartCount": 2}
            ],
        },
    }


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.lab = Mock()
        self.lab.data = Path(self.temp.name)
        self.lab.workspace = self.lab.data
        self.lab.repo.side_effect = lambda name: self.lab.data / name
        self.lab.pins = {"projects": {name: {"commit": "a" * 40} for name in PROJECTS}}
        self.lab.env.return_value = {"LIMA_HOME": str(self.lab.data / "owned-lima")}
        self.lab.inventory.return_value = [{"name": "it-grc", "status": "Stopped"}]

    def test_offline_interfaces_with_ready_workloads_offer_reconnect(self):
        workloads = [{"name": "security-lab", "vm_state": "Running", "state": "ready"}]
        for states in (("stopped", "stopped", "stopped"), ("stopped", "healthy", "healthy")):
            services = [
                {"key": key, "state": state}
                for key, state in zip(("viewer", "identity", "login"), states, strict=True)
            ]
            result = access_diagnostics(services, workloads)
            self.assertEqual(result[0]["code"], "local-access-offline")

    def test_reconnect_is_not_suggested_for_workload_or_policy_failures(self):
        stopped = [{"key": key, "state": "stopped"} for key in ("viewer", "identity", "login")]
        for vm in (
            {"name": "security-lab", "vm_state": "Stopped", "state": "stopped"},
            {"name": "security-lab", "vm_state": "Running", "state": "degraded"},
            {"name": "security-lab", "vm_state": "Running", "state": "unknown"},
        ):
            self.assertEqual(access_diagnostics(stopped, [vm]), [])
        ready = [{"name": "security-lab", "vm_state": "Running", "state": "ready"}]
        for state in ("degraded", "unknown"):
            services = [dict(item) for item in stopped]
            services[1]["state"] = state
            self.assertEqual(access_diagnostics(services, ready), [])
        self.assertEqual(access_diagnostics([], ready), [])
        self.assertEqual(access_diagnostics(stopped, []), [])

    def test_healthy_interfaces_have_no_reconnect_notice(self):
        services = [
            {"key": "viewer", "state": "reachable"},
            {"key": "identity", "state": "healthy"},
            {"key": "login", "state": "healthy"},
        ]
        self.assertEqual(
            access_diagnostics(
                services, [{"name": "security-lab", "vm_state": "Running", "state": "ready"}]
            ),
            [],
        )

    def test_credential_expiry_blocks_misleading_proxy_reconnect_guidance(self):
        workloads = [{"name": "security-lab", "vm_state": "Running", "state": "ready"}]
        services = [{"key": key, "state": "stopped"} for key in ("viewer", "identity", "login")]
        for state in ("expired", "unknown", "stopped"):
            self.assertEqual(access_diagnostics(services, workloads, {"state": state}), [])
        for state in ("current", "expiring"):
            self.assertEqual(
                access_diagnostics(services, workloads, {"state": state})[0]["code"],
                "local-access-offline",
            )

    def test_credentials_are_refreshed_with_health_and_cache_expiry(self):
        monitor = Monitor(self.lab)
        with (
            patch("agent_security_lab.runtime.image_versions", return_value={}),
            patch("agent_security_lab.runtime.source_info", return_value={}),
            patch("agent_security_lab.runtime.probe", return_value={}),
            patch("agent_security_lab.runtime.workload_health", return_value={}),
            patch(
                "agent_security_lab.runtime.credential_health", return_value={"state": "expiring"}
            ) as credentials,
        ):
            self.assertEqual(monitor.snapshot()["credentials"]["state"], "expiring")
            monitor.snapshot()
            self.assertEqual(credentials.call_count, 1)
            credentials.return_value = {"state": "expired"}
            monitor.expires = 0
            self.assertEqual(monitor.snapshot()["credentials"]["state"], "expired")
            self.assertEqual(credentials.call_count, 2)

    def test_source_version_requires_snapshot_verification(self):
        with patch(
            "agent_security_lab.runtime.pinned_text", return_value='{"version":"0.4.0"}'
        ) as source:
            result = source_info(self.lab, "hipaa-fhir-mcp")
            self.assertEqual(result["version"], "0.4.0")
            self.lab.verify.side_effect = LabError("Source snapshot changed")
            result = source_info(self.lab, "hipaa-fhir-mcp")
            self.assertEqual(result["integrity"], "unverified")
            self.assertIsNone(result["version"])
            self.assertEqual(source.call_count, 1)

    def test_library_and_experiment_are_not_daemon_health(self):
        with patch("agent_security_lab.runtime.pinned_text", return_value='{"version":"0.1.0"}'):
            self.assertEqual(source_info(self.lab, "mcp-spiffe-bridge")["kind"], "library")
            self.assertEqual(source_info(self.lab, "ai-assurance")["kind"], "experiment")

    def test_version_mapping_requires_exact_repository_and_digest(self):
        digest = "sha256:" + "a" * 64

        def source(lab, name, path):
            if path.endswith(".yaml"):
                return "image: registry.example/spire:1.2.3@" + digest
            if path.endswith(".json"):
                return '{"images":{}}'
            return 'IMAGE="registry.example/idp:v4" "@' + digest + '"'

        with patch("agent_security_lab.runtime.pinned_text", side_effect=source):
            versions = image_versions(self.lab)
        self.assertEqual(versions["registry.example/spire@" + digest], "1.2.3")
        self.assertNotIn("registry.example/other@" + digest, versions)
        self.assertNotIn("registry.example/spire:1.2.3", versions)
        raw = {"items": [pod(image="registry.example/spire:1.2.3")]}
        self.assertIsNone(summarize_pods(raw, "it-grc", versions)[0]["version"])

    def test_pod_readiness_and_public_field_allowlist(self):
        item = pod()
        rows = summarize_pods({"items": [item]}, "it-grc", {})
        self.assertTrue(rows[0]["ready"])
        self.assertNotIn("private", json.dumps(rows))
        self.assertNotIn("declared:latest", json.dumps(rows))
        item["metadata"]["deletionTimestamp"] = "now"
        self.assertFalse(summarize_pods({"items": [item]}, "it-grc", {})[0]["ready"])
        item["metadata"]["namespace"] = "another-project"
        self.assertEqual(summarize_pods({"items": [item]}, "it-grc", {}), [])

    def test_missing_container_status_never_passes(self):
        item = pod()
        item["status"]["containerStatuses"] = []
        row = summarize_pods({"items": [item]}, "it-grc", {})[0]
        self.assertFalse(row["ready"])
        self.assertIsNone(row["image"])

    def test_stopped_vm_is_not_queried(self):
        with patch("agent_security_lab.runtime.subprocess.run") as command:
            self.assertEqual(workload_health(self.lab, "it-grc", "Stopped", {})["state"], "stopped")
        command.assert_not_called()

    def test_missing_expected_workload_is_degraded_and_uses_owned_env(self):
        result = subprocess.CompletedProcess(
            [], 0, json.dumps({"items": [pod()]}), "private stderr"
        )
        with patch("agent_security_lab.runtime.subprocess.run", return_value=result) as command:
            value = workload_health(self.lab, "it-grc", "Running", {})
        self.assertEqual(value["state"], "degraded")
        self.assertIn("frontend", value["missing_containers"])
        self.assertEqual(command.call_args.kwargs["env"], self.lab.env.return_value)
        self.assertEqual(command.call_args.args[0][:3], ["limactl", "shell", "it-grc"])
        self.assertNotIn("private", json.dumps(value))

    def test_kubernetes_timeout_and_malformed_results_are_unknown(self):
        for result in (
            subprocess.TimeoutExpired("private", 8),
            subprocess.CompletedProcess([], 0, "not json", "private"),
        ):
            kwargs = (
                {"side_effect": result}
                if isinstance(result, Exception)
                else {"return_value": result}
            )
            with patch("agent_security_lab.runtime.subprocess.run", **kwargs):
                value = workload_health(self.lab, "it-grc", "Running", {})
            self.assertEqual(value["state"], "unknown")
            self.assertNotIn("private", json.dumps(value))

    def check_response(self, key, status=200, body=b'{"status":"ok"}'):
        response = Mock(status=status)
        response.read.return_value = body
        connection = Mock()
        connection.getresponse.return_value = response
        endpoint = next(x for x in ENDPOINTS if x[0] == key)
        with (
            patch("agent_security_lab.runtime.listening", return_value=True),
            patch("agent_security_lab.runtime.ssl.create_default_context"),
            patch("agent_security_lab.runtime.http.client.HTTPConnection", return_value=connection),
            patch(
                "agent_security_lab.runtime.http.client.HTTPSConnection", return_value=connection
            ),
        ):
            return probe(self.lab, endpoint), connection

    def test_port_open_is_not_sufficient_for_health(self):
        for body in (
            b'{"status":"degraded"}',
            b'{"status":{}}',
            b"[" * 1100,
            b"[]",
            b"not json",
            b"x" * 65537,
        ):
            result, _ = self.check_response("dashboard", body=body)
            self.assertNotEqual(result["state"], "healthy")
        result, connection = self.check_response("dashboard", status=302)
        self.assertEqual(result["state"], "degraded")
        connection.request.assert_called_once()

    def test_health_response_secrets_are_not_returned(self):
        result, _ = self.check_response("grc", body=b'{"status":"ok","token":"private"}')
        self.assertEqual(result["state"], "healthy")
        self.assertNotIn("private", json.dumps(result))

    def test_discovery_issuer_is_checked_and_viewer_is_only_reachable(self):
        good, _ = self.check_response("identity", body=b'{"issuer":"http://localhost:4467"}')
        bad, _ = self.check_response("identity", body=b'{"issuer":"https://example.org"}')
        viewer, _ = self.check_response("viewer", status=302)
        self.assertEqual(good["state"], "healthy")
        self.assertEqual(bad["state"], "unknown")
        self.assertEqual(viewer["state"], "reachable")

    def test_tls_failure_is_not_bypassed(self):
        endpoint = next(x for x in ENDPOINTS if x[0] == "grc")
        with (
            patch("agent_security_lab.runtime.listening", return_value=True),
            patch(
                "agent_security_lab.runtime.ssl.create_default_context",
                side_effect=ssl.SSLError("private"),
            ) as tls,
            patch("agent_security_lab.runtime.http.client.HTTPConnection") as plain,
        ):
            result = probe(self.lab, endpoint)
        self.assertEqual(result["state"], "unknown")
        plain.assert_not_called()
        self.assertEqual(
            tls.call_args.kwargs["cafile"], str(self.lab.repo("it-grc") / "deploy/.data/ca.pem")
        )
        self.assertNotIn("private", json.dumps(result))

    def test_foreign_dashboard_listener_is_not_healthy(self):
        self.lab.service_alive.return_value = False
        result, _ = self.check_response("dashboard")
        self.assertEqual(result["state"], "unknown")

    def test_cache_expiry_rechecks_instead_of_reusing_healthy_results(self):
        monitor = Monitor(self.lab)
        with (
            patch("agent_security_lab.runtime.image_versions", return_value={}),
            patch("agent_security_lab.runtime.source_info", return_value={}),
            patch("agent_security_lab.runtime.probe", return_value={"state": "healthy"}) as check,
            patch("agent_security_lab.runtime.workload_health", return_value={}),
        ):
            first = monitor.snapshot()
            self.assertIs(monitor.snapshot(), first)
            self.assertEqual(check.call_count, len(ENDPOINTS))
            monitor.expires = 0
            check.return_value = {"state": "unknown"}
            new = monitor.snapshot()
            self.assertEqual(new["services"][0]["state"], "unknown")
            self.assertEqual(check.call_count, 2 * len(ENDPOINTS))


if __name__ == "__main__":
    unittest.main()
