# SPDX-License-Identifier: Apache-2.0
"""Local console and SSO boundaries must refuse unrelated browser and API traffic."""

import json
import subprocess
import sys
import tempfile
import threading
import unittest
from http.client import HTTPConnection
from pathlib import Path
from unittest.mock import Mock, patch
from urllib.parse import urlencode

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from agent_security_lab.cli import Lab, LabError
from agent_security_lab.identity_access import GRC, ISSUER, route
from agent_security_lab.sso import POD_RELAY, allowed_request


class IdentityAccessTests(unittest.TestCase):
    def setUp(self):
        self.headers = {"host": "localhost:4467"}
        self.clients = {"grc": GRC + "/callback"}

    def call(self, path, method="GET", headers=None, query=""):
        return route(method, path, self.headers | (headers or {}), query, self.clients)

    def test_console_is_read_only_transport_and_management_needs_browser_token(self):
        self.assertEqual(self.call("/ui/console/"), "api")
        self.assertIsNone(self.call("/ui/console/", "POST"))
        path = "/zitadel.management.v1.ManagementService/ListUsers"
        good = {
            "origin": ISSUER,
            "authorization": "Bearer synthetic",
            "content-type": "application/grpc-web+proto",
        }
        self.assertEqual(self.call(path, "POST", good), "api")
        for field in good:
            headers = {k: v for k, v in good.items() if k != field}
            self.assertIsNone(self.call(path, "POST", headers))
        self.assertIsNone(self.call(path, "POST", good | {"origin": GRC}))
        self.assertIsNone(self.call("/debug/metrics"))
        self.assertIsNone(self.call("/management/v1/orgs/me", "POST", good))

    def test_host_origin_and_encoded_path_boundaries(self):
        for path in [
            "/ui/console/../",
            "/ui/console/%2e%2e/",
            "/ui/console/%252e%252e/",
            "/ui/console/\\private",
            "/ui/console//asset",
        ]:
            self.assertIsNone(self.call(path))
        for headers in [{"host": "evil.example"}, {"origin": "https://evil.example"}]:
            self.assertIsNone(self.call("/ui/console/", headers=headers))

    def test_cross_scheme_sso_navigation_is_bound_to_exact_client_and_callback(self):
        headers = {"sec-fetch-site": "cross-site", "sec-fetch-mode": "navigate"}
        query = urlencode({"client_id": "grc", "redirect_uri": self.clients["grc"]})
        self.assertEqual(self.call("/oauth/v2/authorize", headers=headers, query=query), "api")
        for bad in [
            query + "&client_id=other",
            query.replace("grc", "other", 1),
            urlencode({"client_id": "grc", "redirect_uri": GRC + "/wrong"}),
        ]:
            self.assertIsNone(self.call("/oauth/v2/authorize", headers=headers, query=bad))
        self.assertIsNone(self.call("/oauth/v2/token", "POST", headers))
        self.assertIsNone(
            self.call(
                "/oauth/v2/authorize", headers=headers | {"sec-fetch-mode": "cors"}, query=query
            )
        )

    def test_login_posts_need_issuer_origin_and_token_exchange_can_be_server_side(self):
        self.assertIsNone(self.call("/ui/v2/login/action", "POST"))
        self.assertEqual(self.call("/ui/v2/login/action", "POST", {"origin": ISSUER}), "login")
        self.assertEqual(self.call("/oauth/v2/token", "POST"), "api")
        self.assertIsNone(self.call("/oauth/v2/token", "POST", {"authorization": "Basic x"}))

    def test_backchannel_excludes_console_admin_and_arbitrary_hosts(self):
        for path in ["/.well-known/openid-configuration", "/oauth/v2/keys", "/oidc/v1/userinfo"]:
            self.assertTrue(allowed_request("GET", path, "localhost:4467"))
            self.assertFalse(allowed_request("POST", path, "localhost:4467"))
        self.assertTrue(allowed_request("POST", "/oauth/v2/token", "localhost:4467"))
        for path in [
            "//evil.example/",
            "http://evil.example/",
            "/ui/console/",
            "/oauth/v2/authorize",
            "/management/v1/orgs/me",
            "/oauth/v2/keys#x",
        ]:
            self.assertFalse(allowed_request("GET", path, "localhost:4467"))
        self.assertFalse(allowed_request("GET", "/oauth/v2/keys", "evil.example"))

    def test_relay_restore_is_opt_in_and_waits_for_previous_listener(self):
        with tempfile.TemporaryDirectory() as directory:
            lab = Mock()
            lab.data = Path(directory)
            lab.root = Path("/synthetic")
            Lab.restore_sso(lab)
            lab.stop_service.assert_not_called()
            (lab.data / "identity-access.json").write_text("{}", encoding="utf-8")
            with (
                patch("agent_security_lab.cli.listening", side_effect=[True, False]),
                patch("agent_security_lab.cli.time.sleep"),
            ):
                Lab.restore_sso(lab)
            lab.stop_service.assert_called_once_with("sso-tunnel")
            self.assertEqual(lab.start_service.call_args.args[-1], 18881)
            lab.start_service.reset_mock()
            with (
                patch("agent_security_lab.cli.listening", return_value=True),
                patch("agent_security_lab.cli.time.monotonic", side_effect=[0, 20]),
                self.assertRaises(LabError),
            ):
                Lab.restore_sso(lab)
            lab.start_service.assert_not_called()

    def test_relay_heartbeat_loss_stops_an_orphaned_listener(self):
        code = (
            POD_RELAY.replace('("127.0.0.1",4467)', '("127.0.0.1",0)')
            .replace('emit({"ready":True})', 'emit({"ready":True,"port":server.server_address[1]})')
            .replace("time.monotonic()-heartbeat[0]>12", "time.monotonic()-heartbeat[0]>0.25")
        )
        process = subprocess.Popen(
            [sys.executable, "-u", "-c", code],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            self.assertTrue(json.loads(process.stdout.readline())["ready"])
            self.assertEqual(process.wait(timeout=3), 0)
            self.assertEqual(process.stderr.read(), "")
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            process.stdin.close()
            process.stdout.close()
            process.stderr.close()

    def test_relay_roundtrip_and_eof_cleanup_without_pod_or_disk_changes(self):
        code = POD_RELAY.replace('("127.0.0.1",4467)', '("127.0.0.1",0)').replace(
            'emit({"ready":True})', 'emit({"ready":True,"port":server.server_address[1]})'
        )
        process = subprocess.Popen(
            [sys.executable, "-u", "-c", code],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            ready = json.loads(process.stdout.readline())
            self.assertTrue(ready["ready"])
            observed = []

            def request():
                connection = HTTPConnection("127.0.0.1", ready["port"], timeout=3)
                try:
                    connection.request("GET", "/oauth/v2/keys", headers={"Host": "localhost:4467"})
                    response = connection.getresponse()
                    observed.append((response.status, response.read()))
                finally:
                    connection.close()

            thread = threading.Thread(target=request)
            thread.start()
            frame = json.loads(process.stdout.readline())
            self.assertEqual(frame["target"], "/oauth/v2/keys")
            process.stdin.write(
                json.dumps(
                    {
                        "id": frame["id"],
                        "status": 200,
                        "headers": {"Content-Type": "application/json"},
                        "body": "eyJrZXlzIjpbXX0=",
                    }
                )
                + "\n"
            )
            process.stdin.flush()
            thread.join(4)
            self.assertEqual(observed, [(200, b'{"keys":[]}')])
            process.stdin.close()
            self.assertEqual(process.wait(timeout=4), 0)
            self.assertEqual(process.stderr.read(), "")
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            process.stdout.close()
            process.stderr.close()


if __name__ == "__main__":
    unittest.main()
