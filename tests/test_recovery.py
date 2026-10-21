# SPDX-License-Identifier: Apache-2.0
"""Restart must preserve identity, reject ambiguous state and never leak tokens."""

import base64
import contextlib
import io
import json
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from agent_security_lab import recovery as r


def entries():
    parent = {"trust_domain": "example.org", "path": "/node/security-lab"}
    rows = [
        {
            "spiffe_id": parent,
            "parent_id": {"trust_domain": "example.org", "path": "/spire/server"},
            "selectors": [
                {"type": "k8s_psat", "value": value}
                for value in (
                    "agent_ns:spire-system",
                    "agent_sa:spire-agent",
                    "cluster:security-lab",
                )
            ],
        }
    ]
    for name, account in (
        ("authz", "authz"),
        ("mcp/notes-a", "notes-a"),
        ("mcp/notes-b", "notes-b"),
        ("agent/research", "agent-research"),
        ("agent/intruder", "agent-intruder"),
        ("agent/intruder", "agent-impostor"),
        ("mcp/fhir", "fhir"),
    ):
        rows.append(
            {
                "spiffe_id": {"trust_domain": "example.org", "path": "/" + name},
                "parent_id": parent,
                "jwt_svid_ttl": 60,
                "additional_attributes": {"jwt_svid_include_jti": True},
                "selectors": [
                    {"type": "k8s", "value": "ns:security-lab"},
                    {"type": "k8s", "value": "sa:" + account},
                ],
            }
        )
    return rows


BUNDLE = "-----BEGIN CERTIFICATE-----\nnew-public-bundle\n-----END CERTIFICATE-----"


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.rows = entries()
        self.config_bundle = BUNDLE
        self.foreign = False
        self.k = Mock()
        self.k.checked.side_effect = lambda value: value
        self.k.kube.side_effect = self.kube
        self.k.server.side_effect = lambda args: (
            json.dumps({"entries": self.rows}) if args[0] == "entry" else BUNDLE
        )
        self.k.register.side_effect = lambda: setattr(self, "rows", entries())
        self.k.configmap.return_value = {"metadata": {}}
        self.identity = Mock()
        self.identity.NAMESPACE = "security-lab-identity"
        self.identity.PROFILE = Mock()
        self.identity.settings.return_value = SimpleNamespace(org_id="test-org")
        self.identity.connection.side_effect = contextlib.nullcontext
        self.k.owned_namespace.return_value = True

    def kube(self, args, **kwargs):
        if args[0] != "get":
            return "ready"
        value = {
            "metadata": {
                "uid": args[2],
                "resourceVersion": "1",
                "labels": {
                    "app.kubernetes.io/part-of": "foreign" if self.foreign else "security-lab"
                },
            }
        }
        if args[1] == "configmap":
            value["data"] = {"bundle.pem": self.config_bundle}
        if args[1] == "secret":
            value["data"] = {"token": base64.b64encode(b"private-fixture-token").decode()}
        return json.dumps(value)

    def test_healthy_state_is_read_only(self):
        self.assertFalse(r.recover_workloads(self.k))
        self.k.register.assert_not_called()
        self.k.apply.assert_not_called()

    def test_known_empty_memory_restores_only_fixed_registration_and_agent(self):
        self.rows = []
        self.config_bundle = "old public bundle"
        self.assertTrue(r.recover_workloads(self.k))
        self.k.register.assert_called_once_with()
        self.k.apply.assert_called_once()
        value = self.k.apply.call_args.args[0][0]
        self.assertEqual(value["metadata"], {"uid": "spire-bundle", "resourceVersion": "1"})
        mutations = [
            call.args[0] for call in self.k.kube.call_args_list if call.args[0][0] != "get"
        ]
        self.assertEqual(mutations[0], ["rollout", "restart", "daemonset/spire-agent"])
        self.assertFalse(any("delete" in command for command in mutations))

    def test_partial_foreign_or_weakened_registrations_fail_without_mutation(self):
        variants = [entries()[:-1], entries(), entries(), entries()]
        variants[1][1]["spiffe_id"]["trust_domain"] = "other.example.org"
        variants[2][1]["jwt_svid_ttl"] = 600
        variants[3][1]["admin"] = True
        for rows in variants:
            with self.subTest(rows=rows):
                self.rows = rows
                with self.assertRaises(r.RecoveryError):
                    r.recover_workloads(self.k)
        self.k.register.assert_not_called()
        self.k.apply.assert_not_called()

    def test_ambiguous_empty_registry_is_not_recreated(self):
        self.rows = []
        with self.assertRaises(r.RecoveryError):
            r.recover_workloads(self.k)
        self.k.register.assert_not_called()

    def test_existing_entries_with_changed_bundle_are_not_overwritten(self):
        self.config_bundle = "different"
        with self.assertRaises(r.RecoveryError):
            r.recover_workloads(self.k)
        self.k.apply.assert_not_called()

    def test_foreign_ownership_stops_all_recovery(self):
        self.foreign = True
        with self.assertRaises(r.RecoveryError):
            r.recover_workloads(self.k)
        with self.assertRaises(r.RecoveryError):
            r.reuse_identity(self.k, self.identity)
        self.identity.Bootstrap.assert_not_called()
        self.k.register.assert_not_called()

    def test_existing_identity_uses_mounted_credential_for_read_only_policy_check(self):
        self.assertTrue(r.reuse_identity(self.k, self.identity))
        verifier = self.identity.Bootstrap.return_value
        verifier.verify_native_policy.assert_called_once_with("test-org")
        verifier.client.close.assert_called_once()
        self.identity.read_bootstrap.assert_not_called()
        self.identity.up.assert_not_called()
        self.identity.down.assert_not_called()

    def test_policy_or_credential_failure_has_no_bootstrap_or_reset_fallback(self):
        self.identity.Bootstrap.return_value.verify_native_policy.side_effect = ValueError("denied")
        with self.assertRaises(ValueError):
            r.reuse_identity(self.k, self.identity)
        self.identity.Bootstrap.return_value.client.close.assert_called_once()
        self.identity.up.assert_not_called()
        self.identity.down.assert_not_called()
        self.identity.read_bootstrap.assert_not_called()

    def test_missing_profile_or_namespace_does_not_reset_saved_identity(self):
        self.identity.settings.return_value = None
        with self.assertRaises(r.RecoveryError):
            r.reuse_identity(self.k, self.identity)
        self.k.owned_namespace.return_value = False
        self.identity.PROFILE.exists.return_value = True
        with self.assertRaises(r.RecoveryError):
            r.reuse_identity(self.k, self.identity)
        self.identity.PROFILE.exists.return_value = False
        self.assertFalse(r.reuse_identity(self.k, self.identity))
        self.identity.down.assert_not_called()

    def test_invalid_restore_is_not_applied(self):
        self.rows = []
        self.config_bundle = "old public bundle"
        self.k.register.side_effect = None
        with self.assertRaises(r.RecoveryError):
            r.recover_workloads(self.k)
        self.k.apply.assert_not_called()

    def test_namespace_change_after_restore_is_detected(self):
        self.rows = []
        self.config_bundle = "old public bundle"
        original = self.k.kube.side_effect

        def changed(args, **kwargs):
            result = original(args, **kwargs)
            if args[:2] == ["get", "namespace"] and self.k.apply.called:
                value = json.loads(result)
                value["metadata"]["uid"] = "replacement"
                return json.dumps(value)
            return result

        self.k.kube.side_effect = changed
        with self.assertRaisesRegex(r.RecoveryError, "namespace changed"):
            r.recover_workloads(self.k)

    def test_unreadable_public_registry_and_private_bundle_stop_before_writes(self):
        for invalid in ("not json", json.dumps({}), "PRIVATE KEY"):
            with self.subTest(invalid=invalid):
                self.k.server.side_effect = lambda args, result=invalid: result
                with self.assertRaises((ValueError, r.RecoveryError)):
                    r.recover_workloads(self.k)
        self.k.register.assert_not_called()
        self.k.apply.assert_not_called()
        self.k.server.side_effect = lambda args: (
            json.dumps({"entries": entries()}) if args[0] == "entry" else "PRIVATE KEY"
        )
        with self.assertRaises(r.RecoveryError):
            r.recover_workloads(self.k)
        self.k.register.assert_not_called()

    def test_failed_identity_check_stops_launcher_before_workload_changes(self):
        from agent_security_lab.cli import Lab

        lab = Mock()
        present = Mock()
        present.read_text.return_value = "PRESENT"
        lab.run.return_value = present
        lab.restart_check.side_effect = r.RecoveryError("unsafe identity")
        with self.assertRaises(r.RecoveryError):
            Lab.up(lab)
        lab.restart_check.assert_called_once_with("identity")
        self.assertEqual(lab.make.call_count, 1)
        self.assertEqual(lab.make.call_args.args, ("mcp-svid-auth", "runtime-up"))

    def test_warm_start_reconnects_the_verified_profile_without_provisioning(self):
        from agent_security_lab.cli import Lab

        lab = Mock()
        lab.root = Path("/synthetic")
        lab.data = Path("/synthetic/.data")
        lab.verify.return_value = Path("/synthetic/source")
        lab.repo.return_value = Path("/synthetic/source")
        lab.run.return_value.read_text.return_value = "PRESENT"
        lab.restart_check.side_effect = ["REUSE", "UNCHANGED"]
        Lab.up(lab)
        actions = [call.args[:2] for call in lab.make.call_args_list]
        self.assertLess(
            actions.index(("mcp-svid-auth", "ui-stop")), actions.index(("mcp-svid-auth", "ui"))
        )
        self.assertNotIn(("mcp-svid-auth", "ui-login"), actions)

    def test_terminal_failure_redacts_underlying_errors(self):
        scripts = SimpleNamespace(kubernetes_demo=self.k, zitadel_demo=self.identity)
        self.k.verify_instance.side_effect = ValueError("private-fixture-token")
        output = io.StringIO()
        with patch.dict(sys.modules, {"scripts": scripts}), contextlib.redirect_stderr(output):
            with self.assertRaises(SystemExit):
                r.main()
        self.assertNotIn("private-fixture-token", output.getvalue())
        self.assertIn("without resetting", output.getvalue())


if __name__ == "__main__":
    unittest.main()
