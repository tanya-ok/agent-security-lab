# SPDX-License-Identifier: Apache-2.0
"""Expiration warnings must use real metadata and never export credentials or reset state."""

import json
import subprocess
import unittest
from datetime import UTC, datetime, timedelta
from unittest.mock import Mock, patch

from agent_security_lab.cli import LabError
from agent_security_lab.credentials import EXPIRY_SQL, credential_health, lifetime_records

NOW = datetime(2026, 10, 18, 9, tzinfo=UTC)


def records(hours=48):
    return [
        {
            "id": key,
            "subject_count": 1,
            "token_count": 1,
            "created_at": (NOW - timedelta(minutes=5)).isoformat(),
            "expires_at": (NOW + timedelta(hours=hours)).isoformat(),
            "secret": "private-token",
        }
        for key in ("bootstrap", "login")
    ]


class CredentialTests(unittest.TestCase):
    def test_warning_boundary_and_expiration_are_based_on_timestamps(self):
        for hours, expected in (
            (48, "current"),
            (24, "expiring"),
            (1, "expiring"),
            (0, "expired"),
            (-0.01, "expired"),
        ):
            with self.subTest(hours=hours):
                values = lifetime_records(records(hours), NOW)
                self.assertEqual({item["state"] for item in values}, {expected})
                self.assertNotIn("private-token", json.dumps(values))
        # The same unmodified record transitions as time advances; no file mtime is used.
        values = records(48)
        self.assertEqual(
            lifetime_records(values, NOW + timedelta(hours=25))[0]["state"], "expiring"
        )
        self.assertEqual(lifetime_records(values, NOW + timedelta(hours=48))[0]["state"], "expired")

    def test_offset_dates_are_normalized_without_changing_the_instant(self):
        values = records()
        values[0]["expires_at"] = "2026-10-20T11:00:00+02:00"
        self.assertEqual(
            lifetime_records(values, NOW)[0]["expires_at"], "2026-10-20T09:00:00+00:00"
        )

    def test_missing_ambiguous_or_invalid_metadata_never_reports_current(self):
        cases = [
            None,
            {},
            [],
            records()[:1],
            [records()[0]] * 2,
            [{"id": "foreign"}],
            [{"id": []}, records()[1]],
        ]
        for key, value in (
            ("subject_count", 2),
            ("token_count", 0),
            ("token_count", 2),
            ("token_count", True),
            ("expires_at", None),
            ("expires_at", "private-token"),
            ("expires_at", 42),
            ("expires_at", "2026-10-20T09:00:00"),
            ("expires_at", "2026-10-17T09:00:00Z"),
            ("created_at", "2026-10-19T09:00:00Z"),
        ):
            data = records()
            for row in data:
                row[key] = value
            cases.append(data)
        for data in cases:
            with self.subTest(data=data):
                result = lifetime_records(data, NOW)
                self.assertEqual({item["state"] for item in result}, {"unknown"})
                self.assertTrue(all(item["expires_at"] is None for item in result))
                self.assertNotIn("private-token", json.dumps(result))

    def check_metadata(self, raw):
        lab = Mock()
        with patch("agent_security_lab.credentials.Services") as service_class:
            service = service_class.return_value
            service.target.return_value = {"namespace": "security-lab-identity"}
            service.query.return_value = raw
            result = credential_health(lab, "Running")
        return lab, service, result

    def test_only_owned_pinned_database_is_queried_in_read_only_transaction(self):
        data = records()
        for row in data:
            row["expires_at"] = "2090-10-20T09:00:00Z"
            row["created_at"] = "2020-10-18T09:00:00Z"
        lab, service, result = self.check_metadata(json.dumps(data).encode())
        self.assertEqual(result["state"], "current")
        lab.verify.assert_called_once_with("mcp-svid-auth")
        service.controller.assert_called_once_with({"namespace": "security-lab-identity"})
        args = service.query.call_args.args
        self.assertIn("deployment/identity-postgres", args)
        self.assertIn("BEGIN READ ONLY", args[-1])
        self.assertIn("statement_timeout", args[-1])
        self.assertNotIn("secret", EXPIRY_SQL)
        for value in ("personal_access_tokens3", "users14_machines"):
            self.assertIn(value, EXPIRY_SQL)
        self.assertNotIn("private-token", json.dumps(result))
        lab.make.assert_not_called()
        lab.run.assert_not_called()

    def test_unknown_or_stopped_vm_never_executes_a_query(self):
        for state, expected in (("Stopped", "stopped"), ("Unknown", "unknown")):
            with patch("agent_security_lab.credentials.Services") as service:
                result = credential_health(Mock(), state)
            self.assertEqual(result["state"], expected)
            service.assert_not_called()

    def test_source_or_namespace_failure_stops_before_database_read(self):
        lab = Mock()
        for source_failure in (True, False):
            lab.verify.side_effect = LabError("private failure") if source_failure else None
            with patch("agent_security_lab.credentials.Services") as service:
                service.return_value.controller.side_effect = LabError("private namespace")
                result = credential_health(lab, "Running")
                service.return_value.query.assert_not_called()
            self.assertEqual(result["state"], "unknown")
            self.assertNotIn("private", json.dumps(result))

    def test_query_errors_and_private_payloads_do_not_reach_the_api(self):
        for error in (
            LabError("private"),
            subprocess.TimeoutExpired("private", 8),
            UnicodeError("private"),
            RecursionError("private"),
        ):
            with patch("agent_security_lab.credentials.Services") as service:
                service.return_value.query.side_effect = error
                result = credential_health(Mock(), "Running")
            self.assertEqual(result["state"], "unknown")
            self.assertNotIn("private", json.dumps(result))
        for raw in (b"private", b"\xff", b"x" * 4097, b"[" * 1100):
            _, _, result = self.check_metadata(raw)
            self.assertEqual(result["state"], "unknown")
            self.assertNotIn("private", json.dumps(result))

    def test_partial_observation_cannot_hide_an_expired_credential(self):
        data = records()
        data[0]["created_at"] = "2020-10-18T09:00:00Z"
        data[0]["expires_at"] = "2020-10-19T09:00:00Z"
        data[1]["token_count"] = 2
        _, _, result = self.check_metadata(json.dumps(data).encode())
        self.assertEqual(result["state"], "expired")
        self.assertEqual(result["items"][1]["state"], "unknown")


if __name__ == "__main__":
    unittest.main()
