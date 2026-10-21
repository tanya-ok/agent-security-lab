# SPDX-License-Identifier: Apache-2.0
"""Synthetic identity fixtures must preserve the owner and refuse ambiguous state."""

import importlib.util
import json
import sys
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from agent_security_lab.acceptance import owner_snapshot, validate_access, validate_checks
from agent_security_lab.cli import LabError

spec = importlib.util.spec_from_file_location(
    "identity_acceptance", Path(__file__).resolve().parents[1] / "tools/identity_acceptance.py"
)
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


class AcceptanceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.current = None
        self.calls = []
        self.k = SimpleNamespace(apply=Mock(), checked=lambda value: value, kube=self.kube)
        self.original_apply = self.k.apply
        self.identity = SimpleNamespace(
            ISOLATED=True,
            API_BACKEND="http://127.0.0.1:14567",
            NAMESPACE=fixture.TEST_NAMESPACE,
            PROFILE=self.root / "profile.json",
            ACCOUNTS=self.root / "accounts.json",
        )
        self.identity.up = Mock(side_effect=self.up)
        self.ui = SimpleNamespace(start=Mock(), stop=Mock(), PORT=4566)
        self.suites = [SimpleNamespace(run=Mock()), SimpleNamespace(run=Mock())]

    def kube(self, args, **kwargs):
        self.calls.append((args, kwargs))
        if args[0] == "get":
            return json.dumps(self.current) if self.current else ""
        if args[0] == "create":
            if self.current:
                raise RuntimeError("Already exists")
            self.current = json.loads(kwargs["input_text"])
            self.current["metadata"].update(uid="fixture-uid", resourceVersion="1")
            return json.dumps(self.current)
        if args[0] == "delete":
            self.assertEqual(
                json.loads(kwargs["input_text"])["preconditions"],
                {
                    "uid": "fixture-uid",
                    "resourceVersion": "1",
                },
            )
            self.current = None
        return ""

    def up(self):
        self.k.apply(
            [
                {
                    "kind": "Namespace",
                    "metadata": {
                        "name": fixture.TEST_NAMESPACE,
                        "labels": {"app.kubernetes.io/part-of": "security-lab"},
                    },
                }
            ]
        )
        self.identity.PROFILE.write_text("synthetic", encoding="utf-8")
        self.identity.ACCOUNTS.write_text("synthetic", encoding="utf-8")

    def test_both_real_suites_run_and_only_the_created_fixture_is_deleted(self):
        fixture.exercise(self.k, self.identity, self.ui, self.suites)
        for suite in self.suites:
            suite.run.assert_called_once()
        self.assertIsNone(self.current)
        self.assertIs(self.k.apply, self.original_apply)
        self.assertFalse(self.identity.PROFILE.exists())
        self.assertTrue(all("security-lab-identity" not in str(args) for args, _ in self.calls))

    def test_default_profile_is_refused_before_any_runtime_call(self):
        self.identity.ISOLATED = False
        with self.assertRaises(fixture.FixtureError):
            fixture.exercise(self.k, self.identity, self.ui, self.suites)
        self.assertEqual(self.calls, [])

    def test_existing_profile_is_not_removed(self):
        self.identity.PROFILE.write_text("keep", encoding="utf-8")
        with self.assertRaises(fixture.FixtureError):
            fixture.exercise(self.k, self.identity, self.ui, self.suites)
        self.assertEqual(self.identity.PROFILE.read_text(), "keep")
        self.assertEqual(self.calls, [])

    def test_preexisting_namespace_is_not_reused_or_deleted(self):
        self.current = {"metadata": {"uid": "foreign"}}
        with self.assertRaises(fixture.FixtureError):
            fixture.exercise(self.k, self.identity, self.ui, self.suites)
        self.assertFalse(any(args[0] != "get" for args, _ in self.calls))
        self.identity.up.assert_not_called()

    def test_suite_failure_cleans_own_fixture_and_remains_failed(self):
        self.suites[0].run.side_effect = RuntimeError("Synthetic failure")
        with self.assertRaises(RuntimeError):
            fixture.exercise(self.k, self.identity, self.ui, self.suites)
        self.suites[1].run.assert_not_called()
        self.assertIsNone(self.current)
        self.assertIs(self.k.apply, self.original_apply)

    def test_partial_creation_failure_cleans_only_its_created_namespace(self):
        def failed():
            self.up()
            raise RuntimeError("Synthetic startup failure")

        self.identity.up.side_effect = failed
        with self.assertRaises(RuntimeError):
            fixture.exercise(self.k, self.identity, self.ui, self.suites)
        self.assertIsNone(self.current)
        self.ui.start.assert_not_called()

    def test_replaced_namespace_is_not_deleted(self):
        self.suites[0].run.side_effect = lambda: self.current["metadata"].update(uid="replacement")
        with self.assertRaises(fixture.FixtureError):
            fixture.exercise(self.k, self.identity, self.ui, self.suites)
        self.assertFalse(any(args[0] == "delete" for args, _ in self.calls))
        self.assertIs(self.k.apply, self.original_apply)

    def test_disappeared_namespace_cannot_be_reported_as_clean_success(self):
        self.suites[0].run.side_effect = lambda: setattr(self, "current", None)
        with self.assertRaises(ValueError):
            fixture.exercise(self.k, self.identity, self.ui, self.suites)
        self.assertIs(self.k.apply, self.original_apply)
        self.assertFalse(any(args[0] == "delete" for args, _ in self.calls))
        self.ui.stop.assert_not_called()

    def test_foreign_namespace_request_is_refused_without_creation(self):
        self.identity.up.side_effect = lambda: self.k.apply(
            [
                {"kind": "Namespace", "metadata": {"name": "security-lab-identity"}},
            ]
        )
        with self.assertRaises(fixture.FixtureError):
            fixture.exercise(self.k, self.identity, self.ui, self.suites)
        self.assertFalse(any(args[0] == "create" for args, _ in self.calls))

    def test_owner_document_is_refused_even_when_the_profile_is_isolated(self):
        def write():
            self.up()
            self.k.apply([{"kind": "Secret", "metadata": {"namespace": "security-lab-identity"}}])

        self.identity.up.side_effect = write
        with self.assertRaises(fixture.FixtureError):
            fixture.exercise(self.k, self.identity, self.ui, self.suites)
        self.original_apply.assert_not_called()
        self.assertIsNone(self.current)

    def test_default_api_endpoint_is_refused_before_runtime_access(self):
        self.identity.API_BACKEND = "http://127.0.0.1:14467"
        with self.assertRaises(fixture.FixtureError):
            fixture.exercise(self.k, self.identity, self.ui, self.suites)
        self.assertEqual(self.calls, [])

    def test_creation_conflict_does_not_delete_the_competing_namespace(self):
        def compete():
            self.current = {"metadata": {"uid": "foreign"}}
            self.up()

        self.identity.up.side_effect = compete
        with self.assertRaises(RuntimeError):
            fixture.exercise(self.k, self.identity, self.ui, self.suites)
        self.assertFalse(any(args[0] == "delete" for args, _ in self.calls))
        self.assertIs(self.k.apply, self.original_apply)

    def test_reports_require_all_unique_checks_and_fresh_aware_timestamp(self):
        start = datetime.now(UTC) - timedelta(seconds=1)
        good = {"checked_at": datetime.now(UTC).isoformat(), "passed": ["first", "second"]}
        self.assertIs(validate_checks(good, 2, start.isoformat()), good)
        for change in (
            {"passed": ["same", "same"]},
            {"passed": ["missing"]},
            {"checked_at": (start - timedelta(seconds=1)).isoformat()},
            {"checked_at": (start + timedelta(days=1)).isoformat()},
            {"checked_at": datetime.now().isoformat()},
        ):
            with self.subTest(change=change), self.assertRaises(LabError):
                validate_checks({**good, **change}, 2, start.isoformat())

    def test_final_access_gate_rejects_unavailable_or_unknown_components(self):
        good = {
            "services": [
                {"key": name, "state": state}
                for name, state in {
                    "viewer": "reachable",
                    "identity": "healthy",
                    "login": "healthy",
                    "grc": "healthy",
                    "dashboard": "healthy",
                }.items()
            ],
            "workloads": [{"name": name, "state": "ready"} for name in ("security-lab", "it-grc")],
            "projects": [{"integrity": "verified"} for _ in range(6)],
            "credentials": {"state": "expiring"},
        }
        validate_access(good)
        for group, index, field, value in (
            ("services", 0, "state", "stopped"),
            ("services", 1, "state", "unknown"),
            ("workloads", 0, "state", "degraded"),
            ("projects", 0, "integrity", "unverified"),
        ):
            broken = json.loads(json.dumps(good))
            broken[group][index][field] = value
            with self.subTest(group=group, index=index), self.assertRaises(LabError):
                validate_access(broken)
        for value in ("unknown", "expired"):
            with self.assertRaises(LabError):
                validate_access({**good, "credentials": {"state": value}})
        with self.assertRaises(LabError):
            validate_access({**good, "services": good["services"][:-1]})

    def test_owner_snapshot_is_read_only_and_returns_no_credential_values(self):
        profile = self.root / "deploy/.data/human-auth.json"
        profile.parent.mkdir(parents=True)
        profile.write_text("private owner configuration", encoding="utf-8")
        lab = Mock()
        lab.repo.return_value = self.root
        services = Mock()
        services.target.return_value = {"namespace": "security-lab-identity"}
        services.controller.return_value = ("deployment", {"metadata": {"uid": "owner-db"}})
        services.query.return_value = json.dumps({"count": 1, "digest": "a" * 64}).encode()
        with patch("agent_security_lab.acceptance.Services", return_value=services):
            result = owner_snapshot(lab)
            self.assertNotIn("private owner configuration", json.dumps(result))
            sql = services.query.call_args.args[-1]
            self.assertIn("BEGIN READ ONLY", sql)
            self.assertNotIn("SELECT *", sql)
            services.query.return_value = json.dumps({"count": 0, "digest": "a" * 64}).encode()
            self.assertEqual(owner_snapshot(lab)["methods"]["count"], 0)
            services.query.return_value = b'{"count":0,"digest":"unknown"}'
            with self.assertRaises(LabError):
                owner_snapshot(lab)
