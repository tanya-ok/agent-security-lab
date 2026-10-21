# SPDX-License-Identifier: Apache-2.0
"""Public candidates must never inherit raw private issue content."""

import hashlib
import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location(
    "publication", Path(__file__).resolve().parents[1] / "tools/publication.py"
)
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)


class PublicationTests(unittest.TestCase):
    def row(self, labels):
        return {
            "id": "example-1",
            "title": "Public feature",
            "status": "open",
            "priority": 2,
            "issue_type": "feature",
            "labels": labels,
            "description": "private description",
            "notes": "private notes",
            "owner": "private actor",
            "dependencies": [{"id": "private-reference"}],
        }

    def test_private_default_and_veto_win_over_public(self):
        for labels in (
            [],
            ["Public", "SECURITY"],
            ["public", "local"],
            ["public", "personal"],
            ["public", "private"],
        ):
            self.assertEqual(
                p.public_issues([self.row(labels)], {"example-1": "Public feature"}), []
            )

    def test_export_is_flat_minimal_and_explicitly_selected(self):
        rows = p.public_issues([self.row(["public"])], {"example-1": "Public feature"})
        self.assertEqual(set(rows[0]), p.FIELDS)
        self.assertNotIn("private", json.dumps(rows))
        self.assertEqual(p.public_issues([self.row(["public"])], {}), [])

    def test_title_change_duplicate_and_bad_metadata_fail_closed(self):
        for change in ({"title": "Changed"}, {"priority": True}, {"status": "unknown"}):
            with self.subTest(change=change), self.assertRaises(p.BoundaryError):
                p.public_issues(
                    [{**self.row(["public"]), **change}], {"example-1": "Public feature"}
                )
        with self.assertRaises(p.BoundaryError):
            p.public_issues([self.row(["public"])] * 2, {"example-1": "Public feature"})

    def files(self):
        files = {"README.md": b"Safe overview", ".beads/issues.jsonl": b""}
        manifest = {
            "schema": 1,
            "publication_authorized": False,
            "public_issues": {},
            "files": [
                {"path": n, "sha256": hashlib.sha256(b).hexdigest()} for n, b in files.items()
            ],
        }
        return {**files, p.MANIFEST: json.dumps(manifest).encode()}

    def test_unlisted_file_or_changed_bytes_are_blocked(self):
        files = self.files()
        p.check(files)
        for candidate in (
            {**files, "docs/new.md": b"unreviewed"},
            {**files, "README.md": b"changed"},
        ):
            with self.assertRaises(p.BoundaryError):
                p.check(candidate)

    def test_private_paths_and_content_are_blocked_without_echoing_values(self):
        for name in (".data/report.json", ".beads/private.db", "AGENTS.local.md", "../secret"):
            self.assertFalse(p.safe_path(name))
        for value in (
            b"/Users/synthetic/private/",
            b"PRIVATE-REVIEW-ONLY",
            b"-----BEGIN PRIVATE KEY-----",
        ):
            with self.assertRaisesRegex(p.BoundaryError, "^Private content marker"):
                p.check_text("index.html", value)

    def test_raw_beads_fields_are_refused_even_with_matching_hash(self):
        files = self.files()
        files[".beads/issues.jsonl"] = json.dumps(self.row(["public"])).encode()
        manifest = json.loads(files[p.MANIFEST])
        next(row for row in manifest["files"] if row["path"] == ".beads/issues.jsonl")["sha256"] = (
            hashlib.sha256(files[".beads/issues.jsonl"]).hexdigest()
        )
        files[p.MANIFEST] = json.dumps(manifest).encode()
        with self.assertRaises(p.BoundaryError):
            p.check(files)

    def test_secret_scanner_failure_is_blocking_and_output_is_private(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(p, "ROOT", Path(temporary)):
            with patch.object(p.subprocess, "run", return_value=Mock(returncode=1)) as run:
                with self.assertRaises(p.BoundaryError):
                    p.secret_scan({"README.md": b"synthetic"})
            self.assertEqual(run.call_args.kwargs["stdout"], subprocess.DEVNULL)
            self.assertEqual(run.call_args.kwargs["stderr"], subprocess.DEVNULL)
            self.assertIn("--ignore-gitleaks-allow", run.call_args.args[0])
            self.assertFalse(list((Path(temporary) / ".data/private-review").glob("candidate-*")))

    def test_history_scanner_targets_head_without_private_backup_refs(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(p, "ROOT", Path(temporary)):
            with patch.object(p.subprocess, "run", return_value=Mock(returncode=0)) as run:
                p.secret_scan({"README.md": b"synthetic"}, history=True)
            self.assertEqual(len(run.call_args_list), 2)
            self.assertIn("--log-opts=HEAD", run.call_args.args[0])
            self.assertNotIn("--all", run.call_args.args[0])

    def test_staged_snapshot_does_not_scan_a_cleaner_worktree(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            subprocess.run(["git", "init", "-q", temporary], check=True)
            (root / "README.md").write_text("PRIVATE-REVIEW-ONLY", encoding="utf-8")
            subprocess.run(["git", "add", "README.md"], cwd=root, check=True)
            (root / "README.md").write_text("cleaner working file", encoding="utf-8")
            self.assertEqual(p.snapshot(root, staged=True)["README.md"], b"PRIVATE-REVIEW-ONLY")

    def test_symlink_is_refused_in_worktree_and_index(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            subprocess.run(["git", "init", "-q", temporary], check=True)
            (root / "link.md").symlink_to("missing-private-file")
            subprocess.run(["git", "add", "link.md"], cwd=root, check=True)
            for staged in (True, False):
                with self.assertRaises(p.BoundaryError):
                    p.snapshot(root, staged=staged)
