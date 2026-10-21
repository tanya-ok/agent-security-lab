# SPDX-FileCopyrightText: 2026 Tanya Babitskaya
# SPDX-License-Identifier: Apache-2.0
"""Local publication candidate checks. A passing scan never authorizes a push."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ".publication.json"
PRIVATE_LABELS = {"local", "private", "security", "personal"}
FIELDS = {"id", "title", "status", "priority", "issue_type", "labels"}
PUBLIC_TEXT = {".md", ".html", ".json", ".jsonl", ".svg", ".mmd", ".txt"}
PATTERNS = (
    re.compile(rb"/(?:Users|home)/[^/\s]+/"),
    re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(rb"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    re.compile(rb"\bop://[^\s]+"),
    re.compile(rb"\bPRIVATE-REVIEW-ONLY\b"),
)


class BoundaryError(ValueError):
    """Fixed diagnostic without source contents."""


def git(*args, root=ROOT):
    return subprocess.check_output(["git", *args], cwd=root, timeout=30)


def safe_path(name):
    path = PurePosixPath(name)
    return (
        not path.is_absolute()
        and ".." not in path.parts
        and not set(path.parts) & {".data", ".dolt", ".git", "node_modules", "site"}
        and not name.endswith((".db", ".log", ".patch", ".bundle", ".pem", ".pat", ".key"))
        and path.name != "AGENTS.local.md"
        and (".beads" not in path.parts or name in {".beads/config.yaml", ".beads/issues.jsonl"})
    )


def snapshot(root=ROOT, staged=False, ref=None):
    if ref or staged:
        args = ["ls-tree", "-r", "-z", ref] if ref else ["ls-files", "--stage", "-z"]
        entries = git(*args, root=root).split(b"\0")
        names = []
        for entry in filter(None, entries):
            metadata, name = entry.split(b"\t", 1)
            if metadata.split()[0] not in {b"100644", b"100755"}:
                raise BoundaryError("Unsupported file mode in publication candidate")
            names.append(name)
    else:
        names = git(
            "ls-files", "--cached", "--others", "--exclude-standard", "-z", root=root
        ).split(b"\0")
    result = {}
    for raw in names:
        if not raw:
            continue
        name = raw.decode("utf-8")
        if not safe_path(name):
            raise BoundaryError("Private or unsupported path in publication candidate")
        if ref or staged:
            spec = (ref or "") + ":" + name
            result[name] = git("show", spec, root=root)
        elif (root / name).is_symlink():
            raise BoundaryError("Symlink in publication candidate")
        elif (root / name).exists():
            if (root / name).is_symlink():
                raise BoundaryError("Symlink in publication candidate")
            result[name] = (root / name).read_bytes()
    return result


def check_text(name, data):
    if Path(name).suffix in PUBLIC_TEXT and any(p.search(data) for p in PATTERNS):
        raise BoundaryError("Private content marker in publication candidate")


def public_issues(records, approved):
    result = []
    seen = set()
    for record in records:
        labels = {str(x).lower() for x in record.get("labels", [])}
        identifier = record.get("id")
        if "public" not in labels or labels & PRIVATE_LABELS or identifier not in approved:
            continue
        if identifier in seen or record.get("title") != approved[identifier]:
            raise BoundaryError("Public issue selection needs explicit title review")
        seen.add(identifier)
        row = {k: record[k] for k in FIELDS - {"labels"}}
        row["labels"] = ["public"]
        if (
            row["status"] not in {"open", "in_progress", "blocked", "deferred", "closed"}
            or row["issue_type"] not in {"task", "bug", "feature", "epic", "chore", "decision"}
            or type(row["priority"]) is not int
            or not 0 <= row["priority"] <= 4
        ):
            raise BoundaryError("Invalid public issue metadata")
        check_text("issues.jsonl", json.dumps(row).encode())
        result.append(row)
    return sorted(result, key=lambda row: row["id"])


def check(files):
    manifest = json.loads(files[MANIFEST])
    if manifest.get("schema") != 1 or manifest.get("publication_authorized") is not False:
        raise BoundaryError("Publication manifest is not a local candidate")
    actual = {n: hashlib.sha256(b).hexdigest() for n, b in files.items() if n != MANIFEST}
    listed = manifest["files"]
    if any(set(row) != {"path", "sha256"} for row in listed):
        raise BoundaryError("Unexpected manifest fields")
    expected = {row["path"]: row["sha256"] for row in listed}
    if len(expected) != len(listed) or actual != expected:
        raise BoundaryError("Candidate contents changed; review the manifest locally")
    for name, data in files.items():
        check_text(name, data)
    rows = [json.loads(line) for line in files[".beads/issues.jsonl"].splitlines() if line]
    if any(set(row) != FIELDS or row.get("labels") != ["public"] for row in rows):
        raise BoundaryError("Nonpublic issue data in public projection")
    if rows != public_issues(rows, manifest["public_issues"]):
        raise BoundaryError("Public issue projection differs from the reviewed selection")


def secret_scan(files, history=False):
    private = ROOT / ".data/private-review"
    private.mkdir(mode=0o700, parents=True, exist_ok=True)
    report = private / "secret-scan.json"
    options = [
        "--redact",
        "--no-banner",
        "--log-level",
        "error",
        "--ignore-gitleaks-allow",
        "--report-format",
        "json",
        "--report-path",
        str(report),
    ]
    with tempfile.TemporaryDirectory(prefix="candidate-", dir=private) as temporary:
        for name, data in files.items():
            target = Path(temporary) / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        commands = [["gitleaks", "dir", temporary, *options]]
        if history:
            commands.append(["gitleaks", "git", str(ROOT), "--log-opts=HEAD", *options])
        for command in commands:
            result = subprocess.run(
                command,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=120,
                check=False,
            )
            if report.exists():
                report.chmod(0o600)
            if result.returncode:
                raise BoundaryError("Local secret scan requires private review")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--staged", action="store_true")
    parser.add_argument("--secrets", action="store_true")
    parser.add_argument("--history", action="store_true")
    parser.add_argument("--site", type=Path)
    parser.add_argument("--refresh", action="store_true")
    parser.add_argument("--export", type=Path, dest="export_input")
    args = parser.parse_args()
    try:
        if args.export_input:
            manifest = json.loads((ROOT / MANIFEST).read_text(encoding="utf-8"))
            records = [
                json.loads(s) for s in args.export_input.read_text(encoding="utf-8").splitlines()
            ]
            rows = public_issues(records, manifest["public_issues"])
            (ROOT / ".beads/issues.jsonl").write_text(
                "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8"
            )
        elif args.refresh:
            files = snapshot()
            manifest = json.loads(files[MANIFEST])
            manifest["files"] = [
                {"path": n, "sha256": hashlib.sha256(b).hexdigest()}
                for n, b in sorted(files.items())
                if n != MANIFEST
            ]
            (ROOT / MANIFEST).write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        else:
            files = snapshot(staged=args.staged)
            check(files)
            if args.secrets:
                secret_scan(files, history=args.history)
            if args.history:
                for ref in git("rev-list", "HEAD").decode().splitlines():
                    check(snapshot(ref=ref))
            if args.site:
                for path in args.site.rglob("*"):
                    if path.is_symlink():
                        raise BoundaryError("Symlink in documentation output")
                    if path.is_file():
                        check_text(path.name, path.read_bytes())
            print("Publication candidate boundary passed; owner approval is still required")
    except (
        BoundaryError,
        OSError,
        ValueError,
        KeyError,
        TypeError,
        subprocess.SubprocessError,
        UnicodeError,
        RecursionError,
    ):
        print("Publication boundary blocked; inspect the candidate privately", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
