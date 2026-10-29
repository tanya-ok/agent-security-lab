# SPDX-FileCopyrightText: 2026 Tanya Babitskaya
# SPDX-License-Identifier: Apache-2.0
"""Owned local demo orchestration. No cloud, publication or model API operations."""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import io
import json
import os
import re
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import uuid
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.request import ProxyHandler, build_opener

ROOT = Path(__file__).resolve().parents[2]
PROJECTS = (
    "mcp-svid-auth",
    "mcp-spiffe-bridge",
    "hipaa-fhir-mcp",
    "it-grc",
    "engineering-os",
    "ai-assurance",
)
PORTS = {
    "viewer": 4466,
    "identity": 4467,
    "login": 4468,
    "grc": 18443,
    "dashboard": 18766,
    "hub": 18879,
}


class LabError(ValueError):
    """Fixed public error messages; raw logs stay private."""


def stamp():
    return datetime.now(UTC).isoformat()


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=".lab-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2)
            stream.write("\n")
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def digest(path):
    if path.is_symlink():
        return "link:" + os.readlink(path)
    return hashlib.sha256(path.read_bytes()).hexdigest()


def tool_path():
    """Keep caller tool versions, adding stable paths absent in desktop sessions."""
    candidates = os.environ.get("PATH", "").split(os.pathsep) + [
        str(Path.home() / ".local/bin"),
        str(Path.home() / ".local/share/fnm/aliases/default/bin"),
        "/opt/homebrew/bin",
        "/usr/local/bin",
        "/usr/bin",
        "/bin",
        "/usr/sbin",
        "/sbin",
    ]
    return os.pathsep.join(dict.fromkeys(p for p in candidates if Path(p).is_absolute()))


def git(repo, *args):
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        env={**os.environ, "PATH": tool_path(), "GIT_NO_REPLACE_OBJECTS": "1"},
        check=False,
    )
    if result.returncode:
        raise LabError("A required local Git object is unavailable")
    return result.stdout


def fingerprint(pid):
    result = subprocess.run(
        ["ps", "-p", str(pid), "-o", "lstart=", "-o", "command="],
        capture_output=True,
        text=True,
        check=False,
    )
    return result.stdout.strip() if result.returncode == 0 else ""


def listening(port):
    with socket.socket() as connection:
        connection.settimeout(0.3)
        return connection.connect_ex(("127.0.0.1", port)) == 0


def local_json(url):
    with build_opener(ProxyHandler({})).open(url, timeout=5) as response:
        return json.load(response)


def validate_security_report(raw, started_at):
    results = raw.get("results", [])
    if (
        raw.get("passed") is not True
        or len(results) != 18
        or {x.get("scenario") for x in results if isinstance(x, dict)} != set(range(1, 19))
        or not all(isinstance(x, dict) and x.get("passed") is True for x in results)
    ):
        raise LabError("Fresh security report is incomplete")
    try:
        captured = datetime.fromisoformat(raw["timestamp"])
        started = datetime.fromisoformat(started_at)
        if captured.utcoffset() is None or not started <= captured <= datetime.now(UTC):
            raise LabError("Security evidence is stale or future-dated")
    except (ValueError, KeyError, TypeError):
        raise LabError("Security evidence is stale or future-dated") from None
    return raw


class Lab:
    def __init__(self, root=ROOT, workspace=None):
        self.root = root.resolve()
        self.data = self.root / ".data"
        self.workspace = (workspace or self.root.parent).resolve()
        self.pins = read(self.root / "lab.lock.json")
        if self.pins.get("schema") != 1 or set(self.pins.get("projects", {})) != set(PROJECTS):
            raise LabError("Unexpected project inventory")
        for name, pin in self.pins["projects"].items():
            if pin.get("local_source") != name or not re.fullmatch("[0-9a-f]{40}", pin["commit"]):
                raise LabError("Invalid project pin")
        self.run_dir = None
        self.report = None
        self.cancel = threading.Event()

    def owned(self):
        if self.data.is_symlink():
            raise LabError("Runtime directory must not be a symlink")
        self.data.mkdir(mode=0o700, exist_ok=True)
        self.data.chmod(0o700)
        marker = self.data / "owner.json"
        if marker.exists():
            if marker.is_symlink() or read(marker).get("root") != str(self.root):
                raise LabError("Runtime directory belongs to another launcher")
        else:
            if any(self.data.iterdir()):
                raise LabError("Unowned runtime directory is not empty")
            write(marker, {"root": str(self.root), "id": uuid.uuid4().hex})
        home = self.data / "lima"
        if home.is_symlink():
            raise LabError("Lima home must not be a symlink")
        home.mkdir(mode=0o700, exist_ok=True)
        return home

    @contextlib.contextmanager
    def exclusive(self):
        self.owned()
        with (self.data / "operation.lock").open("a", encoding="utf-8") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise LabError("Another lab operation is already running") from None
            yield

    def env(self):
        # No API keys, AWS profiles, proxy configuration or SSH agent is inherited.
        env = {
            key: os.environ[key]
            for key in ("PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "USER", "LOGNAME")
            if key in os.environ
        }
        env.update(
            PATH=tool_path(),
            LIMA_HOME=str(self.owned()),
            ONNXRUNTIME_NODE_INSTALL="skip",
            UV_CACHE_DIR=str(self.data / "uv-cache"),
            PYTHONUNBUFFERED="1",
            PLAYWRIGHT_SKIP_BROWSER_GC="1",
            LIMA_SHELLENV_BLOCK="*",
            LIMA_SHELLENV_ALLOW="",
        )
        return env

    def repo(self, name):
        return self.data / "checkouts" / name

    def verify(self, name):
        repo = self.repo(name)
        pin = self.pins["projects"][name]
        if repo.is_symlink():
            raise LabError("Source snapshot does not match its pin")
        # Trust the caller-selected Git commit, not mutable snapshot metadata.
        tree = git(self.workspace / name, "ls-tree", "-rz", pin["commit"])
        for entry in tree.split(b"\0"):
            if not entry:
                continue
            metadata, raw_path = entry.split(b"\t", 1)
            mode, kind, expected = metadata.split()
            relative = raw_path.decode("utf-8")
            path = repo / relative
            if kind != b"blob" or not path.parent.resolve().is_relative_to(repo.resolve()):
                raise LabError("Unexpected source object")
            if mode == b"120000":
                if not path.is_symlink() or not path.resolve().is_relative_to(repo.resolve()):
                    raise LabError("Source symlink escapes its snapshot")
                content = os.readlink(path).encode("utf-8")
            elif mode in {b"100644", b"100755"}:
                if path.is_symlink() or not path.is_file():
                    raise LabError("Source file is missing or replaced")
                content = path.read_bytes()
            else:
                raise LabError("Unsupported source file mode")
            actual = (
                hashlib.sha1(
                    b"blob " + str(len(content)).encode("ascii") + b"\0" + content,
                    usedforsecurity=False,
                )
                .hexdigest()
                .encode("ascii")
            )
            if actual != expected:
                raise LabError("Source snapshot changed; refusing execution")
        return repo

    def sync(self):
        self.owned()
        for name, pin in self.pins["projects"].items():
            target = self.repo(name)
            if target.exists():
                self.verify(name)
                print("Verified source:", name, pin["commit"][:7], flush=True)
                continue
            source = self.workspace / name
            if git(source, "cat-file", "-t", pin["commit"]).strip() != b"commit":
                raise LabError("Source pin is not a commit")
            archive = git(source, "archive", "--format=tar", pin["commit"])
            target.parent.mkdir(parents=True, exist_ok=True)
            with tempfile.TemporaryDirectory(dir=target.parent, prefix=".stage-") as temporary:
                stage = Path(temporary)
                with tarfile.open(fileobj=io.BytesIO(archive)) as bundle:
                    bundle.extractall(stage, filter="data")
                if (stage / ".ai-assurance").exists():
                    raise LabError("Historical assurance scaffold must not be materialized")
                files = {
                    str(p.relative_to(stage)): digest(p)
                    for p in stage.rglob("*")
                    if p.is_file() or p.is_symlink()
                }
                # Metadata is separate from source and cannot authorize extra commands.
                write(
                    self.data / "snapshots" / (name + ".json"),
                    {"commit": pin["commit"], "files": files},
                )
                stage.rename(target)
                stage.mkdir()  # TemporaryDirectory owns only its now-empty staging path.
            self.verify(name)
            print("Locked source:", name, pin["commit"][:7], flush=True)

    def begin(self, operation):
        self.owned()
        run_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:6]
        self.run_dir = self.data / "runs" / run_id
        self.run_dir.mkdir(parents=True, mode=0o700)
        self.report = {
            "schema": 1,
            "run_id": run_id,
            "operation": operation,
            "started_at": stamp(),
            "state": "running",
            "synthetic_data_only": True,
            "source_pins": self.pins["projects"],
            "steps": [],
            "limits": [
                "No real Google login or physical passkey enrollment",
                "No cloud deployment, model API calls or certification",
                "AI Assurance control experiment only; no profile installation",
                "Engineering OS uses fixture data; no private vault or RAG model",
            ],
        }
        self.save()

    def save(self):
        if self.report is not None:
            write(self.run_dir / "report.json", self.report)
            write(self.data / "latest.json", self.report)
            if self.report["operation"] == "demo":
                write(self.data / "demo-latest.json", self.report)

    def finish(self, passed):
        self.report.update(state="passed" if passed else "failed", finished_at=stamp())
        self.save()
        print("Report:", self.run_dir / "report.json", flush=True)

    def check_cancelled(self):
        if self.cancel.is_set():
            raise LabError("Operation cancelled")

    def run(self, name, args, repo=None, timeout=1800):
        self.check_cancelled()
        step = {"name": name, "started_at": stamp(), "state": "running"}
        self.report["steps"].append(step)
        self.save()
        log = self.run_dir / (str(len(self.report["steps"])).zfill(2) + ".log")
        print("Starting:", name, flush=True)
        started = time.monotonic()
        with log.open("w", encoding="utf-8") as output:
            log.chmod(0o600)
            try:
                process = subprocess.Popen(
                    args,
                    cwd=repo or self.root,
                    env=self.env(),
                    stdout=output,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                )
            except OSError:
                output.write("Process could not start\n")
                code = -2
            else:
                try:
                    while True:
                        remaining = timeout - (time.monotonic() - started)
                        if self.cancel.is_set() or remaining <= 0:
                            raise subprocess.TimeoutExpired(args, timeout)
                        try:
                            code = process.wait(timeout=min(0.25, remaining))
                            break
                        except subprocess.TimeoutExpired:
                            continue
                except (subprocess.TimeoutExpired, KeyboardInterrupt):
                    with contextlib.suppress(ProcessLookupError):
                        os.killpg(process.pid, signal.SIGTERM)
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        with contextlib.suppress(ProcessLookupError):
                            os.killpg(process.pid, signal.SIGKILL)
                        process.wait()
                    code = -1
        step.update(
            state="passed" if code == 0 else "failed",
            exit_code=code,
            finished_at=stamp(),
            duration_seconds=round(time.monotonic() - started, 2),
        )
        self.save()
        print(step["state"].upper() + ": " + name, flush=True)
        self.check_cancelled()
        if code:
            raise LabError("Demo step failed; inspect its private local log")
        return log

    def artifact(self, name, path):
        value = read(path)
        target = self.run_dir / "artifacts" / (name + ".json")
        write(target, value)
        self.report.setdefault("artifacts", {})[name] = {
            "path": str(target.relative_to(self.run_dir)),
            "sha256": digest(target),
        }
        self.save()
        return value

    def make(self, name, target, timeout=1800, extra=()):
        repo = self.verify(name)
        if (
            name == "mcp-svid-auth"
            and target == "ui"
            and (self.data / "identity-access.json").exists()
        ):
            return self.run(
                "Start owner-approved local identity access",
                [str(repo / ".venv/bin/python"), str(self.root / "tools/identity_ui.py"), "start"],
                repo,
                timeout,
            )
        return self.run(
            name + ": " + target,
            ["make", target, "PYTHON=" + sys.executable, *extra],
            repo,
            timeout,
        )

    def prepare(self):
        self.sync()
        self.run("Install locked WebAuthn browser helper", ["pnpm", "install", "--frozen-lockfile"])
        self.run(
            "Install pinned Chromium for synthetic WebAuthn",
            ["pnpm", "exec", "playwright", "install", "chromium"],
        )
        self.run(
            "Install locked Python lab dependencies",
            ["uv", "sync", "--locked"],
            self.verify("mcp-svid-auth"),
        )
        for name in ("mcp-spiffe-bridge", "hipaa-fhir-mcp"):
            repo = self.verify(name)
            self.run(name + ": frozen install", ["pnpm", "install", "--frozen-lockfile"], repo)
            self.run(name + ": build", ["pnpm", "build"], repo)
        repo = self.verify("engineering-os") / "dashboard"
        self.run("Engineering OS: frozen install", ["pnpm", "install", "--frozen-lockfile"], repo)
        self.run("Engineering OS: build dashboard", ["pnpm", "run", "build"], repo)

    def service_file(self, role):
        return self.data / "processes" / (role + ".json")

    def service_alive(self, role):
        path = self.service_file(role)
        if not path.exists():
            return False
        record = read(path)
        current = fingerprint(record["pid"])
        return bool(current and current == record["fingerprint"] and str(self.root) in current)

    def start_service(self, role, args, cwd, port):
        self.check_cancelled()
        if self.service_alive(role):
            return
        if listening(port):
            raise LabError("A required port belongs to another process")
        path = self.data / (role + ".log")
        with path.open("a", encoding="utf-8") as log:
            path.chmod(0o600)
            process = subprocess.Popen(
                args,
                cwd=cwd,
                env=self.env(),
                stdout=log,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        for _ in range(300 if role == "sso-tunnel" else 100):
            if process.poll() is not None:
                raise LabError("An owned service exited before readiness")
            if listening(port):
                write(
                    self.service_file(role),
                    {"pid": process.pid, "fingerprint": fingerprint(process.pid)},
                )
                return
            time.sleep(0.1)
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=5)
        raise LabError("An owned service did not become ready")

    def stop_service(self, role):
        if self.service_alive(role):
            record = read(self.service_file(role))
            if role == "sso-tunnel":
                # Give the supervisor time to close the remote exec stdin first.
                os.kill(record["pid"], signal.SIGTERM)
                deadline = time.monotonic() + 12
                while self.service_alive(role) and time.monotonic() < deadline:
                    time.sleep(0.1)
                if self.service_alive(role):
                    os.killpg(record["pid"], signal.SIGTERM)
            else:
                os.killpg(record["pid"], signal.SIGTERM)
        self.service_file(role).unlink(missing_ok=True)

    def inventory(self):
        home = self.data / "lima"
        if not home.exists():
            return []
        result = subprocess.run(
            ["limactl", "list", "--json"],
            capture_output=True,
            text=True,
            env=self.env(),
            timeout=15,
            check=False,
        )
        if result.returncode:
            raise LabError("Cannot inspect owned Lima runtime")
        return [
            {"name": x["name"], "status": x["status"]}
            for line in result.stdout.splitlines()
            if (x := json.loads(line))
        ]

    def restart_check(self, action):
        log = self.run(
            "Verify preserved " + action,
            [
                "uv",
                "run",
                "--locked",
                "python",
                str(self.root / "src/agent_security_lab/recovery.py"),
                action,
            ],
            self.verify("mcp-svid-auth"),
        )
        result = log.read_text(encoding="utf-8").strip()
        allowed = {"identity": {"REUSE", "NEW"}, "workloads": {"RESTORED", "UNCHANGED"}}
        if result not in allowed[action]:
            raise LabError("Unexpected restart verification result")
        return result

    def up(self):
        for name in PROJECTS:
            self.verify(name)
        self.make("mcp-svid-auth", "runtime-up")
        check = self.run(
            "Inspect owned security namespaces",
            [
                "uv",
                "run",
                "--locked",
                "python",
                "-c",
                "from scripts import kubernetes_demo as k; "
                "print('PRESENT' if all(k.owned_namespace(n) for n in "
                "('security-lab', 'spire-system')) else 'ABSENT')",
            ],
            self.repo("mcp-svid-auth"),
        )
        if check.read_text(encoding="utf-8").strip().endswith("ABSENT"):
            self.run(
                "Build and start shared security services",
                ["uv", "run", "--locked", "python", "-m", "scripts.kubernetes_demo", "up"],
                self.repo("mcp-svid-auth"),
            )
        # Validate identity before restoring any lost workload state. Never reset it.
        identity = self.restart_check("identity")
        if self.restart_check("workloads") == "RESTORED":
            from agent_security_lab.services import Services

            Services(self).restart("fhir")
        if identity == "REUSE":
            self.make("mcp-svid-auth", "ui-stop")
        self.make("mcp-svid-auth", "ui" if identity == "REUSE" else "ui-login")
        self.make("it-grc", "grc-up", timeout=2400)
        self.make("it-grc", "grc-admin")
        self.make("it-grc", "grc-bootstrap")
        self.restore_sso()
        repo = self.repo("engineering-os") / "dashboard"
        self.start_service(
            "dashboard",
            [
                "node",
                str(repo / "dist/cli.js"),
                "serve",
                "--fixture",
                "--port",
                str(PORTS["dashboard"]),
            ],
            repo,
            PORTS["dashboard"],
        )
        self.start_service(
            "hub", [sys.executable, str(self.root / "lab"), "_serve"], self.root, PORTS["hub"]
        )

    def demo(self):
        from agent_security_lab.services import Services

        self.up()
        # The pinned audit probe expects only this run's four FHIR records.
        # Roll out that stateless service without resetting the enrolled identity.
        Services(self).restart("fhir")
        self.run(
            "SPIRE, OAuth and FHIR: 18 real-stack scenarios",
            ["uv", "run", "--locked", "python", "-m", "scripts.run_demo"],
            self.verify("mcp-svid-auth"),
        )
        report_path = self.repo("mcp-svid-auth") / "deploy/.data/demo-report.json"
        raw = validate_security_report(read(report_path), self.report["started_at"])
        self.artifact("security", report_path)
        self.report["security_scenarios"] = len(raw["results"])
        self.identity_demos()
        self.package_demos()
        self.make("it-grc", "grc-verify")
        self.make("it-grc", "grc-bridge-check")
        # Always this run's generated report, never the project's retained fixture.
        self.make("it-grc", "grc-demo", extra=("REPORT=" + str(report_path),))
        repo = self.verify("ai-assurance")
        self.run(
            "AI Assurance: bounded synthetic control experiment",
            [
                sys.executable,
                "tools/control_experiment.py",
                "--json",
                str(self.run_dir / "ai-controls.json"),
                "--markdown",
                str(self.run_dir / "ai-controls.md"),
            ],
            repo,
        )
        health = local_json("http://127.0.0.1:18766/api/health")
        graph = local_json("http://127.0.0.1:18766/api/graph")
        if health.get("status") != "ok" or not graph.get("nodes"):
            raise LabError("Synthetic dashboard health/graph check failed")
        self.report["dashboard"] = {"fixture": True, "nodes": len(graph["nodes"])}
        self.report["grc_input_sha256"] = digest(report_path)
        self.verify_access()
        self.save()

    def verify_access(self):
        from agent_security_lab.acceptance import validate_access
        from agent_security_lab.runtime import Monitor

        observation = Monitor(self).snapshot()
        write(self.run_dir / "final-health.json", observation)
        validate_access(observation)
        self.report["local_access_verified"] = True
        self.save()

    def identity_demos(self):
        from agent_security_lab.acceptance import owner_snapshot, validate_checks

        self.run(
            "Ensure pinned synthetic browser",
            ["pnpm", "exec", "playwright", "install", "chromium"],
        )
        before = owner_snapshot(self)
        write(self.run_dir / "owner-before.json", before)
        try:
            self.run(
                "Synthetic identity acceptance",
                [
                    "uv",
                    "run",
                    "--locked",
                    "python",
                    str(self.root / "tools/identity_acceptance.py"),
                ],
                self.verify("mcp-svid-auth"),
            )
        finally:
            after = owner_snapshot(self)
            write(self.run_dir / "owner-after.json", after)
            self.report["owner_identity_preserved"] = before == after
            self.save()
            if before != after:
                raise LabError("Owner preservation check failed")
        folder = self.repo("mcp-svid-auth") / "deploy/.data/passkey"
        for name, filename, expected in (
            ("identity", "identity-demo-report.json", 11),
            ("google-setup", "google-setup-report.json", 4),
        ):
            validate_checks(read(folder / filename), expected, self.report["started_at"])
            self.artifact(name, folder / filename)
        self.report.update(
            identity_checks=11, google_setup_checks=4, synthetic_identity_profile="isolated"
        )
        self.save()

    def package_demos(self):
        # Consumers only exercise local tarballs; no package is published.
        base = self.data / "consumers"
        base.mkdir(exist_ok=True)
        for name in ("mcp-spiffe-bridge", "hipaa-fhir-mcp"):
            repo = self.verify(name)
            directory = Path(tempfile.mkdtemp(prefix=name + "-", dir=base))
            self.run(
                name + ": pack local artifact",
                ["npm", "pack", "--pack-destination", str(directory)],
                repo,
            )
            consumer = directory / "consumer"
            consumer.mkdir()
            write(consumer / "package.json", {"private": True, "type": "module"})
            packages = list(directory.glob("*.tgz"))
            if len(packages) != 1:
                raise LabError("Expected exactly one local package")
            self.run(
                name + ": install independent consumer",
                [
                    "npm",
                    "install",
                    "--prefix",
                    str(consumer),
                    "--ignore-scripts",
                    "--no-audit",
                    "--no-fund",
                    str(packages[0]),
                ],
            )
            command = (
                ["node", "scripts/verify-installed.mjs", str(consumer)]
                if name == "mcp-spiffe-bridge"
                else [
                    "node",
                    "scripts/demo-package.mjs",
                    str(consumer / "node_modules" / name / "dist/server.js"),
                ]
            )
            self.run(name + ": independent TLS/package demo", command, repo)

    def restore_sso(self):
        if not (self.data / "identity-access.json").exists():
            return
        self.stop_service("sso-tunnel")
        deadline = time.monotonic() + 12
        while listening(18881):
            self.check_cancelled()
            if time.monotonic() >= deadline:
                raise LabError("Previous local SSO relay did not stop")
            time.sleep(0.1)
        self.start_service(
            "sso-tunnel",
            [sys.executable, str(self.root / "tools/sso_tunnel.py")],
            self.root,
            18881,
        )

    def reset_identity(self):
        self.make("mcp-svid-auth", "ui-stop")
        self.make("mcp-svid-auth", "ui-login-down")

    def reset_security(self):
        self.make("mcp-svid-auth", "runtime-up")
        self.make("mcp-svid-auth", "down")

    def down(self, keep_hub=False):
        self.owned()
        self.stop_service("dashboard")
        self.stop_service("sso-tunnel")
        entries = {x["name"]: x["status"] for x in self.inventory()}
        if entries.get("security-lab") == "Running":
            self.make("mcp-svid-auth", "down")
            self.make("mcp-svid-auth", "runtime-stop")
        if entries.get("it-grc") == "Running":
            self.make("it-grc", "grc-stop")
        if not keep_hub:
            self.stop_service("hub")

    def status(self):
        return {
            "runtimes": self.inventory(),
            "demo": read(self.data / "demo-latest.json")
            if (self.data / "demo-latest.json").exists()
            else None,
            "ports": {name: listening(port) for name, port in PORTS.items()},
            "latest": read(self.data / "latest.json")
            if (self.data / "latest.json").exists()
            else None,
        }

    def doctor(self):
        for executable in ("git", "uv", "pnpm", "node", "npm", "make", "limactl", "openssl"):
            if shutil.which(executable) is None:
                raise LabError("A required local executable is missing")
        if shutil.disk_usage(self.root).free < 20 * 1024**3:
            raise LabError("At least 20 GiB free disk is required for the first full run")
        if len(str(self.data / "lima/security-lab/ha.sock")) >= 100:
            raise LabError("Checkout path is too long for Lima sockets")
        self.sync()
        print("Ready: six locked sources; owned Lima home; no source worktree changes")


class Controls:
    """A single browser operation, sharing the CLI lock and owned runner."""

    def __init__(self, lab):
        self.lab = lab
        self.token = secrets.token_urlsafe(32)
        self.lock = threading.Lock()
        self.active = None
        self.thread = None
        self.stopping = False
        self.message = "Ready. Start the stack or run all demos."

    def status(self):
        with self.lock:
            active = self.active is not None
            # A separate CLI operation also holds the same filesystem lock.
            external = False
            if not active:
                try:
                    with self.lab.exclusive():
                        pass
                except LabError:
                    external = True
            return {
                "busy": active or external,
                "external": external,
                "stopping": self.stopping,
                "message": "Another local operation is running" if external else self.message,
            }

    def submit(self, action):
        from .services import PROTECTED, Services

        restart = isinstance(action, str) and action.startswith("restart:")
        if restart:
            key = action.removeprefix("restart:")
            Services.target(key)
            if key in PROTECTED:
                raise LabError("Individual restart would discard temporary identity state")
        if not restart and action not in {"start", "demo", "stop"}:
            raise LabError("Unknown action")
        with self.lock:
            if self.active is not None:
                if action == "stop" and not self.stopping:
                    self.stopping = True
                    self.message = "Cancelling the current operation, then stopping the stack"
                    self.active.cancel.set()
                    return
                raise LabError("Another lab operation is already running")
            # Reserve the shared lock before acknowledging the request. No queue
            # and no window in which a second browser or CLI mutation can race.
            runner = Lab(self.lab.root, self.lab.workspace)
            operation_lock = self.lab.exclusive()
            operation_lock.__enter__()
            self.active = runner
            self.stopping = action == "stop"
            self.message = {
                "start": "Starting the stack",
                "demo": "Running all demos. Timed security checks take several minutes.",
                "stop": "Stopping the stack. Saved evidence and GRC data will remain.",
            }.get(action, "Restarting " + action.removeprefix("restart:"))
            self.thread = threading.Thread(
                target=self.execute, args=(runner, action, operation_lock), daemon=False
            )
            try:
                self.thread.start()
            except RuntimeError:
                self.active = None
                self.stopping = False
                operation_lock.__exit__(None, None, None)
                raise LabError("Cannot start local operation") from None

    def execute(self, runner, action, operation_lock):
        try:
            while True:
                restart = action.startswith("restart:")
                operation = (
                    "restart"
                    if restart
                    else {"start": "up", "stop": "down", "demo": "demo"}[action]
                )
                runner.begin(operation)
                if restart:
                    runner.report["service"] = action.removeprefix("restart:")
                try:
                    if restart:
                        from .services import Services

                        Services(runner).restart(action.removeprefix("restart:"))
                    elif action == "stop":
                        runner.down(keep_hub=True)
                    else:
                        getattr(runner, operation)()
                    runner.check_cancelled()
                except Exception as error:
                    runner.report["error"] = (
                        str(error)
                        if isinstance(error, LabError)
                        else "Local operation failed; inspect private logs"
                    )
                    runner.finish(False)
                else:
                    runner.finish(True)
                with self.lock:
                    if self.stopping and action != "stop":
                        runner.cancel.clear()
                        action = "stop"
                        self.message = "Stopping the stack. The control panel will stay available."
                        continue
                    if runner.report["state"] == "failed":
                        self.message = runner.report["error"]
                    else:
                        self.message = {
                            "start": "Stack started. Open a demo or run all checks.",
                            "demo": "All demos passed. Fresh evidence is ready to inspect.",
                            "stop": "Stack stopped. Start it again whenever you are ready.",
                        }.get(
                            action, "Service restart completed: " + action.removeprefix("restart:")
                        )
                    break
        except Exception:
            with self.lock:
                self.message = "Local operation failed; inspect private logs"
        finally:
            with self.lock:
                operation_lock.__exit__(None, None, None)
                self.active = None
                self.stopping = False


def handler(lab, controls):
    from . import history
    from .runtime import Monitor
    from .services import Services

    monitor = Monitor(lab)
    services = Services(lab)
    log_slots = threading.BoundedSemaphore(2)

    class Handler(BaseHTTPRequestHandler):
        def allowed_host(self):
            return self.headers.get_all("Host") in (["127.0.0.1:18879"], ["localhost:18879"])

        def respond(self, code, value, mime="application/json", download=None):
            data = value if isinstance(value, bytes) else json.dumps(value).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", mime + "; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            if download:
                self.send_header("Content-Disposition", f'attachment; filename="{download}"')
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
            )
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            if not self.allowed_host():
                self.respond(403, {"error": "Forbidden host"})
                return
            mapping = {
                "/": ("web/index.html", "text/html"),
                "/app.css": ("web/app.css", "text/css"),
                "/app.js": ("web/app.js", "text/javascript"),
                "/runtime": ("web/runtime.html", "text/html"),
                "/runtime.js": ("web/runtime.js", "text/javascript"),
                "/credentials.mjs": ("web/credentials.mjs", "text/javascript"),
            }
            if self.path == "/api/session":
                self.respond(200, {"token": controls.token})
            elif self.path == "/api/runtime":
                try:
                    value = {
                        **monitor.snapshot(),
                        "management": services.catalog(),
                        "control": controls.status(),
                    }
                    self.respond(200, value)
                except (LabError, OSError, ValueError, KeyError, TypeError):
                    self.respond(503, {"error": "Runtime inventory unavailable"})
            elif self.path == "/api/status":
                try:
                    value = lab.status()
                    value["control"] = controls.status()
                    self.respond(200, value)
                except (LabError, OSError, ValueError, subprocess.TimeoutExpired):
                    self.respond(503, {"error": "Local status unavailable"})
            elif self.path == "/api/runs":
                try:
                    self.respond(200, {"runs": history.runs(lab.data)})
                except (OSError, ValueError):
                    self.respond(503, {"error": "Run history unavailable"})
            elif self.path == "/api/diagnostic":
                try:
                    report = history.diagnostic(lab.data, lab.status(), lab.pins["projects"])
                    self.respond(200, report, download="agent-security-lab-diagnostic.json")
                except (LabError, OSError, ValueError, KeyError, subprocess.TimeoutExpired):
                    self.respond(503, {"error": "Diagnostic report unavailable"})
            elif self.path in mapping:
                filename, mime = mapping[self.path]
                self.respond(200, (lab.root / filename).read_bytes(), mime)
            else:
                self.respond(404, {"error": "Not found"})

        def do_POST(self):
            if (
                not self.allowed_host()
                or self.headers.get_all("Origin") != ["http://" + self.headers.get("Host", "")]
                or self.headers.get_all("X-Lab-Token") != [controls.token]
                or self.headers.get("Sec-Fetch-Site", "same-origin") != "same-origin"
            ):
                self.respond(403, {"error": "Reload this local panel before using controls"})
                return
            if self.path not in {"/api/control", "/api/service"}:
                self.respond(404, {"error": "Not found"})
                return
            lengths = self.headers.get_all("Content-Length", [])
            if (
                self.headers.get("Content-Type") != "application/json"
                or self.headers.get("Transfer-Encoding") is not None
                or len(lengths) != 1
                or len(lengths[0]) > 4
                or not lengths[0].isascii()
                or not lengths[0].isdigit()
                or not 0 < int(lengths[0]) <= 1024
            ):
                self.respond(400, {"error": "Expected a small JSON action"})
                return
            self.connection.settimeout(3)
            try:
                value = json.loads(self.rfile.read(int(lengths[0])))
                expected = {"action", "service"} if self.path == "/api/service" else {"action"}
                if not isinstance(value, dict) or set(value) != expected:
                    raise ValueError
                if self.path == "/api/service":
                    if value["action"] not in ("restart", "logs"):
                        raise ValueError
                    Services.target(value["service"])
                elif value["action"] not in ("start", "demo", "stop"):
                    raise ValueError
            except (ValueError, UnicodeError, OSError, RecursionError):
                self.respond(400, {"error": "Unknown or malformed action"})
                return
            if self.path == "/api/service" and value["action"] == "logs":
                if not log_slots.acquire(blocking=False):
                    self.respond(429, {"error": "Another log request is running"})
                    return
                try:
                    self.respond(200, services.logs(value["service"]))
                except (LabError, OSError, ValueError, KeyError, TypeError):
                    self.respond(
                        503, {"error": "Service logs unavailable; runtime data is unchanged"}
                    )
                finally:
                    log_slots.release()
                return
            try:
                controls.submit(
                    "restart:" + value["service"]
                    if self.path == "/api/service"
                    else value["action"]
                )
            except LabError as error:
                self.respond(409, {"error": str(error)})
            else:
                self.respond(202, {"accepted": True})

        def log_message(self, *_):
            pass

    return Handler


def serve(lab):
    controls = Controls(lab)
    ThreadingHTTPServer(("127.0.0.1", PORTS["hub"]), handler(lab, controls)).serve_forever()


def main():
    os.environ["PATH"] = tool_path()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command",
        choices=[
            "doctor",
            "sync",
            "prepare",
            "up",
            "demo",
            "status",
            "report",
            "down",
            "reset-identity",
            "reset-security",
            "_serve",
        ],
    )
    parser.add_argument("--workspace", type=Path, help="Local source repository parent")
    args = parser.parse_args()
    lab = Lab(workspace=args.workspace)
    try:
        if args.command == "_serve":
            serve(lab)
        elif args.command == "status":
            print(json.dumps(lab.status(), indent=2))
        elif args.command == "report":
            print(json.dumps(read(lab.data / "latest.json"), indent=2))
        else:
            with lab.exclusive():
                if args.command in {"doctor", "sync"}:
                    getattr(lab, args.command.replace("-", "_"))()
                else:
                    lab.begin(args.command)
                    try:
                        getattr(lab, args.command.replace("-", "_"))()
                    except BaseException:
                        lab.finish(False)
                        raise
                    lab.finish(True)
        return 0
    except (LabError, OSError, ValueError, KeyError, subprocess.TimeoutExpired) as error:
        print(
            str(error)
            if isinstance(error, LabError)
            else "Local operation failed; inspect private logs",
            file=sys.stderr,
        )
        return 1
    except KeyboardInterrupt:
        print("Operation interrupted; owned runtime data retained", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
