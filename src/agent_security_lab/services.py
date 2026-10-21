# SPDX-FileCopyrightText: 2026 Tanya Babitskaya
# SPDX-License-Identifier: Apache-2.0
"""Fixed owned service actions and an allowlisted diagnostic log projection."""

import json
import os
import re
import stat
import subprocess
import time
from datetime import datetime

from .cli import PORTS, LabError, listening, stamp

TARGETS = {}
for name in ("authz", "authz-strict", "fhir", "headlamp", "notes-a", "notes-b", "notes-rogue"):
    TARGETS[name] = {
        "vm": "security-lab",
        "namespace": "security-lab",
        "controller": name,
        "container": name,
    }
for key, controller, container in (
    ("postgres", "identity-postgres", "postgres"),
    ("zitadel", "zitadel", "zitadel"),
    ("zitadel-login", "zitadel-login", "zitadel-login"),
    ("spire-server", "spire-server", "spire-server"),
    ("spire-agent", "spire-agent", "spire-agent"),
):
    TARGETS[key] = {
        "vm": "security-lab",
        "namespace": "spire-system" if key.startswith("spire-") else "security-lab-identity",
        "controller": controller,
        "container": container,
    }
for key, controller, container in (
    ("grc-backend", "it-grc-ciso-assistant-backend", "backend"),
    ("grc-huey", "it-grc-ciso-assistant-backend", "huey"),
    ("grc-frontend", "it-grc-ciso-assistant-frontend", "frontend"),
    ("grc-tls", "it-grc-tls", "caddy"),
):
    TARGETS[key] = {
        "vm": "it-grc",
        "namespace": "it-grc",
        "controller": controller,
        "container": container,
    }
TARGETS["viewer"] = {**TARGETS["headlamp"], "host": True}
TARGETS["dashboard"] = {"host": True, "container": "dashboard"}
PROTECTED = {"postgres", "zitadel", "spire-server", "spire-agent"}
SIGNALS = (
    (r"connection refused|failed to (connect|dial)", "Connection failed"),
    (r"deadline exceeded|timed? ?out|timeout", "Operation timed out"),
    (r"certificate.*(expired|invalid|unknown)|tls.*(fail|error)|x509", "TLS or certificate issue"),
    (r"permission denied|forbidden|unauthorized|authentication failed", "Access denied"),
    (r"address already in use|EADDRINUSE", "Port already in use"),
    (r"no such file|file not found|ENOENT", "Required file unavailable"),
    (r"crashloop|panic|fatal|traceback", "Process failure"),
    (
        r"listening|server started|started server|application startup complete",
        "Service started or listening",
    ),
    (r"shutting down|shutdown|terminated|stopping", "Service stopping"),
    (r"Loaded [0-9]+ issues|fixture", "Synthetic fixture activity"),
    (r"migration|migrating", "Database migration activity"),
    (r"rotat|renew", "Credential or key rotation activity"),
    (r"ready|healthy|health check", "Readiness activity"),
)


def project_logs(text):
    """Never return arbitrary message, URL, JSON field or exception content."""
    entries = []
    hidden = 0
    lines = text[-32768:].splitlines()[-100:]
    for line in lines:
        timestamp = None
        match = re.match(r"^(\d{4}-\d\d-\d\dT[0-9:.+-]+Z?)\s", line)
        if match:
            try:
                timestamp = datetime.fromisoformat(match[1]).isoformat()
            except ValueError:
                pass
        level = next(
            (
                name
                for name in ("FATAL", "ERROR", "WARN", "INFO", "DEBUG")
                if re.search(r"\b" + name + r"\b", line, re.I)
            ),
            "UNKNOWN",
        )
        signals = [label for pattern, label in SIGNALS if re.search(pattern, line, re.I)]
        http = re.search(r'HTTP/[12](?:\.\d)?["\s]+([1-5]\d\d)\b', line)
        if http:
            signals.append("HTTP " + http[1])
        if not signals and level in {"ERROR", "FATAL", "WARN"}:
            signals.append(
                "Application reported " + ("a warning" if level == "WARN" else "an error")
            )
        if not signals:
            hidden += 1
            continue
        entries.append({"time": timestamp, "level": level, "summary": "; ".join(signals)})
    return {"entries": entries, "hidden_lines": hidden, "sampled_lines": len(lines)}


class Services:
    def __init__(self, lab):
        self.lab = lab

    @staticmethod
    def target(key):
        if not isinstance(key, str) or key not in TARGETS:
            raise LabError("Unknown service")
        return TARGETS[key]

    @staticmethod
    def catalog():
        return [
            {
                "id": key,
                "container": value["container"],
                "namespace": value.get("namespace"),
                "host": value.get("host", False),
                "restartable": key not in PROTECTED,
                "note": "Temporary identity state. Use the stack lifecycle for recovery."
                if key in PROTECTED
                else "Restarts backend and worker together; persistent data remains."
                if key in {"grc-backend", "grc-huey"}
                else "Restarts viewer and identity proxy. Logs cover Headlamp."
                if key == "viewer"
                else "",
            }
            for key, value in TARGETS.items()
        ]

    def command(self, target, *args):
        return [
            "limactl",
            "shell",
            target["vm"],
            "sudo",
            "k3s",
            "kubectl",
            "--kubeconfig=/etc/rancher/k3s/k3s.yaml",
            "--server=https://127.0.0.1:6443",
            *args,
        ]

    def query(self, target, *args):
        try:
            result = subprocess.run(
                self.command(target, *args),
                env=self.lab.env(),
                capture_output=True,
                timeout=8,
                check=False,
            )
            if result.returncode:
                raise LabError("Service observation unavailable")
            return result.stdout
        except (OSError, subprocess.TimeoutExpired):
            raise LabError("Service observation unavailable") from None

    def controller(self, target):
        # Namespace and controller ownership are checked before logs or mutation.
        namespace = json.loads(
            self.query(target, "get", "namespace", target["namespace"], "-o", "json")
        )
        labels = namespace["metadata"].get("labels", {})
        owner = "security-lab" if target["vm"] == "security-lab" else "it-grc-system-of-record"
        if labels.get("app.kubernetes.io/part-of") != owner:
            raise LabError("Service namespace ownership is not verified")
        kind = "daemonset" if target["controller"] == "spire-agent" else "deployment"
        obj = json.loads(
            self.query(
                target, "-n", target["namespace"], "get", kind, target["controller"], "-o", "json"
            )
        )
        labels = obj["metadata"].get("labels", {})
        owned = labels.get("app.kubernetes.io/part-of") == owner
        if target["vm"] == "it-grc" and target["controller"] != "it-grc-tls":
            owned = (
                labels.get("app.kubernetes.io/instance") == "it-grc"
                and labels.get("app.kubernetes.io/name") == "ciso-assistant"
            )
        if not owned:
            raise LabError("Service controller ownership is not verified")
        if target["container"] not in {
            c["name"] for c in obj["spec"]["template"]["spec"]["containers"]
        }:
            raise LabError("Service container does not match its controller")
        return kind, obj

    def restart(self, key):
        target = self.target(key)
        if key in PROTECTED:
            raise LabError("Individual restart would discard temporary identity state")
        if key == "dashboard":
            self.lab.verify("engineering-os")
            self.lab.stop_service("dashboard")
            deadline = time.monotonic() + 5
            while listening(PORTS["dashboard"]):
                self.lab.check_cancelled()
                if time.monotonic() >= deadline:
                    raise LabError("Dashboard port did not become available")
                time.sleep(0.1)
            repo = self.lab.repo("engineering-os") / "dashboard"
            self.lab.start_service(
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
            return
        project = "mcp-svid-auth" if target["vm"] == "security-lab" else "it-grc"
        self.lab.verify(project)
        kind, obj = self.controller(target)
        if key == "viewer":
            self.reconnect_viewer()
            return
        patch = [
            {"op": "test", "path": "/metadata/uid", "value": obj["metadata"]["uid"]},
            {
                "op": "test",
                "path": "/metadata/resourceVersion",
                "value": obj["metadata"]["resourceVersion"],
            },
        ]
        if "annotations" not in obj["spec"]["template"]["metadata"]:
            patch.append({"op": "add", "path": "/spec/template/metadata/annotations", "value": {}})
        patch.append(
            {
                "op": "add",
                "path": (
                    "/spec/template/metadata/annotations/"
                    "agent-security-lab.example.org~1restarted-at"
                ),
                "value": stamp(),
            }
        )
        self.lab.run(
            "Restart " + key,
            self.command(
                target,
                "-n",
                target["namespace"],
                "patch",
                kind,
                target["controller"],
                "--type=json",
                "-p",
                json.dumps(patch),
            ),
            timeout=15,
        )
        self.lab.run(
            "Wait for " + key,
            self.command(
                target,
                "-n",
                target["namespace"],
                "rollout",
                "status",
                kind + "/" + target["controller"],
                "--timeout=120s",
            ),
            timeout=125,
        )

        if key in {"headlamp", "zitadel-login"}:
            # Pod-bound forwards must reconnect after a successful rollout.
            self.reconnect_viewer()

        if key in {"grc-backend", "grc-huey"}:
            self.lab.restore_sso()

        if key == "grc-tls":
            # kubectl port-forward holds a pod connection across the rollout.
            # Reconnect only this owned VM's fixed unit, leaving GRC storage intact.
            self.lab.run(
                "Reconnect GRC HTTPS access",
                [
                    "limactl",
                    "shell",
                    "it-grc",
                    "sudo",
                    "systemctl",
                    "restart",
                    "it-grc-https.service",
                ],
                timeout=20,
            )

    def reconnect_viewer(self):
        # Reuse only a verified existing profile; this action cannot provision one.
        if self.lab.restart_check("identity") != "REUSE":
            raise LabError("Viewer reconnect requires a verified existing identity")
        self.lab.make("mcp-svid-auth", "ui-stop")
        self.lab.make("mcp-svid-auth", "ui")

    def logs(self, key):
        target = self.target(key)
        if key == "dashboard":
            self.lab.owned()
            path = self.lab.data / "dashboard.log"
            try:
                descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                with os.fdopen(descriptor, "rb") as stream:
                    if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                        raise LabError("Service log is not a regular file")
                    stream.seek(max(0, os.fstat(stream.fileno()).st_size - 32768))
                    raw = stream.read(32768)
            except OSError:
                raise LabError("No retained service log is available") from None
        else:
            kind, obj = self.controller(target)
            # A fixed reviewed controller, not a browser-provided pod or selector.
            raw = self.query(
                target,
                "-n",
                target["namespace"],
                "logs",
                kind + "/" + target["controller"],
                "-c",
                target["container"],
                "--tail=100",
                "--limit-bytes=32768",
                "--since=15m",
                "--timestamps=true",
                "--request-timeout=5s",
            )
        return {
            "service": key,
            "checked_at": stamp(),
            "scope": "Safe diagnostic signals from recent logs; free-form content is hidden",
            **project_logs(raw.decode("utf-8", errors="replace")),
        }
