# SPDX-FileCopyrightText: 2026 Tanya Babitskaya
# SPDX-License-Identifier: Apache-2.0
"""Read-only local observations. A source pin is not a running-build attestation."""

from __future__ import annotations

import ast
import http.client
import json
import re
import ssl
import subprocess
import threading
import time
import tomllib
from concurrent.futures import ThreadPoolExecutor

from .cli import PROJECTS, LabError, git, listening, read, stamp
from .credentials import credential_health

NAMESPACES = {
    "security-lab": {"security-lab", "spire-system", "security-lab-identity"},
    "it-grc": {"it-grc"},
}
EXPECTED = {
    "security-lab": {
        "authz",
        "authz-strict",
        "notes-a",
        "notes-b",
        "notes-rogue",
        "fhir",
        "headlamp",
        "postgres",
        "zitadel",
        "zitadel-login",
        "spire-server",
        "spire-agent",
    },
    "it-grc": {"backend", "huey", "frontend", "caddy"},
}
MANIFESTS = {
    "mcp-svid-auth": "pyproject.toml",
    "mcp-spiffe-bridge": "package.json",
    "hipaa-fhir-mcp": "package.json",
    "engineering-os": "dashboard/package.json",
    "ai-assurance": "pyproject.toml",
}
ENDPOINTS = (
    ("viewer", "Security viewer", 4466, "/", "http://localhost:4466/c/main/security-lab"),
    (
        "identity",
        "ZITADEL discovery",
        4467,
        "/.well-known/openid-configuration",
        "http://localhost:4467/.well-known/openid-configuration",
    ),
    (
        "login",
        "ZITADEL Login",
        4467,
        "/ui/v2/login/healthy",
        "http://localhost:4467/ui/v2/login/healthy",
    ),
    ("grc", "CISO Assistant", 18443, "/api/health/", "https://localhost:18443/api/health/"),
    ("dashboard", "Engineering OS", 18766, "/api/health", "http://127.0.0.1:18766/api/health"),
)


def pinned_text(lab, name, path):
    pin = lab.pins["projects"][name]["commit"]
    return git(lab.workspace / name, "show", pin + ":" + path).decode("utf-8")


def source_info(lab, name):
    result = {
        "name": name,
        "commit": lab.pins["projects"][name]["commit"],
        "version": None,
        "integrity": "unknown",
        "kind": "library"
        if name == "mcp-spiffe-bridge"
        else "experiment"
        if name == "ai-assurance"
        else "application",
    }
    try:
        lab.verify(name)
        result["integrity"] = "verified"
        if name in MANIFESTS:
            path = MANIFESTS[name]
            text = pinned_text(lab, name, path)
            manifest = tomllib.loads(text) if path.endswith(".toml") else json.loads(text)
            version = manifest.get("project", manifest).get("version")
            if isinstance(version, str) and re.fullmatch(r"[0-9][0-9A-Za-z.+-]{0,63}", version):
                result["version"] = version
    except (LabError, OSError, ValueError, KeyError, UnicodeError):
        result["integrity"] = "unverified"
    return result


def image_versions(lab):
    """Map a human version only when repository AND observed digest match the lock."""
    references = []
    try:
        text = pinned_text(lab, "mcp-svid-auth", "deploy/kubernetes/services.yaml")
        references.extend(re.findall(r"image: (\S+@sha256:[a-f0-9]{64})", text))
        for path in ("scripts/zitadel_demo.py", "scripts/kubernetes_ui.py"):
            tree = ast.parse(pinned_text(lab, "mcp-svid-auth", path))
            for node in tree.body:
                if (
                    isinstance(node, ast.Assign)
                    and any(
                        isinstance(t, ast.Name) and t.id.endswith("_IMAGE") for t in node.targets
                    )
                    and isinstance(node.value, ast.Constant)
                    and isinstance(node.value.value, str)
                ):
                    references.append(node.value.value)
        upstream = json.loads(pinned_text(lab, "it-grc", "deploy/upstream.json"))
        for item in upstream["images"].values():
            references.append(
                f"{item['registry']}/{item['repository']}:{item['tag']}@{item['digest']}"
            )
    except (LabError, OSError, ValueError, KeyError, SyntaxError, UnicodeError):
        pass
    versions = {}
    for reference in references:
        if not re.fullmatch(r"[a-zA-Z0-9./:_-]+@sha256:[a-f0-9]{64}", reference):
            continue
        tagged, digest = reference.split("@")
        repository, tag = tagged.rsplit(":", 1)
        versions[repository + "@" + digest] = tag
    return versions


def summarize_pods(raw, vm, versions):
    rows = []
    for pod in raw["items"]:
        namespace = pod["metadata"]["namespace"]
        if namespace not in NAMESPACES[vm]:
            continue
        status = pod.get("status", {})
        ready = any(
            x.get("type") == "Ready" and x.get("status") == "True"
            for x in status.get("conditions", [])
        )
        statuses = {x["name"]: x for x in status.get("containerStatuses", [])}
        for container in pod["spec"]["containers"]:
            current = statuses.get(container["name"], {})
            image = current.get("imageID", "")
            for prefix in ("docker-pullable://", "containerd://", "docker://"):
                if image.startswith(prefix):
                    image = image[len(prefix) :]
            rows.append(
                {
                    "namespace": namespace,
                    "pod": pod["metadata"]["name"],
                    "name": container["name"],
                    "phase": status.get("phase", "Unknown"),
                    "ready": ready
                    and current.get("ready") is True
                    and not pod["metadata"].get("deletionTimestamp"),
                    "image": image or None,
                    "version": versions.get(image),
                    "restarts": current.get("restartCount", 0),
                }
            )
    return sorted(rows, key=lambda x: (x["namespace"], x["name"], x["pod"]))


def workload_health(lab, vm, state, versions):
    result = {
        "name": vm,
        "vm_state": state,
        "state": "unknown",
        "containers": [],
        "missing_containers": [],
    }
    if state == "Stopped":
        return {**result, "state": "stopped"}
    if state != "Running":
        return result
    try:
        process = subprocess.run(
            [
                "limactl",
                "shell",
                vm,
                "sudo",
                "k3s",
                "kubectl",
                "--kubeconfig=/etc/rancher/k3s/k3s.yaml",
                "--server=https://127.0.0.1:6443",
                "get",
                "pods",
                "-A",
                "-o",
                "json",
            ],
            env=lab.env(),
            capture_output=True,
            text=True,
            timeout=8,
            check=False,
        )
        if process.returncode:
            return result
        rows = summarize_pods(json.loads(process.stdout), vm, versions)
        missing = sorted(EXPECTED[vm] - {x["name"] for x in rows})
        result.update(
            containers=rows,
            missing_containers=missing,
            state="ready" if rows and not missing and all(x["ready"] for x in rows) else "degraded",
        )
    except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired):
        pass
    return result


def probe(lab, endpoint):
    key, label, port, path, url = endpoint
    result = {
        "key": key,
        "name": label,
        "url": url,
        "checked_at": stamp(),
        "state": "unknown",
        "http_status": None,
        "latency_ms": None,
    }
    started = time.monotonic()
    if not listening(port):
        return {**result, "state": "stopped", "detail": "No local listener"}
    connection = None
    try:
        if key == "grc":
            ca = lab.repo("it-grc") / "deploy/.data/ca.pem"
            context = ssl.create_default_context(cafile=str(ca))
            connection = http.client.HTTPSConnection("localhost", port, timeout=2, context=context)
        else:
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
        connection.request(
            "GET", path, headers={"Host": f"localhost:{port}", "Accept": "application/json"}
        )
        response = connection.getresponse()
        body = response.read(65537)
        result["http_status"] = response.status
        result["latency_ms"] = round((time.monotonic() - started) * 1000)
        if key == "viewer" and response.status in {200, 302, 303, 401, 403}:
            result.update(state="reachable", detail="HTTP responds; sign-in is a separate check")
        elif response.status == 200 and len(body) <= 65536:
            if key in {"dashboard", "grc"}:
                value = json.loads(body)
                if not isinstance(value, dict):
                    raise ValueError
                healthy = value.get("status") in ("ok", "healthy")
                result.update(
                    state="healthy" if healthy else "degraded", detail="Application health response"
                )
            elif key == "identity":
                value = json.loads(body)
                if not isinstance(value, dict) or value.get("issuer") != "http://localhost:4467":
                    raise ValueError
                result.update(
                    state="healthy",
                    detail="OIDC discovery issuer verified; sign-in is a separate check",
                )
            else:
                result.update(state="healthy", detail="Application readiness response")
        else:
            result.update(state="degraded", detail="Endpoint did not report readiness")
        if key == "dashboard" and not lab.service_alive("dashboard"):
            result.update(state="unknown", detail="Listener ownership is not verified")
    except (OSError, ValueError, RecursionError, http.client.HTTPException):
        result.update(
            state="unknown", detail="Health check unavailable; TLS verification remains enabled"
        )
    finally:
        if connection is not None:
            connection.close()
    return result


def access_diagnostics(services, workloads, credentials=None):
    """Recommend reconnect only for missing host listeners with ready workloads."""
    if credentials is not None and credentials.get("state") not in {"current", "expiring"}:
        return []
    vm = next((item for item in workloads if item.get("name") == "security-lab"), None)
    if vm is None or vm.get("vm_state") != "Running" or vm.get("state") != "ready":
        return []
    states = {item.get("key"): item.get("state") for item in services}
    keys = ("viewer", "identity", "login")
    if any(states.get(key) not in {"healthy", "reachable", "stopped"} for key in keys):
        return []
    if not any(states[key] == "stopped" for key in keys):
        return []
    return [
        {
            "code": "local-access-offline",
            "title": "Reconnect local access",
            "detail": (
                "Security workloads are ready, but a local viewer "
                "or identity interface is offline. "
                "Reconnect the shared proxy without resetting identities or GRC data."
            ),
        }
    ]


class Monitor:
    def __init__(self, lab):
        self.lab = lab
        self.lock = threading.Lock()
        self.cached = None
        self.expires = 0

    def snapshot(self):
        with self.lock:
            if self.cached is not None and time.monotonic() < self.expires:
                return self.cached
            started = stamp()
            try:
                states = {x["name"]: x["status"] for x in self.lab.inventory()}
            except (LabError, OSError, ValueError, subprocess.TimeoutExpired):
                states = {}
            versions = image_versions(self.lab)
            with ThreadPoolExecutor(max_workers=4) as pool:
                services = [pool.submit(probe, self.lab, item) for item in ENDPOINTS]
                workloads = [
                    pool.submit(workload_health, self.lab, vm, states.get(vm, "Unknown"), versions)
                    for vm in NAMESPACES
                ]
                credentials = pool.submit(
                    credential_health, self.lab, states.get("security-lab", "Unknown")
                )
                services = [future.result() for future in services]
                workloads = [future.result() for future in workloads]
                credentials = credentials.result()
            projects = [source_info(self.lab, name) for name in PROJECTS]
            last_demo = None
            try:
                path = self.lab.data / "demo-latest.json"
                if path.exists():
                    report = read(path)
                    last_demo = {
                        key: report.get(key)
                        for key in ("run_id", "state", "started_at", "finished_at")
                    }
            except (OSError, ValueError):
                pass
            self.cached = {
                "checked_at": stamp(),
                "started_at": started,
                "refresh_seconds": 15,
                "services": services,
                "workloads": workloads,
                "projects": projects,
                "credentials": credentials,
                "diagnostics": access_diagnostics(services, workloads, credentials),
                "last_demo": last_demo,
            }
            self.expires = time.monotonic() + 15
            return self.cached
