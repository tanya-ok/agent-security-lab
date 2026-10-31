# SPDX-FileCopyrightText: 2026 Tanya Babitskaya
# SPDX-License-Identifier: Apache-2.0
"""Read-only run history and an allowlisted diagnostic report for the local panel."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime

RUN_ID = re.compile(r"^\d{8}T\d{6}Z-[0-9a-f]{6}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._:/()+-]{0,119}$")
STATES = {"running", "passed", "failed"}
OPERATIONS = {"prepare", "up", "demo", "down", "restart", "reset-identity", "reset-security"}
RUNTIME_STATES = {"Running", "Stopped", "Broken", "Unknown"}
HISTORY_LIMIT = 50
EXCLUDED = [
    "command logs and step output",
    "error messages",
    "artifacts and evidence files",
    "filesystem paths",
    "session tokens and environment",
]


def _text(value, pattern=NAME):
    return value if isinstance(value, str) and pattern.fullmatch(value) else None


def _time(value):
    if not isinstance(value, str):
        return None
    try:
        datetime.fromisoformat(value)
    except ValueError:
        return None
    return value


def _choice(value, allowed):
    return value if value in allowed else "unknown"


def _steps(report):
    steps = report.get("steps")
    return [step for step in steps if isinstance(step, dict)] if isinstance(steps, list) else []


def summary(report):
    steps = _steps(report)
    failed = next((step for step in steps if step.get("state") == "failed"), None)
    return {
        "run_id": _text(report.get("run_id"), RUN_ID),
        "operation": _choice(report.get("operation"), OPERATIONS),
        "state": _choice(report.get("state"), STATES),
        "started_at": _time(report.get("started_at")),
        "finished_at": _time(report.get("finished_at")),
        "steps_total": len(steps),
        "steps_passed": sum(step.get("state") == "passed" for step in steps),
        "failed_step": _text(failed.get("name")) if failed else None,
    }


def runs(data, limit=HISTORY_LIMIT):
    folder = data / "runs"
    if folder.is_symlink() or not folder.is_dir():
        return []
    result = []
    names = sorted((p.name for p in folder.iterdir() if RUN_ID.fullmatch(p.name)), reverse=True)
    for name in names:
        if len(result) >= limit:
            break
        run = folder / name
        path = run / "report.json"
        if run.is_symlink() or path.is_symlink() or not path.is_file():
            continue
        try:
            report = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError, UnicodeError):
            continue
        if isinstance(report, dict) and report.get("run_id") == name:
            result.append(summary(report))
    return result


def diagnostic(data, status, pins):
    latest = status.get("latest")
    detail = None
    if isinstance(latest, dict):
        detail = summary(latest) | {
            "steps": [
                {
                    "name": _text(step.get("name")),
                    "state": _choice(step.get("state"), STATES),
                    "duration_seconds": step.get("duration_seconds")
                    if isinstance(step.get("duration_seconds"), int | float)
                    else None,
                }
                for step in _steps(latest)
            ]
        }
    runtimes = status.get("runtimes") if isinstance(status.get("runtimes"), list) else []
    ports = status.get("ports") if isinstance(status.get("ports"), dict) else {}
    return {
        "schema": 1,
        "kind": "agent-security-lab-diagnostic",
        "generated_at": datetime.now(UTC).isoformat(),
        "synthetic_data_only": True,
        "source_pins": {
            name: pin["commit"][:12]
            for name, pin in pins.items()
            if isinstance(pin, dict) and _text(pin.get("commit"), COMMIT)
        },
        "runtimes": [
            {"name": _text(vm.get("name")), "status": _choice(vm.get("status"), RUNTIME_STATES)}
            for vm in runtimes
            if isinstance(vm, dict)
        ],
        "ports": {
            name: value for name, value in ports.items() if _text(name) and isinstance(value, bool)
        },
        "latest": detail,
        "history": runs(data, limit=10),
        "excluded": EXCLUDED,
    }
