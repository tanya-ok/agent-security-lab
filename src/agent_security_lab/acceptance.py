# SPDX-FileCopyrightText: 2026 Tanya Babitskaya
# SPDX-License-Identifier: Apache-2.0
"""Read-only owner preservation checks around synthetic identity acceptance."""

import json
import re
from datetime import UTC, datetime

from .cli import LabError, digest
from .services import Services

METHODS_SQL = """
BEGIN READ ONLY;
SET LOCAL statement_timeout='3000ms';
SELECT json_build_object('count',count(*),'digest',
    encode(sha256(convert_to(COALESCE(
        json_agg(row_to_json(m) ORDER BY user_id,method_type,token_id)::text,'[]'),
        'UTF8')),'hex'))
FROM (SELECT user_id,method_type,token_id,creation_date,state,
    resource_owner,instance_id,name,domain FROM projections.user_auth_methods5) m;
COMMIT;
"""


def owner_snapshot(lab):
    lab.verify("mcp-svid-auth")
    services = Services(lab)
    target = services.target("postgres")
    _, controller = services.controller(target)
    raw = services.query(
        target,
        "-n",
        target["namespace"],
        "exec",
        "deployment/identity-postgres",
        "-c",
        "postgres",
        "--",
        "psql",
        "-X",
        "-qAt",
        "-U",
        "postgres",
        "-d",
        "zitadel",
        "-v",
        "ON_ERROR_STOP=1",
        "-c",
        METHODS_SQL,
    )
    if len(raw) > 1024:
        raise LabError("Owner preservation check unavailable")
    value = json.loads(raw.decode("utf-8"))
    if (
        not isinstance(value, dict)
        or type(value.get("count")) is not int
        or value["count"] < 0
        or not isinstance(value.get("digest"), str)
        or not re.fullmatch(r"[a-f0-9]{64}", value["digest"])
    ):
        raise LabError("Owner preservation check unavailable")
    return {
        "profile": digest(lab.repo("mcp-svid-auth") / "deploy/.data/human-auth.json"),
        "database_controller": controller["metadata"]["uid"],
        "methods": value,
    }


def validate_checks(value, expected, started):
    try:
        checked = datetime.fromisoformat(value["checked_at"])
        earliest = datetime.fromisoformat(started)
        rows = value["passed"]
        if (
            checked.utcoffset() is None
            or not earliest <= checked <= datetime.now(UTC)
            or not isinstance(rows, list)
            or len(rows) != expected
            or not all(isinstance(row, str) and row for row in rows)
            or len(set(rows)) != expected
        ):
            raise ValueError
    except (KeyError, TypeError, ValueError):
        raise LabError("Synthetic identity acceptance evidence incomplete") from None
    return value


def validate_access(observation):
    expected = {
        "viewer": "reachable",
        "identity": "healthy",
        "login": "healthy",
        "grc": "healthy",
        "dashboard": "healthy",
    }
    try:
        if (
            len(observation["services"]) != len(expected)
            or {row["key"]: row["state"] for row in observation["services"]} != expected
            or len(observation["workloads"]) != 2
            or {row["name"]: row["state"] for row in observation["workloads"]}
            != {"security-lab": "ready", "it-grc": "ready"}
            or len(observation["projects"]) != 6
            or any(row["integrity"] != "verified" for row in observation["projects"])
            or observation["credentials"]["state"] not in {"current", "expiring"}
        ):
            raise ValueError
    except (KeyError, TypeError, ValueError):
        raise LabError("Final local access verification failed") from None
