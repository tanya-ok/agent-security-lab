# SPDX-FileCopyrightText: 2026 Tanya Babitskaya
# SPDX-License-Identifier: Apache-2.0
"""Read only the two pinned synthetic service accounts' PAT expiration metadata."""

import json
import subprocess
from datetime import UTC, datetime, timedelta

from .cli import LabError
from .services import Services

WARNING_HOURS = 24
SUBJECTS = {"bootstrap": "Profile bootstrap", "login": "ZITADEL Login"}
# Fixed identifiers from the locked local driver. No credential or user input is read.
# Multiple subjects/PATs are ambiguous: never guess which credential is mounted.
EXPIRY_SQL = """
BEGIN READ ONLY;
SET LOCAL statement_timeout = '3000ms';
WITH subjects(kind, username) AS (
    VALUES ('bootstrap', 'lab-bootstrap'), ('login', 'lab-login')
)
SELECT json_agg(row_to_json(result)) FROM (
    SELECT s.kind AS id, count(DISTINCT m.user_id) AS subject_count,
        count(p.id) AS token_count,
        CASE WHEN count(p.id)=1 THEN max(p.creation_date) END AS created_at,
        CASE WHEN count(p.id)=1 THEN max(p.expiration) END AS expires_at
    FROM subjects s
    LEFT JOIN projections.users14 u ON u.username=s.username
    LEFT JOIN projections.users14_machines m
        ON m.user_id=u.id AND m.instance_id=u.instance_id
    LEFT JOIN projections.personal_access_tokens3 p
        ON p.user_id=m.user_id AND p.instance_id=m.instance_id AND p.owner_removed=false
    GROUP BY s.kind ORDER BY s.kind
) result;
COMMIT;
"""


def lifetime_records(raw, now):
    """Project validated timestamps only; unrelated DB fields never leave the observer."""
    result = [
        {"id": key, "name": label, "state": "unknown", "expires_at": None}
        for key, label in SUBJECTS.items()
    ]
    if (
        not isinstance(raw, list)
        or len(raw) != len(SUBJECTS)
        or any(
            not isinstance(row, dict)
            or not isinstance(row.get("id"), str)
            or row["id"] not in SUBJECTS
            for row in raw
        )
        or len({row["id"] for row in raw}) != len(SUBJECTS)
    ):
        return result
    rows = {row["id"]: row for row in raw}
    for item in result:
        row = rows[item["id"]]
        try:
            if any(
                type(row.get(key)) is not int or row[key] != 1
                for key in ("subject_count", "token_count")
            ):
                continue
            dates = []
            for key in ("created_at", "expires_at"):
                value = row[key]
                if not isinstance(value, str) or len(value) > 64:
                    raise ValueError
                parsed = datetime.fromisoformat(value)
                if parsed.utcoffset() is None:
                    raise ValueError
                dates.append(parsed.astimezone(UTC))
            created, expires = dates
            if created > now or expires < created:
                continue
            item.update(
                state="expired"
                if expires <= now
                else "expiring"
                if expires <= now + timedelta(hours=WARNING_HOURS)
                else "current",
                expires_at=expires.isoformat(),
            )
        except (ValueError, TypeError, KeyError, OverflowError):
            continue
    return result


def credential_health(lab, vm_state):
    now = datetime.now(UTC)
    result = {
        "checked_at": now.isoformat(),
        "state": "unknown",
        "warning_hours": WARNING_HOURS,
        "source": "ZITADEL database expiration metadata",
        "scope": (
            "Expiration only. Revocation, mounted-token identity and sign-in are separate checks."
        ),
        "items": lifetime_records(None, now),
    }
    if vm_state != "Running":
        if vm_state == "Stopped":
            result["state"] = "stopped"
        return result
    try:
        lab.verify("mcp-svid-auth")
        services = Services(lab)
        target = services.target("postgres")
        services.controller(target)
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
            EXPIRY_SQL,
        )
        if len(raw) > 4096:
            return result
        result["items"] = lifetime_records(json.loads(raw.decode("utf-8")), now)
    except (
        LabError,
        OSError,
        ValueError,
        KeyError,
        TypeError,
        UnicodeError,
        RecursionError,
        subprocess.TimeoutExpired,
    ):
        return result
    states = {item["state"] for item in result["items"]}
    result["state"] = next(
        state for state in ("expired", "unknown", "expiring", "current") if state in states
    )
    return result
