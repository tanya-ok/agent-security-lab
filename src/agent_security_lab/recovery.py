# SPDX-FileCopyrightText: 2026 Tanya Babitskaya
# SPDX-License-Identifier: Apache-2.0
"""Narrow restart recovery against the reviewed component driver, never a reset."""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

OWNER = "security-lab"
PARENT = {"trust_domain": "example.org", "path": "/node/security-lab"}


class RecoveryError(ValueError):
    """Fixed diagnostics only; credentials and remote responses are never printed."""


def owned(k, kind, name, namespace):
    value = json.loads(k.checked(k.kube(["get", kind, name, "-o", "json"], namespace=namespace)))
    metadata = value.get("metadata", {})
    if metadata.get("labels", {}).get("app.kubernetes.io/part-of") != OWNER:
        raise RecoveryError("Restart recovery refused: ownership mismatch")
    if not metadata.get("uid") or not metadata.get("resourceVersion"):
        raise RecoveryError("Restart recovery refused: incomplete resource identity")
    return value


def registrations(k):
    value = json.loads(k.server(["entry", "show", "-output", "json"]))
    if not isinstance(value, dict) or not isinstance(value.get("entries"), list):
        raise RecoveryError("Restart recovery refused: unknown registration state")
    return value["entries"]


def expected_entries(entries):
    expected = {
        (
            "/node/security-lab",
            "/spire/server",
            (
                ("k8s_psat", "agent_ns:spire-system"),
                ("k8s_psat", "agent_sa:spire-agent"),
                ("k8s_psat", "cluster:security-lab"),
            ),
        )
    }
    for identity, account in (
        ("authz", "authz"),
        ("mcp/notes-a", "notes-a"),
        ("mcp/notes-b", "notes-b"),
        ("agent/research", "agent-research"),
        ("agent/intruder", "agent-intruder"),
        ("agent/intruder", "agent-impostor"),
        ("mcp/fhir", "fhir"),
    ):
        expected.add(
            (
                "/" + identity,
                PARENT["path"],
                (
                    ("k8s", "ns:security-lab"),
                    ("k8s", "sa:" + account),
                ),
            )
        )
    observed = set()
    for entry in entries:
        identity, parent = entry["spiffe_id"], entry["parent_id"]
        if (
            identity["trust_domain"] != "example.org"
            or parent["trust_domain"] != "example.org"
            or entry.get("admin")
            or entry.get("downstream")
            or entry.get("federates_with")
        ):
            return False
        if parent["path"] == PARENT["path"] and (
            entry.get("jwt_svid_ttl") != 60
            or entry.get("additional_attributes", {}).get("jwt_svid_include_jti") is not True
        ):
            return False
        observed.add(
            (
                identity["path"],
                parent["path"],
                tuple(
                    sorted((selector["type"], selector["value"]) for selector in entry["selectors"])
                ),
            )
        )
    return len(entries) == len(expected) and observed == expected


def recover_workloads(k):
    k.verify_instance()
    namespaces = {
        name: owned(k, "namespace", name, None)["metadata"]["uid"]
        for name in ("security-lab", "spire-system")
    }
    owned(k, "deployment", "spire-server", "spire-system")
    owned(k, "daemonset", "spire-agent", "spire-system")
    config = owned(k, "configmap", "spire-bundle", "spire-system")
    entries = registrations(k)
    bundle = k.server(["bundle", "show"]).strip()
    if (
        not bundle.startswith("-----BEGIN CERTIFICATE-----")
        or not bundle.endswith("-----END CERTIFICATE-----")
        or "PRIVATE KEY" in bundle
    ):
        raise RecoveryError("Restart recovery refused: invalid public bundle")
    current = config.get("data", {}).get("bundle.pem", "").strip()
    if entries:
        if not expected_entries(entries) or current != bundle:
            raise RecoveryError("Restart recovery refused: existing trust or registrations differ")
        return False
    if not current or current == bundle:
        raise RecoveryError("Restart recovery refused: ambiguous empty registration state")
    # Only the known empty-memory state qualifies. Partial or unknown state is never reset.
    k.register()
    if not expected_entries(registrations(k)):
        raise RecoveryError("Restart recovery refused: restored registrations differ")
    value = k.configmap("spire-bundle", {"bundle.pem": bundle}, "spire-system")
    for key in ("uid", "resourceVersion"):
        value["metadata"][key] = config["metadata"][key]
    k.apply([value])
    k.checked(k.kube(["rollout", "restart", "daemonset/spire-agent"], namespace="spire-system"))
    k.checked(
        k.kube(
            ["rollout", "status", "daemonset/spire-agent", "--timeout=180s"],
            namespace="spire-system",
            timeout=200,
        )
    )
    for name, uid in namespaces.items():
        if owned(k, "namespace", name, None)["metadata"]["uid"] != uid:
            raise RecoveryError("Restart recovery refused: namespace changed")
    return True


def reuse_identity(k, identity):
    if not k.owned_namespace(identity.NAMESPACE):
        if identity.PROFILE.exists():
            raise RecoveryError("Restart recovery refused: saved identity namespace is absent")
        return False
    owned(k, "namespace", identity.NAMESPACE, None)
    config = identity.settings()
    if config is None:
        raise RecoveryError("Restart recovery refused: missing identity profile")
    for name in ("identity-postgres", "zitadel", "zitadel-login"):
        owned(k, "deployment", name, identity.NAMESPACE)
        identity.ready(name)
    secret = owned(k, "secret", "identity-login", identity.NAMESPACE)
    token = base64.b64decode(secret["data"]["token"], validate=True).decode("utf-8")
    if not token or len(token) > 4096:
        raise RecoveryError("Restart recovery refused: invalid login credential")
    # The already-mounted Login service credential remains in memory only. Any policy
    # or authentication error stops startup; there is no bootstrap/reset fallback.
    with identity.connection():
        verifier = identity.Bootstrap(token)
        try:
            verifier.verify_native_policy(config.org_id)
        finally:
            verifier.client.close()
    return True


def main():
    try:
        sys.path.insert(0, str(Path.cwd()))
        from scripts import kubernetes_demo as k
        from scripts import zitadel_demo as identity

        k.verify_instance()
        action = sys.argv[1]
        if action == "identity":
            print("REUSE" if reuse_identity(k, identity) else "NEW")
        elif action == "workloads":
            print("RESTORED" if recover_workloads(k) else "UNCHANGED")
        else:
            raise RecoveryError("Unsupported restart check")
    except Exception:
        print(
            "Owned restart recovery failed; inspect state without resetting the saved profile",
            file=sys.stderr,
        )
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
