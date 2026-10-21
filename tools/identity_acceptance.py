# SPDX-FileCopyrightText: 2026 Tanya Babitskaya
# SPDX-License-Identifier: Apache-2.0
"""Run real synthetic identity acceptance on the component's fixed isolated profile."""

import json
import os
import secrets
import sys
import traceback
from pathlib import Path

TEST_NAMESPACE = "security-lab-passkey"
MARKER = "agent-security-lab.example.org/acceptance-run"


class FixtureError(ValueError):
    """Fixed diagnostics; source responses and credentials stay private."""


def exercise(k, identity, ui, suites):
    if (
        not identity.ISOLATED
        or identity.NAMESPACE != TEST_NAMESPACE
        or identity.API_BACKEND != "http://127.0.0.1:14567"
        or ui.PORT != 4566
    ):
        raise FixtureError("Synthetic profile boundary refused")
    if identity.PROFILE.exists() or identity.ACCOUNTS.exists():
        raise FixtureError("Existing synthetic profile requires private review")
    present = k.checked(
        k.kube(
            ["get", "namespace", TEST_NAMESPACE, "--ignore-not-found=true", "-o", "json"],
            namespace=None,
        )
    )
    if present.strip():
        raise FixtureError("Existing namespace requires private review")
    original_apply = k.apply
    marker, uid = secrets.token_hex(16), None

    def apply(documents):
        nonlocal uid
        for document in documents:
            if document.get("kind") == "Namespace":
                if document.get("metadata", {}).get("name") != TEST_NAMESPACE or uid is not None:
                    raise FixtureError("Unexpected synthetic namespace")
                document["metadata"].setdefault("annotations", {})[MARKER] = marker
                created = json.loads(
                    k.checked(
                        k.kube(
                            ["create", "-f", "-", "-o", "json"],
                            namespace=None,
                            input_text=json.dumps(document),
                        )
                    )
                )
                uid = created["metadata"]["uid"]
            else:
                if document.get("metadata", {}).get("namespace") != TEST_NAMESPACE:
                    raise FixtureError("Synthetic document boundary refused")
                original_apply([document])

    k.apply = apply
    try:
        identity.up()
        ui.start()
        for suite in suites:
            suite.run()
    finally:
        k.apply = original_apply
        if uid is not None:
            current = json.loads(
                k.checked(
                    k.kube(
                        ["get", "namespace", TEST_NAMESPACE, "-o", "json"],
                        namespace=None,
                    )
                )
            )
            meta = current["metadata"]
            if (
                meta.get("uid") != uid
                or meta.get("annotations", {}).get(MARKER) != marker
                or meta.get("labels", {}).get("app.kubernetes.io/part-of") != "security-lab"
            ):
                raise FixtureError("Synthetic cleanup ownership refused")
            ui.stop()
            k.checked(
                k.kube(
                    ["delete", "--raw", "/api/v1/namespaces/" + TEST_NAMESPACE, "-f", "-"],
                    namespace=None,
                    input_text=json.dumps(
                        {
                            "apiVersion": "v1",
                            "kind": "DeleteOptions",
                            "preconditions": {
                                "uid": uid,
                                "resourceVersion": meta["resourceVersion"],
                            },
                        }
                    ),
                )
            )
            k.checked(
                k.kube(
                    ["wait", "--for=delete", "namespace/" + TEST_NAMESPACE, "--timeout=90s"],
                    namespace=None,
                    timeout=100,
                )
            )
            identity.PROFILE.unlink(missing_ok=True)
            identity.ACCOUNTS.unlink(missing_ok=True)


def main():
    lab = None
    try:
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
        from agent_security_lab.cli import Lab, write

        lab = Lab()
        if os.environ.get("LIMA_HOME") != str(lab.owned()):
            raise FixtureError("Owned runtime required")
        if Path.cwd().resolve() != lab.verify("mcp-svid-auth").resolve():
            raise FixtureError("Locked component checkout required")
        os.environ["SVID_IDENTITY_PROFILE"] = "isolated"
        sys.path.insert(0, str(Path.cwd()))
        from scripts import kubernetes_demo as k
        from scripts import kubernetes_ui as ui
        from scripts import run_google_setup_demo, run_identity_demo
        from scripts import zitadel_demo as identity

        k.verify_instance()
        exercise(k, identity, ui, (run_identity_demo, run_google_setup_demo))
    except Exception as error:
        if lab is not None:
            write(
                lab.data / "private-review/identity-location.json",
                {
                    "type": type(error).__name__,
                    "frames": [
                        {
                            "file": Path(frame.filename).name,
                            "function": frame.name,
                            "line": frame.lineno,
                        }
                        for frame in traceback.extract_tb(error.__traceback__)[-16:]
                        if Path(frame.filename).resolve().is_relative_to(lab.root)
                    ],
                },
            )
        print("Synthetic identity acceptance failed; details remain private", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
