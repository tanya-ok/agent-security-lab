# SPDX-FileCopyrightText: 2026 Tanya Babitskaya
# SPDX-License-Identifier: Apache-2.0
"""Optional lab-owned console overlay; the pinned component remains unchanged."""

import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from agent_security_lab.cli import Lab, read  # noqa: E402
from agent_security_lab.identity_access import route  # noqa: E402


def create_proxy():
    import httpx2
    from scripts.oidc_gate import FLOW_COOKIE, SESSION_COOKIE
    from scripts.zitadel_demo import API_BACKEND, LOGIN_BACKEND
    from starlette.applications import Starlette
    from starlette.background import BackgroundTask
    from starlette.responses import JSONResponse, StreamingResponse
    from starlette.routing import Route

    config = read(ROOT / ".data/identity-access.json")
    clients = config["clients"]

    async def dispatch(request):
        target = route(
            request.method, request.url.path, request.headers, request.url.query, clients
        )
        if target is None:
            return JSONResponse({"error": "local_access_only"}, status_code=403)
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > 131072:
                return JSONResponse({"error": "request_too_large"}, status_code=413)
        allowed = {
            "accept",
            "accept-encoding",
            "content-type",
            "user-agent",
            "origin",
            "rsc",
            "next-action",
            "next-router-state-tree",
            "next-router-prefetch",
            "next-url",
            "authorization",
            "x-grpc-web",
            "x-user-agent",
            "grpc-timeout",
            "x-zitadel-orgid",
        }
        headers = {k: v for k, v in request.headers.items() if k.lower() in allowed}
        if target == "login":
            headers.pop("authorization", None)
        cookies = [
            c.strip()
            for c in request.headers.get("cookie", "").split(";")
            if c.split("=", 1)[0].strip() not in {SESSION_COOKIE, FLOW_COOKIE}
        ]
        if any(cookies):
            headers["Cookie"] = "; ".join(cookies)
        headers.update({"Host": "localhost:4467", "X-Forwarded-Proto": "http"})
        client = httpx2.AsyncClient(trust_env=False, follow_redirects=False, timeout=30)
        url = (LOGIN_BACKEND if target == "login" else API_BACKEND) + request.url.path
        if request.url.query:
            url += "?" + request.url.query
        try:
            upstream = await client.send(
                client.build_request(request.method, url, headers=headers, content=bytes(body)),
                stream=True,
            )
        except httpx2.HTTPError:
            await client.aclose()
            return JSONResponse({"error": "identity_unavailable"}, status_code=503)

        async def close():
            await upstream.aclose()
            await client.aclose()

        response = StreamingResponse(
            upstream.aiter_raw(),
            status_code=upstream.status_code,
            headers={
                k: v
                for k, v in upstream.headers.items()
                if k.lower()
                in {
                    "content-type",
                    "content-encoding",
                    "location",
                    "x-action-redirect",
                    "x-action-revalidated",
                    "grpc-status",
                    "grpc-message",
                    "content-disposition",
                    "content-security-policy",
                    "x-frame-options",
                    "permissions-policy",
                }
            },
            background=BackgroundTask(close),
        )
        for cookie in upstream.headers.get_list("set-cookie"):
            if cookie.split("=", 1)[0].strip() not in {SESSION_COOKIE, FLOW_COOKIE}:
                response.raw_headers.append((b"set-cookie", cookie.encode("latin1")))
        response.headers.update(
            {
                "Cache-Control": "no-store",
                "Referrer-Policy": "no-referrer",
                "X-Content-Type-Options": "nosniff",
            }
        )
        return response

    return Starlette(
        routes=[
            Route(
                "/{path:path}",
                dispatch,
                methods=["GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
            )
        ]
    )


def main():
    lab = Lab(ROOT)
    repo = lab.verify("mcp-svid-auth")
    if Path.cwd() != repo:
        raise ValueError("Identity overlay requires the verified source directory")
    sys.path.insert(0, str(repo))
    from scripts import kubernetes_ui as ui

    ui.create_proxy = create_proxy
    if sys.argv[1:] == ["serve"]:
        ui.serve()
        return
    if sys.argv[1:] != ["start"]:
        raise ValueError("Unsupported identity overlay operation")
    ui.configured_identity()
    with ui.launch_lock():
        if ui.running():
            return
        ui.check_ports()
        ui.SESSION.unlink(missing_ok=True)
        process = subprocess.Popen(
            [sys.executable, str(Path(__file__).resolve()), "serve"],
            cwd=repo,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        deadline = time.monotonic() + 300
        try:
            while process.poll() is None and time.monotonic() < deadline:
                if ui.running():
                    return
                time.sleep(0.2)
            raise ValueError("Identity overlay startup failed")
        except Exception:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            raise


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("Local identity access unavailable; diagnostics remain private")
        raise SystemExit(1) from None
