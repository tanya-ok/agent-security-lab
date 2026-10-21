# SPDX-FileCopyrightText: 2026 Tanya Babitskaya
# SPDX-License-Identifier: Apache-2.0
"""Issuer-only relay over the owned Kubernetes exec channel, without pod changes."""

import base64
import concurrent.futures
import contextlib
import http.client
import json
import signal
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from agent_security_lab.cli import Lab, LabError  # noqa: E402
from agent_security_lab.services import Services  # noqa: E402
from agent_security_lab.sso import MAX_BODY, POD_RELAY, allowed_request  # noqa: E402


def run():
    lab = Lab(ROOT)
    lab.verify("it-grc")
    services = Services(lab)
    target = services.target("grc-backend")
    services.controller(target)
    process = subprocess.Popen(
        services.command(
            target,
            "-n",
            "it-grc",
            "exec",
            "-i",
            "deployment/" + target["controller"],
            "-c",
            "backend",
            "--",
            "python",
            "-u",
            "-c",
            POD_RELAY,
        ),
        env=lab.env(),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    lock = threading.Lock()
    ready = threading.Event()
    stopped = threading.Event()

    def forward(value):
        connection = None
        answer = {"id": value["id"], "status": 503, "headers": {}, "body": ""}
        try:
            if not allowed_request(value["method"], value["target"], value["host"]):
                answer["status"] = 403
            else:
                body = base64.b64decode(value["body"], validate=True)
                if len(body) > MAX_BODY:
                    raise ValueError
                headers = {
                    k: v
                    for k, v in value["headers"].items()
                    if k.lower()
                    in {
                        "accept",
                        "content-type",
                        "authorization",
                    }
                }
                headers["Host"] = "localhost:4467"
                connection = http.client.HTTPConnection("127.0.0.1", 4467, timeout=12)
                connection.request(value["method"], value["target"], body=body, headers=headers)
                response = connection.getresponse()
                data = response.read(MAX_BODY + 1)
                if len(data) > MAX_BODY:
                    raise ValueError
                answer.update(
                    status=response.status,
                    headers={
                        k: v
                        for k, v in response.getheaders()
                        if k.lower()
                        in {
                            "content-type",
                            "cache-control",
                        }
                    },
                    body=base64.b64encode(data).decode("ascii"),
                )
        except (OSError, ValueError, http.client.HTTPException):
            pass
        finally:
            if connection:
                connection.close()
        with lock:
            with contextlib.suppress(OSError, ValueError):
                process.stdin.write(json.dumps(answer).encode("utf-8") + b"\n")
                process.stdin.flush()

    def receive():
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                for line in iter(lambda: process.stdout.readline(MAX_BODY * 2), b""):
                    value = json.loads(line)
                    if value == {"ready": True}:
                        ready.set()
                    else:
                        pool.submit(forward, value)
        except (OSError, ValueError):
            pass
        finally:
            stopped.set()

    signal.signal(signal.SIGTERM, lambda *_: stopped.set())
    signal.signal(signal.SIGINT, lambda *_: stopped.set())
    thread = threading.Thread(target=receive, daemon=True)
    thread.start()
    try:
        if not ready.wait(25) or stopped.is_set():
            raise LabError("Local SSO backchannel unavailable")

        class Health(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_GET(self):
                self.send_response(200 if process.poll() is None else 503)
                self.send_header("Content-Type", "application/json")
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(b'{"relay":"running"}')

        with HTTPServer(("127.0.0.1", 18881), Health) as server:
            server.timeout = 0.5
            while not stopped.is_set() and process.poll() is None:
                with lock:
                    process.stdin.write(b'{"ping":true}\n')
                    process.stdin.flush()
                server.handle_request()
    finally:
        process.stdin.close()
        with contextlib.suppress(subprocess.TimeoutExpired):
            process.wait(timeout=5)
        if process.poll() is None:
            process.terminate()
            with contextlib.suppress(subprocess.TimeoutExpired):
                process.wait(timeout=5)
        if process.poll() is None:
            process.kill()
            process.wait()


if __name__ == "__main__":
    try:
        run()
    except Exception:
        print("Local SSO backchannel unavailable; diagnostics remain private")
        raise SystemExit(1) from None
