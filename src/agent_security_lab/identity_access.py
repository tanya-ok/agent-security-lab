# SPDX-FileCopyrightText: 2026 Tanya Babitskaya
# SPDX-License-Identifier: Apache-2.0
"""Opt-in, fixed-origin routing policy for owner-approved local identity access."""

import re
from urllib.parse import parse_qs, unquote

ISSUER = "http://localhost:4467"
GRC = "https://localhost:18443"
PANEL = "http://localhost:4466"
PUBLIC = {
    "/.well-known/openid-configuration",
    "/oauth/v2/authorize",
    "/oauth/v2/token",
    "/oauth/v2/keys",
    "/oidc/v1/userinfo",
    "/oidc/v1/end_session",
    "/idps/callback",
}


def route(method, path, headers, query, clients):
    """Return an upstream name or refuse; never supply authentication credentials."""
    path = unquote(path)
    origin = headers.get("origin")
    if (
        headers.get("host") != "localhost:4467"
        or origin not in {None, ISSUER, PANEL, GRC}
        or "\\" in path
        or "%" in path
        or any(p in {".", ".."} for p in path.split("/"))
        or "//" in path
    ):
        return None
    authorization = headers.get("authorization")
    if authorization and not authorization.startswith("Bearer "):
        return None
    login = path == "/ui/v2/login" or path.startswith("/ui/v2/login/")
    console = path == "/ui/console" or path.startswith("/ui/console/")
    api = bool(re.fullmatch(r"/zitadel\.(?:auth|management|admin)\.v1\.[A-Za-z]+/[A-Za-z]+", path))
    if console:
        return "api" if method in {"GET", "HEAD"} else None
    if api:
        return (
            "api"
            if method == "POST"
            and origin == ISSUER
            and headers.get("authorization", "").startswith("Bearer ")
            and headers.get("content-type", "").startswith("application/grpc-web")
            else None
        )
    if login and method == "POST" and origin != ISSUER:
        return None
    if not login and path not in PUBLIC:
        return None
    if method not in {"GET", "HEAD", "POST"}:
        return None
    if headers.get("sec-fetch-site") == "cross-site":
        # Cross-scheme GRC-to-issuer navigation is a valid local SSO entry.
        params = parse_qs(query)
        authorization = (
            path == "/oauth/v2/authorize"
            and len(params.get("client_id", [])) == 1
            and len(params.get("redirect_uri", [])) == 1
            and clients.get(params["client_id"][0]) == params["redirect_uri"][0]
        )
        navigation = headers.get("sec-fetch-mode") == "navigate" and method == "GET"
        if not (navigation and (authorization or login or path == "/idps/callback")):
            return None
    if origin == GRC and path != "/oauth/v2/authorize":
        return None
    return "login" if login else "api"
