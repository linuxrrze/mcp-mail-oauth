"""Sub-directory deployment behind a prefix-stripping reverse proxy
(docs/reverse-proxy.md). These pin down the URLs FastMCP generates from a
BASE_URL with a path, since the documented proxy rules depend on them."""

import asyncio
from unittest import mock

import httpx2
import pytest

from mcp_mail import auth as auth_module
from mcp_mail.config import load
from mcp_mail.server import create_server, http_middleware

from .conftest import BASE_ENV, ISSUER

PUBLIC = "https://ai.example.com/mcp/mail-oauth"
HEADERS = {"Accept": "application/json, text/event-stream"}


async def _serve(app, requests):
    """Run the app's lifespan in its own task (see test_server_http.py)."""
    ready, stop = asyncio.Event(), asyncio.Event()

    async def run():
        async with app.router.lifespan_context(app):
            ready.set()
            await stop.wait()

    task = asyncio.create_task(run())
    await ready.wait()
    try:
        # Requests arrive as the proxy forwards them: prefix stripped, internal host.
        async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app), base_url="http://mcp-mail:8000") as c:
            return await requests(c)
    finally:
        stop.set()
        await task


def _app(settings, verifier, provider=None):
    provider = provider or auth_module.build_auth(settings, verifier)
    return create_server(settings, provider).http_app(path="/mcp", stateless_http=True, json_response=True,
                                                      middleware=http_middleware(settings))


async def test_resource_mode_under_prefix(keypair, make_token):
    settings = load({**BASE_ENV, "BASE_URL": PUBLIC})
    app = _app(settings, auth_module.build_token_verifier(settings, public_key=keypair.public_key))

    async def requests(c):
        anonymous = await c.post("/mcp", headers=HEADERS, json={})
        authed = await c.post("/mcp", headers={**HEADERS, "Authorization": f"Bearer {make_token()}"},
                              json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
        # Forwarded unchanged by the proxy (root path + resource path).
        metadata = await c.get("/.well-known/oauth-protected-resource/mcp/mail-oauth/mcp")
        slash = await c.post("/mcp/", headers={**HEADERS, "Authorization": f"Bearer {make_token()}"},
                             json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
        root = await c.post("/", headers=HEADERS, json={})
        return anonymous, authed, metadata, slash, root

    anonymous, authed, metadata, slash, root = await _serve(app, requests)
    assert anonymous.status_code == 401
    assert ('resource_metadata="https://ai.example.com/.well-known/oauth-protected-resource/mcp/mail-oauth/mcp"'
            in anonymous.headers["www-authenticate"])
    assert authed.status_code == 200
    assert metadata.json()["resource"] == PUBLIC + "/mcp"
    # A trailing slash is served, not redirected: a redirect would point at the
    # internal host without the prefix (http://mcp-mail:8000/mcp).
    assert slash.status_code == 200, slash.text
    assert {t["name"] for t in slash.json()["result"]["tools"]} >= {"whoami"}
    # The prefix alone (Open WebUI URL without /mcp) names the real endpoint.
    assert root.status_code == 404
    assert PUBLIC + "/mcp" in root.text


DISCOVERY = {
    "issuer": ISSUER,
    "authorization_endpoint": ISSUER + "/protocol/openid-connect/auth",
    "token_endpoint": ISSUER + "/protocol/openid-connect/token",
    "jwks_uri": ISSUER + "/protocol/openid-connect/certs",
    "userinfo_endpoint": ISSUER + "/protocol/openid-connect/userinfo",
    "response_types_supported": ["code"],
    "subject_types_supported": ["public"],
    "id_token_signing_alg_values_supported": ["RS256"],
}


async def test_proxy_mode_under_prefix(keypair, tmp_path, monkeypatch):
    monkeypatch.setattr("fastmcp.settings.home", tmp_path)  # OIDCProxy's encrypted store
    settings = load({**BASE_ENV, "BASE_URL": PUBLIC, "AUTH_MODE": "proxy", "OIDC_CLIENT_ID": "mcp-mail",
                     "OIDC_CLIENT_SECRET": "secret", "JWT_SIGNING_KEY": "k" * 32})
    verifier = auth_module.build_token_verifier(settings, public_key=keypair.public_key)
    discovery = httpx2.Response(200, json=DISCOVERY, request=httpx2.Request("GET", ISSUER))
    with mock.patch("httpx2.get", return_value=discovery):
        provider = auth_module.build_auth(settings, verifier)
    app = _app(settings, verifier, provider)

    async def requests(c):
        # Rewritten by the proxy from /.well-known/oauth-authorization-server/mcp/mail-oauth.
        return await c.get("/.well-known/oauth-authorization-server")

    metadata = (await _serve(app, requests)).json()
    assert metadata["issuer"].rstrip("/") == PUBLIC
    for key, path in [("authorization_endpoint", "/authorize"), ("token_endpoint", "/token"),
                      ("registration_endpoint", "/register")]:
        assert metadata[key] == PUBLIC + path
    # Keycloak's redirect URI for the mcp-mail client.
    assert str(provider.base_url).rstrip("/") + provider._redirect_path == PUBLIC + "/auth/callback"


@pytest.mark.parametrize("path", ["/auth/callback", "/authorize", "/token", "/register", "/consent"])
async def test_proxy_mode_routes_exist_without_prefix(keypair, tmp_path, monkeypatch, path):
    """After StripPrefix, the OAuth endpoints must exist at the bare paths."""
    monkeypatch.setattr("fastmcp.settings.home", tmp_path)
    settings = load({**BASE_ENV, "BASE_URL": PUBLIC, "AUTH_MODE": "proxy", "OIDC_CLIENT_ID": "mcp-mail",
                     "OIDC_CLIENT_SECRET": "secret", "JWT_SIGNING_KEY": "k" * 32})
    verifier = auth_module.build_token_verifier(settings, public_key=keypair.public_key)
    discovery = httpx2.Response(200, json=DISCOVERY, request=httpx2.Request("GET", ISSUER))
    with mock.patch("httpx2.get", return_value=discovery):
        app = _app(settings, verifier)
    assert path in {getattr(route, "path", None) for route in app.routes}
