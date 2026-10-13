"""End-to-end through the real HTTP stack: FastMCP's auth middleware, the
JWT verifier (issuer/audience/signature/expiry), per-tool scope filtering,
and the tools. Only the IMAP/SMTP layer (mcp_mail.mail) is replaced."""

import asyncio
import json

import httpx2
import pytest

from mcp_mail import auth as auth_module
from mcp_mail import mail
from mcp_mail.server import create_server

HEADERS = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}


@pytest.fixture
def app(settings, keypair):
    verifier = auth_module.build_token_verifier(settings, public_key=keypair.public_key)
    mcp = create_server(settings, auth=auth_module.build_auth(settings, verifier))
    return mcp.http_app(path="/mcp", stateless_http=True, json_response=True)


@pytest.fixture
async def client(app):
    # The lifespan (it starts the MCP session manager's task group) must be
    # entered and exited in one task; pytest-asyncio runs fixture setup and
    # teardown in different ones, so it gets a task of its own.
    ready, stop = asyncio.Event(), asyncio.Event()

    async def run_lifespan():
        async with app.router.lifespan_context(app):
            ready.set()
            await stop.wait()

    task = asyncio.create_task(run_lifespan())
    await ready.wait()
    transport = httpx2.ASGITransport(app=app)
    async with httpx2.AsyncClient(transport=transport, base_url="https://mcp-mail.example.com") as c:
        yield c
    stop.set()
    await task


async def rpc(client, token, method, params=None):
    headers = dict(HEADERS)
    if token:
        headers["Authorization"] = f"Bearer {token}"
    body = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}
    return await client.post("/mcp", headers=headers, content=json.dumps(body))


async def tool_names(client, token):
    resp = await rpc(client, token, "tools/list")
    assert resp.status_code == 200, resp.text
    return {t["name"] for t in resp.json()["result"]["tools"]}


async def call(client, token, name, arguments=None):
    resp = await rpc(client, token, "tools/call", {"name": name, "arguments": arguments or {}})
    assert resp.status_code == 200, resp.text
    return resp.json()["result"]


# ── Who gets in ───────────────────────────────────────────────────────────────

async def test_no_token_is_401_with_resource_metadata(client):
    resp = await rpc(client, None, "tools/list")
    assert resp.status_code == 401
    assert "resource_metadata" in resp.headers["www-authenticate"]


async def test_protected_resource_metadata_names_keycloak(client, settings):
    resp = await client.get("/.well-known/oauth-protected-resource/mcp")
    assert resp.status_code == 200
    body = resp.json()
    assert body["resource"] == "https://mcp-mail.example.com/mcp"
    assert body["authorization_servers"] == [settings.oidc_issuer]
    assert set(body["scopes_supported"]) == {"mcp:mail/read", "mcp:mail/send", "mcp:mail/draft", "mcp:mail/organize"}


@pytest.mark.parametrize("override", [
    {"audience": ["dovecot"]},                                # not meant for this server
    {"issuer": "https://evil.example/realms/mail"},           # other issuer
    {"expires_in": -120},                                     # expired
])
async def test_rejected_tokens(client, make_token, override):
    assert (await rpc(client, make_token(**override), "tools/list")).status_code == 401


async def test_token_signed_by_another_key_is_rejected(client):
    from fastmcp.server.auth.providers.jwt import RSAKeyPair

    from .conftest import ISSUER

    foreign = RSAKeyPair.generate().create_token(issuer=ISSUER, audience=["mcp-mail"], scopes=["mcp:mail/read"])
    assert (await rpc(client, foreign, "tools/list")).status_code == 401


async def test_healthz_needs_no_token(client):
    assert (await client.get("/healthz")).text == "ok"


# ── Protocol versions ─────────────────────────────────────────────────────────

# Open WebUI and most MCP clients still run the initialize handshake of the
# 2025 protocol versions; MCP SDK v2 (FastMCP 4) must keep serving them.
@pytest.mark.parametrize("version", ["2025-03-26", "2025-06-18", "2025-11-25"])
async def test_handshake_era_clients(client, make_token, version):
    token = make_token()
    init = await rpc(client, token, "initialize", {
        "protocolVersion": version, "capabilities": {},
        "clientInfo": {"name": "open-webui", "version": "0"},
    })
    assert init.status_code == 200, init.text
    assert init.json()["result"]["protocolVersion"] == version
    headers = {**HEADERS, "Authorization": f"Bearer {token}", "MCP-Protocol-Version": version}
    body = {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "whoami", "arguments": {}}}
    resp = await client.post("/mcp", headers=headers, content=json.dumps(body))
    assert resp.status_code == 200, resp.text
    assert resp.json()["result"]["structuredContent"]["mailbox"] == "alice@example.com"


# ── Scope-based tool visibility ───────────────────────────────────────────────

async def test_tools_follow_scopes(client, make_token):
    assert await tool_names(client, make_token(scopes=["openid", "email"])) == {"whoami"}
    read = {"whoami", "list_folders", "list_messages", "search_messages", "read_message", "get_message_info",
            "get_thread", "get_attachment", "folder_status"}
    assert await tool_names(client, make_token(scopes=["mcp:mail/read"])) == read
    assert await tool_names(client, make_token(scopes=["mcp:mail/send"])) == {"whoami", "send_message", "forward_message"}
    assert await tool_names(client, make_token(scopes=["mcp:mail/draft"])) == {"whoami", "save_draft"}
    assert await tool_names(client, make_token(scopes=["mcp:mail/organize"])) == {
        "whoami", "set_flags", "move_messages", "trash_messages"}
    assert await tool_names(client, make_token()) == read | {"send_message", "forward_message"}


async def test_get_attachment_returns_an_image_as_image_content(client, make_token, monkeypatch):
    def fake(cfg, username, token, folder, uid, index, max_chars):
        return {"uid": uid, "folder": folder, "index": index, "filename": "a.png", "content_type": "image/png",
                "size": 4, "image": b"\x89PNG"}

    monkeypatch.setattr(mail, "get_attachment", fake)
    result = await call(client, make_token(), "get_attachment", {"uid": "7", "index": 1})
    assert not result.get("isError"), result
    kinds = [c["type"] for c in result["content"]]
    assert kinds == ["text", "image"]
    assert result["content"][1]["mimeType"] == "image/png"
    assert result["structuredContent"]["filename"] == "a.png" and "image" not in result["structuredContent"]


async def test_whoami_explains_missing_scopes(client, make_token):
    result = await call(client, make_token(scopes=["openid", "email"]), "whoami")
    data = result["structuredContent"]
    assert data["mailbox"] == "alice@example.com"
    assert data["client"] == "openwebui"
    assert data["missing_scopes"] == ["mcp:mail/read", "mcp:mail/send", "mcp:mail/draft", "mcp:mail/organize"]
    assert "token" not in json.dumps(data).replace("expires", "")


async def test_calling_tool_without_scope_fails(client, make_token):
    resp = await rpc(client, make_token(scopes=["mcp:mail/read"]), "tools/call",
                     {"name": "send_message", "arguments": {"to": ["b@example.com"], "subject": "s", "body": "b"}})
    body = resp.json()
    assert "error" in body or body["result"].get("isError")


# ── The token is what reaches the mail server ─────────────────────────────────

async def test_mail_layer_gets_the_callers_token_and_email(client, make_token, monkeypatch):
    seen = {}

    def fake_list_messages(cfg, username, token, folder, limit, offset, unread_only):
        seen.update(username=username, token=token, folder=folder, limit=limit)
        return {"folder": folder, "total": 0, "offset": offset, "messages": []}

    monkeypatch.setattr(mail, "list_messages", fake_list_messages)
    token = make_token(email="bob@example.com")
    result = await call(client, token, "list_messages", {"folder": "Archiv", "limit": 5})
    assert not result.get("isError")
    assert seen == {"username": "bob@example.com", "token": token, "folder": "Archiv", "limit": 5}


async def test_with_token_exchange_the_mail_layer_gets_the_exchanged_token(settings, keypair, make_token, monkeypatch):
    """MAIL_TOKEN_EXCHANGE=on: the incoming token never reaches the mail server."""
    seen = {}

    class FakeExchanger:
        async def mail_token(self, subject):
            seen["subject"] = subject
            return "exchanged-mail-token"

    def fake_list_folders(cfg, username, token):
        seen.update(username=username, token=token)
        return []

    monkeypatch.setattr(mail, "list_folders", fake_list_folders)
    verifier = auth_module.build_token_verifier(settings, public_key=keypair.public_key)
    app = create_server(settings, auth=auth_module.build_auth(settings, verifier),
                        exchanger=FakeExchanger()).http_app(path="/mcp", stateless_http=True, json_response=True)
    token = make_token()
    async with app.router.lifespan_context(app):
        async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app), base_url="https://x") as c:
            resp = await rpc(c, token, "tools/call", {"name": "list_folders", "arguments": {}})
    assert resp.status_code == 200 and not resp.json()["result"].get("isError"), resp.text
    assert seen == {"subject": token, "username": "alice@example.com", "token": "exchanged-mail-token"}


async def test_missing_username_claim_is_a_clear_tool_error(client, make_token):
    result = await call(client, make_token(email=None), "list_folders")
    assert result["isError"]
    assert "'email' claim" in result["content"][0]["text"]


@pytest.mark.parametrize("verified", [False, None])
async def test_unverified_email_selects_no_mailbox(client, make_token, monkeypatch, verified):
    monkeypatch.setattr(mail, "list_folders", lambda *a, **k: pytest.fail("must not be called"))
    result = await call(client, make_token(email_verified=verified), "list_folders")
    assert result["isError"]
    assert "not verified" in result["content"][0]["text"]
    who = await call(client, make_token(email_verified=verified), "whoami")
    assert who["structuredContent"]["email_verified"] == verified


async def test_unverified_email_allowed_when_switched_off(settings, keypair, make_token, monkeypatch):
    monkeypatch.setattr(mail, "list_folders", lambda cfg, username, token: [{"name": "INBOX", "flags": []}])
    import dataclasses
    relaxed = dataclasses.replace(settings, mail=dataclasses.replace(settings.mail, require_email_verified=False))
    verifier = auth_module.build_token_verifier(relaxed, public_key=keypair.public_key)
    app = create_server(relaxed, auth=auth_module.build_auth(relaxed, verifier)).http_app(
        path="/mcp", stateless_http=True, json_response=True)
    async with app.router.lifespan_context(app):
        async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app), base_url="https://x") as c:
            resp = await rpc(c, make_token(email_verified=False), "tools/call", {"name": "list_folders", "arguments": {}})
    assert not resp.json()["result"].get("isError"), resp.text


async def test_mail_server_rejection_becomes_tool_error_with_hint(client, make_token, monkeypatch):
    def reject(*args, **kwargs):
        raise mail.MailAuthError("IMAP authentication failed. " + mail._auth_hint())

    monkeypatch.setattr(mail, "list_folders", reject)
    result = await call(client, make_token(), "list_folders")
    assert result["isError"]
    assert "aud" in result["content"][0]["text"]


async def test_limit_is_validated_before_touching_the_mail_server(client, make_token, monkeypatch):
    monkeypatch.setattr(mail, "list_messages", lambda *a, **k: pytest.fail("must not be called"))
    resp = await rpc(client, make_token(), "tools/call", {"name": "list_messages", "arguments": {"limit": 500}})
    body = resp.json()
    assert "error" in body or body["result"]["isError"]


# ── Proxy mode also accepts directly forwarded tokens ─────────────────────────

async def test_proxy_falls_back_to_direct_verification(monkeypatch):
    class Verifier:
        async def verify_token(self, token):
            return f"direct:{token}"

    async def proxy_rejects(self, token):
        return None

    monkeypatch.setattr(auth_module.OIDCProxy, "load_access_token", proxy_rejects)
    proxy = object.__new__(auth_module.ProxyAcceptingDirectTokens)  # skip discovery in __init__
    proxy._direct_verifier = Verifier()
    assert await proxy.load_access_token("kc-token") == "direct:kc-token"


async def test_proxy_prefers_its_own_tokens(monkeypatch):
    async def proxy_accepts(self, token):
        return "proxy"

    monkeypatch.setattr(auth_module.OIDCProxy, "load_access_token", proxy_accepts)
    proxy = object.__new__(auth_module.ProxyAcceptingDirectTokens)
    proxy._direct_verifier = None
    assert await proxy.load_access_token("fastmcp-token") == "proxy"


def test_proxy_keeps_consent_screen_and_explicit_signing_key(monkeypatch):
    """D15/D13: consent must stay on (confused-deputy protection for DCR
    clients) and JWT_SIGNING_KEY must reach the proxy."""
    from mcp_mail.config import load

    from .conftest import BASE_ENV

    captured = {}
    monkeypatch.setattr(auth_module.OIDCProxy, "__init__", lambda self, **kw: captured.update(kw))
    monkeypatch.setattr(auth_module.OIDCProxy, "update_default_scopes", lambda self, scopes: captured.update(default_scopes=scopes))

    settings = load({**BASE_ENV, "AUTH_MODE": "proxy", "OIDC_CLIENT_ID": "mcp-mail",
                     "OIDC_CLIENT_SECRET": "s", "JWT_SIGNING_KEY": "k" * 32})
    provider = auth_module.build_auth(settings, verifier=object())
    assert isinstance(provider, auth_module.ProxyAcceptingDirectTokens)
    assert captured["require_authorization_consent"] is True
    assert captured["jwt_signing_key"] == "k" * 32
    assert captured["config_url"] == settings.oidc_issuer + "/.well-known/openid-configuration"
    assert set(captured["default_scopes"]) >= {"mcp:mail/read", "mcp:mail/send"}
