"""End-to-end checks against the disposable test stack (test-stack/README.md).

Runs inside the mcp-mail-oauth image, on the stack's network. Users get their
tokens the way Open WebUI's do (client `openwebui`, the realm's default
scopes), here via the password grant instead of a browser. Each check names
the link in the chain it proves; the first failure stops the run.
"""

from __future__ import annotations

import asyncio
import base64
import dataclasses
import json
import os
import smtplib
import sys
import time
import uuid

import httpx2
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport
from fastmcp.exceptions import ToolError

from mcp_mail import mail
from mcp_mail.config import load

OIDC = os.environ.get("KEYCLOAK_URL", "http://keycloak:8080") + "/realms/mail/protocol/openid-connect"
MCP_URL = os.environ.get("MCP_URL", "http://mcp-mail:8000/mcp")
CLIENT = {"client_id": "openwebui", "client_secret": "openwebui-test-secret"}
ALL_TOOLS = {"whoami", "list_folders", "list_messages", "search_messages", "read_message", "send_message"}

passed = 0


def check(description: str, condition: bool, detail: object = "") -> None:
    global passed
    if not condition:
        print(f"FAIL  {description}\n      {detail}", flush=True)
        sys.exit(1)
    passed += 1
    print(f"ok    {description}", flush=True)


def login(username: str) -> dict:
    resp = httpx2.post(f"{OIDC}/token", data={
        **CLIENT, "grant_type": "password", "username": username, "password": username,
        "scope": "openid email",
    })
    check(f"Keycloak issues a token for {username}", resp.status_code == 200, resp.text)
    return resp.json()


def claims(token: str) -> dict:
    payload = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))


def mcp(token: str) -> Client:
    return Client(StreamableHttpTransport(MCP_URL, headers={"Authorization": f"Bearer {token}"}))


async def tool(token: str, name: str, **arguments) -> dict:
    async with mcp(token) as client:
        return (await client.call_tool(name, arguments)).structured_content


async def main() -> None:
    settings = load()

    # ── Keycloak: the token Open WebUI would forward ──────────────────────────
    alice = login("alice")
    c = claims(alice["access_token"])
    aud = c["aud"] if isinstance(c["aud"], list) else [c["aud"]]
    check("token audience names mcp-mail and dovecot (mail scope's mappers)",
          {"mcp-mail", "dovecot"} <= set(aud), c)
    check("token carries mail, mcp:mail/read, mcp:mail/send as default scopes",
          {"mail", "mcp:mail/read", "mcp:mail/send"} <= set(c["scope"].split()), c["scope"])
    check("token issuer is the configured OIDC_ISSUER", c["iss"] == settings.oidc_issuer, c["iss"])
    token = alice["access_token"]

    # ── MCP server: JWT verification and scope-based tool list ────────────────
    async with mcp(token) as client:
        names = {t.name for t in await client.list_tools()}
    check("MCP server accepts the token and lists all six tools", names == ALL_TOOLS, names)
    me = await tool(token, "whoami")
    check("whoami maps the token to alice@example.com", me["mailbox"] == "alice@example.com", me)

    # ── IMAP: Dovecot validates the same token by introspection ───────────────
    resp = httpx2.post(f"{OIDC}/token/introspect", data={"token": token},
                       auth=("dovecot", "dovecot-test-secret"))
    answer = resp.json() if resp.status_code == 200 else {}
    check("Keycloak introspection as the dovecot client: active, with the email claim",
          answer.get("active") is True and answer.get("email") == "alice@example.com",
          {"status": resp.status_code, "keys": sorted(answer)})
    folders = await tool(token, "list_folders")
    names = {f["name"] for f in folders["result"]} if isinstance(folders, dict) and "result" in folders else \
        {f["name"] for f in folders}
    check("IMAP login with the forwarded token (XOAUTH2, Dovecot oauth2)", {"INBOX", "Sent"} <= names, names)

    # ── SMTP: Postfix SASL via Dovecot, LMTP delivery, Sent copy ──────────────
    subject = f"e2e {uuid.uuid4()}"
    sent = await tool(token, "send_message", to=["bob@example.com"], subject=subject, body="hello from the test stack")
    check("SMTP submission with the forwarded token (Postfix -> Dovecot auth)", sent["status"] == "sent", sent)
    check("copy saved to Sent", sent.get("saved_to") == "Sent", sent)

    bob = login("bob")["access_token"]
    found: dict = {"total": 0}
    for _ in range(30):
        found = await tool(bob, "search_messages", subject=subject)
        if found["total"]:
            break
        await asyncio.sleep(1)
    check("message delivered to bob's INBOX (LMTP)", found["total"] == 1, found)
    message = await tool(bob, "read_message", uid=found["messages"][0]["uid"])
    check("bob reads it: From alice, body intact",
          "alice@example.com" in message["from"] and "hello from the test stack" in message["body"], message)
    mine = await tool(token, "search_messages", subject=subject)
    check("mailboxes are per user: not in alice's INBOX", mine["total"] == 0, mine)
    mine = await tool(token, "search_messages", folder="Sent", subject=subject)
    check("but in alice's Sent", mine["total"] == 1, mine)

    # ── The other SASL mechanism, without the MCP layer ───────────────────────
    bearer = dataclasses.replace(settings.mail, sasl_mechanism="OAUTHBEARER")
    folders = await asyncio.to_thread(mail.list_folders, bearer, "alice@example.com", token)
    check("IMAP login with OAUTHBEARER", any(f["name"] == "INBOX" for f in folders), folders)
    with mail.smtp_session(bearer, "alice@example.com", token):
        pass
    check("SMTP login with OAUTHBEARER", True)

    # ── Postfix: a user can only send as themselves ───────────────────────────
    refused = None
    try:
        with mail.smtp_session(settings.mail, "alice@example.com", token) as smtp:
            smtp.sendmail("bob@example.com", ["bob@example.com"], f"Subject: {subject} spoof\r\n\r\nx")
    except (smtplib.SMTPSenderRefused, smtplib.SMTPRecipientsRefused) as exc:
        refused = exc
    check("Postfix refuses a sender address other than the login (reject_sender_login_mismatch)",
          refused is not None, "spoofed sender was accepted")

    # ── Revocation: Dovecot asks Keycloak every time (force_introspection) ────
    resp = httpx2.post(f"{OIDC}/logout", data={**CLIENT, "refresh_token": alice["refresh_token"]})
    check("Keycloak ends alice's session", resp.status_code == 204, resp.text)
    try:
        await tool(token, "list_folders")
        rejected, detail = False, "IMAP login still worked after logout"
    except ToolError as exc:
        rejected, detail = "IMAP authentication failed" in str(exc), str(exc)
    check("after logout, Dovecot rejects the still-unexpired token", rejected, detail)

    # ── Tokens the MCP server must not accept ─────────────────────────────────
    resp = httpx2.post(MCP_URL, json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                       headers={"Accept": "application/json, text/event-stream"})
    check("no token: 401 with resource metadata",
          resp.status_code == 401 and "resource_metadata" in resp.headers.get("www-authenticate", ""), resp.status_code)
    tampered = bob[:-4] + ("AAAA" if not bob.endswith("AAAA") else "BBBB")
    resp = httpx2.post(MCP_URL, json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                       headers={"Accept": "application/json, text/event-stream", "Authorization": f"Bearer {tampered}"})
    check("token with a broken signature: 401", resp.status_code == 401, resp.status_code)

    print(f"\nall {passed} checks passed", flush=True)


if __name__ == "__main__":
    started = time.monotonic()
    asyncio.run(main())
    print(f"({time.monotonic() - started:.1f}s)")
