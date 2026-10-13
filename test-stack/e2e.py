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
import subprocess
import sys
import time
import uuid
from email.message import EmailMessage

import httpx2
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport
from fastmcp.exceptions import ToolError

from mcp_mail import mail
from mcp_mail.auth import build_exchanger
from mcp_mail.config import load

OIDC = os.environ.get("KEYCLOAK_URL", "http://keycloak:8080") + "/realms/mail/protocol/openid-connect"
MCP_URL = os.environ.get("MCP_URL", "http://mcp-mail:8000/mcp")
CLIENT = {"client_id": "openwebui", "client_secret": "openwebui-test-secret"}
ALL_TOOLS = {"whoami", "list_folders", "list_messages", "search_messages", "read_message", "get_message_info",
             "get_thread", "get_attachment", "folder_status", "send_message", "forward_message", "save_draft",
             "set_flags", "move_messages", "trash_messages"}
TOOL_SCOPES = {"mcp:mail/read", "mcp:mail/send", "mcp:mail/draft", "mcp:mail/organize"}

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
    exchange = settings.token_exchange
    print(f"mode: MAIL_TOKEN_EXCHANGE={'on' if exchange else 'off'}", flush=True)
    alice = login("alice")
    c = claims(alice["access_token"])
    aud = set(c["aud"] if isinstance(c["aud"], list) else [c["aud"]])
    scopes = set(c["scope"].split())
    if exchange:
        check("token audience is mcp-mail only, not dovecot (tool scopes' mappers)",
              "mcp-mail" in aud and "dovecot" not in aud, c)
        check("token carries the four mcp:mail/* scopes but not mail",
              TOOL_SCOPES <= scopes and "mail" not in scopes, c["scope"])
    else:
        check("token audience names mcp-mail and dovecot (mail scope's mappers)", {"mcp-mail", "dovecot"} <= aud, c)
        check("token carries mail and the four mcp:mail/* scopes as default scopes",
              {"mail"} | TOOL_SCOPES <= scopes, c["scope"])
    check("token issuer is the configured OIDC_ISSUER", c["iss"] == settings.oidc_issuer, c["iss"])
    token = alice["access_token"]

    # ── MCP server: JWT verification and scope-based tool list ────────────────
    async with mcp(token) as client:
        names = {t.name for t in await client.list_tools()}
    check("MCP server accepts the token and lists all fifteen tools", names == ALL_TOOLS, names)
    me = await tool(token, "whoami")
    check("whoami maps the token to alice@example.com", me["mailbox"] == "alice@example.com", me)

    # ── IMAP: Dovecot validates the same token by introspection ───────────────
    def introspect(t: str) -> dict:
        resp = httpx2.post(f"{OIDC}/token/introspect", data={"token": t}, auth=("dovecot", "dovecot-test-secret"))
        return resp.json() if resp.status_code == 200 else {"status": resp.status_code}

    if exchange:
        # The point of the mode: what Open WebUI holds doesn't open the mailbox.
        answer = introspect(token)
        check("Keycloak introspection as dovecot: Open WebUI's token is NOT active for Dovecot",
              answer.get("active") is False, sorted(answer))
        try:
            await asyncio.to_thread(mail.list_folders, settings.mail, "alice@example.com", token)
            direct = "IMAP login succeeded"
        except mail.MailAuthError:
            direct = None
        check("Open WebUI's token alone can't log in to IMAP", direct is None, direct)
        mail_token = await build_exchanger(settings).mail_token(token)
        mc = claims(mail_token)
        maud = set(mc["aud"] if isinstance(mc["aud"], list) else [mc["aud"]])
        check("exchanged token: issued to mcp-mail, audience dovecot, scope mail, same user",
              mc.get("azp") == "mcp-mail" and "dovecot" in maud and "mail" in mc["scope"].split()
              and mc.get("email") == "alice@example.com" and mc.get("sub") == c.get("sub"),
              {k: mc.get(k) for k in ("azp", "aud", "scope", "email")})
    else:
        mail_token = token
    answer = introspect(mail_token)
    check("Keycloak introspection as dovecot: the mail token is active, with the email claim",
          answer.get("active") is True and answer.get("email") == "alice@example.com", sorted(answer))
    folders = await tool(token, "list_folders")
    names = {f["name"] for f in folders["result"]} if isinstance(folders, dict) and "result" in folders else \
        {f["name"] for f in folders}
    check("list_folders: IMAP login with the mail token (XOAUTH2, Dovecot oauth2)", {"INBOX", "Sent"} <= names, names)

    # ── SMTP: Postfix SASL via Dovecot, LMTP delivery, Sent copy ──────────────
    subject = f"e2e {uuid.uuid4()}"
    # The display name carries an address: it must stay a name (security review, finding 1).
    sent = await tool(token, "send_message", to=['"Bob, alice@example.com" <bob@example.com>'], subject=subject,
                      body="hello from the test stack")
    check("send_message: SMTP submission with the mail token (Postfix -> Dovecot auth)", sent["status"] == "sent", sent)
    check("copy saved to Sent", sent.get("saved_to") == "Sent", sent)

    bob = login("bob")["access_token"]
    found: dict = {"total": 0}
    for _ in range(30):
        found = await tool(bob, "search_messages", subject=subject)
        if found["total"]:
            break
        await asyncio.sleep(1)
    check("message delivered to bob's INBOX (LMTP)", found["total"] == 1, found)
    found_bob = found
    message = await tool(bob, "read_message", uid=found["messages"][0]["uid"])
    check("bob reads it: From alice, body intact",
          "alice@example.com" in message["from"] and "hello from the test stack" in message["body"], message)
    mine = await tool(token, "search_messages", subject=subject)
    check("mailboxes are per user: not in alice's INBOX", mine["total"] == 0, mine)
    mine = await tool(token, "search_messages", folder="Sent", subject=subject)
    check("but in alice's Sent", mine["total"] == 1, mine)

    # ── Large message: structure only, never the attachment ───────────────────
    big = EmailMessage()
    big["From"], big["To"], big["Subject"] = "carol@example.com", "alice@example.com", f"{subject} big"
    big.set_content("Grüße, siehe Anhang.\n" * 50, cte="quoted-printable")
    big.add_alternative("<p>Gr&uuml;&szlig;e</p>", subtype="html")
    big.add_attachment(os.urandom(3_000_000), maintype="application", subtype="octet-stream",
                       filename="Bericht März.bin")
    big.add_attachment("Notiz: Termin am Freitag\n", filename="notiz.txt")
    with mail.imap_session(settings.mail, "alice@example.com", mail_token) as conn:
        conn.append('"INBOX"', None, None, big.as_bytes())
    found = await tool(token, "search_messages", subject=f"{subject} big")
    uid = found["messages"][0]["uid"]
    info = await tool(token, "get_message_info", uid=uid)
    check("get_message_info: attachment name (RFC 2231), type and size, no body",
          "body" not in info and info["body_type"] == "text/plain"
          and [(a["filename"], a["content_type"]) for a in info["attachments"]]
          == [("Bericht März.bin", "application/octet-stream"), ("notiz.txt", "text/plain")]
          and abs(info["attachments"][0]["size"] - 3_000_000) < 50_000, info)
    started_read = time.monotonic()
    message = await tool(token, "read_message", uid=uid, max_chars=30)
    check("read_message on a 4 MB message: QP text part decoded and cut, attachment listed",
          message["body"] == ("Grüße, siehe Anhang.\n" * 2)[:30] and message["body_truncated"]
          and len(message["attachments"]) == 2, {k: message[k] for k in ("body", "body_truncated", "attachments")})
    print(f"      ({time.monotonic() - started_read:.2f}s)", flush=True)
    note = await tool(token, "get_attachment", uid=uid, index=2)
    check("get_attachment: a text attachment's content", note["text"] == "Notiz: Termin am Freitag\n", note)
    try:
        await tool(token, "get_attachment", uid=uid, index=1)
        refused = "binary attachment was returned"
    except ToolError as exc:
        refused = None if "can't be shown" in str(exc) else str(exc)
    check("get_attachment refuses a binary attachment instead of dumping it", refused is None, refused)
    status = await tool(token, "folder_status", folder="INBOX")
    check("folder_status: message and unread counts", status["folders"][0]["messages"] >= 1
          and status["folders"][0]["unread"] >= 1, status)

    # ── Replies, threads, drafts, forwarding ──────────────────────────────────
    bob_uid = found_bob["messages"][0]["uid"]
    reply = await tool(bob, "send_message", reply_to_uid=bob_uid, reply_all=True, body="Danke!")
    check("reply_all without `to`: goes to the sender, never to yourself",
          reply["to"] == ["alice@example.com"] and reply["cc"] == [], reply)
    answer: dict = {"total": 0}
    for _ in range(30):
        answer = await tool(token, "search_messages", subject=f"Re: {subject}")
        if answer["total"]:
            break
        await asyncio.sleep(1)
    check("the reply reaches alice", answer["total"] == 1, answer)
    reply_uid = answer["messages"][0]["uid"]
    thread = await tool(token, "get_thread", uid=reply_uid)
    check("get_thread: alice's original (Sent) and bob's reply (INBOX), oldest first",
          [(m["folder"], m["subject"]) for m in thread["messages"]] == [("Sent", subject), ("INBOX", f"Re: {subject}")],
          thread)
    draft = await tool(token, "save_draft", reply_to_uid=reply_uid, body="Gern geschehen")
    check("save_draft: stored in the \\Drafts folder (found by special-use flag)",
          draft["folder"] == "Entwürfe" and draft["to"] == ["bob@example.com"], draft)
    drafts = await tool(token, "search_messages", folder="Entwürfe", subject=f"Re: {subject}")
    check("the draft is in Entwürfe, not sent", drafts["total"] == 1, drafts)
    forwarded = await tool(token, "forward_message", uid=uid, to=["bob@example.com"], comment="FYI")
    check("forward_message: sent with a copy in Sent", forwarded["status"] == "sent"
          and forwarded["saved_to"] == "Sent", forwarded)
    fwd: dict = {"total": 0}
    for _ in range(30):
        fwd = await tool(bob, "search_messages", subject=f"Fwd: {subject} big")
        if fwd["total"]:
            break
        await asyncio.sleep(1)
    check("the forward reaches bob", fwd["total"] == 1, fwd)
    fwd_info = await tool(bob, "get_message_info", uid=fwd["messages"][0]["uid"])
    inner = await tool(bob, "get_attachment", uid=fwd["messages"][0]["uid"], index=1)
    check("the original is attached as message/rfc822, readable with get_attachment",
          fwd_info["attachments"][0]["content_type"] == "message/rfc822"
          and f"Subject: {subject} big" in inner["text"] and "Grüße, siehe Anhang." in inner["text"],
          {"attachments": fwd_info["attachments"], "text": inner["text"][:300]})

    # ── Organizing ────────────────────────────────────────────────────────────
    await tool(token, "set_flags", uids=[reply_uid], seen=False, flagged=True)
    listed = await tool(token, "search_messages", subject=f"Re: {subject}")
    check("set_flags: unread and flagged", listed["messages"][0]["unread"] and listed["messages"][0]["flagged"], listed)
    await tool(token, "move_messages", uids=[reply_uid], target_folder="Archive")
    archived = await tool(token, "search_messages", folder="Archive", subject=f"Re: {subject}")
    gone = await tool(token, "search_messages", subject=f"Re: {subject}")
    check("move_messages: from INBOX to Archive", archived["total"] == 1 and gone["total"] == 0, (archived, gone))
    trashed = await tool(token, "trash_messages", uids=[drafts["messages"][0]["uid"]], folder="Entwürfe")
    in_trash = await tool(token, "search_messages", folder="Papierkorb", subject=f"Re: {subject}")
    check("trash_messages: into the \\Trash folder (found by special-use flag)",
          trashed["to"] == "Papierkorb" and in_trash["total"] == 1, (trashed, in_trash))

    # ── mcp-mail-diagnose: the operator's tool, against the real chain ────────
    diag = await asyncio.to_thread(
        subprocess.run, ["mcp-mail-diagnose", "--introspect-client-id", "dovecot", "--imap"],
        input=token + "\n", capture_output=True, text=True,
        env={**os.environ, "INTROSPECT_CLIENT_SECRET": "dovecot-test-secret"},
    )
    check("mcp-mail-diagnose passes every check" + (" (incl. the exchange)" if exchange else ""),
          diag.returncode == 0 and token not in diag.stdout, diag.stdout[-1500:] + diag.stderr[-500:])

    # ── The other SASL mechanism, without the MCP layer ───────────────────────
    bearer = dataclasses.replace(settings.mail, sasl_mechanism="OAUTHBEARER")
    folders = await asyncio.to_thread(mail.list_folders, bearer, "alice@example.com", mail_token)
    check("IMAP login with OAUTHBEARER", any(f["name"] == "INBOX" for f in folders), folders)
    with mail.smtp_session(bearer, "alice@example.com", mail_token):
        pass
    check("SMTP login with OAUTHBEARER", True)

    # ── Postfix: a user can only send as themselves ───────────────────────────
    refused = None
    try:
        with mail.smtp_session(settings.mail, "alice@example.com", mail_token) as smtp:
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
    check("after logout, Dovecot rejects the still-unexpired token"
          + (" (and the cached exchanged one)" if exchange else ""), rejected, detail)

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
