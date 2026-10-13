"""The MCP server: tool definitions on top of auth.py and mail.py."""

from __future__ import annotations

import asyncio
import functools
import logging
import time
from typing import Annotated, Any

from fastmcp import FastMCP
from fastmcp.dependencies import CurrentAccessToken
from fastmcp.exceptions import ToolError
from fastmcp.server.auth import AccessToken, AuthProvider, require_scopes
from pydantic import Field
from starlette.requests import Request
from starlette.responses import PlainTextResponse

from . import __version__, mail
from .auth import READ_SCOPE, SEND_SCOPE, TOOL_SCOPES, build_auth
from .config import Settings

logger = logging.getLogger(__name__)

READ_ONLY = {"readOnlyHint": True, "openWorldHint": True}


def _identity(settings: Settings, token: AccessToken) -> tuple[str, str]:
    """(mailbox username, bearer token) for this request.

    The username comes from a claim of the very token that authenticates the
    mail session (D7), so it can't drift from what Dovecot derives from the
    same token via username_attribute, and the model can't pick another mailbox.
    """
    claim = settings.mail.username_claim
    username = (token.claims or {}).get(claim)
    if not isinstance(username, str) or not username:
        raise ToolError(
            f"Your access token has no {claim!r} claim, so the mailbox can't be determined. "
            f"Make sure the Keycloak user has it set and the client's token includes it "
            f"(for `email`: the `email` client scope must be a Default scope)."
        )
    return username, token.token


async def _run(func, *args, **kwargs) -> Any:
    try:
        return await asyncio.to_thread(functools.partial(func, *args, **kwargs))
    except mail.MailError as exc:
        logger.info("%s failed: %s", func.__name__, exc)
        raise ToolError(str(exc)) from None


def create_server(settings: Settings, auth: AuthProvider | None = None) -> FastMCP:
    mcp = FastMCP(
        "mcp-mail-oauth",
        version=__version__,
        instructions=(
            "Access the signed-in user's own mailbox over IMAP/SMTP. Message UIDs are "
            "per folder: pass the same folder to read_message that list/search returned. "
            "send_message really sends mail - confirm recipients and content with the user first."
        ),
        auth=auth if auth is not None else build_auth(settings),
    )
    cfg = settings.mail

    @mcp.custom_route("/healthz", methods=["GET"])
    async def healthz(request: Request) -> PlainTextResponse:
        return PlainTextResponse("ok")

    @mcp.tool(annotations={"readOnlyHint": True, "openWorldHint": False})
    async def whoami(token: AccessToken = CurrentAccessToken()) -> dict:
        """Show who you are signed in as, which mailbox that maps to, and which
        mail permissions your token carries. Needs no scope, so it works even
        when the other tools are hidden for lack of one."""
        claims = token.claims or {}
        scopes = set(token.scopes or [])
        return {
            "subject": claims.get("sub"),
            "mailbox": claims.get(cfg.username_claim),
            "mailbox_claim": cfg.username_claim,
            "client": claims.get("azp") or token.client_id,
            "audience": claims.get("aud"),
            "scopes": sorted(scopes),
            "missing_scopes": [s for s in TOOL_SCOPES if s not in scopes],
            "expires_in_seconds": int(token.expires_at - time.time()) if token.expires_at else None,
        }

    @mcp.tool(auth=require_scopes(READ_SCOPE), annotations=READ_ONLY)
    async def list_folders(token: AccessToken = CurrentAccessToken()) -> list[dict]:
        """List the mailbox's folders (name and IMAP flags such as \\Sent, \\Trash)."""
        return await _run(mail.list_folders, cfg, *_identity(settings, token))

    @mcp.tool(auth=require_scopes(READ_SCOPE), annotations=READ_ONLY)
    async def list_messages(
        folder: str = "INBOX",
        limit: Annotated[int, Field(ge=1, le=mail.MAX_LIST_LIMIT)] = 20,
        offset: Annotated[int, Field(ge=0)] = 0,
        unread_only: bool = False,
        token: AccessToken = CurrentAccessToken(),
    ) -> dict:
        """List messages in a folder, newest first, with sender, subject, date and
        read state. Use offset to page further back."""
        return await _run(mail.list_messages, cfg, *_identity(settings, token), folder, limit, offset, unread_only)

    @mcp.tool(auth=require_scopes(READ_SCOPE), annotations=READ_ONLY)
    async def search_messages(
        folder: str = "INBOX",
        sender: str | None = None,
        recipient: str | None = None,
        subject: str | None = None,
        text: Annotated[str | None, Field(description="Matches headers and body")] = None,
        since: Annotated[str | None, Field(description="YYYY-MM-DD, inclusive")] = None,
        before: Annotated[str | None, Field(description="YYYY-MM-DD, exclusive")] = None,
        unread_only: bool = False,
        limit: Annotated[int, Field(ge=1, le=mail.MAX_LIST_LIMIT)] = 20,
        token: AccessToken = CurrentAccessToken(),
    ) -> dict:
        """Search a folder (server-side IMAP SEARCH, substring matching). All given
        criteria must match. Returns newest matches first."""
        return await _run(
            mail.search_messages, cfg, *_identity(settings, token), folder, limit,
            from_=sender, to=recipient, subject=subject, text=text,
            since=since, before=before, unread_only=unread_only,
        )

    @mcp.tool(auth=require_scopes(READ_SCOPE), annotations=READ_ONLY)
    async def read_message(
        uid: str,
        folder: str = "INBOX",
        max_chars: Annotated[int, Field(ge=1, le=mail.MAX_BODY_CHARS)] = mail.DEFAULT_BODY_CHARS,
        mark_read: Annotated[bool, Field(description="Also mark the message as read")] = False,
        token: AccessToken = CurrentAccessToken(),
    ) -> dict:
        """Read one message: headers, plain-text body (HTML converted to text) and
        the list of attachments. Does not mark it as read unless mark_read is set."""
        return await _run(mail.read_message, cfg, *_identity(settings, token), folder, uid, max_chars, mark_read)

    @mcp.tool(auth=require_scopes(SEND_SCOPE), annotations={"destructiveHint": False, "openWorldHint": True})
    async def send_message(
        to: Annotated[list[str], Field(min_length=1, description='Addresses, e.g. ["Ann <ann@example.com>"]')],
        body: str,
        subject: Annotated[str | None, Field(description="Optional when replying (defaults to Re: <original>)")] = None,
        cc: list[str] | None = None,
        bcc: list[str] | None = None,
        reply_to_uid: Annotated[str | None, Field(description="UID of the message being answered (sets threading headers)")] = None,
        reply_folder: str = "INBOX",
        token: AccessToken = CurrentAccessToken(),
    ) -> dict:
        """Send a plain-text email from the signed-in user's own address and save a
        copy to the Sent folder. This really sends mail: confirm with the user first."""
        return await _run(
            mail.send_message, cfg, *_identity(settings, token),
            to=to, subject=subject, body=body, cc=cc, bcc=bcc,
            reply_to_uid=reply_to_uid, reply_folder=reply_folder,
        )

    return mcp
