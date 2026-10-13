"""The MCP server: tool definitions on top of auth.py and mail.py."""

from __future__ import annotations

import asyncio
import functools
import json
import logging
import time
from typing import Annotated, Any

from fastmcp import FastMCP
from fastmcp.dependencies import CurrentAccessToken
from fastmcp.exceptions import ToolError
from fastmcp.server.auth import AccessToken, AuthProvider, require_scopes
from fastmcp.tools import ToolResult
from fastmcp.utilities.types import Image
from mcp.types import TextContent
from pydantic import Field
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import PlainTextResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from . import __version__, mail
from .auth import DRAFT_SCOPE, ORGANIZE_SCOPE, READ_SCOPE, SEND_SCOPE, TOOL_SCOPES, build_auth, build_exchanger
from .config import Settings
from .exchange import TokenExchanger, TokenExchangeError

logger = logging.getLogger(__name__)

READ_ONLY = {"readOnlyHint": True, "openWorldHint": True}

MCP_PATH = "/mcp"

# Shared parameter descriptions (module level: annotations are evaluated here).
REPLY_TO_UID = ("UID of the message being answered (sets threading headers; without `to`, "
                "replies to its sender)")
REPLY_ALL = "With reply_to_uid: also copy the original's To and Cc recipients (your own address excluded)"
UidList = Annotated[list[str], Field(min_length=1, max_length=mail.MAX_BATCH, description="Message UIDs")]


class EndpointPaths:
    """Forgive the two endpoint URLs people configure by mistake.

    - `/mcp/` is served as `/mcp`. Starlette would otherwise redirect it to
      `/mcp`, built from the internal Host and without a reverse proxy's
      stripped prefix (e.g. http://mcp-mail:8000/mcp), which no client can
      reach. Open WebUI then just reports a failed connection.
    - `/` (the server's base URL, or a proxy prefix without `/mcp`) gets a 404
      that names the actual endpoint instead of an empty one.
    """

    def __init__(self, app: ASGIApp, endpoint: str) -> None:
        self.app = app
        self.endpoint = endpoint

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            if scope["path"] == MCP_PATH + "/":
                scope = {**scope, "path": MCP_PATH, "raw_path": MCP_PATH.encode()}
            elif scope["path"] == "/":
                response = PlainTextResponse(f"Not the MCP endpoint. Use {self.endpoint}\n", status_code=404)
                await response(scope, receive, send)
                return
        await self.app(scope, receive, send)


def client_settings(settings: Settings) -> list[str]:
    """What to enter in an MCP client for this configuration, logged at startup."""
    endpoint = settings.base_url.rstrip("/") + MCP_PATH
    lines = [
        "MCP client settings (Open WebUI: Admin Panel > Settings > External Tools > +):",
        "  Type: MCP (Streamable HTTP)",
        f"  URL:  {endpoint}",
        f"        (BASE_URL + {MCP_PATH}; Open WebUI on the same Docker network may use"
        f" http://<this container>:{settings.port}{MCP_PATH} instead)",
        "  Auth: OAuth  (forwards the user's own Keycloak token; not 'OAuth 2.1', 'Bearer' or 'Session')",
        f"  Tokens must come from {settings.oidc_issuer}, with {settings.mcp_audience!r} in aud"
        f" and the scope {TOOL_SCOPES[0]}; {', '.join(TOOL_SCOPES[1:])} each enable more tools"
        " (Keycloak: Default client scopes)",
    ]
    if settings.mail.username_claim == "email" and settings.mail.require_email_verified:
        lines.append("  Mailbox: the token's email claim, only if email_verified is true (MAIL_REQUIRE_EMAIL_VERIFIED)")
    if settings.token_exchange:
        lines.append(
            f"  Mail credential: token exchange (MAIL_TOKEN_EXCHANGE=on). Client {settings.oidc_client_id!r} exchanges"
            f" the token for one with audience {settings.mail_token_audience!r}; the client's own token must NOT"
            " carry the `mail` scope (docs/mail-credential.md)"
        )
    else:
        lines.append("  Mail credential: forwarded token (default). The same token logs in to IMAP/SMTP, so it"
                     " also needs the `mail` scope and the mail server's audience (docs/mail-credential.md)")
    if settings.auth_mode == "proxy":
        lines += [
            "  AUTH_MODE=proxy: other MCP clients (or Open WebUI with Auth: OAuth 2.1) can sign in through",
            f"  this server; Keycloak client {settings.oidc_client_id!r} needs the redirect URI"
            f" {settings.base_url.rstrip('/')}/auth/callback",
        ]
    return lines


def http_middleware(settings: Settings) -> list[Middleware]:
    """ASGI middleware for the HTTP app (`run()` and `http_app()` alike)."""
    return [Middleware(EndpointPaths, endpoint=settings.base_url.rstrip("/") + MCP_PATH)]


def _identity(settings: Settings, token: AccessToken) -> tuple[str, str]:
    """(mailbox username, bearer token) for this request.

    The username comes from a claim of the incoming token (D7), so the model
    can't pick another mailbox. Without token exchange the same token is the
    mail credential, so it can't drift from what Dovecot derives via
    username_attribute; with exchange, Keycloak issues the mail token for the
    same user and session.
    """
    claim = settings.mail.username_claim
    claims = token.claims or {}
    username = claims.get(claim)
    if not isinstance(username, str) or not username:
        raise ToolError(
            f"Your access token has no {claim!r} claim, so the mailbox can't be determined. "
            f"Make sure the Keycloak user has it set and the client's token includes it "
            f"(for `email`: the `email` client scope must be a Default scope)."
        )
    # An email address nobody has verified is just a string a user typed:
    # with self-service profile editing it could name someone else's mailbox
    # (D24).
    if claim == "email" and settings.mail.require_email_verified and claims.get("email_verified") is not True:
        raise ToolError(
            f"Your email address {username!r} is not verified (email_verified is not true in your token), "
            "so it can't be used to select a mailbox. Ask an administrator to verify it in Keycloak "
            "(Users > user > Email verified)."
        )
    return username, token.token


async def _run(func, *args, **kwargs) -> Any:
    try:
        return await asyncio.to_thread(functools.partial(func, *args, **kwargs))
    except mail.MailError as exc:
        logger.info("%s failed: %s", func.__name__, exc)
        raise ToolError(str(exc)) from None


def create_server(settings: Settings, auth: AuthProvider | None = None,
                  exchanger: TokenExchanger | None = None) -> FastMCP:
    mcp = FastMCP(
        "mcp-mail-oauth",
        version=__version__,
        instructions=(
            "Access the signed-in user's own mailbox over IMAP/SMTP. Message UIDs are "
            "per folder: pass the same folder to read_message that list/search returned. "
            "send_message and forward_message really send mail - confirm recipients and content with the "
            "user first; save_draft only stores a draft. Nothing is ever deleted permanently: "
            "trash_messages moves to Trash."
        ),
        auth=auth if auth is not None else build_auth(settings),
    )
    cfg = settings.mail
    if exchanger is None:
        exchanger = build_exchanger(settings)

    async def credentials(token: AccessToken) -> tuple[str, str]:
        """(mailbox username, mail-server token): the incoming token itself,
        or with MAIL_TOKEN_EXCHANGE=on a separate one exchanged for it (D23)."""
        username, bearer = _identity(settings, token)
        if exchanger is None:
            return username, bearer
        try:
            return username, await exchanger.mail_token(bearer)
        except TokenExchangeError as exc:
            raise ToolError(str(exc)) from None

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
            "email_verified": claims.get("email_verified"),
            "client": claims.get("azp") or token.client_id,
            "audience": claims.get("aud"),
            "scopes": sorted(scopes),
            "missing_scopes": [s for s in TOOL_SCOPES if s not in scopes],
            "mail_credential": "token exchange (RFC 8693)" if exchanger else "forwarded (default)",
            "expires_in_seconds": int(token.expires_at - time.time()) if token.expires_at else None,
        }

    @mcp.tool(auth=require_scopes(READ_SCOPE), annotations=READ_ONLY)
    async def list_folders(token: AccessToken = CurrentAccessToken()) -> list[dict]:
        """List the mailbox's folders (name and IMAP flags such as \\Sent, \\Trash)."""
        return await _run(mail.list_folders, cfg, *(await credentials(token)))

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
        return await _run(mail.list_messages, cfg, *(await credentials(token)), folder, limit, offset, unread_only)

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
            mail.search_messages, cfg, *(await credentials(token)), folder, limit,
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
        return await _run(mail.read_message, cfg, *(await credentials(token)), folder, uid, max_chars, mark_read)

    @mcp.tool(auth=require_scopes(READ_SCOPE), annotations=READ_ONLY)
    async def get_message_info(
        uid: str,
        folder: str = "INBOX",
        token: AccessToken = CurrentAccessToken(),
    ) -> dict:
        """One message's metadata without its body: headers, read/flagged state,
        size and attachment names, types and sizes. Cheaper than read_message when
        only that is needed. Never marks the message as read."""
        return await _run(mail.message_info, cfg, *(await credentials(token)), folder, uid)

    @mcp.tool(auth=require_scopes(READ_SCOPE), annotations=READ_ONLY)
    async def get_thread(
        uid: str,
        folder: str = "INBOX",
        limit: Annotated[int, Field(ge=1, le=mail.MAX_LIST_LIMIT)] = 20,
        token: AccessToken = CurrentAccessToken(),
    ) -> dict:
        """The conversation a message belongs to (its earlier messages and the
        replies), oldest first, from the given folder and the Sent folder. Each
        entry names its folder; read one with read_message(uid, folder)."""
        return await _run(mail.get_thread, cfg, *(await credentials(token)), folder, uid, limit)

    @mcp.tool(auth=require_scopes(READ_SCOPE), annotations=READ_ONLY, output_schema=None)
    async def get_attachment(
        uid: str,
        index: Annotated[int, Field(ge=1, description="The attachment's index from read_message/get_message_info")],
        folder: str = "INBOX",
        max_chars: Annotated[int, Field(ge=1, le=mail.MAX_BODY_CHARS)] = mail.DEFAULT_BODY_CHARS,
        token: AccessToken = CurrentAccessToken(),
    ) -> ToolResult:
        """Read one attachment: text and HTML files, PDFs (their text), attached
        emails and images (PNG, JPEG, GIF, WebP, returned as an image). Other
        types are refused."""
        result = await _run(mail.get_attachment, cfg, *(await credentials(token)), folder, uid, index, max_chars)
        image = result.pop("image", None)
        content = [TextContent(type="text", text=json.dumps(result, ensure_ascii=False))]
        if image is not None:
            content.append(Image(data=image, format=result["content_type"].split("/")[1]).to_image_content())
        return ToolResult(content=content, structured_content=result)

    @mcp.tool(auth=require_scopes(READ_SCOPE), annotations=READ_ONLY)
    async def folder_status(
        folder: Annotated[str | None, Field(description="One folder; omit for all folders")] = None,
        token: AccessToken = CurrentAccessToken(),
    ) -> dict:
        """Number of messages and unread messages per folder, without listing them."""
        return await _run(mail.folder_status, cfg, *(await credentials(token)), folder)

    @mcp.tool(auth=require_scopes(SEND_SCOPE), annotations={"destructiveHint": False, "openWorldHint": True})
    async def send_message(
        body: str,
        to: Annotated[list[str] | None, Field(description='Addresses, e.g. ["Ann <ann@example.com>"]; '
                                                          "optional when replying")] = None,
        subject: Annotated[str | None, Field(description="Optional when replying (defaults to Re: <original>)")] = None,
        cc: list[str] | None = None,
        bcc: list[str] | None = None,
        reply_to_uid: Annotated[str | None, Field(description=REPLY_TO_UID)] = None,
        reply_folder: str = "INBOX",
        reply_all: Annotated[bool, Field(description=REPLY_ALL)] = False,
        token: AccessToken = CurrentAccessToken(),
    ) -> dict:
        """Send a plain-text email from the signed-in user's own address and save a
        copy to the Sent folder. This really sends mail: confirm recipients and
        content with the user first (with reply_all, read the original to know them).
        The result lists who it went to."""
        return await _run(
            mail.send_message, cfg, *(await credentials(token)),
            to=to, subject=subject, body=body, cc=cc, bcc=bcc,
            reply_to_uid=reply_to_uid, reply_folder=reply_folder, reply_all=reply_all,
        )

    @mcp.tool(auth=require_scopes(SEND_SCOPE), annotations={"destructiveHint": False, "openWorldHint": True})
    async def forward_message(
        uid: str,
        to: Annotated[list[str], Field(min_length=1, description='Addresses, e.g. ["Ann <ann@example.com>"]')],
        folder: str = "INBOX",
        comment: Annotated[str, Field(description="Your text above the forwarded message")] = "",
        cc: list[str] | None = None,
        bcc: list[str] | None = None,
        token: AccessToken = CurrentAccessToken(),
    ) -> dict:
        """Forward a message, unchanged and with its attachments, as an attachment of
        a new mail from the user's own address; a copy goes to Sent. This really
        sends mail: confirm recipients with the user first."""
        return await _run(
            mail.forward_message, cfg, *(await credentials(token)),
            folder=folder, uid=uid, to=to, comment=comment, cc=cc, bcc=bcc,
        )

    @mcp.tool(auth=require_scopes(DRAFT_SCOPE), annotations={"destructiveHint": False, "openWorldHint": False})
    async def save_draft(
        body: str,
        to: Annotated[list[str] | None, Field(description='Addresses, e.g. ["Ann <ann@example.com>"]')] = None,
        subject: str | None = None,
        cc: list[str] | None = None,
        bcc: list[str] | None = None,
        reply_to_uid: Annotated[str | None, Field(description=REPLY_TO_UID)] = None,
        reply_folder: str = "INBOX",
        reply_all: Annotated[bool, Field(description=REPLY_ALL)] = False,
        token: AccessToken = CurrentAccessToken(),
    ) -> dict:
        """Save a plain-text email as a draft in the Drafts folder, without sending
        it. The user reviews and sends it from their mail client."""
        return await _run(
            mail.save_draft, cfg, *(await credentials(token)),
            to=to, subject=subject, body=body, cc=cc, bcc=bcc,
            reply_to_uid=reply_to_uid, reply_folder=reply_folder, reply_all=reply_all,
        )

    @mcp.tool(auth=require_scopes(ORGANIZE_SCOPE),
              annotations={"destructiveHint": False, "idempotentHint": True, "openWorldHint": False})
    async def set_flags(
        uids: UidList,
        folder: str = "INBOX",
        seen: Annotated[bool | None, Field(description="true = mark read, false = mark unread")] = None,
        flagged: Annotated[bool | None, Field(description="true = flag/star, false = unflag")] = None,
        token: AccessToken = CurrentAccessToken(),
    ) -> dict:
        """Mark messages read or unread, and/or flagged or unflagged."""
        return await _run(mail.set_flags, cfg, *(await credentials(token)), folder, uids, seen, flagged)

    @mcp.tool(auth=require_scopes(ORGANIZE_SCOPE), annotations={"destructiveHint": False, "openWorldHint": False})
    async def move_messages(
        uids: UidList,
        target_folder: Annotated[str, Field(description="Existing folder, e.g. Archive (see list_folders)")],
        folder: str = "INBOX",
        token: AccessToken = CurrentAccessToken(),
    ) -> dict:
        """Move messages to another existing folder, e.g. to archive them. Their
        UIDs change in the new folder."""
        return await _run(mail.move_messages, cfg, *(await credentials(token)), folder, uids, target_folder)

    @mcp.tool(auth=require_scopes(ORGANIZE_SCOPE), annotations={"destructiveHint": True, "openWorldHint": False})
    async def trash_messages(
        uids: UidList,
        folder: str = "INBOX",
        token: AccessToken = CurrentAccessToken(),
    ) -> dict:
        """Move messages to the Trash folder (the user can restore them from there).
        Nothing is deleted permanently. Confirm with the user first."""
        return await _run(mail.trash_messages, cfg, *(await credentials(token)), folder, uids)

    return mcp
