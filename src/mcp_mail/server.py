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
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import PlainTextResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from . import __version__, mail
from .auth import READ_SCOPE, SEND_SCOPE, TOOL_SCOPES, build_auth, build_exchanger
from .config import Settings
from .exchange import TokenExchanger, TokenExchangeError

logger = logging.getLogger(__name__)

READ_ONLY = {"readOnlyHint": True, "openWorldHint": True}

MCP_PATH = "/mcp"


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
        f" and the scopes {', '.join(TOOL_SCOPES)} (Keycloak: Default client scopes)",
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
            "send_message really sends mail - confirm recipients and content with the user first."
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
            mail.send_message, cfg, *(await credentials(token)),
            to=to, subject=subject, body=body, cc=cc, bcc=bcc,
            reply_to_uid=reply_to_uid, reply_folder=reply_folder,
        )

    return mcp
