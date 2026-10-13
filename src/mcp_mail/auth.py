"""Inbound authentication: which bearer tokens this MCP server accepts.

Two modes (docs/decisions.md, D3), one acceptance rule for both: a
**Keycloak access token whose `aud` contains MCP_AUDIENCE**, signature
checked against the realm's JWKS. Whatever arrives, the tool code downstream
ends up with that same Keycloak token in `AccessToken.token`, and that is
the credential it hands to IMAP/SMTP (D2). There is no second OAuth flow
and no mailbox-specific token to mint, store or refresh.

- ``resource`` (default): a pure OAuth resource server. Open WebUI's MCP
  auth type "OAuth" (``system_oauth``) forwards the user's own SSO access
  token, which is accepted directly. No Keycloak client, no state.
- ``proxy``: additionally runs FastMCP's OIDCProxy, so MCP clients that
  insist on the MCP authorization flow with Dynamic Client Registration
  (Claude Desktop, MCP Inspector, Open WebUI's "OAuth 2.1" type) can log in
  too. FastMCP's token swap returns the *upstream* Keycloak token to tools,
  and refreshes it transparently. Directly-forwarded tokens keep working in
  this mode as well, so a single deployment serves both kinds of client.
"""

from __future__ import annotations

import logging

import httpx
from fastmcp.server.auth import AccessToken, AuthProvider, RemoteAuthProvider
from fastmcp.server.auth.oidc_proxy import OIDCProxy
from fastmcp.server.auth.providers.jwt import JWTVerifier

from .config import ConfigError, Settings

logger = logging.getLogger(__name__)

READ_SCOPE = "mcp:mail/read"
SEND_SCOPE = "mcp:mail/send"
TOOL_SCOPES = [READ_SCOPE, SEND_SCOPE]


def discover_jwks_uri(issuer: str, timeout: float = 10.0) -> str:
    """Read jwks_uri from the issuer's OIDC discovery document.

    Also checks that the document's `issuer` equals OIDC_ISSUER exactly. A
    mismatch almost always means Keycloak is being reached under a different
    hostname than the one it puts in tokens (typical in Docker: internal
    http://keycloak:8080 vs. public https://sso.example.com). Every token
    would then fail the `iss` check, so the server refuses to start rather
    than rejecting every user later with nothing but a 401.
    """
    url = f"{issuer}/.well-known/openid-configuration"
    try:
        resp = httpx.get(url, timeout=timeout)
        resp.raise_for_status()
        document = resp.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise ConfigError(
            f"Could not load OIDC discovery from {url}: {exc}. If Keycloak is only "
            "reachable from this container under an internal URL, keep OIDC_ISSUER "
            "set to the public issuer and set OIDC_JWKS_URI to the internal "
            ".../protocol/openid-connect/certs URL."
        ) from exc
    if document.get("issuer", "").rstrip("/") != issuer:
        raise ConfigError(
            f"OIDC_ISSUER={issuer!r} but the discovery document says issuer="
            f"{document.get('issuer')!r}. OIDC_ISSUER must be the exact `iss` "
            "value in the tokens (Keycloak: <public frontend URL>/realms/<realm>)."
        )
    return document["jwks_uri"]


def build_token_verifier(settings: Settings, *, jwks_uri: str | None = None, public_key: str | None = None) -> JWTVerifier:
    """Signature, issuer, expiry and audience check for Keycloak access tokens.

    No global required_scopes: each tool enforces its own scope (D10), and
    `whoami` deliberately needs none, so a user whose token is missing a
    scope can still see *which* scopes they do have.
    """
    if public_key is None and jwks_uri is None:
        jwks_uri = settings.oidc_jwks_uri or discover_jwks_uri(settings.oidc_issuer)
    return JWTVerifier(
        jwks_uri=jwks_uri,
        public_key=public_key,
        issuer=settings.oidc_issuer,
        audience=settings.mcp_audience,
    )


class ProxyAcceptingDirectTokens(OIDCProxy):
    """OIDCProxy that also accepts Keycloak access tokens presented directly.

    OIDCProxy on its own only accepts the FastMCP-issued reference tokens
    from its own login flow. A token forwarded by Open WebUI's "OAuth" auth
    type is a raw Keycloak token, so it's checked with the same verifier the
    proxy uses for its upstream tokens: same issuer, same audience rule.
    """

    def __init__(self, *, direct_verifier: JWTVerifier, **kwargs) -> None:
        super().__init__(token_verifier=direct_verifier, **kwargs)
        self._direct_verifier = direct_verifier

    async def load_access_token(self, token: str) -> AccessToken | None:  # type: ignore[override]
        access = await super().load_access_token(token)
        if access is not None:
            return access
        return await self._direct_verifier.verify_token(token)


def build_auth(settings: Settings, verifier: JWTVerifier | None = None) -> AuthProvider:
    verifier = verifier or build_token_verifier(settings)

    if settings.auth_mode == "resource":
        # Publishes RFC 9728 protected-resource metadata naming Keycloak as
        # the authorization server, so a spec-compliant client can find it.
        return RemoteAuthProvider(
            token_verifier=verifier,
            authorization_servers=[settings.oidc_issuer],
            base_url=settings.base_url,
            scopes_supported=TOOL_SCOPES,
            resource_name="mcp-mail-oauth",
        )

    proxy = ProxyAcceptingDirectTokens(
        direct_verifier=verifier,
        config_url=f"{settings.oidc_issuer}/.well-known/openid-configuration",
        client_id=settings.oidc_client_id,
        client_secret=settings.oidc_client_secret,
        base_url=settings.base_url,
        # Keep FastMCP's consent screen (D15). Any DCR client can register
        # an arbitrary redirect URI; without this screen a user with a live
        # Keycloak session who opens a crafted authorize link is silently
        # redirected, code and all, to that client (confused deputy).
        require_authorization_consent=True,
        # Explicit key: the default is derived from the client secret, so
        # rotating the secret would silently invalidate every stored DCR
        # registration and issued session (D13).
        jwt_signing_key=settings.jwt_signing_key,
    )
    # DCR clients that send no scope get these; clients may only register for
    # scopes in this list.
    proxy.update_default_scopes(["openid", "email", *TOOL_SCOPES])
    return proxy
