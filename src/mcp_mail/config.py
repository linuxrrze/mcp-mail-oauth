"""Settings, read once from environment variables.

Every variable is documented in .env.example; the reasoning behind the
defaults is in docs/decisions.md. Validation happens here, at startup, so a
misconfiguration fails the container immediately instead of surfacing as a
confusing error on a user's first tool call.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Literal

AuthMode = Literal["resource", "proxy"]
Security = Literal["tls", "starttls"]
Mechanism = Literal["XOAUTH2", "OAUTHBEARER"]


class ConfigError(ValueError):
    """Raised for missing or invalid settings."""


def _require(env: dict[str, str], key: str) -> str:
    value = env.get(key, "").strip()
    if not value:
        raise ConfigError(f"{key} is required (see .env.example).")
    return value


def _choice(env: dict[str, str], key: str, default: str, allowed: tuple[str, ...], *, upper: bool = False) -> str:
    value = env.get(key, "").strip() or default
    value = value.upper() if upper else value.lower()
    if value not in allowed:
        raise ConfigError(f"{key}={value!r} is invalid; expected one of {', '.join(allowed)}.")
    return value


def _int(env: dict[str, str], key: str, default: int) -> int:
    raw = env.get(key, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        raise ConfigError(f"{key}={raw!r} is not an integer.") from None


@dataclass(frozen=True)
class MailSettings:
    imap_host: str
    imap_port: int
    imap_security: Security
    smtp_host: str
    smtp_port: int
    smtp_security: Security
    sasl_mechanism: Mechanism
    username_claim: str
    ca_file: str | None
    sent_folder: str
    timeout: int
    # With username_claim "email": only accept tokens whose email_verified
    # claim is true (MAIL_REQUIRE_EMAIL_VERIFIED, D24).
    require_email_verified: bool = True


@dataclass(frozen=True)
class Settings:
    auth_mode: AuthMode
    oidc_issuer: str
    oidc_jwks_uri: str | None
    mcp_audience: str
    base_url: str
    # proxy mode and token exchange
    oidc_client_id: str | None
    oidc_client_secret: str | None
    jwt_signing_key: str | None
    # MAIL_TOKEN_EXCHANGE=on (D23)
    token_exchange: bool
    oidc_token_endpoint: str | None
    mail_token_audience: str
    mail: MailSettings
    host: str
    port: int


def load(env: dict[str, str] | None = None) -> Settings:
    env = dict(os.environ if env is None else env)

    auth_mode = _choice(env, "AUTH_MODE", "resource", ("resource", "proxy"))
    oidc_client_id = env.get("OIDC_CLIENT_ID", "").strip() or None
    oidc_client_secret = env.get("OIDC_CLIENT_SECRET", "").strip() or None
    if auth_mode == "proxy" and not (oidc_client_id and oidc_client_secret):
        raise ConfigError("AUTH_MODE=proxy requires OIDC_CLIENT_ID and OIDC_CLIENT_SECRET.")

    mcp_audience = env.get("MCP_AUDIENCE", "").strip() or "mcp-mail"
    token_exchange = _choice(env, "MAIL_TOKEN_EXCHANGE", "off", ("off", "on")) == "on"
    if token_exchange:
        if not (oidc_client_id and oidc_client_secret):
            raise ConfigError("MAIL_TOKEN_EXCHANGE=on requires OIDC_CLIENT_ID and OIDC_CLIENT_SECRET "
                              "(the Keycloak client that exchanges tokens).")
        # Keycloak only exchanges a token that names the requesting client in
        # `aud`; the token's audience is MCP_AUDIENCE.
        if mcp_audience != oidc_client_id:
            raise ConfigError(f"MAIL_TOKEN_EXCHANGE=on requires MCP_AUDIENCE ({mcp_audience!r}) to equal "
                              f"OIDC_CLIENT_ID ({oidc_client_id!r}): Keycloak only exchanges tokens whose "
                              "aud contains the exchanging client.")

    imap_security = _choice(env, "MAIL_IMAP_SECURITY", "tls", ("tls", "starttls"))
    smtp_security = _choice(env, "MAIL_SMTP_SECURITY", "starttls", ("tls", "starttls"))

    mail = MailSettings(
        imap_host=_require(env, "MAIL_IMAP_HOST"),
        imap_port=_int(env, "MAIL_IMAP_PORT", 993 if imap_security == "tls" else 143),
        imap_security=imap_security,
        smtp_host=_require(env, "MAIL_SMTP_HOST"),
        smtp_port=_int(env, "MAIL_SMTP_PORT", 465 if smtp_security == "tls" else 587),
        smtp_security=smtp_security,
        sasl_mechanism=_choice(env, "MAIL_SASL_MECHANISM", "XOAUTH2", ("XOAUTH2", "OAUTHBEARER"), upper=True),
        username_claim=env.get("MAIL_USERNAME_CLAIM", "").strip() or "email",
        ca_file=env.get("MAIL_CA_FILE", "").strip() or None,
        # "Sent" unless explicitly set; an explicitly empty value disables
        # saving a copy (e.g. when the MTA already does it via sieve).
        sent_folder=env["MAIL_SENT_FOLDER"].strip() if "MAIL_SENT_FOLDER" in env else "Sent",
        timeout=_int(env, "MAIL_TIMEOUT", 30),
        require_email_verified=_choice(env, "MAIL_REQUIRE_EMAIL_VERIFIED", "on", ("on", "off")) == "on",
    )

    return Settings(
        auth_mode=auth_mode,
        oidc_issuer=_require(env, "OIDC_ISSUER").rstrip("/"),
        oidc_jwks_uri=env.get("OIDC_JWKS_URI", "").strip() or None,
        mcp_audience=mcp_audience,
        base_url=_require(env, "BASE_URL").rstrip("/"),
        oidc_client_id=oidc_client_id,
        oidc_client_secret=oidc_client_secret,
        jwt_signing_key=env.get("JWT_SIGNING_KEY", "").strip() or None,
        token_exchange=token_exchange,
        oidc_token_endpoint=env.get("OIDC_TOKEN_ENDPOINT", "").strip() or None,
        mail_token_audience=env.get("MAIL_TOKEN_AUDIENCE", "").strip() or "dovecot",
        mail=mail,
        host=env.get("HOST", "").strip() or "0.0.0.0",
        port=_int(env, "PORT", 8000),
    )
