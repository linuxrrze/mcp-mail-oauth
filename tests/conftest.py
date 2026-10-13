"""Shared fixtures. No Keycloak or mail server needed: tokens are signed with
a local RSA key and the IMAP/SMTP layer is replaced by fakes."""

import pytest
from fastmcp.server.auth.providers.jwt import RSAKeyPair

from mcp_mail.config import load

ISSUER = "https://sso.example.com/realms/mail"
BASE_ENV = {
    "OIDC_ISSUER": ISSUER,
    "BASE_URL": "https://mcp-mail.example.com",
    "MAIL_IMAP_HOST": "imap.example.com",
    "MAIL_SMTP_HOST": "smtp.example.com",
}


@pytest.fixture
def settings():
    return load(dict(BASE_ENV))


@pytest.fixture(scope="session")
def keypair():
    return RSAKeyPair.generate()


@pytest.fixture
def make_token(keypair):
    """Keycloak-shaped access token: `scope` as a space-separated string,
    `aud` naming both this server and Dovecot's introspection client."""

    def _make(
        scopes=("openid", "email", "mail", "mcp:mail/read", "mcp:mail/send"),
        audience=("mcp-mail", "dovecot"),
        email="alice@example.com",
        issuer=ISSUER,
        expires_in=300,
        email_verified=True,
    ):
        claims = {"azp": "openwebui"}
        if email is not None:
            claims["email"] = email
        if email_verified is not None:
            claims["email_verified"] = email_verified
        return keypair.create_token(
            subject="user-alice",
            issuer=issuer,
            audience=list(audience),
            scopes=list(scopes),
            expires_in_seconds=expires_in,
            additional_claims=claims,
        )

    return _make
