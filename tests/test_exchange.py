"""RFC 8693 token exchange (MAIL_TOKEN_EXCHANGE=on, decisions.md D23)."""

import base64
import json
import time
from urllib.parse import parse_qs

import httpx2
import pytest

from mcp_mail import exchange
from mcp_mail.config import ConfigError, load
from mcp_mail.exchange import TokenExchanger, TokenExchangeError

from .conftest import BASE_ENV

ENDPOINT = "https://sso.example.com/realms/mail/protocol/openid-connect/token"


def jwt(exp: float, marker: str = "") -> str:
    """Unsigned JWT-shaped string; the exchanger only reads `exp`."""
    enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()  # noqa: E731
    return f"{enc({'alg': 'none'})}.{enc({'exp': exp, 'm': marker})}.sig"


@pytest.fixture
def keycloak(monkeypatch):
    """Fake token endpoint; records requests, answers with a fresh token."""
    calls = []
    answer = {"status": 200}

    def handler(request: httpx2.Request) -> httpx2.Response:
        form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
        calls.append({"form": form, "auth": request.headers.get("authorization")})
        if answer["status"] != 200:
            return httpx2.Response(answer["status"], json={"error": "invalid_request",
                                                           "error_description": "nope"})
        return httpx2.Response(200, json={"access_token": jwt(time.time() + 300, f"mail{len(calls)}")})

    real = httpx2.AsyncClient
    monkeypatch.setattr(exchange.httpx2, "AsyncClient",
                        lambda **kw: real(transport=httpx2.MockTransport(handler), **kw))
    return calls, answer


def exchanger():
    return TokenExchanger(ENDPOINT, "mcp-mail", "s3cret", "dovecot")


async def test_request_is_rfc8693_with_client_auth_and_audience(keycloak):
    calls, _ = keycloak
    subject = jwt(time.time() + 300, "subject")
    mail_token = await exchanger().mail_token(subject)
    assert mail_token != subject
    form = calls[0]["form"]
    assert form["grant_type"] == "urn:ietf:params:oauth:grant-type:token-exchange"
    assert form["subject_token"] == subject
    assert form["subject_token_type"] == form["requested_token_type"] == "urn:ietf:params:oauth:token-type:access_token"
    assert form["audience"] == "dovecot"
    assert calls[0]["auth"] == "Basic " + base64.b64encode(b"mcp-mail:s3cret").decode()


async def test_one_exchange_per_subject_token(keycloak):
    calls, _ = keycloak
    ex = exchanger()
    a, b = jwt(time.time() + 300, "a"), jwt(time.time() + 300, "b")
    first = await ex.mail_token(a)
    assert await ex.mail_token(a) == first
    assert await ex.mail_token(b) != first
    assert len(calls) == 2


async def test_not_cached_beyond_the_subject_tokens_expiry(keycloak):
    calls, _ = keycloak
    ex = exchanger()
    nearly_expired = jwt(time.time() + 10, "old")   # inside the 30 s margin
    await ex.mail_token(nearly_expired)
    await ex.mail_token(nearly_expired)
    assert len(calls) == 2


async def test_refusal_is_a_readable_error(keycloak):
    _, answer = keycloak
    answer["status"] = 400
    with pytest.raises(TokenExchangeError, match="invalid_request: nope"):
        await exchanger().mail_token(jwt(time.time() + 300))


def test_config_requires_client_credentials():
    with pytest.raises(ConfigError, match="OIDC_CLIENT_ID"):
        load({**BASE_ENV, "MAIL_TOKEN_EXCHANGE": "on"})


def test_config_requires_audience_equal_to_client():
    with pytest.raises(ConfigError, match="MCP_AUDIENCE"):
        load({**BASE_ENV, "MAIL_TOKEN_EXCHANGE": "on", "OIDC_CLIENT_ID": "other", "OIDC_CLIENT_SECRET": "x"})


def test_config_defaults():
    s = load({**BASE_ENV, "MAIL_TOKEN_EXCHANGE": "on", "OIDC_CLIENT_ID": "mcp-mail", "OIDC_CLIENT_SECRET": "x"})
    assert s.token_exchange and s.mail_token_audience == "dovecot" and s.oidc_token_endpoint is None
    assert not load(dict(BASE_ENV)).token_exchange
