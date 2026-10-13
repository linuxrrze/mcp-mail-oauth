"""The startup summary tells admins what to enter in Open WebUI."""

from mcp_mail.config import load
from mcp_mail.server import client_settings

from .conftest import BASE_ENV


def test_endpoint_is_base_url_plus_mcp_behind_a_prefix():
    text = "\n".join(client_settings(load({**BASE_ENV, "BASE_URL": "https://ai.example.com/mcp/mail-oauth/"})))
    assert "URL:  https://ai.example.com/mcp/mail-oauth/mcp\n" in text
    assert "Auth: OAuth " in text
    assert "mcp:mail/read, mcp:mail/send" in text
    assert "AUTH_MODE=proxy" not in text


def test_proxy_mode_names_the_redirect_uri():
    settings = load({**BASE_ENV, "AUTH_MODE": "proxy", "OIDC_CLIENT_ID": "mcp-mail", "OIDC_CLIENT_SECRET": "s"})
    text = "\n".join(client_settings(settings))
    assert settings.base_url.rstrip("/") + "/auth/callback" in text
