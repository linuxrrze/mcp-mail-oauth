import pytest

from mcp_mail.config import ConfigError, load

from .conftest import BASE_ENV


def test_defaults():
    s = load(dict(BASE_ENV))
    assert s.auth_mode == "resource"
    assert s.mcp_audience == "mcp-mail"
    assert (s.mail.imap_port, s.mail.imap_security) == (993, "tls")
    assert (s.mail.smtp_port, s.mail.smtp_security) == (587, "starttls")
    assert s.mail.sasl_mechanism == "XOAUTH2"
    assert s.mail.username_claim == "email"
    assert s.mail.sent_folder == "Sent"
    assert s.mail.require_email_verified is True
    assert load({**BASE_ENV, "MAIL_REQUIRE_EMAIL_VERIFIED": "off"}).mail.require_email_verified is False


def test_trailing_slashes_are_normalized():
    s = load({**BASE_ENV, "OIDC_ISSUER": BASE_ENV["OIDC_ISSUER"] + "/", "BASE_URL": "https://x.example/"})
    assert s.oidc_issuer == BASE_ENV["OIDC_ISSUER"]
    assert s.base_url == "https://x.example"


def test_port_defaults_follow_security():
    s = load({**BASE_ENV, "MAIL_IMAP_SECURITY": "starttls", "MAIL_SMTP_SECURITY": "tls"})
    assert s.mail.imap_port == 143
    assert s.mail.smtp_port == 465


def test_empty_sent_folder_disables_saving():
    assert load({**BASE_ENV, "MAIL_SENT_FOLDER": ""}).mail.sent_folder == ""


def test_mechanism_is_case_insensitive():
    assert load({**BASE_ENV, "MAIL_SASL_MECHANISM": "oauthbearer"}).mail.sasl_mechanism == "OAUTHBEARER"


@pytest.mark.parametrize("missing", ["OIDC_ISSUER", "BASE_URL", "MAIL_IMAP_HOST", "MAIL_SMTP_HOST"])
def test_required(missing):
    env = {k: v for k, v in BASE_ENV.items() if k != missing}
    with pytest.raises(ConfigError, match=missing):
        load(env)


def test_proxy_mode_requires_client_credentials():
    with pytest.raises(ConfigError, match="OIDC_CLIENT_ID"):
        load({**BASE_ENV, "AUTH_MODE": "proxy"})
    s = load({**BASE_ENV, "AUTH_MODE": "proxy", "OIDC_CLIENT_ID": "mcp-mail", "OIDC_CLIENT_SECRET": "s"})
    assert s.auth_mode == "proxy"


@pytest.mark.parametrize("key,value", [
    ("AUTH_MODE", "both"),
    ("MAIL_IMAP_SECURITY", "none"),  # no plaintext option on purpose (D9)
    ("MAIL_SASL_MECHANISM", "PLAIN"),
    ("MAIL_IMAP_PORT", "abc"),
])
def test_invalid_values(key, value):
    with pytest.raises(ConfigError, match=key):
        load({**BASE_ENV, key: value})
