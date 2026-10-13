import time

from mcp_mail.diagnose import check_claims, decode_claims

from .conftest import ISSUER

GOOD = {
    "iss": ISSUER, "aud": ["mcp-mail", "dovecot"], "azp": "openwebui",
    "scope": "openid email mail mcp:mail/read mcp:mail/send", "email": "alice@example.com", "email_verified": True,
    "exp": time.time() + 300,
}


def check(**override):
    return check_claims({**GOOD, **override}, issuer=ISSUER, audience="mcp-mail",
                        username_claim="email", introspect_client="dovecot")


def test_good_token_passes():
    assert check() == []


def test_each_rule_is_reported_with_its_fix():
    assert "MCP_AUDIENCE" in check(aud=["dovecot"])[0]
    assert "active=false" in check(aud="mcp-mail")[0]  # string aud, dovecot missing
    assert "DEFAULT" in check(scope="openid email")[0]
    assert "'email' claim" in check(email=None)[0]
    assert "OIDC_ISSUER" in check(iss="https://other.example")[0]
    assert "expired" in check(exp=time.time() - 10)[0]
    assert "email_verified" in check(email_verified=False)[0]


def test_decode_claims_reads_jwt_payload(make_token):
    claims = decode_claims(make_token())
    assert claims["email"] == "alice@example.com"
    assert "mcp-mail" in claims["aud"]


def test_missing_secret_without_terminal_fails_clearly(monkeypatch, tmp_path, make_token, capsys):
    """With the token on stdin there's no terminal: never prompt (getpass
    would read an empty secret from stdin), fail with a clear message."""
    from mcp_mail import diagnose

    from .conftest import BASE_ENV

    for key, value in BASE_ENV.items():
        monkeypatch.setenv(key, value)
    monkeypatch.delenv("INTROSPECT_CLIENT_SECRET", raising=False)
    monkeypatch.chdir(tmp_path)  # no stray .env
    monkeypatch.setattr(diagnose, "_terminal_available", lambda: False)
    monkeypatch.setattr(diagnose.getpass, "getpass", lambda *a: (_ for _ in ()).throw(AssertionError("prompted")))
    token_file = tmp_path / "token.txt"
    token_file.write_text(make_token())

    assert diagnose.main(["--token-file", str(token_file), "--introspect-client-id", "dovecot"]) == 2
    assert "INTROSPECT_CLIENT_SECRET" in capsys.readouterr().out


def test_introspection_endpoint_follows_the_internal_keycloak_url():
    from mcp_mail.config import load
    from mcp_mail.diagnose import introspection_endpoint

    from .conftest import BASE_ENV

    internal = "http://keycloak:8080/realms/mail/protocol/openid-connect/"
    for key, url in [("OIDC_JWKS_URI", internal + "certs"), ("OIDC_TOKEN_ENDPOINT", internal + "token")]:
        assert introspection_endpoint(load({**BASE_ENV, key: url})) == internal + "token/introspect"
