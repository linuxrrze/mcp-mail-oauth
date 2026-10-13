"""mcp-mail-diagnose: check one access token against every link of the chain.

Reads the same environment/.env settings as the server, then for a given
Keycloak access token reports:

1. its claims (decoded locally, signature NOT checked - display only),
2. whether this MCP server would accept it (issuer, audience, scopes, claim),
3. with MAIL_TOKEN_EXCHANGE=on, the token exchange and the mail token it
   yields (steps 4 and 5 then use that mail token, as the server would),
4. optionally, what Keycloak's introspection endpoint says when asked by the
   client Dovecot uses (--introspect-client-id), which is exactly Dovecot's view,
5. optionally (--imap), a real IMAP login with it.

The token is read from a file or stdin, never from argv (shell history,
`ps`), and is never printed. An easy way to get one for a test user: Keycloak
admin console -> Clients -> <client> -> Client scopes -> Evaluate -> pick the
user -> "Generated access token".
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import getpass
import json
import os
import sys
import time

import httpx2
from dotenv import load_dotenv

from . import mail
from .auth import TOOL_SCOPES, build_exchanger
from .config import ConfigError, load
from .exchange import TokenExchangeError

OK, FAIL, INFO = "  [ok]  ", "  [FAIL]", "  [info]"


def decode_claims(token: str) -> dict:
    try:
        payload = token.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    except (IndexError, ValueError) as exc:
        raise SystemExit(f"Not a JWT access token ({exc}). Is the realm issuing opaque/lightweight tokens?") from None


def _aud_list(claims: dict) -> list[str]:
    aud = claims.get("aud", [])
    return [aud] if isinstance(aud, str) else list(aud)


def check_claims(claims: dict, *, issuer: str, audience: str, username_claim: str, introspect_client: str | None,
                 require_email_verified: bool = True) -> list[str]:
    """Return a list of failure messages (empty = everything this server checks passes)."""
    failures: list[str] = []
    auds = _aud_list(claims)
    scopes = (claims.get("scope") or "").split()

    if claims.get("iss", "").rstrip("/") != issuer:
        failures.append(f"iss={claims.get('iss')!r} but OIDC_ISSUER={issuer!r}: the server will reject it.")
    if audience not in auds:
        failures.append(
            f"aud {auds} lacks MCP_AUDIENCE {audience!r}: the server will reject it (401). "
            "Add an Audience mapper (included custom audience) to the `mail` client scope."
        )
    if introspect_client and introspect_client not in auds:
        failures.append(
            f"aud {auds} lacks {introspect_client!r}: Keycloak 26.6.2+ answers active=false "
            "to that client's introspection, so Dovecot rejects the login. Add an Audience "
            "mapper (included client audience) for it to the `mail` client scope."
        )
    # Only the read scope is essential; send/draft/organize are grants an
    # admin may withhold on purpose (main() lists them as info).
    missing = [s for s in TOOL_SCOPES[:1] if s not in scopes]
    if missing:
        failures.append(
            f"scope lacks {missing}: those tools will be hidden. Assign the client scopes as "
            "DEFAULT (not Optional) on the client that issued this token "
            f"(azp={claims.get('azp')!r})."
        )
    if not claims.get(username_claim):
        failures.append(f"no {username_claim!r} claim (MAIL_USERNAME_CLAIM): no mailbox can be derived.")
    elif username_claim == "email" and require_email_verified and claims.get("email_verified") is not True:
        failures.append("email_verified is not true: the server refuses unverified addresses "
                        "(Keycloak: Users > user > Email verified; or MAIL_REQUIRE_EMAIL_VERIFIED=off).")
    exp = claims.get("exp")
    if exp and exp < time.time():
        failures.append(f"token expired {int(time.time() - exp)}s ago.")
    return failures


KEYCLOAK_OIDC_PATH = "/protocol/openid-connect/"


def introspection_endpoint(settings) -> str:
    """Keycloak's introspection URL, reached the way the server reaches Keycloak.

    If an internal URL is configured (OIDC_JWKS_URI or OIDC_TOKEN_ENDPOINT,
    for containers that can't reach the public issuer), derive it from that,
    since all Keycloak endpoints share .../protocol/openid-connect/. Otherwise
    read it from the issuer's discovery document.
    """
    for url in (settings.oidc_jwks_uri, settings.oidc_token_endpoint):
        if url and KEYCLOAK_OIDC_PATH in url:
            return url.split(KEYCLOAK_OIDC_PATH)[0] + KEYCLOAK_OIDC_PATH + "token/introspect"
    discovery = httpx2.get(f"{settings.oidc_issuer}/.well-known/openid-configuration", timeout=10).json()
    return discovery["introspection_endpoint"]


def introspect(endpoint: str, token: str, client_id: str, client_secret: str) -> dict:
    resp = httpx2.post(
        endpoint, data={"token": token},
        auth=(client_id, client_secret), timeout=10,
    )
    resp.raise_for_status()
    return resp.json()


def _terminal_available() -> bool:
    """Whether getpass can prompt. Without a terminal it silently falls back to
    stdin, which here already held the token, and returns an empty secret.
    /dev/tty can exist yet be unusable (`docker exec -T`), so try to open it."""
    try:
        with open("/dev/tty"):
            return True
    except OSError:
        return False


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--token-file", help="file containing the access token (default: read stdin)")
    parser.add_argument("--introspect-client-id", help="client Dovecot uses for introspection (e.g. dovecot)")
    parser.add_argument("--imap", action="store_true", help="also try a real IMAP login with the token")
    args = parser.parse_args(argv)

    load_dotenv()
    try:
        settings = load()
    except ConfigError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 2

    if args.token_file:
        with open(args.token_file) as f:
            token = f.read().strip()
    else:
        if sys.stdin.isatty():
            print("Paste the access token, then press Enter:", file=sys.stderr)
        token = sys.stdin.readline().strip()

    claims = decode_claims(token)
    print("Token claims (not signature-checked):")
    for key in ("iss", "azp", "aud", "sub", settings.mail.username_claim, "scope"):
        print(f"{INFO} {key} = {claims.get(key)!r}")
    if claims.get("exp"):
        print(f"{INFO} expires in {int(claims['exp'] - time.time())}s")

    print("\nThis MCP server's checks:")
    failures = check_claims(
        claims, issuer=settings.oidc_issuer, audience=settings.mcp_audience,
        username_claim=settings.mail.username_claim,
        # With exchange, the incoming token is deliberately not a mail credential.
        introspect_client=None if settings.token_exchange else args.introspect_client_id,
        require_email_verified=settings.mail.require_email_verified,
    )
    for failure in failures:
        print(f"{FAIL} {failure}")
    if not failures:
        print(f"{OK} issuer, audience, scopes and {settings.mail.username_claim!r} claim all fine")
    optional = [s for s in TOOL_SCOPES[1:] if s not in (claims.get("scope") or "").split()]
    if optional:
        print(f"{INFO} not granted (their tools stay hidden; fine if intended): {', '.join(optional)}")

    mail_credential = token
    if settings.token_exchange:
        print(f"\nToken exchange (MAIL_TOKEN_EXCHANGE=on, client {settings.oidc_client_id!r}):")
        try:
            mail_credential = asyncio.run(build_exchanger(settings).mail_token(token))
        except (TokenExchangeError, ConfigError) as exc:
            print(f"{FAIL} {exc}")
            return 1
        mail_claims = decode_claims(mail_credential)
        print(f"{OK} mail token: aud={mail_claims.get('aud')!r}, scope={mail_claims.get('scope')!r}, "
              f"{settings.mail.username_claim}={mail_claims.get(settings.mail.username_claim)!r}")
        if args.introspect_client_id and args.introspect_client_id not in _aud_list(mail_claims):
            print(f"{FAIL} the mail token's aud lacks {args.introspect_client_id!r}")
            failures.append("exchange")

    if args.introspect_client_id:
        print(f"\nKeycloak introspection as {args.introspect_client_id!r} (what Dovecot sees):")
        secret = os.environ.get("INTROSPECT_CLIENT_SECRET")
        if not secret:
            if not _terminal_available():
                print(f"{FAIL} set INTROSPECT_CLIENT_SECRET (no terminal to prompt on)")
                return 2
            secret = getpass.getpass("Client secret: ")
        try:
            result = introspect(introspection_endpoint(settings), mail_credential, args.introspect_client_id, secret)
        except httpx2.HTTPError as exc:
            print(f"{FAIL} introspection request failed: {exc}")
            failures.append("introspection")
        else:
            if result.get("active"):
                print(f"{OK} active=true, {settings.mail.username_claim}={result.get(settings.mail.username_claim)!r}, "
                      f"scope={result.get('scope')!r}")
            else:
                print(f"{FAIL} active=false. RFC 7662 hides every other field now, so no claim is "
                      "'missing': the whole token was rejected. Most likely cause: the client isn't in `aud`.")
                failures.append("introspection")

    if args.imap:
        print(f"\nIMAP login at {settings.mail.imap_host}:{settings.mail.imap_port} ({settings.mail.sasl_mechanism}):")
        username = claims.get(settings.mail.username_claim, "")
        try:
            folders = mail.list_folders(settings.mail, username, mail_credential)
        except mail.MailError as exc:
            print(f"{FAIL} {exc}")
            failures.append("imap")
        else:
            print(f"{OK} logged in as {username!r}, {len(folders)} folders")

    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
