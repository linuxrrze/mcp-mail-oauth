# Troubleshooting

Work down the chain; each step can only fail if the previous ones pass.

## `mcp-mail-diagnose`

Checks one token against every rule. Get a token for a test user from
Keycloak: *Clients → openwebui → Client scopes → Evaluate → (user) →
Generated access token*.

```bash
read -rsp "dovecot client secret: " INTROSPECT_CLIENT_SECRET; echo; export INTROSPECT_CLIENT_SECRET
mcp-mail-diagnose --introspect-client-id dovecot --imap < token.txt
# or in the container:
docker compose exec -T -e INTROSPECT_CLIENT_SECRET="$INTROSPECT_CLIENT_SECRET" mcp-mail \
  mcp-mail-diagnose --introspect-client-id dovecot --imap < token.txt
```

It reads the same `.env` as the server and takes the `dovecot` client secret
from `INTROSPECT_CLIENT_SECRET`. It only prompts for it when that's unset and
a terminal is attached, which isn't the case when the token comes from stdin.
It never prints the token, and exits non-zero if any check fails.

## Symptoms

| Symptom | Cause | Fix |
|---|---|---|
| Server won't start: *discovery document says issuer=...* | `OIDC_ISSUER` differs from the issuer Keycloak advertises, e.g. internal vs. public hostname | `OIDC_ISSUER` = the public issuer (the `iss` in tokens). If the container can only reach Keycloak internally, set `OIDC_JWKS_URI` to the internal `.../protocol/openid-connect/certs` |
| Every request 401, even `whoami` | Token lacks `mcp-mail` in `aud`, wrong issuer, or Open WebUI auth type isn't "OAuth" | Audience mapper in the `mail` scope, assigned **Default** (keycloak.md). Users must log in again after scope changes |
| Only `whoami` visible ("no tools") | Token lacks `mcp:mail/read` / `mcp:mail/send` | `whoami` lists `missing_scopes`. Assign them as **Default**, not Optional |
| *Your access token has no 'email' claim* | User without email, or `email` scope not Default | Set the user's email; make `email` a Default scope |
| *IMAP authentication failed* | Dovecot rejected the token; this server already accepted it | See next section |
| Dovecot log: *Introspection failed: No username returned*, although introspection returns `email` | Dovecot 2.3.19 | Upgrade to 2.3.21+ or 2.4 (mail-server.md, Versions) |
| Works for a while, then stops until re-login | Open WebUI couldn't refresh the token (refresh token expired with the SSO idle timeout) | `offline_access` in `OAUTH_SCOPES`, stable `WEBUI_SECRET_KEY` (open-webui.md, D16) |
| *TLS certificate ... could not be verified* | Private CA | `MAIL_CA_FILE` |
| Startup fails with a certificate error on OIDC discovery | Keycloak certificate from a private CA | `SSL_CERT_FILE` with a bundle that includes it (D21) |
| Open WebUI can't connect; server log shows `"POST / HTTP/1.1" 404` | The configured URL lacks the endpoint path | End the URL with `/mcp`, e.g. `https://ai.example.com/mcp/mail-oauth/mcp` (reverse-proxy.md) |
| *refused sender* on send | Postfix's sender-login map doesn't map the address to the login | Map each address to itself (deploy/postfix/main.cf.snippet) |

## Dovecot rejects the token

Dovecot's auth log has the real reason (`doveadm log errors`, or
`auth_debug = yes` temporarily). In order of likelihood:

1. **Introspection says `active: false`.** The `dovecot` client isn't in the
   token's `aud`. RFC 7662 hides every other field in that case, so it can
   look like a missing claim when actually the whole token was rejected.
   `mcp-mail-diagnose --introspect-client-id dovecot` shows this directly.
2. **Username mismatch.** Dovecot's `username_attribute` names a different
   claim than `MAIL_USERNAME_CLAIM`, or the userdb doesn't know that name.
3. **Scope.** The token lacks the scope set in Dovecot's oauth2 `scope`
   (`mail`).
4. **Mechanism not enabled.** `auth_mechanisms` lacks `xoauth2`/`oauthbearer`,
   or the passdb's `mechanisms` doesn't include the one in
   `MAIL_SASL_MECHANISM`.

## Logs

`LOG_LEVEL=DEBUG` covers this package's logs. `FASTMCP_LOG_LEVEL=DEBUG`
covers FastMCP's own, including token-validation failures (e.g. *audience
mismatch*). Tokens are never logged.
