# Keycloak setup

What the realm needs (reasons: [decisions.md](decisions.md) D4, D5, D6):

| Object | Type | Why |
|---|---|---|
| `mail` | client scope, **in token scope** | Dovecot requires `scope = mail`. Carries two audience mappers |
| ├ audience `mcp-mail` | audience mapper, *included custom audience* | this server only accepts tokens with `MCP_AUDIENCE` in `aud` |
| └ audience `dovecot` | audience mapper, *included client audience* | Keycloak 26.6.2+ returns `active: false` to an introspecting client that isn't in `aud` |
| `mcp:mail/read`, `mcp:mail/send` | client scopes, in token scope | per-tool permissions |
| `dovecot` | confidential client, **every flow off** | credentials for Dovecot's introspection calls, nothing else |
| your Open WebUI client | existing | gets `mail`, `mcp:mail/read`, `mcp:mail/send` as **Default** scopes |

Make sure each audience mapper has *Add to access token* and *Add to token
introspection* **on**. Keep *lightweight access tokens* **off** for these
clients: this server reads claims from the token itself.

## Option A: script against an existing realm

```bash
kcadm.sh config credentials --server https://sso.example.com --realm master --user admin
REALM=mail OPENWEBUI_CLIENT=openwebui deploy/keycloak/setup-kcadm.sh
```

The script is idempotent (it skips what exists) and prints the `dovecot`
client secret for Dovecot's `introspection_url`. Variables: `REALM`
(required), `OPENWEBUI_CLIENT` (default `openwebui`), `DOVECOT_CLIENT`
(`dovecot`), `MCP_AUDIENCE` (`mcp-mail`, must match the server's
`MCP_AUDIENCE`).

## Option B: disposable test stack

[`test-stack/`](../test-stack/README.md) starts a throwaway Keycloak with
Postfix, Dovecot and this server, and configures the realm with the Option A
script. Use it to try the setup, or to see a working configuration next to
yours.

## Option C: by hand (admin console)

1. *Client scopes → Create*: `mail`, type None, *Include in token scope* on.
   In its *Mappers*: *By configuration → Audience* twice:
   - name `audience-mcp-mail`, *Included Custom Audience* `mcp-mail`
   - name `audience-dovecot`, *Included Client Audience* `dovecot`

   Both with *Add to access token* and *Add to token introspection* on.
2. *Client scopes → Create*: `mcp:mail/read` and `mcp:mail/send`, *Include in
   token scope* on.
3. *Clients → Create*: `dovecot`, *Client authentication* on, and **untick**
   Standard flow, Direct access grants, and everything else. Copy the secret
   from *Credentials*.
4. *Clients → openwebui → Client scopes → Add client scope*: `mail`,
   `mcp:mail/read`, `mcp:mail/send`, each as **Default**. Optional scopes are
   only issued when requested, and Open WebUI doesn't request them.

## Verify

*Clients → openwebui → Client scopes → Evaluate*, pick a user, open
*Generated access token*. It must show:

```json
"aud": ["mcp-mail", "dovecot", ...],
"scope": "openid email profile mail mcp:mail/read mcp:mail/send",
"email": "alice@example.com"
```

Paste it into `mcp-mail-diagnose --introspect-client-id dovecot` (see
[troubleshooting.md](troubleshooting.md)) to check Dovecot's view too.

## Proxy mode

For MCP clients that can't forward a Keycloak token and instead run the MCP
OAuth flow with Dynamic Client Registration (Claude Desktop, MCP Inspector,
Open WebUI's "OAuth 2.1" type):

1. Create a confidential client `mcp-mail` with Standard flow, redirect URI
   `<BASE_URL>/auth/callback`, and the same three Default scopes. Or run
   `setup-kcadm.sh --proxy https://mcp-mail.example.com`.
2. Set `AUTH_MODE=proxy`, `OIDC_CLIENT_ID=mcp-mail`, `OIDC_CLIENT_SECRET`,
   and a long random `JWT_SIGNING_KEY` (D13). Keep the `/data` volume.
3. `BASE_URL` must now be reachable **by users' browsers** (Keycloak
   redirects there after login), not just by Open WebUI.

Forwarded Open WebUI tokens keep working in proxy mode. Users of DCR clients
see FastMCP's consent page once per client (D15).

## Token exchange (optional)

`MAIL_TOKEN_EXCHANGE=on` gives the mail server its own tokens instead of the
one Open WebUI forwards (reasons and trade-offs: [decisions.md](decisions.md)
D23). Needs Keycloak 26.2+.

```bash
REALM=mail OPENWEBUI_CLIENT=openwebui deploy/keycloak/setup-kcadm.sh --exchange   # add --proxy URL if used
```

What `--exchange` changes:

| Object | Change |
|---|---|
| `mcp:mail/read`, `mcp:mail/send` | get an audience mapper `mcp-mail` (custom audience) |
| Open WebUI's client | keeps the two `mcp:mail/*` scopes, **loses** `mail` |
| `mcp-mail` | confidential client (created if missing), *Standard token exchange* on, `mail` as Default scope |

The server then needs:

```
MAIL_TOKEN_EXCHANGE=on
OIDC_CLIENT_ID=mcp-mail              # must equal MCP_AUDIENCE
OIDC_CLIENT_SECRET=<printed by the script>
#OIDC_TOKEN_ENDPOINT=http://keycloak:8080/realms/mail/protocol/openid-connect/token   # if the issuer isn't reachable
#MAIL_TOKEN_AUDIENCE=dovecot          # Dovecot's introspection client
```

Dovecot and Postfix stay unchanged. Users log in to Open WebUI again once,
so their tokens lose `mail`/`dovecot`. Until then, their old tokens still
work, because the exchange accepts them too.

**Check:** a token generated for the Open WebUI client (*Client scopes →
Evaluate*) now shows `"aud": ["mcp-mail", ...]` without `dovecot`, and
`mcp-mail-diagnose --introspect-client-id dovecot --imap` reports the
exchange and logs in with the exchanged token.

**Going back:** run the script without `--exchange`, which re-adds `mail` to
Open WebUI's client. Then set `MAIL_TOKEN_EXCHANGE=off`.
