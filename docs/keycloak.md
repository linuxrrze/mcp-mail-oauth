# Keycloak setup

What the realm needs depends on the **mail credential**: forwarded token
(default) or token exchange. Pick one first
([mail-credential.md](mail-credential.md), with diagrams of both layouts).
Reasons: [decisions.md](decisions.md) D4, D5, D6, D23. Three ways to set it
up: the script, the admin console, or the Admin REST API with the JSON in
[keycloak-api.md](keycloak-api.md) (per setup type and client).

## Common to both

| Object | Type | Why |
|---|---|---|
| `mail` | client scope, **in token scope** | Dovecot requires `scope = mail` |
| └ audience `dovecot` | audience mapper, *included client audience* | Keycloak 26.6.2+ returns `active: false` to an introspecting client that isn't in `aud` |
| `mcp:mail/read`, `mcp:mail/send`, `mcp:mail/draft`, `mcp:mail/organize` | client scopes, in token scope | per-tool permissions ([which tools](#tool-scopes)) |
| `dovecot` | confidential client, **every flow off** | credentials for Dovecot's introspection calls, nothing else |

Make sure each audience mapper has *Add to access token* and *Add to token
introspection* **on**. Keep *lightweight access tokens* **off** for these
clients: this server reads claims from the token itself. Assign scopes as
**Default**, never Optional. Optional scopes are only issued when requested,
and Open WebUI doesn't request them.

## Forwarded token (default)

| Object | Setting |
|---|---|
| `mail` | **also** an audience mapper `mcp-mail` (*included custom audience*, = the server's `MCP_AUDIENCE`) |
| Open WebUI's client | Default scopes `mail` and the `mcp:mail/*` scopes you grant |

**Script** (idempotent, skips what exists, prints the `dovecot` secret):

```bash
kcadm.sh config credentials --server https://sso.example.com --realm master --user admin
REALM=mail OPENWEBUI_CLIENT=openwebui deploy/keycloak/setup-kcadm.sh
```

Variables: `REALM` (required), `OPENWEBUI_CLIENT` (default `openwebui`),
`DOVECOT_CLIENT` (`dovecot`), `MCP_AUDIENCE` (`mcp-mail`, must match the
server's `MCP_AUDIENCE`).

**By hand** (admin console):
1. *Client scopes → Create* `mail`, type None, *Include in token scope* on.
   *Mappers → By configuration → Audience*, twice:
   `audience-mcp-mail` with *Included Custom Audience* `mcp-mail`, and
   `audience-dovecot` with *Included Client Audience* `dovecot`.
2. *Client scopes → Create* `mcp:mail/read`, `mcp:mail/send`,
   `mcp:mail/draft` and `mcp:mail/organize`, *Include in token scope* on.
3. *Clients → Create* `dovecot`, *Client authentication* on, every flow
   unticked. Copy the secret from *Credentials*.
4. *Clients → openwebui → Client scopes → Add client scope*: `mail` and
   the `mcp:mail/*` scopes, each **Default**.

**Admin REST API:** [keycloak-api.md](keycloak-api.md#forwarded-token-default).

**Check:** *Clients → openwebui → Client scopes → Evaluate*, pick a user,
*Generated access token*:

```json
"aud": ["mcp-mail", "dovecot"],
"scope": "openid email profile mail mcp:mail/read mcp:mail/send mcp:mail/draft mcp:mail/organize",
"email": "alice@example.com"
```

## Token exchange

Needs Keycloak 26.2+ (standard token exchange).

| Object | Setting |
|---|---|
| `mail` | only the `dovecot` audience mapper is needed |
| the `mcp:mail/*` scopes | **each** an audience mapper `mcp-mail` (*included custom audience*) |
| Open WebUI's client | Default scopes `mcp:mail/*`, **not** `mail` |
| `mcp-mail` | confidential client, *Standard token exchange* on, Default scope `mail`. Its client ID must equal the server's `MCP_AUDIENCE`: Keycloak only exchanges tokens whose `aud` names the exchanging client |

**Script** (idempotent; removes `mail` from Open WebUI's client; prints the
`mcp-mail` and `dovecot` secrets):

```bash
kcadm.sh config credentials --server https://sso.example.com --realm master --user admin
REALM=mail OPENWEBUI_CLIENT=openwebui deploy/keycloak/setup-kcadm.sh --exchange
```

The `mail` scope may keep its `mcp-mail` mapper from the default setup. It
does no harm, because only `mcp-mail` gets `mail` now.

**By hand** (admin console):
1. Steps 1 to 3 of the default setup (the `mcp-mail` mapper on `mail` is
   optional).
2. On each `mcp:mail/*` scope: *Mappers → By configuration → Audience*,
   `audience-mcp-mail`, *Included Custom Audience* `mcp-mail`.
3. *Clients → Create* `mcp-mail`, *Client authentication* on, every flow
   unticked except **Standard Token Exchange**. Copy the secret. *Client
   scopes → Add client scope* `mail` as **Default**.
4. *Clients → openwebui → Client scopes*: the `mcp:mail/*` scopes as
   **Default**. **Remove `mail`** if it is assigned.

**Admin REST API:** [keycloak-api.md](keycloak-api.md#token-exchange).

**Check:** the same *Evaluate* view for `openwebui`:

```json
"aud": "mcp-mail",
"scope": "openid email profile mcp:mail/read mcp:mail/send mcp:mail/draft mcp:mail/organize",
"email": "alice@example.com"
```

`dovecot` and `mail` must be **absent**. Otherwise Open WebUI's token still
opens the mailbox directly, and the exchange gains nothing.

Then configure the server: `MAIL_TOKEN_EXCHANGE=on`, `OIDC_CLIENT_ID=mcp-mail`,
`OIDC_CLIENT_SECRET` ([mail-credential.md](mail-credential.md#token-exchange)).
To switch between the two: [mail-credential.md](mail-credential.md#switching).

## Tool scopes

Each scope unlocks a group of tools; a token without it doesn't even list
them. `setup-kcadm.sh` assigns all four. To withhold one, remove it from the
client's Default scopes (*Clients → openwebui → Client scopes*); users then
log in again.

| Scope | Tools | Grant to |
|---|---|---|
| `mcp:mail/read` | `list_folders`, `list_messages`, `search_messages`, `read_message`, `get_message_info`, `get_thread`, `get_attachment`, `folder_status` | everyone (needed for anything useful) |
| `mcp:mail/send` | `send_message` (incl. reply-all), `forward_message` | users who want the assistant to send |
| `mcp:mail/draft` | `save_draft` | everyone: the user sends drafts from their mail client, so nothing leaves without them |
| `mcp:mail/organize` | `set_flags`, `move_messages`, `trash_messages` | users who want the assistant to file mail; nothing is ever deleted permanently |

Keycloak scopes apply per client, not per user. To grant `send` to some
users only, use a second Open WebUI client or Keycloak's client-scope
policies.

## Users can't change their own address

Both variants. The mailbox is the token's `email` claim, so whoever can edit
a user's email can point that user at another mailbox. The server only
accepts verified addresses (`MAIL_REQUIRE_EMAIL_VERIFIED`, D24). Also make
the attribute admin-only, since Dovecot can't check `email_verified`:

*Realm settings → User profile → email → Permissions*: *Who can edit*
**admin** only. Or with kcadm:

```sh
kcadm.sh get users/profile -r mail > profile.json
jq '.attributes |= map(if .name == "email" then .permissions.edit = ["admin"] else . end)' \
  profile.json > profile-locked.json
kcadm.sh update users/profile -r mail -f profile-locked.json
```

Each user also needs *Email verified* on (*Users → user*), or the server
answers *your email address ... is not verified*.

## Either way: Dovecot's view

Save the generated token in `token.txt` and run, in the container:

```bash
mcp-mail-diagnose --introspect-client-id dovecot --imap < token.txt
```

With token exchange, it also performs the exchange and checks the exchanged
token. Every line must say `[ok]` ([troubleshooting.md](troubleshooting.md)).

## Disposable test stack

[`test-stack/`](../test-stack/README.md) runs a throwaway Keycloak with
Postfix, Dovecot and this server, configured by the same script, in either
variant (`MAIL_TOKEN_EXCHANGE=off|on`). Use it to try the setup, or to
compare a working realm with yours.

## Proxy mode

`AUTH_MODE=proxy` is independent of the mail credential. It serves MCP
clients that can't forward a Keycloak token and instead run the MCP OAuth
flow with Dynamic Client Registration (Claude Desktop, MCP Inspector, Open
WebUI's "OAuth 2.1" type).

1. A confidential client `mcp-mail` with Standard flow, redirect URI
   `<BASE_URL>/auth/callback`, and the scopes `mail` and `mcp:mail/*` as
   Default. Or: `setup-kcadm.sh --proxy https://mcp-mail.example.com`,
   combinable with `--exchange` (one `mcp-mail` client then does both).
   JSON for both variants: [keycloak-api.md](keycloak-api.md#proxy-mode).
2. Set `AUTH_MODE=proxy`, `OIDC_CLIENT_ID=mcp-mail`, `OIDC_CLIENT_SECRET`,
   and a long random `JWT_SIGNING_KEY` (D13). Keep the `/data` volume.
3. `BASE_URL` must now be reachable **by users' browsers** (Keycloak
   redirects there after login), not just by Open WebUI.

Forwarded Open WebUI tokens keep working in proxy mode. Users of DCR clients
see FastMCP's consent page once per client (D15). The Keycloak tokens from
the proxy login never leave the server: clients only get FastMCP's own
tokens.
