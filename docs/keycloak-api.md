# Keycloak via the Admin REST API (JSON)

The objects from [keycloak.md](keycloak.md) as JSON for Keycloak's Admin
REST API, per setup type and client. Equivalent to
`deploy/keycloak/setup-kcadm.sh`; use whichever fits your tooling
(Terraform/OpenTofu, Ansible, plain curl). Written for Keycloak 26.

| Setup | Client scopes | `dovecot` | Open WebUI's client | `mcp-mail` |
|---|---|---|---|---|
| [Forwarded token](#forwarded-token-default) (default) | [mail + 2 mappers, tools](#client-scopes-forwarded-token) | [same everywhere](#dovecot) | [`mail` + tools](#openwebui-forwarded-token) | none |
| [Token exchange](#token-exchange) | [mail, tools with mapper](#client-scopes-token-exchange) | [same everywhere](#dovecot) | [tools only](#openwebui-token-exchange) | [exchange only](#mcp-mail-token-exchange) |
| [Proxy mode](#proxy-mode), forwarded token | as forwarded token | [same everywhere](#dovecot) | as forwarded token | [login flow](#mcp-mail-proxy-mode) |
| [Proxy mode](#proxy-mode) + token exchange | as token exchange | [same everywhere](#dovecot) | as token exchange | [login flow + exchange](#mcp-mail-proxy-mode--token-exchange) |

## Applying the JSON

Endpoints are relative to `https://sso.example.com/admin/realms/<realm>`.
Order matters: **client scopes first**, then clients. Clients refer to
scopes by name, and Keycloak skips a name it doesn't know with only a log
warning.

| What | Request |
|---|---|
| create a client scope (mappers included) | `POST /client-scopes` |
| add a mapper to an existing scope | `POST /client-scopes/<scope-id>/protocol-mappers/models` |
| create a client | `POST /clients` |
| change an existing client | `GET /clients/<id>`, edit, `PUT /clients/<id>` (full representation) |
| add a Default scope to an existing client | `PUT /clients/<id>/default-client-scopes/<scope-id>` (no body) |
| remove a Default scope | `DELETE /clients/<id>/default-client-scopes/<scope-id>` |
| read the generated secret | `GET /clients/<id>/client-secret` |
| look up ids | `GET /clients?clientId=<clientId>`, `GET /client-scopes` (match `name`) |

**`defaultClientScopes` is only honored on create** (`POST /clients`). A
`PUT` ignores it, so assign scopes to an *existing* client (normally Open
WebUI's) with the per-scope endpoint. A client created with
`defaultClientScopes` gets exactly that list instead of the realm's default
scopes. The lists below therefore repeat Keycloak 26's built-in defaults
(`acr`, `basic`, `email`, `profile`, `roles`, `web-origins`). Keep `basic`
(it carries `sub`) and `email` (the mailbox claim, Dovecot's
`username_attribute`).

Leave out `secret` and Keycloak generates one. Read it afterwards and don't
echo it to a log (D17).

```bash
KC=https://sso.example.com REALM=mail
# Admin token without putting the password on the command line.
read -rsp 'admin password: ' KC_PW; echo
TOKEN=$(curl -fsS "$KC/realms/master/protocol/openid-connect/token" \
  -d grant_type=password -d client_id=admin-cli -d username=admin \
  --data-urlencode "password=$KC_PW" | jq -r .access_token); unset KC_PW
api() {  # method path [json-file]
  curl -fsS -X "$1" -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
    ${3:+--data-binary "@$3"} "$KC/admin/realms/$REALM$2"
}

api POST /client-scopes scope-mail.json                    # one call per scope file
api POST /clients client-dovecot.json
id=$(api GET '/clients?clientId=dovecot' | jq -r '.[0].id')
api GET "/clients/$id/client-secret" | jq -r .value > dovecot.secret  # for introspection_url

# Existing Open WebUI client: assign scopes one by one.
owui=$(api GET '/clients?clientId=openwebui' | jq -r '.[0].id')
for name in mail mcp:mail/read mcp:mail/send mcp:mail/draft mcp:mail/organize; do
  sid=$(api GET /client-scopes | jq -r --arg n "$name" '.[] | select(.name == $n) | .id')
  api PUT "/clients/$owui/default-client-scopes/$sid"
done
```

## Building blocks

### Audience mappers

Two kinds, embedded in the client scopes below. *Included client audience*
names a client by `clientId` (it must exist). *Included custom audience* is
a plain string, so it doesn't need a client of that name.

```json
{
  "name": "audience-dovecot",
  "protocol": "openid-connect",
  "protocolMapper": "oidc-audience-mapper",
  "config": {
    "included.client.audience": "dovecot",
    "access.token.claim": "true",
    "introspection.token.claim": "true",
    "id.token.claim": "false",
    "lightweight.claim": "false"
  }
}
```

```json
{
  "name": "audience-mcp-mail",
  "protocol": "openid-connect",
  "protocolMapper": "oidc-audience-mapper",
  "config": {
    "included.custom.audience": "mcp-mail",
    "access.token.claim": "true",
    "introspection.token.claim": "true",
    "id.token.claim": "false",
    "lightweight.claim": "false"
  }
}
```

`mcp-mail` is the server's `MCP_AUDIENCE`; change both together.

### `dovecot`

The same in every setup: a confidential client with every flow off. Dovecot
only uses its credentials for introspection.

```json
{
  "clientId": "dovecot",
  "name": "Dovecot token introspection",
  "protocol": "openid-connect",
  "enabled": true,
  "publicClient": false,
  "clientAuthenticatorType": "client-secret",
  "standardFlowEnabled": false,
  "implicitFlowEnabled": false,
  "directAccessGrantsEnabled": false,
  "serviceAccountsEnabled": false,
  "attributes": {
    "oauth2.device.authorization.grant.enabled": "false",
    "oidc.ciba.grant.enabled": "false",
    "standard.token.exchange.enabled": "false"
  }
}
```

## Forwarded token (default)

### Client scopes (forwarded token)

`mail`, with both audience mappers:

```json
{
  "name": "mail",
  "protocol": "openid-connect",
  "attributes": {
    "include.in.token.scope": "true",
    "display.on.consent.screen": "true",
    "consent.screen.text": "Access your mailbox"
  },
  "protocolMappers": [
    {
      "name": "audience-mcp-mail",
      "protocol": "openid-connect",
      "protocolMapper": "oidc-audience-mapper",
      "config": {
        "included.custom.audience": "mcp-mail",
        "access.token.claim": "true",
        "introspection.token.claim": "true",
        "id.token.claim": "false",
        "lightweight.claim": "false"
      }
    },
    {
      "name": "audience-dovecot",
      "protocol": "openid-connect",
      "protocolMapper": "oidc-audience-mapper",
      "config": {
        "included.client.audience": "dovecot",
        "access.token.claim": "true",
        "introspection.token.claim": "true",
        "id.token.claim": "false",
        "lightweight.claim": "false"
      }
    }
  ]
}
```

The four tool scopes, without mappers. `mcp:mail/read` shown; the others
differ only in `name` and `consent.screen.text`:

| `name` | `consent.screen.text` |
|---|---|
| `mcp:mail/read` | Read your email |
| `mcp:mail/send` | Send email on your behalf |
| `mcp:mail/draft` | Save email drafts |
| `mcp:mail/organize` | Flag, move and trash your email |

```json
{
  "name": "mcp:mail/read",
  "protocol": "openid-connect",
  "attributes": {
    "include.in.token.scope": "true",
    "display.on.consent.screen": "true",
    "consent.screen.text": "Read your email"
  }
}
```

### `openwebui` (forwarded token)

Normally the client already exists: assign `mail` and the tool scopes with
`PUT /clients/<id>/default-client-scopes/<scope-id>`, and check that
lightweight access tokens are off. A new client for Open WebUI looks like
this (redirect URI = Open WebUI's `WEBUI_URL` + `/oauth/oidc/callback`):

```json
{
  "clientId": "openwebui",
  "name": "Open WebUI",
  "protocol": "openid-connect",
  "enabled": true,
  "publicClient": false,
  "clientAuthenticatorType": "client-secret",
  "standardFlowEnabled": true,
  "implicitFlowEnabled": false,
  "directAccessGrantsEnabled": false,
  "serviceAccountsEnabled": false,
  "redirectUris": ["https://ai.example.com/oauth/oidc/callback"],
  "webOrigins": ["+"],
  "attributes": {
    "pkce.code.challenge.method": "S256",
    "post.logout.redirect.uris": "+",
    "client.use.lightweight.access.token.enabled": "false"
  },
  "defaultClientScopes": [
    "acr", "basic", "email", "profile", "roles", "web-origins",
    "mail", "mcp:mail/read", "mcp:mail/send", "mcp:mail/draft", "mcp:mail/organize"
  ],
  "optionalClientScopes": ["offline_access"]
}
```

Leave out the tool scopes you don't grant ([keycloak.md](keycloak.md#tool-scopes)).
`offline_access` stays Optional: Open WebUI requests it (`OAUTH_SCOPES`, D16).

## Token exchange

Keycloak 26.2+.

### Client scopes (token exchange)

`mail` with only the Dovecot audience (an existing `audience-mcp-mail` on it
does no harm, [keycloak.md](keycloak.md#token-exchange)):

```json
{
  "name": "mail",
  "protocol": "openid-connect",
  "attributes": {
    "include.in.token.scope": "true",
    "display.on.consent.screen": "true",
    "consent.screen.text": "Access your mailbox"
  },
  "protocolMappers": [
    {
      "name": "audience-dovecot",
      "protocol": "openid-connect",
      "protocolMapper": "oidc-audience-mapper",
      "config": {
        "included.client.audience": "dovecot",
        "access.token.claim": "true",
        "introspection.token.claim": "true",
        "id.token.claim": "false",
        "lightweight.claim": "false"
      }
    }
  ]
}
```

Each tool scope now carries the MCP audience (names and texts as in the
[table above](#client-scopes-forwarded-token)):

```json
{
  "name": "mcp:mail/read",
  "protocol": "openid-connect",
  "attributes": {
    "include.in.token.scope": "true",
    "display.on.consent.screen": "true",
    "consent.screen.text": "Read your email"
  },
  "protocolMappers": [
    {
      "name": "audience-mcp-mail",
      "protocol": "openid-connect",
      "protocolMapper": "oidc-audience-mapper",
      "config": {
        "included.custom.audience": "mcp-mail",
        "access.token.claim": "true",
        "introspection.token.claim": "true",
        "id.token.claim": "false",
        "lightweight.claim": "false"
      }
    }
  ]
}
```

For scopes that already exist, add the mapper with
`POST /client-scopes/<scope-id>/protocol-mappers/models` and the mapper
JSON from [Audience mappers](#audience-mappers).

### `openwebui` (token exchange)

The tool scopes, **not** `mail`. On an existing client: `PUT` the tool
scopes and `DELETE /clients/<id>/default-client-scopes/<mail-scope-id>`.
For a new client, the [forwarded-token JSON](#openwebui-forwarded-token)
with this list:

```json
{
  "defaultClientScopes": [
    "acr", "basic", "email", "profile", "roles", "web-origins",
    "mcp:mail/read", "mcp:mail/send", "mcp:mail/draft", "mcp:mail/organize"
  ]
}
```

### `mcp-mail` (token exchange)

Confidential, every flow off except standard token exchange, Default scope
`mail`. `clientId` must equal the server's `MCP_AUDIENCE`.

```json
{
  "clientId": "mcp-mail",
  "name": "mcp-mail-oauth",
  "protocol": "openid-connect",
  "enabled": true,
  "publicClient": false,
  "clientAuthenticatorType": "client-secret",
  "standardFlowEnabled": false,
  "implicitFlowEnabled": false,
  "directAccessGrantsEnabled": false,
  "serviceAccountsEnabled": false,
  "attributes": {
    "standard.token.exchange.enabled": "true",
    "client.use.lightweight.access.token.enabled": "false"
  },
  "defaultClientScopes": [
    "acr", "basic", "email", "profile", "roles", "web-origins",
    "mail"
  ]
}
```

The secret is the server's `OIDC_CLIENT_SECRET`.

## Proxy mode

Independent of the mail credential ([keycloak.md](keycloak.md#proxy-mode)):
client scopes, `dovecot` and Open WebUI's client stay as in the chosen
setup. `mcp-mail` gets the login flow. Its redirect URI is the server's
`BASE_URL` + `/auth/callback`.

### `mcp-mail` (proxy mode)

```json
{
  "clientId": "mcp-mail",
  "name": "mcp-mail-oauth",
  "protocol": "openid-connect",
  "enabled": true,
  "publicClient": false,
  "clientAuthenticatorType": "client-secret",
  "standardFlowEnabled": true,
  "implicitFlowEnabled": false,
  "directAccessGrantsEnabled": false,
  "serviceAccountsEnabled": false,
  "redirectUris": ["https://mcp-mail.example.com/auth/callback"],
  "attributes": {
    "pkce.code.challenge.method": "S256",
    "client.use.lightweight.access.token.enabled": "false"
  },
  "defaultClientScopes": [
    "acr", "basic", "email", "profile", "roles", "web-origins",
    "mail", "mcp:mail/read", "mcp:mail/send", "mcp:mail/draft", "mcp:mail/organize"
  ]
}
```

### `mcp-mail` (proxy mode + token exchange)

One client for both: the proxy client plus
`"standard.token.exchange.enabled": "true"`.

```json
{
  "clientId": "mcp-mail",
  "name": "mcp-mail-oauth",
  "protocol": "openid-connect",
  "enabled": true,
  "publicClient": false,
  "clientAuthenticatorType": "client-secret",
  "standardFlowEnabled": true,
  "implicitFlowEnabled": false,
  "directAccessGrantsEnabled": false,
  "serviceAccountsEnabled": false,
  "redirectUris": ["https://mcp-mail.example.com/auth/callback"],
  "attributes": {
    "pkce.code.challenge.method": "S256",
    "standard.token.exchange.enabled": "true",
    "client.use.lightweight.access.token.enabled": "false"
  },
  "defaultClientScopes": [
    "acr", "basic", "email", "profile", "roles", "web-origins",
    "mail", "mcp:mail/read", "mcp:mail/send", "mcp:mail/draft", "mcp:mail/organize"
  ]
}
```

## Check

The same as after the script: the *Evaluate* view and `mcp-mail-diagnose`
([keycloak.md](keycloak.md#either-way-dovecots-view)). Over the API:

```bash
api GET "/clients/$owui/default-client-scopes" | jq -r '.[].name'
```
