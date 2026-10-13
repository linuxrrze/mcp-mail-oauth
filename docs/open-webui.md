# Open WebUI

## 1. SSO with Keycloak

Merge `deploy/open-webui/openwebui.env.example` into Open WebUI's
environment. The parts that matter for mail:

- **`WEBUI_SECRET_KEY` set and stable.** Open WebUI encrypts the stored OAuth
  sessions, the ones whose tokens it forwards, with this key. A changing key
  makes every stored session undecryptable.
- **`OAUTH_SCOPES=openid email profile offline_access`.** The mail scopes need
  not be listed: they're Default scopes on the `openwebui` client.
  `offline_access` is recommended (D16). Open WebUI refreshes the forwarded
  token with the refresh token, and a normal refresh token expires with
  Keycloak's SSO idle timeout (30 min by default). After that the mail tools
  stop working until the user logs in again.

Users who were logged in before you assigned the scopes must log out and in
again: an existing session keeps its old token contents.

## 2. Add the MCP server

*Admin Panel → Settings → External Tools → Add* (or *Integrations*,
depending on version):

| Field | Value |
|---|---|
| Type | MCP (Streamable HTTP) |
| URL | **`BASE_URL` + `/mcp`**, as reachable from the Open WebUI server, e.g. `https://mcp-mail.example.com/mcp`, or `https://ai.example.com/mcp/mail-oauth/mcp` behind a reverse proxy sub-directory |
| Auth | **OAuth**: forwards the user's SSO access token |

The container logs the exact values at startup:

```
INFO mcp_mail.__main__: MCP client settings (Open WebUI: Admin Panel > Settings > External Tools > +):
INFO mcp_mail.__main__:   Type: MCP (Streamable HTTP)
INFO mcp_mail.__main__:   URL:  https://ai.example.com/mcp/mail-oauth/mcp
INFO mcp_mail.__main__:   Auth: OAuth  (forwards the user's own Keycloak token; not 'OAuth 2.1', 'Bearer' or 'Session')
...
```

(`docker logs mcp-mail 2>&1 | grep -A6 "MCP client settings"`)

**The URL must end in `/mcp`**, the endpoint path. The server's base URL or
a reverse-proxy prefix alone isn't the endpoint: the server answers it with
a 404 naming the right URL (log: `"POST / HTTP/1.1" 404`). A trailing slash
(`.../mcp/`) is accepted.

Don't pick "OAuth 2.1": that runs a separate per-user authorization against
this server, which only works in `AUTH_MODE=proxy` and costs each user a
consent click. Don't pick "Bearer" or "Session" either: those send a static
key or Open WebUI's own session token, neither of which Keycloak or Dovecot
can validate.

In resource mode no browser ever talks to this server, so the URL may be an
internal one (e.g. `http://mcp-mail:8000/mcp` in the same compose network).
`BASE_URL` should still be the URL clients use, because it appears in the
protected-resource metadata.

## 3. Check

In a chat with the tool enabled, ask *"run whoami"*. Expect your address
under `mailbox` and an empty `missing_scopes`. Then *"list my last 5
emails"*.

If `whoami` itself is missing, the request isn't authenticated at all. See
[troubleshooting.md](troubleshooting.md).
