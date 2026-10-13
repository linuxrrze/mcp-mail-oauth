# Running behind a reverse proxy, under a sub-directory

The server can live under a path such as `https://ai.example.com/mcp/mail-oauth/`
without code changes. The proxy strips the prefix before forwarding, and
`BASE_URL` tells the server its public location, so every URL it advertises
carries the prefix.

```
BASE_URL=https://ai.example.com/mcp/mail-oauth
```

The MCP endpoint is then **`https://ai.example.com/mcp/mail-oauth/mcp`**:
the server's own `/mcp` path sits under your prefix. This is the URL to enter
in Open WebUI, and the container logs it at startup (*MCP client settings*).

Examples for Traefik v3:
- Docker labels: [`deploy/traefik/docker-compose.traefik.yml`](../deploy/traefik/docker-compose.traefik.yml)
  (an override for `deploy/docker-compose.existing-stack.yml`, with host and
  prefix as variables)
- file provider: [`deploy/traefik/dynamic-mcp-mail.yml`](../deploy/traefik/dynamic-mcp-mail.yml)

## Which URLs need routing

| Public URL | Forward to the app as | Needed |
|---|---|---|
| `/mcp/mail-oauth/…` (everything under the prefix) | prefix stripped: `/mcp`, `/healthz`; in proxy mode also `/authorize`, `/token`, `/register`, `/consent`, `/auth/callback` | always |
| `/.well-known/oauth-protected-resource/mcp/mail-oauth/mcp` | **unchanged** | for clients that discover authentication themselves; Open WebUI's "OAuth" mode doesn't |
| `/.well-known/oauth-authorization-server/mcp/mail-oauth` | rewritten to `/.well-known/oauth-authorization-server` | `AUTH_MODE=proxy` only |

**Why two of them sit outside the sub-directory.** OAuth metadata URLs are
defined relative to the host root, with the resource's or issuer's path
*appended* (RFC 9728 for protected-resource metadata, RFC 8414 for
authorization-server metadata, both used by the MCP authorization spec). So
a resource at `/mcp/mail-oauth/mcp` has its metadata at
`/.well-known/oauth-protected-resource/mcp/mail-oauth/mcp`, not under
`/mcp/mail-oauth/`.

- The server registers the protected-resource route under that full path
  itself, so the proxy forwards it as-is.
- The authorization-server metadata is served at the plain
  `/.well-known/oauth-authorization-server`, while clients look for it with
  the issuer path appended. Hence the rewrite.

These paths are what FastMCP 4.1 generates (unchanged since 3.4), and `tests/test_reverse_proxy.py`
pins them down so an upgrade that changes them fails CI.

## Things to get right

- **The client URL ends in `/mcp`**: `https://ai.example.com/mcp/mail-oauth/mcp`.
  `…/mcp/` works too: the server serves it directly instead of redirecting,
  because the redirect would go to the internal host without the stripped
  prefix (`http://mcp-mail:8000/mcp`). The prefix alone (`…/mcp/mail-oauth/`)
  gets a 404 that names the right URL; in the server log it shows up as
  `"POST / HTTP/1.1" 404`.
- **No trailing slash in `BASE_URL`.**
- **Match on `PathPrefix(`/mcp/mail-oauth/`)`**, with the trailing slash, so
  `/mcp/mail-oauth-other` can't match by accident. Strip `/mcp/mail-oauth`,
  without it.
- **Proxy mode: Keycloak's redirect URI** for the `mcp-mail` client becomes
  `https://ai.example.com/mcp/mail-oauth/auth/callback`.
- **Open WebUI on the same Docker network** doesn't need the proxy at all: it
  can call `http://mcp-mail:8000/mcp` directly. `BASE_URL` still names the
  public URL, because that's what goes into the metadata.

## Verify

```bash
curl -s https://ai.example.com/mcp/mail-oauth/healthz                    # ok
curl -s -o /dev/null -w '%{http_code}\n' -X POST https://ai.example.com/mcp/mail-oauth/mcp \
  -H 'Accept: application/json, text/event-stream' -d '{}'               # 401
curl -s -D- -o /dev/null -X POST https://ai.example.com/mcp/mail-oauth/mcp \
  -H 'Accept: application/json, text/event-stream' -d '{}' | grep -i www-authenticate
# resource_metadata="https://ai.example.com/.well-known/oauth-protected-resource/mcp/mail-oauth/mcp"
curl -s https://ai.example.com/.well-known/oauth-protected-resource/mcp/mail-oauth/mcp   # JSON, "resource" with prefix
# proxy mode:
curl -s https://ai.example.com/.well-known/oauth-authorization-server/mcp/mail-oauth     # JSON, endpoints with prefix
```
