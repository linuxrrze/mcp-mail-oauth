# Relation to the MCP authorization specification

How this server relates to the
[MCP authorization specification (draft)][spec] and its subpages
[Authorization Server Discovery][spec-disc], [Client Registration][spec-reg]
and [Security Considerations][spec-sec], as of October 2026. The draft builds
on the 2025-11-25 revision (the one D4 quotes). It adds RFC 9207 `iss`
validation, refresh-token guidance and the deprecation of Dynamic Client
Registration in favour of Client ID Metadata Documents (CIMD).

The reasons behind each choice are in [decisions.md](decisions.md). This page
maps them onto the spec's requirements. The behaviour described here was
checked against the code (FastMCP 4.1.0, MCP SDK 2.3.0), not just taken from
documentation.

## Keeping this page current

**Last checked against the draft: 2026-10-15.** The draft changes between
releases, and each release freezes it under a dated URL
(`/specification/<YYYY-MM-DD>/basic/authorization`). Check again:

- when a new spec revision is released: compare it with the dated URL this
  page was checked against, via the [changelog][spec-changelog];
- after upgrading FastMCP or the MCP SDK (D14, D21), since the proxy-mode
  behaviour described here comes from FastMCP;
- every few months otherwise, by re-reading the [draft][spec].

Then update this page, the date above, and any affected decision (D4 still
cites the 2025-11-25 revision).

## Summary

| Area | `AUTH_MODE=resource` (default) | `AUTH_MODE=proxy` |
|---|---|---|
| Protected Resource Metadata (RFC 9728), `resource_metadata` in 401 | conforms | conforms |
| Authorization server metadata, PKCE, `iss` | Keycloak's job (it provides them) | conforms (FastMCP) |
| Client registration | not applicable: pre-registered Keycloak clients | CIMD, DCR (deprecated) and pre-registration offered |
| Token validation: signature, issuer, expiry, audience | conforms | conforms |
| Audience is the server's canonical URI (RFC 8707) | partly: a configurable string, `mcp-mail` by default | FastMCP tokens: yes. Forwarded Keycloak tokens: as in resource mode |
| `scope` in `WWW-Authenticate`, 403 `insufficient_scope`, step-up | **deviates** (SHOULD): tools are hidden instead | **deviates**, same |
| No token pass-through to upstream APIs | **deviates** with `MAIL_TOKEN_EXCHANGE=off` (default); conforms with `on` | same |
| Confused deputy: consent per DCR client | not applicable: no browser flow | conforms (FastMCP consent screen, D15) |
| HTTPS | the reverse proxy's job; not enforced by the server | same |

The three deviations are deliberate and listed with their reasons under
[Deviations](#deviations).

## Roles

| Spec role | In this project |
|---|---|
| MCP server (OAuth resource server) | this server, at `BASE_URL` + `/mcp` |
| Authorization server | **resource mode:** Keycloak (`OIDC_ISSUER`). **Proxy mode:** this server (FastMCP OIDCProxy), which in turn is a confidential Keycloak client (`OIDC_CLIENT_ID`) |
| MCP client | Open WebUI ("OAuth" auth type, `system_oauth`), or in proxy mode any client running the MCP authorization flow (Claude Desktop, MCP Inspector, Open WebUI's "OAuth 2.1" type) |
| Upstream API | Dovecot (IMAP) and Postfix (SMTP), which validate tokens by Keycloak introspection (D6) |

Open WebUI's "OAuth" type doesn't run the spec's authorization flow at all.
It sends the access token from the user's own Open WebUI sign-in (D2). That
token comes from the same Keycloak realm that the Protected Resource
Metadata names, so it satisfies the spec's client-side rule "MCP clients
**MUST NOT** send tokens to the MCP server other than ones issued by the MCP
server's authorization server". The client-side discovery, PKCE, `resource`
and `iss` requirements apply to clients that do run the flow.

The spec applies to HTTP transports only. This server only offers
streamable HTTP (D12).

## Authorization server discovery

> MCP servers **MUST** implement the OAuth 2.0 Protected Resource Metadata
> (RFC 9728) … The Protected Resource Metadata document … **MUST** include
> the `authorization_servers` field containing at least one authorization
> server.

**Conforms.** `GET /.well-known/oauth-protected-resource/mcp` (path-aware,
including a reverse-proxy prefix: `tests/test_reverse_proxy.py`) returns:

| Field | Resource mode | Proxy mode |
|---|---|---|
| `resource` | `BASE_URL/mcp` | `BASE_URL/mcp` |
| `authorization_servers` | `[OIDC_ISSUER]` (Keycloak) | `[BASE_URL/]` (the proxy) |
| `scopes_supported` | the four `mcp:mail/*` scopes | `openid`, `email` and the four `mcp:mail/*` scopes |
| `bearer_methods_supported` | `["header"]` | `["header"]` |

> MCP servers **MUST** implement one of the following discovery mechanisms:
> `WWW-Authenticate` header … Well-Known URI …

**Both are implemented.** Every 401 carries
`WWW-Authenticate: Bearer resource_metadata="…/.well-known/oauth-protected-resource/mcp"`
(`tests/test_server_http.py`). The root URI
`/.well-known/oauth-protected-resource` returns 404, which is allowed: a
client tries the path-aware URI first and finds it there.

**Authorization server metadata** (RFC 8414 / OIDC Discovery):

- *Resource mode:* Keycloak serves OIDC Discovery at
  `<issuer>/.well-known/openid-configuration`, the third URL in the spec's
  probing order for issuers with a path (`/realms/<realm>`). It includes
  `code_challenge_methods_supported`, which the spec requires of
  authorization servers that offer OIDC Discovery. At startup the server
  itself checks that the discovery document's `issuer` equals `OIDC_ISSUER`
  exactly, the same check the spec requires of clients (D14).
- *Proxy mode:* the server publishes RFC 8414 metadata at
  `/.well-known/oauth-authorization-server` with
  `code_challenge_methods_supported: ["S256"]`,
  `client_id_metadata_document_supported: true`,
  `registration_endpoint` and `authorization_response_iss_parameter_supported: true`.

## Client registration

- *Resource mode:* nothing to register with this server. Open WebUI is a
  pre-registered Keycloak client (`openwebui`). Generic MCP clients that
  follow the PRM to Keycloak need either a pre-registered client or
  Keycloak's own DCR/CIMD support, which this project neither configures nor
  relies on.
- *Proxy mode:* FastMCP offers all three mechanisms the spec lists: CIMD
  (URL-shaped `client_id`s, enabled by default in FastMCP 4), DCR at
  `/register` (deprecated by the draft, kept for clients that only speak
  it) and pre-registration. Toward Keycloak the proxy is one
  pre-registered confidential client (`OIDC_CLIENT_ID`). Registrations
  persist in `FASTMCP_HOME` (D13).

## Scope selection and scope challenges

> MCP servers **SHOULD** include a `scope` parameter in the
> `WWW-Authenticate` header … When a client makes a request with an access
> token with insufficient scope … the server **SHOULD** respond with
> `HTTP 403 Forbidden` … `error="insufficient_scope"` …

**Deviates (SHOULD).** The 401 challenge has no `scope` parameter, and the
server never answers 403. Each tool requires its own scope
(`require_scopes`, D10, D25). FastMCP leaves out of `tools/list` any tool
whose scope the token lacks, and a `tools/call` for such a tool returns a
JSON-RPC result with `isError: true` and "Unknown tool", over HTTP 200. A
client therefore never sees a scope challenge to step up from. See
[Deviations](#scope-challenges-and-step-up-authorization).

`scopes_supported` is still published. A client without a challenge falls
back to requesting all of them, which is what Keycloak's Default client
scopes give a token anyway (D5). `offline_access` is not in
`scopes_supported`, as the draft asks of servers. Open WebUI may still
request it from Keycloak (D16).

The scopes are flat, so there is no scope hierarchy to account for.

## Resource parameter and audience

> MCP servers **MUST** validate that access tokens were issued specifically
> for them as the intended audience, according to RFC 8707 Section 2.

**Conforms on validation; the audience value is a deployment choice.**
Every token must have `MCP_AUDIENCE` in `aud`, along with a valid signature
(JWKS), issuer and expiry (`build_token_verifier`). A token for another
audience (e.g. only `dovecot`), another issuer, an expired one or one signed
with another key gets 401 `invalid_token` (`tests/test_server_http.py`).

Keycloak doesn't implement RFC 8707, so it ignores the `resource` parameter
that spec-following clients send. The audience comes from an Audience mapper
instead (D4, D5). `MCP_AUDIENCE` defaults to `mcp-mail`, not to the
canonical URI the PRM announces as `resource`. To align the two, set
`MCP_AUDIENCE` to `BASE_URL/mcp` and use the same string in the mapper.
This is not possible with `MAIL_TOKEN_EXCHANGE=on`, where `MCP_AUDIENCE` must
equal the client ID (D23).

In proxy mode, FastMCP checks a client's `resource` parameter against the
server's URL (`invalid_target` on mismatch) and binds the tokens it issues
to that URL. It passes `resource` on to Keycloak, which ignores it.

## Access token usage

- **Header only.** Tokens are read from `Authorization: Bearer` only
  (`bearer_methods_supported: ["header"]`), never from the query string.
- **401 for invalid or expired tokens**, with `error="invalid_token"` and
  `resource_metadata`, as OAuth 2.1 Section 5.3 and the spec require.
- **Each request is authenticated on its own.** The transport is stateless
  (D12), so no MCP session outlives a token.
- `/healthz` needs no token. It isn't an MCP endpoint and returns nothing
  but `ok`.

## Token pass-through

> If the MCP server makes requests to upstream APIs … The access token used
> at the upstream API is a separate token, issued by the upstream
> authorization server. The MCP server **MUST NOT** pass through the token
> it received from the MCP client.

| `MAIL_TOKEN_EXCHANGE` | IMAP/SMTP credential | Spec |
|---|---|---|
| `off` (default, D2) | the token the client sent (in proxy mode: the upstream Keycloak token behind it) | **deviates** |
| `on` (D23) | a separate token from RFC 8693 token exchange: issued to `OIDC_CLIENT_ID`, `aud` `dovecot`, same user and session | conforms |

Inbound, both variants only accept tokens for this server ("MCP servers
**MUST** only accept tokens that are valid for use with their own
resources"). See [Deviations](#token-pass-through-to-imapsmtp).

## Refresh tokens

The server holds no refresh tokens in resource mode: Open WebUI refreshes
(D16). In proxy mode FastMCP holds Keycloak's refresh tokens in its
encrypted store, issues its own to the client, and swaps in fresh upstream
tokens transparently (D2, D13).

## Security considerations

| Spec requirement | How it's met |
|---|---|
| Audience binding and validation | [Resource parameter and audience](#resource-parameter-and-audience) |
| Token theft: secure storage, no logging | Tokens are never logged or echoed (D17). The exchange cache is keyed by a SHA-256 hash of the incoming token (D23). Proxy-mode storage is encrypted, with an explicit key (D13). Keycloak's 5-minute access tokens are recommended (D16) |
| Communication security: HTTPS for authorization endpoints and redirect URIs | The server speaks plain HTTP and relies on a TLS-terminating reverse proxy ([reverse-proxy.md](reverse-proxy.md)). It doesn't refuse an `http://` `BASE_URL`, so in proxy mode HTTPS depends on the deployment. Upstream, IMAP/SMTP always use verified TLS (D9) |
| PKCE (S256) | Proxy mode: advertised and enforced by FastMCP, which also uses PKCE toward Keycloak. Resource mode: Keycloak's |
| Mix-up attacks (RFC 9207 `iss`) | Proxy mode: FastMCP advertises and sends `iss`. Resource mode: Keycloak's. Validating it is the client's job |
| Open redirection: exact redirect URI matching | Proxy mode: FastMCP matches redirect URIs exactly against the client's registration. The registration itself accepts any URI (`allowed_client_redirect_uris` isn't set), which the consent screen covers (next row). Toward Keycloak there is only one redirect URI, `BASE_URL/auth/callback` |
| Confused deputy: consent per dynamically registered client | Proxy mode keeps FastMCP's consent screen (`require_authorization_consent=True`, D15). It shows the requesting client and its redirect URI before forwarding to Keycloak |
| CIMD security (SSRF, localhost redirect URIs) | Proxy mode: left to FastMCP's CIMD implementation (fetch limits, cache). Resource mode: not used |
| Access token privilege restriction | Signature, issuer, expiry and audience are checked before any request is processed. Per-tool scopes (D10). The mailbox comes only from the token's verified `email` claim (D7, D24) |

## Deviations

### Token pass-through to IMAP/SMTP

**What.** With `MAIL_TOKEN_EXCHANGE=off`, the default, the server logs in to
Dovecot and Postfix with the token it received. That is exactly what the
spec's "**MUST NOT** pass through" forbids.

**Why it's the default** (D2, D4). It removes a whole OAuth flow, two
Keycloak clients and all per-user state. The risks the rule guards against
are largely covered in other ways:

- Dovecot doesn't trust the token because this server forwarded it. It
  introspects it at Keycloak and checks its own audience, the `mail` scope
  and revocation. There's no confused deputy.
- The token is issued for both audiences from the start (`mcp-mail` and
  `dovecot`), only to clients that have the `mail` client scope.

What remains: a token leaked from the client also opens the mailbox at
IMAP/SMTP directly, for its lifetime (5 minutes by default).

**How to conform.** `MAIL_TOKEN_EXCHANGE=on` (D23, [mail-credential.md](mail-credential.md)).
It needs Keycloak 26.2+ and a third, confidential client. A leaked Open
WebUI token is then refused by Dovecot.

### Scope challenges and step-up authorization

**What.** There is no `scope` in the 401 challenge and no 403
`insufficient_scope`. Tools whose scope is missing are hidden, and calling
one returns "Unknown tool".

**Why.** It is FastMCP's model for per-tool scopes. It also fits the clients
this server is built for:

- Keycloak issues every tool scope as a Default client scope (D5), so a
  client can't get a token with *more* scopes by asking. A missing scope is
  a Keycloak configuration matter, not something a step-up flow could fix.
- Open WebUI's "OAuth" type forwards an existing token and can't re-authorize.
- `whoami` needs no scope and reports `missing_scopes`, so a missing scope
  is diagnosable from inside the chat (D10).

**Consequence.** A spec client in proxy mode that requested fewer scopes
won't be prompted to step up. It sees fewer tools until it re-authorizes.

### Audience string instead of the canonical URI

**What.** The token's `aud` must contain `MCP_AUDIENCE` (default
`mcp-mail`), not the `resource` URI the PRM announces.

**Why.** Keycloak doesn't support RFC 8707. A custom audience string works
in both modes without an extra client (D4). The spec's requirement, that the
server validates tokens were issued for it, holds either way. Operators who
want the URI can set `MCP_AUDIENCE` to it, except with token exchange.

## Verified by

- `tests/test_server_http.py`: 401 with `resource_metadata`, the PRM
  document, rejection of wrong audience, issuer, expiry and signing key,
  scope-based tool visibility.
- `tests/test_reverse_proxy.py`: PRM and `resource_metadata` under a path
  prefix.
- `test-stack/e2e.py` (CI, D22): the real chain with Keycloak, Dovecot 2.3
  and 2.4, token exchange off and on, including that Open WebUI's token is
  refused by Dovecot when exchange is on.

[spec]: https://modelcontextprotocol.io/specification/draft/basic/authorization
[spec-disc]: https://modelcontextprotocol.io/specification/draft/basic/authorization/authorization-server-discovery
[spec-reg]: https://modelcontextprotocol.io/specification/draft/basic/authorization/client-registration
[spec-sec]: https://modelcontextprotocol.io/specification/draft/basic/authorization/security-considerations
[spec-changelog]: https://modelcontextprotocol.io/specification/draft/changelog
