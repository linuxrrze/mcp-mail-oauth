# Design decisions

Each decision lists its context, the options considered, what was chosen and
why, and what it costs. Several are direct responses to findings from the
predecessor project, `mcp-oauth-test` (`tools/mail` and `tools/mailapp`),
which is called "the predecessor" below.

The target setup everything is measured against:

> Users sign in to **Open WebUI** with **Keycloak** (OIDC). Open WebUI calls
> this MCP server. The server reads and sends the user's mail on a
> **Dovecot (IMAP) + Postfix (SMTP)** server that accepts OAuth tokens from
> **the same Keycloak realm**.

---

## D1. Scope: one service, one code path

**Context.** The predecessor carried three demos and, for each, two copies of
the same tool code (a monorepo path and a standalone path) "kept in sync by
hand", plus three copies of its OAuth client module. Its own review found
those copies to be the main maintenance risk.

**Decision.** This project is only the mail MCP service: one Python package
(`src/mcp_mail`), one entry point, one container image. No demos, no
monorepo/standalone split.

**Consequences.** Nothing has to be kept in sync by hand. The service is
deliberately *not* a general OAuth client for arbitrary mail providers (see
D18).

---

## D2. One token end to end (the central change)

**Context.** The predecessor ran two OAuth flows per user:

1. the MCP login (`mcp-mail` client, through FastMCP's OIDCProxy), and
2. a second, *separate* Authorization Code flow for the mailbox
   (`mcp-mail-backend` client): the user had to call `authorize_mail`, open
   the returned URL manually, and the server kept the resulting token in an
   in-memory per-user cache with its own refresh logic and a
   `/backend/callback` route.

With Open WebUI and a Dovecot server, that adds up to **four Keycloak
clients** (openwebui, mcp-mail, mcp-mail-backend, Dovecot's introspection
client) plus a DCR registration inside the proxy, a manual click per user,
and lost tokens on every restart. The predecessor's review also found that
`/backend/callback` could not bind the authorization to the browser that
started it (no session to compare against), so a user could be tricked into
linking their mailbox to someone else's account.

Two facts make the second flow unnecessary when the mail server trusts the
same realm:

- Open WebUI's MCP auth type **"OAuth"** (`system_oauth`) sends *the access
  token from the user's own Open WebUI SSO sign-in* as the bearer token
  ([Open WebUI MCP docs][owui-mcp]). That token is already a Keycloak token
  for this user.
- In proxy mode, FastMCP's OIDCProxy hands tools the **upstream** Keycloak
  access token, not its own reference token, and refreshes it transparently
  (verified in `fastmcp/server/auth/oauth_proxy/proxy.py`,
  `load_access_token`, FastMCP 3.4.x).

Dovecot validates a Keycloak token by introspection, regardless of which
client it was issued to. So the token the MCP server receives can itself be
the IMAP/SMTP credential.

**Options.**

| | Second OAuth flow per user (predecessor) | Reuse the incoming token (chosen) | RFC 8693 token exchange |
|---|---|---|---|
| Keycloak clients (Open WebUI setup) | 4 | **2** (openwebui, dovecot) | 3 (+ exchange client) |
| Extra user interaction | manual `authorize_mail` click | **none** | none |
| Server-side token state | per-user cache, lost on restart | **none** | none, or a short cache |
| Mailbox-binding weakness | present | **impossible**, the identity *is* the token | none |
| Keycloak requirement | any | any | 26.2+ (standard token exchange) |

**Decision.** There is no second OAuth flow and no mailbox-specific token.
Each tool call uses the bearer token of that very request (in proxy mode:
the upstream Keycloak token behind it) as the XOAUTH2/OAUTHBEARER credential.

**The predecessor's counterargument, and why it no longer holds.** The
predecessor kept the two clients apart so that "a single token's scope
[wouldn't] satisfy both `require_scopes()` and your mail server's oauth2
passdb at once ... widening what a single leaked token grants." Two things
have changed:

- *What a leaked MCP token grants was already mailbox access.* With the
  predecessor, anyone holding a user's MCP token could call `list_mails`,
  `read_mail` and `send_mail`, which used that user's cached mailbox token.
  Separating the clients never made a leaked MCP token less valuable. It only
  meant the attacker went through the MCP server instead of IMAP.
- *Mail access stays narrowly gated.* Dovecot accepts a token only if
  (a) Keycloak says it is active, (b) its `aud` contains Dovecot's
  introspection client, and (c) its `scope` contains `mail` (Dovecot's oauth2
  `scope` setting). Only clients that have the `mail` client scope assigned
  get such tokens; every other client in the realm does not.

What does widen: a leaked token can be used on IMAP directly, which allows
operations the MCP tools don't offer (deleting mail, for example). That is
bounded by the access-token lifetime, 5 minutes by Keycloak's default (D16).
Open WebUI also holds a token that works on the mail server. It already sees
all mail content that passes through tool calls, so this doesn't move the
trust boundary.

**Consequences.**
- Two Keycloak clients instead of four, and since Open WebUI's client exists
  anyway, only one of them is new. No `authorize_mail` step, no callback
  route, no per-user token cache, no in-memory state lost on restart.
- Only works when the mail server trusts the same issuer (D18).
- Upgrade path, if the shared-token trade-off ever becomes unacceptable:
  RFC 8693 token exchange, so Open WebUI's token is audience-restricted to
  this server and the server exchanges it for a Dovecot-audience token. That
  costs one confidential client and Keycloak 26.2+. It is not implemented
  (YAGNI), but D4's audience separation already prepares for it.

---

## D3. Two inbound modes, one acceptance rule

**Context.** Open WebUI can forward its SSO token. Other MCP clients (Claude
Desktop, MCP Inspector, Open WebUI's own "OAuth 2.1" type) instead run the MCP
authorization flow with Dynamic Client Registration (DCR). Keycloak's DCR
needs 26.6.0+ with a fix for MCP clients (per FastMCP's
`KeycloakAuthProvider` docstring) plus registration policies. The
predecessor solved that with OIDCProxy, which is stateful.

**Decision.** `AUTH_MODE=resource` (default) or `AUTH_MODE=proxy`. In both, a
request is accepted only with a **Keycloak access token whose `aud` contains
`MCP_AUDIENCE`**, with signature (JWKS), issuer and expiry checked:

- `resource`: FastMCP `RemoteAuthProvider` + `JWTVerifier`. Pure resource
  server. Publishes RFC 9728 protected-resource metadata naming Keycloak as
  the authorization server. Stateless, needs no client of its own.
- `proxy`: OIDCProxy for DCR clients, subclassed (`ProxyAcceptingDirectTokens`)
  so that directly forwarded tokens are *also* accepted. One deployment can
  then serve Open WebUI ("OAuth") and generic MCP clients at the same time.

**Why resource is the default.** The target setup needs nothing more, and it
is the mode with no state, no client secret and no browser-facing endpoints.

**Consequences.** Proxy mode adds one Keycloak client (`mcp-mail`), persistent
state (D13) and a consent screen (D15). The subclass overrides
`load_access_token`, the documented extension point that
`OAuthProvider.verify_token` delegates to. It calls the same `JWTVerifier`
the proxy uses for its upstream tokens, so both paths apply identical rules.

---

## D4. Audience binding: `MCP_AUDIENCE`, a custom audience string

**Context.** The MCP authorization spec requires servers to accept only
tokens issued for them, and forbids "token passthrough" of tokens meant for
someone else. Keycloak does not implement RFC 8707 resource indicators, so it
won't put the server's URL into `aud` on request.

**Decision.** The server requires `MCP_AUDIENCE` (default `mcp-mail`) in
`aud`. Keycloak adds it through an **Audience mapper with "included custom
audience"** in the `mail` client scope (D5).

**Why a custom string rather than a client audience.** "Included client
audience" only accepts names of existing clients, and in resource mode no
`mcp-mail` client exists. A custom audience works in both modes. Use the
server's URL as `MCP_AUDIENCE` if you prefer it, and set the same string in
the mapper.

**About passthrough.** The token *is* issued for this server: its `aud` names
it, and that is checked. That the same token is also accepted by Dovecot is
the deliberate design of D2, made explicit by a second `aud` entry, not a
token being smuggled to a party it wasn't meant for.

---

## D5. Keycloak layout: one `mail` client scope, all scopes Default

**Context.** The predecessor found two Keycloak pitfalls the hard way:

- Recent Keycloak (26.6.2+, hardened for CVE-2026-37979, per the predecessor's
  investigation; also described for Keycloak 26 in [this guide][kc26-dovecot])
  answers an introspection call with `active: false` unless the
  **introspecting client is in the token's `aud`**. Keycloak only fills
  `azp`, never `aud`, by default.
- Optional client scopes are only issued when the client asks for them.
  Open WebUI doesn't ask, so the tool scopes must be **Default** scopes, or
  FastMCP silently hides the tools.

**Decision.** Three client scopes:

| Client scope | In `scope` claim | Mappers | Purpose |
|---|---|---|---|
| `mail` | yes | audience `mcp-mail` (custom), audience `dovecot` (client) | gates mailbox access: Dovecot requires `scope = mail` |
| `mcp:mail/read` | yes | none | MCP read tools |
| `mcp:mail/send` | yes | none | MCP `send_message` |

All three are assigned as **Default** client scopes to `openwebui` (and to
`mcp-mail` in proxy mode). The mappers live in a shared client scope, not in a
client's dedicated scope, so every client that should reach mail gets them
from one place.

**Consequences.** Adding another client that may reach the mailbox is one
scope assignment. `deploy/keycloak/setup-kcadm.sh` does all of this
idempotently on an existing realm, and `deploy/keycloak/realm-mail.json` is
an importable test realm.

---

## D6. Dovecot validates by introspection, not local JWT validation

**Options.** Dovecot's oauth2 passdb can ask Keycloak (`introspection_mode =
post`) or validate JWTs locally (`introspection_mode = local`, Dovecot
2.3.11+, keys from a dict).

**Decision.** Introspection.
- Logout and session revocation take effect immediately (`active_attribute
  = active`). A locally validated token stays valid until it expires.
- No signing keys to copy into Dovecot and keep current across Keycloak key
  rotations.

**Cost.** One more Keycloak client (`dovecot`, credentials only, every flow
disabled) and its audience entry (D5). One HTTP request per IMAP/SMTP login.
That is cheap at the rate tools log in, and Dovecot's auth cache can absorb
it.

**Alternative kept open.** With local validation, the `dovecot` client and
its audience mapper go away, which leaves **zero** clients beyond Open
WebUI's own. That is a valid choice for operators who accept the revocation
delay.

---

## D7. Mailbox identity comes from a token claim

**Context.** The predecessor resolved each user's address with an extra call
to a userinfo endpoint, cached it, and fell back to a global `MAIL_ADDRESS`.

**Decision.** The IMAP/SMTP login name, and the From address, is the claim
named by `MAIL_USERNAME_CLAIM` (default `email`) of the request's own token.

- Dovecot derives the user from *the same token* via `username_attribute`.
  Configure both to the same claim and they cannot disagree.
- There's no extra HTTP call and nothing to cache.
- The model can't choose a mailbox: no tool takes an account parameter, and
  there is no global fallback address that could be mixed up between users.

**Consequence.** Users need that claim (an email in Keycloak, and the `email`
scope as Default). Without it, tools fail with an explicit message saying
which claim is missing, and `whoami` shows it.

---

## D8. SASL mechanism: XOAUTH2 by default, OAUTHBEARER selectable

XOAUTH2 is the de-facto format almost every OAuth-capable mail server
accepts. It is what the predecessor and typical Keycloak/Dovecot guides use.
OAUTHBEARER (RFC 7628) is the standardized one. Dovecot supports both
(`mechanisms = xoauth2 oauthbearer`). `MAIL_SASL_MECHANISM` switches; the
shipped Dovecot configs enable both, so switching needs no server change.

---

## D9. TLS is mandatory, and verified

**Decision.** IMAP: `tls` (993) or `starttls` (143). SMTP: `starttls` (587) or
`tls` (465). There is **no plaintext option**, and certificates are always
verified. `MAIL_CA_FILE` replaces the trust store for private CAs.

**Why.** The credential is a bearer token that grants full mailbox access
until it expires. A misconfigured plaintext hop leaks it, and "only for
testing" settings tend to survive into production.

---

## D10. Tool surface and authorization

**Decision.**

| Tool | Scope | Notes |
|---|---|---|
| `whoami` | none | identity, mailbox, scopes, `missing_scopes`; works when everything else is hidden |
| `list_folders` | `mcp:mail/read` | |
| `list_messages` | `mcp:mail/read` | newest first, paged (`limit` ≤ 50, `offset`) |
| `search_messages` | `mcp:mail/read` | server-side IMAP SEARCH; UTF-8 search terms supported |
| `read_message` | `mcp:mail/read` | `BODY.PEEK`: does **not** mark as read unless `mark_read=true`; body truncated (default 20k chars) |
| `send_message` | `mcp:mail/send` | plain text, From is always the authenticated user, optional reply threading |

- **Per-tool scopes, no global scope requirement**, so `whoami` stays
  reachable. Missing scopes were the predecessor's most confusing failure
  ("Tools: []"), and this makes them self-diagnosing.
- **No delete, move or flag tools.** Irreversible changes driven by a
  language model are the riskiest thing a mail tool can offer. Reading and
  sending cover the use case. Sending is the one consequential action, and
  the tool description tells the model to confirm with the user first.
- **Reading doesn't change state.** An assistant skimming the inbox
  shouldn't make messages look read to the human.
- **Sender can't be chosen.** It's the token's claim (D7), which also lines
  up with Postfix's `reject_sender_login_mismatch`.
- **Errors are MCP tool errors** (`isError: true`) with an actionable message,
  not success-shaped `{"status": ...}` payloads as in the predecessor. Clients
  and models treat them as failures.

---

## D11. A fresh connection per call, and robust SASL handling

**Decision.** Every tool call opens its own IMAP/SMTP connection,
authenticates with the current request's token, and closes it.

- No connection pool keyed by user, so no state, and a refreshed token is
  used the moment it arrives. Mailbox latency dominates either way.
- **SMTP AUTH sends the token as a continuation** (`AUTH XOAUTH2` → `334` →
  token), never inline. A base64 Keycloak token is 2-4 KB, far beyond
  RFC 5321's 512-octet command line. Inline long tokens are a known failure
  that other clients fixed exactly this way ([Net_SMTP #70][net-smtp]).
  RFC 4954 permits both forms.
- **The SASL error round is handled.** A server rejecting a token first sends
  a JSON error challenge and expects a dummy reply (empty for XOAUTH2, `^A`
  for OAUTHBEARER). The client sends that reply instead of the token again,
  and reports the server's JSON (e.g. `{"status":"401"}`) in the error.
- **A failed Sent-folder copy is reported, not raised.** The message is
  already delivered at that point, and an error would invite a retry that
  sends it twice.

---

## D12. Stateless streamable HTTP

**Decision.** `stateless_http=True`. No MCP session state lives in the
process: replicas need no session affinity and restarts drop nothing. In
resource mode the whole server is stateless. In proxy mode only the OAuth
store remains (D13).

---

## D13. Proxy-mode state: persistent store and an explicit signing key

**Context.** OIDCProxy keeps DCR registrations, OAuth transactions and
upstream tokens in an encrypted file store under `FASTMCP_HOME`. The
predecessor found that without a volume every image rebuild silently
deleted every client's registration. Reading FastMCP's source also shows
that, without `jwt_signing_key`, the signing key **and** the store's
encryption key and directory are derived from the client secret. Rotating
the secret therefore silently orphans every registration and session.

**Decision.** The image sets `FASTMCP_HOME=/data` (a volume in compose), and
`JWT_SIGNING_KEY` is exposed and recommended.

**Consequences.** Several proxy-mode replicas would need a shared store,
which FastMCP supports via `client_storage` but this project does not
configure. Resource mode has no such constraint, which is one more reason it
is the default.

---

## D14. Packaging and startup checks

- **Compatible-range pins** (`fastmcp>=3.4,<4`, ...). The predecessor pinned
  nothing, while this server relies on FastMCP auth internals that change
  between majors (D3).
- **Configuration is validated at startup** (`config.load`), so a typo stops
  the container with a clear message instead of failing on a user's first
  call.
- **The issuer is checked against discovery at startup.** If Keycloak's
  discovery document reports a different `issuer` than `OIDC_ISSUER`, the
  server refuses to start. Typical cause: reaching Keycloak under an
  internal Docker hostname, which would make every token fail the `iss`
  check later. `OIDC_JWKS_URI` decouples "where to fetch keys" from "what
  `iss` must say".
- **Non-root container** with a `/healthz` endpoint for health checks.
- **No startup banner.** Displaying FastMCP's banner also triggers its update
  check, an HTTP request to pypi.org on every start (seen in the smoke test).
  A server that holds mailbox credentials makes no outbound calls beyond
  Keycloak and the mail server.

---

## D15. Proxy mode keeps FastMCP's consent screen

**Context.** The predecessor set `require_authorization_consent="external"`
to skip FastMCP's consent page.

**Decision.** Proxy mode uses `require_authorization_consent=True`. With DCR,
anyone can register a client with an arbitrary redirect URI. If the proxy
doesn't ask, a user with a live Keycloak session who opens a crafted
authorize link is redirected, authorization code and all, to the attacker's
URI without ever seeing a prompt. This is the "confused deputy" problem the
MCP security guidance describes. Keycloak's own consent screen, even if
enabled, would show `mcp-mail`, not the attacker's client. FastMCP's screen
shows the registering client and its redirect URI.

**Cost.** One extra click on first use per client, in proxy mode only.
Resource mode, the Open WebUI path, has no browser flow at all.

---

## D16. Token lifetime and refresh

**Context.** The token reaching the mail server is short-lived (Keycloak
default: 5 minutes) and must be refreshed by whoever holds the refresh token:
Open WebUI (resource mode) or OIDCProxy (proxy mode). Open WebUI refreshes
stored OAuth sessions with the refresh token when a token nears expiry, and
deletes the session when that fails. Several Open WebUI bug reports trace
broken MCP tools to exactly that ([#19820][owui-19820], [#28319][owui-28319],
[#29571][owui-29571]), and its docs warn that `system_oauth` tool servers
fail without a usable refresh token ([SSO docs][owui-sso]).

**Decision / recommendations** (docs/open-webui.md):
- Keep Keycloak's access-token lifespan short (5 min). The token is a
  mailbox credential, and the refresh happens automatically.
- Let Open WebUI request `offline_access`. A normal Keycloak refresh token
  dies with the SSO session's idle timeout (default 30 min), after which
  mail tools stop working until the user logs in again. An offline token
  survives idle periods (bounded by Keycloak's offline-session settings).
- Set a stable `WEBUI_SECRET_KEY`: Open WebUI encrypts stored OAuth sessions
  with it.

---

## D17. Observability without leaking tokens

**Context.** To compare tokens against Dovecot's view, the predecessor added
`BACKEND_DEBUG_LOG_TOKENS`, which logged raw tokens.

**Decision.** Tokens are never logged, at any level. Diagnosis instead uses:
- `whoami` (D10): what the server sees for the calling user, minus the token.
- `mcp-mail-diagnose`: given a token on stdin or from a file (never argv),
  it shows the claims and checks every link this design depends on: issuer,
  `MCP_AUDIENCE`, the introspection client's audience, scopes and username
  claim. Then it optionally introspects *as Dovecot's client*, which shows
  exactly Dovecot's view, including the `active: false` case, and optionally
  tries a real IMAP login.
- `LOG_LEVEL` for this package's own loggers. FastMCP's logger is separate
  (`FASTMCP_LOG_LEVEL`) and doesn't propagate, a predecessor finding kept in
  `__main__.py`.

---

## D18. Non-goals

- **Mail servers that trust a different authorization server** (Gmail,
  Microsoft 365 with their own identity platforms). Their tokens can't come
  from the user's Keycloak session, so they need the predecessor's two-flow
  design. That's a different product, deliberately out of scope here.
- Attachment download and sending attachments or HTML mail. Both are
  possible extensions, but they add size and content-safety questions the
  plain-text tool set doesn't have.
- Mailbox modification (delete, move, flag): see D10.

---

## D19. Versions come from git tags, bumped automatically

**Context.** Releases should be fully automatic, and the version shown by the
running server must match the image tag.

**Options.**
- *Version in `pyproject.toml`, bumped by a bot commit.* Needs a bot that may
  push to `main`, which branch protection usually forbids, adds a commit per
  release, and has to be prevented from re-triggering CI.
- *External release tooling* (semantic-release, release-please). Capable,
  but brings a Node toolchain or a PR-based release flow for what is one
  decision per push.
- *Git tags as the single source of truth* (chosen). The next version is
  derived from the last `vX.Y.Z` tag and the commit messages since then.
  Nothing is committed back. setuptools-scm turns the tag into the package
  version, and CI injects it into the Docker build, whose context
  deliberately has no `.git`.

**Bump rules** (`scripts/next_version.py`, unit-tested): `BREAKING CHANGE` or
`type!:` → major, `feat:` → minor, everything else → patch. Free-form
messages still release, as a patch, so nobody has to adopt a commit
convention for releases to happen. A convention only buys bigger bumps.
Below 1.0, a breaking change bumps the minor version (SemVer gives 0.x no
stability promise), and **1.0.0 only happens through a manual `bump: major`**,
because declaring stability is a decision, not a side effect of a commit
message.

**Consequences.** The tag is pushed only after the image is published, so
failed runs leave no gaps. Runs on `main` are serialized (workflow
concurrency) so versions can't collide. A tag pushed by the workflow's own
token doesn't trigger another workflow run, so there is no release loop.

---

## D20. Publishing is gated, and the scanned image is the published image

**Decision.** The image is published only after the test suite (Python 3.11,
3.12, 3.13), a Trivy repository scan (secrets, misconfigurations), a Trivy
image scan and a container smoke test have all passed, and only from `main`.

- **Build once, push that build.** The image is built into the local Docker
  daemon, then scanned, smoke-tested and pushed. Rebuilding for the push
  could pull a newer base image or package than the one that was checked.
  The cost is a single architecture (amd64): multi-arch images can't be
  loaded into a local daemon for scanning.
- **Fail on fixable HIGH/CRITICAL only.** An unfixed CVE has no remedy, so
  failing on it would only block every release until upstream acts, which
  trains people to bypass the gate. Fixable ones always have a remedy.
  Exceptions go into `.trivyignore`, with a written reason, never into a
  lowered threshold.
- **Pending Debian updates are applied** in the Dockerfile, so the
  "fixable" base-image findings mostly fix themselves on the next build.
- **The smoke test checks properties, not just liveness:** health endpoint,
  401 plus resource metadata for an anonymous MCP request, the injected
  version, and the non-root UID.
- **Supply chain:** every third-party action is pinned to a full commit SHA,
  since tags can be moved and popular actions have had their tags hijacked.
  The Trivy binary version is pinned too, explicitly, rather than
  inheriting `trivy-action`'s built-in default, which lags behind Trivy's
  own releases (v0.36.0 of the action defaults to Trivy 0.70.0, while 0.75.0
  is current). Bump it like any dependency: check the release, update the
  pin in its own PR.
- **Verified locally before committing:** `actionlint` passes, and Trivy
  0.75.0's repository scan and a library scan of the resolved dependencies
  find no HIGH/CRITICAL issue. The image scan of the Debian layer and the
  smoke test first run in CI (no Docker on the authoring machine).

[owui-mcp]: https://docs.openwebui.com/features/extensibility/mcp
[owui-sso]: https://docs.openwebui.com/features/authentication-access/auth/sso/
[owui-19820]: https://github.com/open-webui/open-webui/discussions/19820
[owui-28319]: https://github.com/open-webui/open-webui/issues/28319
[owui-29571]: https://github.com/open-webui/open-webui/issues/29571
[kc26-dovecot]: https://deburen.co.uk/5/8/
[net-smtp]: https://github.com/pear/Net_SMTP/pull/70
