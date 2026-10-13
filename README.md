# mcp-mail-oauth

An MCP server that lets an AI assistant read and send the **signed-in user's
own mail** on an IMAP/SMTP server that accepts OAuth tokens (XOAUTH2 /
OAUTHBEARER), using **the user's existing login**: no extra authorization
step, no stored passwords, no per-user state on the server.

Built for this setup:

```
 Browser ──login──▶ Keycloak ◀──introspect (as "dovecot")── Dovecot ◀── Postfix (SASL via Dovecot)
    │                  ▲                                         ▲
    ▼                  │ refresh                                 │ IMAP/SMTP, XOAUTH2 with
 Open WebUI ───────────┘                                         │ the user's Keycloak token
    │  MCP, Authorization: Bearer <user's Keycloak access token>  │
    └──────────────────────────▶ mcp-mail-oauth ──────────────────┘
                                 checks iss, aud ∋ "mcp-mail", scopes
```

1. The user logs in to Open WebUI with Keycloak.
2. Open WebUI's MCP auth type **"OAuth"** forwards that user's access token.
3. mcp-mail-oauth verifies it (signature, issuer, audience `mcp-mail`,
   per-tool scope) and takes the mailbox name from its `email` claim.
4. It logs in to Dovecot/Postfix with **the same token**. Dovecot checks it by
   introspection against Keycloak (active, audience `dovecot`, scope `mail`).

## Why it's built this way

The predecessor project needed **four Keycloak clients**, a second OAuth
flow per user with a manual "authorize mail" click, and an in-memory token
cache that was lost on every restart. Reusing the token the user already has
removes all of that: **two clients** (Open WebUI's, which exists anyway, and
Dovecot's introspection credentials), no extra click, no server-side state.
The reasoning behind every choice, including the trade-offs, is in
**[docs/decisions.md](docs/decisions.md)**. Start with D2.

## Tools

| Tool | Needs scope | What it does |
|---|---|---|
| `whoami` | none | Who you are, which mailbox, which scopes are missing |
| `list_folders` | `mcp:mail/read` | Folders and their flags |
| `list_messages` | `mcp:mail/read` | Newest first, paged, optionally unread only |
| `search_messages` | `mcp:mail/read` | By sender, recipient, subject, text, date range, unread |
| `read_message` | `mcp:mail/read` | Headers, text body, attachment list. Doesn't mark as read by default |
| `send_message` | `mcp:mail/send` | Plain-text mail from your own address, optional reply threading; copy saved to Sent |

Tools whose scope is missing from the token are hidden, and `whoami` tells
you which ones.

## Setup

**Adding it to an existing Open WebUI + Keycloak + Dovecot/Postfix
setup: follow [docs/integration.md](docs/integration.md)**, the step-by-step
walkthrough with a check after each step. In short:

1. **Keycloak**: client scopes, audience mappers, Dovecot's introspection
   client. One script does it: [docs/keycloak.md](docs/keycloak.md).
2. **Dovecot + Postfix**: oauth2 passdb with introspection; Postfix SASL via
   Dovecot. See [docs/mail-server.md](docs/mail-server.md).
3. **This server**:
   ```bash
   cp .env.example .env    # set OIDC_ISSUER, BASE_URL, MAIL_* hosts
   docker compose up -d
   ```
4. **Open WebUI**: SSO with `offline_access`, then add this server as an MCP
   tool server with auth type "OAuth". See [docs/open-webui.md](docs/open-webui.md).
5. **Check**: ask the assistant to run `whoami`, or run
   [`mcp-mail-diagnose`](docs/troubleshooting.md) against a token.

Other MCP clients (Claude Desktop, MCP Inspector) can't forward a Keycloak
token. They need `AUTH_MODE=proxy`; see [docs/keycloak.md](docs/keycloak.md#proxy-mode).

## Releases

Every push to `main` that passes the tests, both Trivy scans and a container
smoke test publishes a new image and tag `vX.Y.Z`. The version is bumped
automatically from commit messages (`feat:` → minor, `!`/`BREAKING CHANGE` →
major, else patch). See [docs/ci.md](docs/ci.md).

## Development

```bash
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/pytest
```

The tests need no Keycloak or mail server. Tokens are signed with a local
key, and the HTTP tests run the real FastMCP auth stack end to end, with only
the IMAP/SMTP calls replaced.

| Path | Contents |
|---|---|
| `src/mcp_mail/auth.py` | Which tokens are accepted (resource/proxy mode) |
| `src/mcp_mail/mail.py` | IMAP/SMTP with XOAUTH2/OAUTHBEARER, parsing, sending |
| `src/mcp_mail/server.py` | The MCP tools |
| `src/mcp_mail/diagnose.py` | `mcp-mail-diagnose` |
| `scripts/next_version.py` | Next release version from tags + commits |
| `.github/workflows/ci.yml` | Tests, Trivy, build, release |
| `deploy/` | Keycloak realm/script, Dovecot 2.3/2.4 and Postfix snippets, Open WebUI env |
| `docs/` | Decisions, setup guides, troubleshooting |
