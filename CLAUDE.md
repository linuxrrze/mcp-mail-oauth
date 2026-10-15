# Codebase guide

MCP server (FastMCP 4.1) that gives an AI assistant the **signed-in user's
own mailbox** on an IMAP/SMTP server accepting OAuth (XOAUTH2/OAUTHBEARER).
The user's Keycloak access token arrives from Open WebUI and is either
forwarded to Dovecot/Postfix as is (default) or exchanged for a mail token
(RFC 8693, `MAIL_TOKEN_EXCHANGE=on`). Dovecot/Postfix validate it by
introspection. No per-user state on the server, no second OAuth flow.

Successor of `~/git/mcp-oauth-test` (`tools/mail`), which needed four
Keycloak clients and a manual "authorize mail" step. Don't copy patterns
from there back in.

**`docs/decisions.md` (D1–D25) is the source of truth for *why*.** Read the
relevant decision before changing auth, scopes, identity, TLS or
packaging, and add or update a decision when you change one of those.
Auth changes also update `docs/mcp-authorization.md` (spec conformance).

## Layout

| Path | Contents |
|---|---|
| `src/mcp_mail/config.py` | `load(env)` → frozen `Settings`/`MailSettings`; all env vars and their validation (`ConfigError`) |
| `src/mcp_mail/auth.py` | Inbound token acceptance: `resource` (JWTVerifier) or `proxy` (`ProxyAcceptingDirectTokens`, an OIDCProxy that also takes raw Keycloak tokens). Scope constants, `TOOL_SCOPES` |
| `src/mcp_mail/exchange.py` | `TokenExchanger`: RFC 8693 exchange, cache keyed by sha256 of the subject token |
| `src/mcp_mail/server.py` | `create_server()`: all MCP tools, `_identity()` (mailbox from token claim + `email_verified` check), `whoami`, `/healthz`, startup client-settings log |
| `src/mcp_mail/mail.py` | Everything IMAP/SMTP, synchronous: SASL, sessions, folder names (modified UTF-7), BODYSTRUCTURE parsing, partial fetches, composing/sending, flags/move/trash |
| `src/mcp_mail/diagnose.py` | `mcp-mail-diagnose`: checks a real token against the whole chain |
| `scripts/next_version.py` | Next release version from tags + commit messages |
| `deploy/` | `keycloak/setup-kcadm.sh` (`--exchange`), Dovecot 2.3/2.4 and Postfix snippets, Open WebUI env, Traefik examples |
| `test-stack/` | Disposable Keycloak + Postfix/Dovecot + server in Docker, configured from `deploy/`; `e2e.py` end-to-end checks |
| `docs/` | `decisions.md`, `integration.md` (setup walkthrough), `keycloak.md`, `keycloak-api.md` (Admin REST API JSON per setup/client), `mail-server.md`, `mail-credential.md`, `mcp-authorization.md` (MCP auth spec conformance), `open-webui.md`, `reverse-proxy.md`, `troubleshooting.md`, `ci.md` |

## Key patterns

- **Mailbox identity comes only from the token** (`MAIL_USERNAME_CLAIM`,
  default `email`, must be `email_verified` unless
  `MAIL_REQUIRE_EMAIL_VERIFIED=off`). Never accept a mailbox or sender
  address as a tool argument (D7, D24).
- **A fresh IMAP/SMTP connection per tool call** (`imap_session`/`smtp_session`
  context managers); `mail.py` is blocking and runs via `server._run()`
  (`asyncio.to_thread`), which turns `MailError` into `ToolError`. Error
  messages from `mail.py` are shown to the user, so they must not contain
  tokens.
- **Scopes, grouped by consequence (D10, D25):** `mcp:mail/read`,
  `mcp:mail/send`, `mcp:mail/draft`, `mcp:mail/organize`. Each tool uses
  `auth=require_scopes(...)`. FastMCP hides tools whose scope is missing;
  `whoami` needs no scope and reports `missing_scopes`. New tool → pick
  an existing scope or add one in `auth.py`, `setup-kcadm.sh` (including the
  exchange-mode audience mappers), `test-stack`, `docs/keycloak.md` and the
  README tool table (and the scope JSON in `docs/keycloak-api.md`).
- **Untrusted mail content:** recipients go through `parse_recipients` →
  `email.headerregistry.Address`; header and SMTP envelope are built from
  the same objects (no display-name smuggling). Reply headers from the
  original are filtered (`_MSGID_RE`). UIDs are validated by `_check_uid`.
  Nothing is ever expunged except the moved UIDs (`UID EXPUNGE`); trash is
  a move.
- **Memory bounds:** never fetch a whole message for reading. Use
  BODYSTRUCTURE (`parse_sexp` → `flatten_bodystructure` → `split_parts`)
  and partial `BODY.PEEK[section]<0.N>` fetches. Full fetches only where
  unavoidable and size-checked first (`MAIL_MAX_ATTACHMENT_BYTES`,
  `MAIL_MAX_FORWARD_BYTES`). Batch tools are capped (`MAX_BATCH`).
- **Special folders:** Drafts/Trash via RFC 6154 special-use flags, falling
  back to `MAIL_DRAFTS_FOLDER`/`MAIL_TRASH_FOLDER`, then "Drafts"/"Trash".
  Sent is `MAIL_SENT_FOLDER` (empty disables the copy). Re-query
  `CAPABILITY` after login before relying on MOVE/UIDPLUS.
- **Images** from `get_attachment` are returned as MCP image content
  (`fastmcp.tools.ToolResult` + `fastmcp.utilities.types.Image`, tool has
  `output_schema=None`).

## Gotchas

- `server.py` uses `from __future__ import annotations`: `Annotated[...]`
  aliases used in tool signatures must be **module-level** (see
  `REPLY_TO_UID`, `UidList`). Closure-local ones raise NameError when
  FastMCP resolves the schema.
- `httpx2`, not `httpx` (FastMCP 4, D21).
- Token exchange requires `MCP_AUDIENCE == OIDC_CLIENT_ID` and Keycloak
  26.2+ (checked in `config.load`).
- Dependencies use compatible-range pins in `pyproject.toml` (D14); FastMCP
  auth internals (OIDCProxy token swap) change between majors.
- Never log or echo bearer tokens or credentials (D17), including in
  scripts and CI logs.

## Tests

```bash
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/pytest
```

No Keycloak or mail server needed. `conftest.py`: `make_token(...)` signs
Keycloak-shaped tokens with a local RSA key (`scopes`, `audience`, `email`,
`email_verified` overridable). `tests/test_mail_helpers.py` has a `FakeIMAP`
that serves real `EmailMessage`s, generating BODYSTRUCTURE from them, and
implements LIST/STATUS/CAPABILITY/APPEND/UID commands; extend it rather
than mocking individual calls. `test_server_http.py` runs the real FastMCP
auth stack over HTTP.

End to end (needs Docker, which this dev box doesn't have; CI runs it):

```bash
docker compose -f test-stack/docker-compose.yml up -d --build
docker compose -f test-stack/docker-compose.yml run --rm e2e
docker compose -f test-stack/docker-compose.yml down -v
```

A new tool should get unit tests and a check in `test-stack/e2e.py`; the
test-stack Dovecot configs (2.3 and 2.4) create Entwürfe (\Drafts),
Papierkorb (\Trash) and Archive to exercise special-use lookup and
non-ASCII folder names.

## CI and releases

`.github/workflows/ci.yml` (details in `docs/ci.md`): tests on Python
3.11–3.13, Trivy, the integration matrix (Dovecot 2.3/2.4, token exchange
off/on), then build → image scan → smoke test → push → tag. Every green
push to `main` releases. Version from commit messages since the last tag:
`feat:` minor, `type!:`/`BREAKING CHANGE` major (minor while 0.x), else
patch. Use conventional commit subjects accordingly; mark config or
behavior changes that require operator action as breaking and say what to
do in the body.

The `gh` CLI isn't installed here. Use the GitHub REST API with curl
(e.g. `workflow_dispatch` to run CI on a branch), reading the token from
`~/.git-credentials` without ever printing it.

Branch → merge with `--no-ff` into `main` → push. Docs reflect the current
release: bump the image tag in `deploy/docker-compose.existing-stack.yml`
and `docs/integration.md` on a minor release.
