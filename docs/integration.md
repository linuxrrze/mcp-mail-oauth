# Integrating into an existing Open WebUI + Keycloak + Dovecot/Postfix setup

This is the end-to-end walkthrough. The per-component pages
([keycloak.md](keycloak.md), [mail-server.md](mail-server.md),
[open-webui.md](open-webui.md)) have the details. This page puts them in
order, with a check after each step, so a problem shows up where it was
introduced instead of as a vague failure in the chat.

## What you need already

- **Keycloak** with a realm your Open WebUI users log in through (OIDC).
- **Open WebUI** using that realm for SSO.
- **Dovecot** (2.3 or 2.4) and **Postfix**, with Postfix doing SMTP AUTH via
  Dovecot (`smtpd_sasl_type = dovecot`), and TLS certificates on IMAP and
  submission.
- Users whose Keycloak **email** equals their mail login name.
- Docker on the host that will run this container.

## What changes where

| Component | Change | Effect on existing users |
|---|---|---|
| Keycloak | 3 client scopes, 1 new client (`dovecot`), scopes added to Open WebUI's client | Open WebUI tokens gain two `aud` entries and three scopes. Nothing else changes. Users must log in again to get them |
| Dovecot | one extra passdb, limited to `xoauth2`/`oauthbearer` | none: password logins keep using your existing passdb |
| Postfix | usually nothing; optionally sender-login enforcement | Postfix starts advertising XOAUTH2/OAUTHBEARER (it offers what Dovecot offers) |
| Open WebUI | `offline_access` in `OAUTH_SCOPES`, one MCP tool server | needs a restart; users log in again once |
| new | the `mcp-mail` container | none |

## Network paths to plan

```
Open WebUI ──HTTP──▶ mcp-mail:8000/mcp            (Docker network, no TLS needed internally)
mcp-mail ───HTTPS──▶ Keycloak JWKS                (signature keys; once at startup + on key rotation)
mcp-mail ───TLS────▶ Dovecot :993, Postfix :587   (hostname must match the certificate)
Dovecot ────HTTPS──▶ Keycloak introspection       (on every IMAP/SMTP login)
```

Two pitfalls decide most first-time failures:

1. **The issuer must be the public one.** `OIDC_ISSUER` must equal the `iss`
   in tokens, which is the URL users' browsers use for Keycloak. If the
   container can't reach that URL (Keycloak only reachable as
   `http://keycloak:8080` internally), keep `OIDC_ISSUER` public and set
   `OIDC_JWKS_URI` to the internal certs URL. The server refuses to start on
   an issuer mismatch, with a message saying exactly this.
2. **Mail hostnames must match the certificates.** The server verifies TLS
   and has no plaintext mode. Use the name on Dovecot's/Postfix's certificate
   (e.g. `mail.example.com`), not a Docker service name or IP. If that name
   doesn't resolve to a reachable address from inside the container (mail
   server on the same host behind NAT), map it with `extra_hosts` (see the
   compose file). If the certificate is from a private CA, mount the CA and
   set `MAIL_CA_FILE`. If Keycloak's certificate is from a private CA too, set
   `SSL_CERT_FILE` as well ([mail-server.md](mail-server.md#tls)).

**Behind a reverse proxy under a sub-directory** (e.g. Traefik serving
`https://ai.example.com/mcp/mail-oauth/`): see [reverse-proxy.md](reverse-proxy.md).
It takes three routes, two of them at the host root, and `BASE_URL` must
include the sub-directory.

## Step 1: Keycloak

```bash
kcadm.sh config credentials --server https://sso.example.com --realm master --user admin
REALM=<your realm> OPENWEBUI_CLIENT=<Open WebUI's client id> deploy/keycloak/setup-kcadm.sh
```

Note the printed `dovecot` client secret. Details and a click-through
version: [keycloak.md](keycloak.md). For separate mail-server tokens
(spec-conforming, a third client), see [Token exchange](keycloak.md#token-exchange-optional);
the checks below then differ as described there.

**Check:** *Clients → (Open WebUI client) → Client scopes → Evaluate*, pick a
real user, open *Generated access token*: `aud` contains `mcp-mail` and
`dovecot`, `scope` contains `mail mcp:mail/read mcp:mail/send`, and `email`
is set. Save that token in a file (`token.txt`) for the checks below. It is
valid for 5 minutes, so generate a new one if a later check reports
"expired".

## Step 2: Dovecot and Postfix

Add the oauth2 passdb (`deploy/dovecot/2.3/` or `2.4/`), with the Keycloak
URL and the `dovecot` secret from step 1. Reload Dovecot. Details:
[mail-server.md](mail-server.md).

**Check:**
```bash
doveconf -n | grep -A3 oauth2          # passdb present
openssl s_client -starttls smtp -connect mail.example.com:587 -quiet <<< "EHLO test" 2>/dev/null | grep AUTH
                                       # must list XOAUTH2 (via Dovecot)
```
The definitive check, a real login with the token, follows in step 3, once
the container (which ships the diagnostic tool) is running.

## Step 3: the container

```bash
mkdir -p /opt/mcp-mail && cd /opt/mcp-mail
curl -LO <repo>/deploy/docker-compose.existing-stack.yml   # or copy it from a checkout
curl -L <repo>/.env.example -o .env
```

Edit `.env`:

| Variable | Value |
|---|---|
| `OIDC_ISSUER` | `https://sso.example.com/realms/<realm>`, exactly the token's `iss` |
| `OIDC_JWKS_URI` | only if the public issuer isn't reachable from the container |
| `BASE_URL` | `http://mcp-mail:8000`, the URL Open WebUI uses (a public URL only for proxy mode) |
| `MAIL_IMAP_HOST`, `MAIL_SMTP_HOST` | names on the certificates |
| `MAIL_IMAP_SECURITY` / `MAIL_SMTP_SECURITY` | as your server offers them (defaults: 993 TLS, 587 STARTTLS) |
| `MAIL_SENT_FOLDER` | your Sent folder's name (e.g. `Sent`, `Gesendet`), or empty if sieve already files sent mail |

Set the image and Open WebUI's network, then start:

```bash
export MCP_MAIL_IMAGE=ghcr.io/linuxrrze/mcp-mail-oauth:0.2   # the default; override for another registry
export OPENWEBUI_NETWORK=$(docker inspect open-webui -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}}{{end}}')
docker compose -f docker-compose.existing-stack.yml up -d
docker compose -f docker-compose.existing-stack.yml logs mcp-mail | head
```

The log shows `Starting mcp-mail-oauth <version> in AUTH_MODE=resource ...`.
A `Configuration error: ...` line names the variable to fix.

**Check, end to end except Open WebUI:**
```bash
read -rsp "dovecot client secret: " INTROSPECT_CLIENT_SECRET; echo   # not echoed, not in history
docker compose -f docker-compose.existing-stack.yml exec -T \
  -e INTROSPECT_CLIENT_SECRET="$INTROSPECT_CLIENT_SECRET" mcp-mail \
  mcp-mail-diagnose --introspect-client-id dovecot --imap < token.txt
```
(The token arrives on stdin, so there's no terminal for an interactive
secret prompt; hence the variable.)
The command checks the token as this server would, then asks Keycloak *as
Dovecot*, then performs a real IMAP login. Every line must say `[ok]`, and a
`[FAIL]` line names the fix. Troubleshooting: [troubleshooting.md](troubleshooting.md).

## Step 4: Open WebUI

1. Add to Open WebUI's environment (see `deploy/open-webui/openwebui.env.example`):
   `OAUTH_SCOPES=openid email profile offline_access`, and make sure
   `WEBUI_SECRET_KEY` is set to a fixed value. Restart Open WebUI.
2. *Admin Panel → Settings → External Tools → Add*: type **MCP (Streamable
   HTTP)**, URL `http://mcp-mail:8000/mcp`, auth **OAuth**. Through a reverse
   proxy instead: `BASE_URL` + `/mcp`, e.g. `https://ai.example.com/mcp/mail-oauth/mcp`.
   The container prints these values at startup (`docker logs mcp-mail 2>&1 | grep -A6 "MCP client settings"`).
3. Users log out and in once, so their tokens carry the new scopes and the
   offline refresh token.

Why these settings: [open-webui.md](open-webui.md).

**Check:** in a chat with the tool enabled:
1. *"Run whoami"*: your address as `mailbox`, `missing_scopes` empty.
2. *"List my five newest emails"*: matches your inbox.
3. *"Send a test mail to myself with subject 'mcp test'"*: arrives, and a
   copy is in the Sent folder.

## Operating it

- **Updates:** `docker compose pull && docker compose up -d`. The `X.Y` tag
  receives patch releases only. Change the tag deliberately for new minor or
  major versions, after reading the release notes.
- **Logs:** `LOG_LEVEL=DEBUG` for this server and `FASTMCP_LOG_LEVEL=DEBUG`
  for the auth layer. Tokens are never logged. Dovecot's auth log shows
  mail-side rejections.
- **Scaling:** the container is stateless in the default mode. Run more
  replicas behind a load balancer if needed.

## Rolling back

In reverse order, each step independent:
1. Remove the tool server in Open WebUI (users immediately lose the tools).
2. `docker compose down` the container.
3. Remove the oauth2 `!include` from Dovecot and reload. Password logins were
   never affected.
4. In Keycloak, remove the three scopes from Open WebUI's client, then delete
   the `dovecot` client and the scopes.
