# Dovecot and Postfix

Dovecot validates the token. Postfix delegates SMTP AUTH to Dovecot, so it
needs no OAuth configuration of its own. Files are in `deploy/`.

Everything on this page is the same for both mail credentials (forwarded
token and token exchange, [mail-credential.md](mail-credential.md)).
Dovecot checks whatever token it gets by introspection as the `dovecot`
client. Which token that is only changes in Keycloak and in this server.

## Versions

| Dovecot | Status |
|---|---|
| 2.4.1 | works, tested in CI (Debian 13 package) |
| 2.3.21.1 | works, tested in CI (Debian 12 backports package) |
| 2.3.19.1 | **does not work**: rejects every token with `Introspection failed: No username returned`, although Keycloak's answer contains `active: true` and `email` (Debian 12's own package) |

Older 2.3 releases are untested. On Debian 12, install Dovecot from
`bookworm-backports`. The test stack reproduces all three
(`DOVECOT=2.4|2.3|2.3.19`, [test-stack/README.md](../test-stack/README.md)).
Postfix was tested at 3.10.3 and 3.10.13. It only relays SASL to Dovecot.

## Dovecot 2.3

1. Copy `deploy/dovecot/2.3/conf.d/auth-oauth2.conf.ext` to
   `/etc/dovecot/conf.d/` and add `!include auth-oauth2.conf.ext` to
   `conf.d/10-auth.conf`.
2. Copy `deploy/dovecot/2.3/dovecot-oauth2.conf.ext` to `/etc/dovecot/`,
   `chmod 0640`, owner `root:dovecot`. Set the realm URL and the `dovecot`
   client secret in `introspection_url` (URL-encode special characters).
3. Keep your existing **userdb**. The oauth2 passdb only authenticates, and
   the userdb must map the login name (the token's `email`) to a mailbox.

The settings that matter, and why:

| Setting | Value | Why |
|---|---|---|
| `introspection_mode` / `introspection_url` | `post`, Keycloak's `.../token/introspect` with `dovecot` credentials | revocation takes effect immediately (D6) |
| `force_introspection` | `yes` | always ask Keycloak, never trust a token unchecked |
| `active_attribute` / `active_value` | `active` / `true` | reject logged-out or revoked tokens |
| `username_attribute` | `email` | must equal the server's `MAIL_USERNAME_CLAIM` (D7) |
| `scope` | `mail` | only tokens from clients with the `mail` scope reach mailboxes (D2) |

## Dovecot 2.4

`deploy/dovecot/2.4/oauth2.conf` expresses the same settings in 2.4 syntax:
the oauth2 settings in an `oauth2 { }` block, and a `passdb oauth2` limited
to the token mechanisms. Include it from `dovecot.conf`, keep your userdb,
and check the result with `doveconf -n`. Tested with 2.4.1 (see Versions).

## Postfix

1. `deploy/dovecot/auth-socket-for-postfix.conf`: Dovecot's auth socket in
   Postfix's queue directory.
2. `deploy/postfix/main.cf.snippet`: `smtpd_sasl_type = dovecot`, plus a
   sender-login map so users can only send as themselves.
3. `deploy/postfix/master.cf.snippet`: submission on 587 with mandatory
   STARTTLS, SASL, and `reject_sender_login_mismatch`.

Postfix advertises whatever mechanisms Dovecot offers, so XOAUTH2 and
OAUTHBEARER appear after `EHLO` once Dovecot is configured. Check with:

```bash
openssl s_client -starttls smtp -connect mail.example.com:587 -quiet <<< "EHLO test"   # 250-AUTH ... XOAUTH2 OAUTHBEARER
```

This server sends the token as a SASL continuation, not inline on the `AUTH`
line, because a 2-4 KB token would exceed command-line limits (D11).

## TLS

This server requires TLS for both IMAP and SMTP, and verifies certificates
(D9). If your certificates come from a private CA, mount the CA bundle and
set `MAIL_CA_FILE`.

`MAIL_CA_FILE` covers IMAP and SMTP only. If **Keycloak**'s certificate also
comes from a private CA, set `SSL_CERT_FILE` to a PEM bundle that includes it
(it replaces the system store for the Keycloak calls; D21).
