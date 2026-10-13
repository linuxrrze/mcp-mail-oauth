#!/bin/sh
set -eu
# Print the effective Dovecot configuration (fails fast on syntax errors).
echo "== doveconf -n"; doveconf -n
echo "== dovecot $(dovecot --version), postfix $(postconf -h mail_version)"
# Dovecot's auth and LMTP sockets live in Postfix's queue directory, which a
# fresh install only creates when Postfix first starts (Debian trixie).
install -d -o postfix -g root -m 0700 /var/spool/postfix/private
dovecot
exec postfix start-fg
