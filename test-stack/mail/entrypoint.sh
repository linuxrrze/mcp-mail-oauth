#!/bin/sh
set -eu
# Print the effective Dovecot configuration (fails fast on syntax errors).
echo "== doveconf -n"; doveconf -n
echo "== dovecot $(dovecot --version), postfix $(postconf -h mail_version)"
dovecot
exec postfix start-fg
