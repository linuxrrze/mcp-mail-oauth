#!/bin/sh
# Install the deploy/ files into the image. The only changes to them are the
# placeholders: Keycloak's URL and the dovecot client secret from the realm.
set -eu
DOVECOT=$1
T=/opt/test-stack
D=/opt/deploy
KEYCLOAK='http://dovecot:dovecot-test-secret@keycloak:8080'
fill() {  # deploy file -> destination, placeholders replaced (and checked)
  sed "s#https://dovecot:CHANGE_ME_DOVECOT_SECRET@sso.example.com#${KEYCLOAK}#" "$1" > "$2"
  if grep -q CHANGE_ME "$2"; then echo "unreplaced placeholder in $1" >&2; exit 1; fi
}

case "$DOVECOT" in
  2.3|2.3.19)
    cp "$T/dovecot-2.3.conf" /etc/dovecot/dovecot.conf
    cp "$D/dovecot/2.3/conf.d/auth-oauth2.conf.ext" /etc/dovecot/conf.d/
    fill "$D/dovecot/2.3/dovecot-oauth2.conf.ext" /etc/dovecot/dovecot-oauth2.conf.ext
    ;;
  2.4)
    cp "$T/dovecot-2.4.conf" /etc/dovecot/dovecot.conf
    fill "$D/dovecot/2.4/oauth2.conf" /etc/dovecot/oauth2.conf
    ;;
  *) echo "DOVECOT must be 2.3, 2.3.19 or 2.4" >&2; exit 1 ;;
esac
cp "$D/dovecot/auth-socket-for-postfix.conf" /etc/dovecot/
chmod 0640 /etc/dovecot/*.conf* && chgrp dovecot /etc/dovecot/*.conf*

cp "$T/main.cf" /etc/postfix/main.cf
cat "$D/postfix/main.cf.snippet" >> /etc/postfix/main.cf
echo '/^(.+)$/ ${1}' > /etc/postfix/sender_login_maps.pcre
[ -f /etc/postfix/master.cf ] || cp /usr/share/postfix/master.cf.dist /etc/postfix/master.cf
cat "$D/postfix/master.cf.snippet" >> /etc/postfix/master.cf
# No chroot in a container: it would need copies of resolv.conf etc. inside
# the queue directory. Socket paths are the same either way.
postconf -F '*/*/chroot = n'
chmod +x "$T/entrypoint.sh"
