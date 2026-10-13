#!/bin/sh
# One-shot init for the test stack: a throwaway CA with a certificate for the
# mail server, and the Keycloak realm to import. Writes to /out (a volume).
set -eu
apk add --no-cache --quiet openssl jq >/dev/null

mkdir -p /out/certs /out/realm
cd /out/certs
if [ ! -f mail.crt ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj "/CN=test-stack CA" \
    -keyout ca.key -out ca.crt 2>/dev/null
  openssl req -newkey rsa:2048 -nodes -subj "/CN=mail.example.com" \
    -keyout mail.key -out mail.csr 2>/dev/null
  printf 'subjectAltName=DNS:mail.example.com\nextendedKeyUsage=serverAuth\n' > ext.cnf
  openssl x509 -req -in mail.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 30 \
    -extfile ext.cnf -out mail.crt 2>/dev/null
  rm -f mail.csr ext.cnf ca.srl ca.key
  chmod 0644 ca.crt mail.crt
  chmod 0600 mail.key   # read by root in the mail container before dropping privileges
fi

# The realm users deploy (deploy/keycloak/realm-mail.json), with test-only
# changes: direct access grants on the openwebui client (so the e2e runner can
# get a user token without a browser) and a second user, bob.
jq '
  (.clients[] | select(.clientId == "openwebui") | .directAccessGrantsEnabled) = true
  | .users += [{
      username: "bob", enabled: true, emailVerified: true, email: "bob@example.com",
      firstName: "Bob", lastName: "Example",
      credentials: [{type: "password", value: "bob", temporary: false}], requiredActions: []
    }]
' /realm-mail.json > /out/realm/realm-mail.json
echo "test-stack init done"
