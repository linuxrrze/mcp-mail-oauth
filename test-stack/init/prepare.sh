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

# A stand-in for "your existing realm": Open WebUI's client and two users,
# nothing for mail yet. Without a `clientScopes` list, Keycloak creates its
# built-in scopes (basic, email, profile, offline_access ...) on import, as in
# any real realm. The mail scopes, the dovecot client and the audience mappers
# then come from deploy/keycloak/setup-kcadm.sh (service keycloak-setup).
# Test-only: direct access grants, so the e2e runner gets user tokens
# without a browser.
user() {  # username -> user JSON (password = username)
  jq -n --arg u "$1" '{
    username: $u, enabled: true, emailVerified: true, email: ($u + "@example.com"),
    firstName: $u, lastName: "Example",
    credentials: [{type: "password", value: $u, temporary: false}]
  }'
}
jq -n --argjson alice "$(user alice)" --argjson bob "$(user bob)" '{
  realm: "mail", enabled: true, sslRequired: "external", accessTokenLifespan: 300,
  clients: [{
    clientId: "openwebui", publicClient: false, secret: "openwebui-test-secret",
    standardFlowEnabled: true, directAccessGrantsEnabled: true,
    redirectUris: ["http://localhost:3000/oauth/oidc/callback"], webOrigins: ["+"],
    attributes: {"pkce.code.challenge.method": "S256", "post.logout.redirect.uris": "+"}
  }],
  users: [$alice, $bob]
}' > /out/realm/realm-mail.json
echo "test-stack init done"
