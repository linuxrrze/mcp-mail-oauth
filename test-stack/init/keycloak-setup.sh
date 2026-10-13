#!/bin/bash
# Configure the test realm with deploy/keycloak/setup-kcadm.sh, the way the
# docs tell users to configure theirs (docs/keycloak.md, option A).
set -euo pipefail
kcadm.sh config credentials --server http://keycloak:8080 --realm master --user admin --password admin

export REALM=mail OPENWEBUI_CLIENT=openwebui
echo "== setup-kcadm.sh --proxy (first run)"
bash /setup-kcadm.sh --proxy http://localhost:8000 > /dev/null

echo "== setup-kcadm.sh --proxy (second run: must change nothing)"
second=$(bash /setup-kcadm.sh --proxy http://localhost:8000 2>&1 >/dev/null)
echo "$second"
if grep -q '^created' <<<"$second"; then
  echo "setup-kcadm.sh is not idempotent" >&2
  exit 1
fi

# Test-only: the mail image's introspection_url has a fixed secret baked in;
# give the dovecot client that secret instead of the generated one.
id=$(kcadm.sh get clients -r mail -q clientId=dovecot --fields id --format csv --noquotes)
kcadm.sh update "clients/$id" -r mail -s secret=dovecot-test-secret
echo "keycloak-setup done"
