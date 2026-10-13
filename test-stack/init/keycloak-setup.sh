#!/bin/bash
# Configure the test realm with deploy/keycloak/setup-kcadm.sh, the way the
# docs tell users to configure theirs (docs/keycloak.md, option A).
set -euo pipefail
kcadm.sh config credentials --server http://keycloak:8080 --realm master --user admin --password admin

export REALM=mail OPENWEBUI_CLIENT=openwebui
args=(--proxy http://localhost:8000)
[[ "${MAIL_TOKEN_EXCHANGE:-off}" == on ]] && args+=(--exchange)
echo "== setup-kcadm.sh ${args[*]} (first run)"
bash /setup-kcadm.sh "${args[@]}" > /dev/null

echo "== setup-kcadm.sh ${args[*]} (second run: must change nothing)"
second=$(bash /setup-kcadm.sh "${args[@]}" 2>&1 >/dev/null)
echo "$second"
if grep -Eq '^(created|enabled|removed)' <<<"$second"; then
  echo "setup-kcadm.sh is not idempotent" >&2
  exit 1
fi

# Test-only: fixed secrets instead of the generated ones (the mail image's
# introspection_url and mcp-mail's OIDC_CLIENT_SECRET have them baked in).
for client in dovecot mcp-mail; do
  id=$(kcadm.sh get clients -r mail -q clientId=$client --fields id --format csv --noquotes)
  kcadm.sh update "clients/$id" -r mail -s secret=$client-test-secret
done
echo "keycloak-setup done"
