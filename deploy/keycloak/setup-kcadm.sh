#!/usr/bin/env bash
# Configure an EXISTING Keycloak realm for mcp-mail-oauth with kcadm.sh.
# Idempotent: re-running skips what already exists. Nothing is deleted.
#
# Creates/ensures:
#   - client scopes  mail (with 2 audience mappers), mcp:mail/read, mcp:mail/send,
#                    mcp:mail/draft, mcp:mail/organize
#   - client         dovecot   (introspection credentials only, no login flow)
#   - client         mcp-mail  (only with --proxy, for AUTH_MODE=proxy, and/or
#                               --exchange, for MAIL_TOKEN_EXCHANGE=on)
#   - assigns these scopes as DEFAULT client scopes on the Open WebUI client
#     (remove a tool scope there afterwards to withhold its tools)
#     (and on mcp-mail with --proxy)
#   With --exchange instead (docs/keycloak.md, "Token exchange"): Open WebUI's
#   client gets only the mcp:mail/* scopes, which then carry the MCP
#   audience, and LOSES the mail scope; mcp-mail gets standard token exchange
#   and the mail scope. Open WebUI's tokens then no longer work at Dovecot.
#
# Usage:
#   kcadm.sh config credentials --server https://sso.example.com --realm master --user admin
#   REALM=mail OPENWEBUI_CLIENT=openwebui ./setup-kcadm.sh [--proxy https://mcp-mail.example.com] [--exchange]
#
# See docs/keycloak.md for what each piece is for.
set -euo pipefail

KCADM=${KCADM:-kcadm.sh}
REALM=${REALM:?set REALM}
OPENWEBUI_CLIENT=${OPENWEBUI_CLIENT:-openwebui}
DOVECOT_CLIENT=${DOVECOT_CLIENT:-dovecot}
MCP_AUDIENCE=${MCP_AUDIENCE:-mcp-mail}
PROXY_CLIENT=${PROXY_CLIENT:-mcp-mail}
PROXY_BASE_URL=""
EXCHANGE=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --proxy) PROXY_BASE_URL=${2:?--proxy needs the server BASE_URL}; shift 2 ;;
    --exchange) EXCHANGE=1; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
if [[ -n "$EXCHANGE" && "$PROXY_CLIENT" != "$MCP_AUDIENCE" ]]; then
  # Keycloak only exchanges tokens whose aud names the exchanging client.
  echo "--exchange needs PROXY_CLIENT ($PROXY_CLIENT) = MCP_AUDIENCE ($MCP_AUDIENCE)" >&2
  exit 2
fi

kc() { "$KCADM" "$@" -r "$REALM"; }

client_uuid() {  # clientId -> internal id (empty if missing)
  kc get clients -q "clientId=$1" --fields id --format csv --noquotes | head -n1
}

scope_uuid() {  # client scope name -> internal id (empty if missing)
  kc get client-scopes --fields id,name --format csv --noquotes | awk -F, -v n="$1" '$2 == n {print $1}'
}

ensure_scope() {  # name, consent text
  local id
  id=$(scope_uuid "$1")
  if [[ -z "$id" ]]; then
    id=$(kc create client-scopes -i -s "name=$1" -s protocol=openid-connect \
      -s 'attributes."include.in.token.scope"=true' \
      -s 'attributes."display.on.consent.screen"=true' \
      -s "attributes.\"consent.screen.text\"=$2")
    echo "created client scope $1" >&2
  fi
  echo "$id"
}

ensure_audience_mapper() {  # scope id, mapper name, config key, value
  if kc get "client-scopes/$1/protocol-mappers/models" --fields name --format csv --noquotes | grep -qx "$2"; then
    return
  fi
  kc create "client-scopes/$1/protocol-mappers/models" -s "name=$2" -s protocol=openid-connect \
    -s protocolMapper=oidc-audience-mapper \
    -s "config.\"$3\"=$4" \
    -s 'config."access.token.claim"=true' \
    -s 'config."introspection.token.claim"=true' \
    -s 'config."id.token.claim"=false' \
    -s 'config."lightweight.claim"=false'
  echo "created audience mapper $2" >&2
}

assign_default_scopes() {  # client uuid, scope ids...
  local client=$1; shift
  for scope in "$@"; do
    kc update "clients/$client/default-client-scopes/$scope" >/dev/null
  done
}

# 1. Dovecot's introspection client: authentication only, every flow off.
dovecot=$(client_uuid "$DOVECOT_CLIENT")
if [[ -z "$dovecot" ]]; then
  dovecot=$(kc create clients -i -s "clientId=$DOVECOT_CLIENT" -s publicClient=false \
    -s standardFlowEnabled=false -s implicitFlowEnabled=false \
    -s directAccessGrantsEnabled=false -s serviceAccountsEnabled=false)
  echo "created client $DOVECOT_CLIENT" >&2
fi

# 2. Client scopes. The audience mapper for Dovecot references its client by
#    clientId ("included client audience"); the MCP audience is a plain string,
#    so it works whether or not a client of that name exists.
mail=$(ensure_scope mail "Access your mailbox")
read=$(ensure_scope "mcp:mail/read" "Read your email")
send=$(ensure_scope "mcp:mail/send" "Send email on your behalf")
draft=$(ensure_scope "mcp:mail/draft" "Save email drafts")
organize=$(ensure_scope "mcp:mail/organize" "Flag, move and trash your email")
tools=("$read" "$send" "$draft" "$organize")
ensure_audience_mapper "$mail" "audience-$MCP_AUDIENCE" included.custom.audience "$MCP_AUDIENCE"
ensure_audience_mapper "$mail" "audience-$DOVECOT_CLIENT" included.client.audience "$DOVECOT_CLIENT"

# 3. DEFAULT (not Optional) on Open WebUI's client: it never asks for these
#    scopes itself, and Optional scopes are only issued when requested.
openwebui=$(client_uuid "$OPENWEBUI_CLIENT")
if [[ -z "$openwebui" ]]; then
  echo "Client $OPENWEBUI_CLIENT not found in realm $REALM - create Open WebUI's client first." >&2
  exit 1
fi
if [[ -z "$EXCHANGE" ]]; then
  assign_default_scopes "$openwebui" "$mail" "${tools[@]}"
  echo "assigned mail scopes as default on $OPENWEBUI_CLIENT" >&2
else
  # The tool scopes carry the MCP audience; the mail scope (Dovecot's
  # audience) is only for tokens the server obtains by exchange.
  for scope in "${tools[@]}"; do
    ensure_audience_mapper "$scope" "audience-$MCP_AUDIENCE" included.custom.audience "$MCP_AUDIENCE"
  done
  assign_default_scopes "$openwebui" "${tools[@]}"
  if kc get "clients/$openwebui/default-client-scopes" --fields id --format csv --noquotes | grep -qx "$mail"; then
    kc delete "clients/$openwebui/default-client-scopes/$mail"
    echo "removed the mail scope from $OPENWEBUI_CLIENT (token exchange)" >&2
  fi
  echo "assigned mcp:mail/* (not mail) as default on $OPENWEBUI_CLIENT" >&2
fi

# 4. Optional: the server's own client, for token exchange and/or AUTH_MODE=proxy.
# (--proxy first: it creates the client with the login flow; --exchange only adds to it.)
if [[ -n "$PROXY_BASE_URL" ]]; then
  proxy=$(client_uuid "$PROXY_CLIENT")
  if [[ -z "$proxy" ]]; then
    proxy=$(kc create clients -i -s "clientId=$PROXY_CLIENT" -s publicClient=false \
      -s standardFlowEnabled=true -s directAccessGrantsEnabled=false \
      -s "redirectUris=[\"${PROXY_BASE_URL%/}/auth/callback\"]" \
      -s 'attributes."pkce.code.challenge.method"=S256')
    echo "created client $PROXY_CLIENT" >&2
  fi
  assign_default_scopes "$proxy" "$mail" "${tools[@]}"
fi

if [[ -n "$EXCHANGE" ]]; then
  proxy=$(client_uuid "$PROXY_CLIENT")
  if [[ -z "$proxy" ]]; then
    proxy=$(kc create clients -i -s "clientId=$PROXY_CLIENT" -s publicClient=false \
      -s standardFlowEnabled=false -s implicitFlowEnabled=false \
      -s directAccessGrantsEnabled=false -s serviceAccountsEnabled=false)
    echo "created client $PROXY_CLIENT" >&2
  fi
  # Whitespace-insensitive: kcadm pretty-prints the client's JSON.
  if ! kc get "clients/$proxy" | tr -d ' \n\t' | grep -q '"standard.token.exchange.enabled":"true"'; then
    kc update "clients/$proxy" -s 'attributes."standard.token.exchange.enabled"=true'
    echo "enabled standard token exchange on $PROXY_CLIENT" >&2
  fi
  # Exchanged tokens get the mail scope: Dovecot's audience and scope = mail.
  assign_default_scopes "$proxy" "$mail"
fi
if [[ -n "$PROXY_BASE_URL$EXCHANGE" ]]; then
  echo "OIDC_CLIENT_SECRET for $PROXY_CLIENT:" >&2
  kc get "clients/$proxy/client-secret" --fields value --format csv --noquotes
fi

echo "Secret for Dovecot's introspection_url ($DOVECOT_CLIENT):" >&2
kc get "clients/$dovecot/client-secret" --fields value --format csv --noquotes
