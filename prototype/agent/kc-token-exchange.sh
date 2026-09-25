#!/bin/bash
# Proof of concept: an agent client exchanges a user token for a
# Dovecot-only token (Keycloak standard token exchange), then reads IMAP
set -e
kc() { runagent -m scratchpad1 podman exec -i keycloak /opt/keycloak/bin/kcadm.sh "$@"; }
R=ad.dom.test KC=https://keycloak.dp.nethserver.net/realms/ad.dom.test/protocol/openid-connect
kc config credentials --server http://127.0.0.1:18080 --realm master --user admin --password "${KC_ADMIN_PASSWORD}" </dev/null >/dev/null
if [ -z "$(kc get clients -r $R -q clientId=hermes-agent --fields id --format csv --noquotes </dev/null)" ]; then
    kc create clients -r $R -f - <<'JSON'
{"clientId":"hermes-agent","name":"Hermes agent (prototype)","protocol":"openid-connect","publicClient":false,
 "standardFlowEnabled":false,"directAccessGrantsEnabled":true,
 "attributes":{"standard.token.exchange.enabled":"true"},
 "protocolMappers":[{"name":"aud-dovecot","protocol":"openid-connect","protocolMapper":"oidc-audience-mapper",
   "config":{"included.client.audience":"dovecot","access.token.claim":"true","id.token.claim":"false","introspection.token.claim":"true"}}]}
JSON
fi
id=$(kc get clients -r $R -q clientId=hermes-agent --fields id --format csv --noquotes </dev/null)
( umask 077; kc get clients/$id/client-secret -r $R </dev/null | jq -r .value > /root/kc-hermes-agent-secret )
S=$(cat /root/kc-hermes-agent-secret)
claims() { cut -d. -f2 | tr '_-' '/+' | { read p; while [ $(( ${#p} % 4 )) -ne 0 ]; do p="$p="; done; echo "$p"; } | base64 -d | jq -c '{azp, aud, preferred_username, scope, exp_in: (.exp - now | floor)}'; }

echo "== 1. user token for the agent client (stands in for the token received at user login)"
T1=$(curl -s $KC/token -d grant_type=password -d client_id=hermes-agent --data-urlencode client_secret=$S \
    -d username=kctest1 --data-urlencode "password=${TEST_PASSWORD}" -d scope=openid | jq -r .access_token)
echo "$T1" | claims

echo "== 2. standard token exchange: audience=dovecot"
R2=$(curl -s $KC/token -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange -d client_id=hermes-agent \
    --data-urlencode client_secret=$S --data-urlencode subject_token=$T1 \
    -d subject_token_type=urn:ietf:params:oauth:token-type:access_token -d audience=dovecot)
T2=$(echo "$R2" | jq -r '.access_token // empty')
[ -z "$T2" ] && { echo "$R2" | jq -c .; exit 1; }
echo "$T2" | claims

echo "== 3. IMAP as kctest1 with the exchanged token"
curl -s -k --login-options AUTH=XOAUTH2 -u kctest1: --oauth2-bearer "$T2" "imaps://rl1.dp.nethserver.net:993/INBOX" -X "EXAMINE INBOX" \
    -w 'exit=%{exitcode}\n' | grep -E 'EXISTS|exit='

echo "== 4. the same exchange for a service outside the agent's allowed audiences"
curl -s $KC/token -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange -d client_id=hermes-agent \
    --data-urlencode client_secret=$S --data-urlencode subject_token=$T1 \
    -d subject_token_type=urn:ietf:params:oauth:token-type:access_token -d audience=nextcloud | jq -c '{error, error_description}'
