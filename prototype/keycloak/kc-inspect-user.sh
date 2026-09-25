#!/bin/bash
# Usage: kc-inspect-user.sh USERNAME [REALM]
kc() { runagent -m scratchpad1 podman exec -i keycloak /opt/keycloak/bin/kcadm.sh "$@" </dev/null; }
U=$1 R=${2:-ldap.dom.test}
kc config credentials --server http://127.0.0.1:18080 --realm master --user admin --password "${KC_ADMIN_PASSWORD}" >/dev/null
id=$(kc get users -r "$R" -q username="$U" -q exact=true --fields id --format csv --noquotes)
[ -z "$id" ] && { echo "user $U not found in $R"; exit 1; }
echo "== user"
kc get "users/$id" -r "$R" | jq '{id, username, email, emailVerified, firstName, lastName, enabled, federationLink, createdTimestamp: (.createdTimestamp/1000|todate), attributes}'
echo "== federated identities"
kc get "users/$id/federated-identity" -r "$R" | jq -c '.[]'
echo "== groups"
kc get "users/$id/groups" -r "$R" | jq -c '[.[].name]'
echo "== broker login events"
runagent -m scratchpad1 podman logs --since 2h keycloak 2>&1 | grep -E 'IDENTITY_PROVIDER|type="(LOGIN|REGISTER|UPDATE_PROFILE)[A-Z_]*"' | grep -E "$U|identity_provider" \
    | grep -oE 'type="[A-Z_]*"|error="[^"]*"|identity_provider="[^"]*"|username="[^"]*"|reason="[^"]*"' | paste -sd' ' | fold -w 200 | head -8
