#!/bin/bash
kc() { runagent -m scratchpad1 podman exec -i keycloak /opt/keycloak/bin/kcadm.sh "$@" </dev/null; }
kc config credentials --server http://127.0.0.1:18080 --realm master --user admin --password "${KC_ADMIN_PASSWORD}" >/dev/null
R=ad.dom.test
echo "== provider log"
runagent -m scratchpad1 podman logs --since 1h keycloak 2>&1 | grep -E "LinkByAttribute|linked to|replacing|link refused" | sed 's/^.*\(Account\|[0-9]* accounts\)/\1/'
echo "== events"
since=$(( ($(date +%s) - 3600) * 1000 ))
kc get events -r $R -q max=100 | jq -r --argjson s $since '.[] | select(.time >= $s) | [(.time/1000|strftime("%H:%M:%S")), .type, .clientId, (.details.username // ""), (.details.identity_provider // ""), (.details.identity_provider_identity // ""), (.error // "")] | @tsv' | tac
echo "== users"
for u in e.user1 dprincipi davide.principi; do
    id=$(kc get users -r $R -q username=$u -q exact=true --fields id --format csv --noquotes)
    [ -z "$id" ] && { echo "$u: not in Keycloak"; continue; }
    kc get users/$id -r $R | jq -c '{username, email, firstName, lastName, oid: .attributes.entra_oid, ldap_id: .attributes.LDAP_ID, federationLink}'
    kc get users/$id/federated-identity -r $R | jq -c '.[] | {identityProvider, userId, userName}'
done
echo "== nextcloud2 users"
runagent -m nextcloud2 podman exec --user www-data nextcloud-app php ./occ user:list --output=json 2>/dev/null </dev/null | jq -r 'to_entries[] | select(.value|test("rincipi|User1")) | "\(.key)\t\(.value)"'
echo "== review profile config"
kc get "authentication/flows/ns8%20first%20broker%20login/executions" -r $R | jq -r '.[] | select(.providerId=="idp-review-profile") | .authenticationConfig' | while read c; do kc get authentication/config/$c -r $R | jq -c .config; done
kc get users/profile -r $R | jq -c '.attributes[] | select(.name|test("^(email|firstName|lastName)$")) | {name, required}'
