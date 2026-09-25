#!/bin/bash
# Replace the ldap_uuid mapper of client "nextcloud" in realm ad.dom.test
# with the uppercase script mapper
set -e
kc() { runagent -m scratchpad1 podman exec -i keycloak /opt/keycloak/bin/kcadm.sh "$@"; }
R=ad.dom.test
kc config credentials --server http://127.0.0.1:18080 --realm master --user admin --password "${KC_ADMIN_PASSWORD}" </dev/null >/dev/null
echo "== registered script mappers"
kc get serverinfo </dev/null | jq -r '.protocolMapperTypes["openid-connect"][] | select(.id|startswith("script-")) | "\(.id): \(.name)"'
CID=$(kc get clients -r $R -q clientId=nextcloud --fields id --format csv --noquotes </dev/null)
old=$(kc get clients/$CID/protocol-mappers/models -r $R </dev/null | jq -r '.[] | select(.name=="ldap_uuid") | .id')
[ -n "$old" ] && kc delete clients/$CID/protocol-mappers/models/$old -r $R </dev/null
kc create clients/$CID/protocol-mappers/models -r $R -f - <<'JSON'
{"name":"ldap_uuid","protocol":"openid-connect","protocolMapper":"script-ldap-id-upper.js",
 "config":{"claim.name":"ldap_uuid","jsonType.label":"String","id.token.claim":"true","access.token.claim":"true",
  "userinfo.token.claim":"true","introspection.token.claim":"true","multivalued":"false"}}
JSON
echo "== token claims for kctest1"
S=$(cat /root/kc-nextcloud2-secret)
curl -s https://keycloak.dp.nethserver.net/realms/$R/protocol/openid-connect/token -d grant_type=password -d client_id=nextcloud \
    --data-urlencode client_secret=$S -d username=kctest1 --data-urlencode "password=${TEST_PASSWORD}" -d scope=openid \
  | jq -r '.id_token // .' | cut -d. -f2 | tr '_-' '/+' | { read p; while [ $(( ${#p} % 4 )) -ne 0 ]; do p="$p="; done; echo "$p"; } \
  | base64 -d | jq -c '{preferred_username, email, ldap_uuid}'
