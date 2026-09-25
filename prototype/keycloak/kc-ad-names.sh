#!/bin/bash
# Align ad.dom.test name mappers with NS8 AD entries:
# cn = user name, displayName = full name, no givenName/sn
set -e
kc() { runagent -m scratchpad1 podman exec -i keycloak /opt/keycloak/bin/kcadm.sh "$@"; }
R=ad.dom.test
kc config credentials --server http://127.0.0.1:18080 --realm master --user admin --password "${KC_ADMIN_PASSWORD}" </dev/null >/dev/null
CID=$(kc get components -r $R --query type=org.keycloak.storage.UserStorageProvider --fields id --format csv --noquotes </dev/null)
mid() { kc get components -r $R --query parent=$CID </dev/null | jq -r --arg n "$1" '.[] | select(.name==$n) | .id'; }

for n in "first name" "last name"; do
    id=$(mid "$n"); [ -n "$id" ] && kc delete components/$id -r $R </dev/null && echo "deleted mapper: $n"
done
id=$(mid "full name")
kc get components/$id -r $R </dev/null \
  | jq '.config["ldap.full.name.attribute"] = ["displayName"] | .config["read.only"] = ["false"] | .config["write.only"] = ["false"]' \
  | kc update components/$id -r $R -f -
kc create components -r $R -f - <<JSON
{"name":"cn","providerId":"user-attribute-ldap-mapper",
 "providerType":"org.keycloak.storage.ldap.mappers.LDAPStorageMapper","parentId":"$CID",
 "config":{"ldap.attribute":["cn"],"user.model.attribute":["username"],"read.only":["false"],
  "always.read.value.from.ldap":["false"],"is.mandatory.in.ldap":["true"]}}
JSON
kc get users/profile -r $R </dev/null \
  | jq '.attributes |= map(if (.name|test("^(firstName|lastName)$")) then del(.required) else . end)' \
  | kc update users/profile -r $R -f -

echo "== mappers"
kc get components -r $R --query parent=$CID </dev/null | jq -r '.[] | "\(.name): \(.config["ldap.attribute"][0] // .config["ldap.full.name.attribute"][0] // "") read.only=\(.config["read.only"][0] // "-")"'
kc get users/profile -r $R </dev/null | jq -c '.attributes[] | select(.name|test("^(firstName|lastName|email)$")) | {name, required}'
echo "== kctest1 after re-read"
kc create "user-storage/$CID/sync?action=triggerFullSync" -r $R -o </dev/null | jq -c .status
kc get users -r $R -q username=kctest1 -q exact=true </dev/null | jq -c '.[] | {firstName, lastName, email}'
