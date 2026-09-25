#!/bin/bash
# Scenario 2 on AD: writable AD federation + Entra ID provider in realm ad.dom.test
set -e
kc() { runagent -m scratchpad1 podman exec -i keycloak /opt/keycloak/bin/kcadm.sh "$@"; }
R=ad.dom.test SRC=ldap.dom.test
PW=/home/scratchpad1/.config/state/ad-svc.pw
kc config credentials --server http://127.0.0.1:18080 --realm master --user admin --password "${KC_ADMIN_PASSWORD}" </dev/null >/dev/null
CID=$(kc get components -r $R --query type=org.keycloak.storage.UserStorageProvider --fields id --format csv --noquotes </dev/null)

echo "== AD provider: writable, keycloak-svc bind"
kc get "components/$CID" -r $R </dev/null | jq --rawfile pw "$PW" '
    .config.bindDn = ["keycloak-svc@ad.dom.test"]
  | .config.bindCredential = [$pw]
  | .config.editMode = ["WRITABLE"]
  | .config.syncRegistrations = ["true"]' \
  | kc update "components/$CID" -r $R -f -

echo "== attribute mappers: allow writes"
for m in $(kc get components -r $R --query parent=$CID </dev/null \
        | jq -r '.[] | select(.name|test("^(username|full name|last name|email)$")) | .id'); do
    kc get "components/$m" -r $R </dev/null | jq '.config["read.only"] = ["false"]' | kc update "components/$m" -r $R -f -
done
kc create components -r $R -f - <<JSON
{"name":"first name","providerId":"user-attribute-ldap-mapper",
 "providerType":"org.keycloak.storage.ldap.mappers.LDAPStorageMapper","parentId":"$CID",
 "config":{"ldap.attribute":["givenName"],"user.model.attribute":["firstName"],"read.only":["false"],
  "always.read.value.from.ldap":["true"],"is.mandatory.in.ldap":["false"]}}
JSON

echo "== user profile attributes"
kc get users/profile -r $R </dev/null | jq '.attributes += [
  {name:"entra_oid", displayName:"Entra object ID", multivalued:false, permissions:{view:["admin"],edit:["admin"]}, validations:{}},
  {name:"entra_groups", displayName:"Entra group IDs", multivalued:true, permissions:{view:["admin"],edit:["admin"]}, validations:{}}]' \
  | kc update users/profile -r $R -f -

echo "== Entra ID provider, copied from $SRC"
kc get identity-provider/instances/entra -r $SRC </dev/null \
  | jq --rawfile s /root/entra-secret 'del(.internalId) | .config.clientSecret = ($s|rtrimstr("\n"))' \
  | kc create identity-provider/instances -r $R -f -
kc get identity-provider/instances/entra/mappers -r $SRC </dev/null | jq -c '.[] | del(.id)' | while read -r m; do
    echo "$m" | kc create identity-provider/instances/entra/mappers -r $R -f -
done

echo "== events"
kc update events/config -r $R -s eventsEnabled=true -s eventsExpiration=172800 -s adminEventsEnabled=true </dev/null

echo "== result"
kc get "components/$CID" -r $R </dev/null | jq -c '{url:.config.connectionUrl[0], bind:.config.bindDn[0], edit:.config.editMode[0], syncReg:.config.syncRegistrations[0]}'
kc get components -r $R --query parent=$CID </dev/null | jq -r '.[] | "\(.name): \(.providerId) \(.config["ldap.attribute"][0] // "") read.only=\(.config["read.only"][0] // "-")"'
kc get identity-provider/instances/entra -r $R </dev/null | jq -c '{alias, enabled, issuer: .config.issuer}'
kc get identity-provider/instances/entra/mappers -r $R </dev/null | jq -r '.[] | "\(.name) [\(.config.syncMode)]"' | paste -sd' '
