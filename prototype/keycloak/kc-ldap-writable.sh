#!/bin/bash
# Scenario 2, option A: make the ldap.dom.test federation writable
set -e
kc() { runagent -m scratchpad1 podman exec -i keycloak /opt/keycloak/bin/kcadm.sh "$@"; }
R=ldap.dom.test
CID=sCNAHDDgQAC9my9yKLEm8Q
PW=/home/scratchpad1/.config/state/ldap-svc.pw
kc config credentials --server http://127.0.0.1:18080 --realm master --user admin --password "${KC_ADMIN_PASSWORD}" </dev/null >/dev/null

echo "== LDAP provider: writable, ldapproxy, keycloak-svc bind"
kc get "components/$CID" -r $R </dev/null | jq --rawfile pw "$PW" '
    .config.connectionUrl = ["ldap://127.0.0.1:20005"]
  | .config.bindDn = ["uid=keycloak-svc,ou=People,dc=ldap,dc=dom,dc=test"]
  | .config.bindCredential = [$pw]
  | .config.editMode = ["WRITABLE"]
  | .config.syncRegistrations = ["true"]
  | .config.usePasswordModifyExtendedOp = ["true"]' \
  | kc update "components/$CID" -r $R -f -

echo "== attribute mappers: allow writes"
for m in $(kc get components -r $R --query parent=$CID </dev/null \
        | jq -r '.[] | select(.name|test("^(username|first name|last name|email)$")) | .id'); do
    kc get "components/$m" -r $R </dev/null | jq '.config["read.only"] = ["false"]' | kc update "components/$m" -r $R -f -
done

echo "== hardcoded posixAccount attributes (placeholders fixed later)"
for kv in gidNumber=1001 uidNumber=1000 homeDirectory=/home/nobody; do
    kc create components -r $R -f - <<JSON
{"name":"posix ${kv%%=*}","providerId":"hardcoded-ldap-attribute-mapper",
 "providerType":"org.keycloak.storage.ldap.mappers.LDAPStorageMapper","parentId":"$CID",
 "config":{"ldap.attribute.name":["${kv%%=*}"],"ldap.attribute.value":["${kv#*=}"]}}
JSON
done

echo "== user profile: names and email editable by admins only, email optional"
kc get users/profile -r $R </dev/null | jq '
  .attributes |= map(if (.name|test("^(email|firstName|lastName)$"))
                     then .permissions.edit = ["admin"] else . end
                   | if .name == "email" then del(.required) else . end)' \
  | kc update users/profile -r $R -f -

echo "== result"
kc get "components/$CID" -r $R </dev/null | jq -c '{url:.config.connectionUrl[0], bind:.config.bindDn[0], edit:.config.editMode[0], syncReg:.config.syncRegistrations[0], pwModifyOp:.config.usePasswordModifyExtendedOp[0]}'
kc get components -r $R --query parent=$CID </dev/null | jq -r '.[] | select(.providerId|test("attribute")) | "\(.name): read.only=\(.config["read.only"][0] // "-") value=\(.config["ldap.attribute.value"][0] // "-")"'
kc get users/profile -r $R </dev/null | jq -c '.attributes[] | select(.name|test("^(email|firstName|lastName)$")) | {name, required, edit: .permissions.edit}'
echo "== sanity: LDAP users still resolve"
kc get users -r $R -q username=u1 -q exact=true </dev/null | jq -c '.[] | {username, federationLink}'
