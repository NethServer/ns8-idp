#!/bin/bash
# Store the entra_oid user attribute in LDAP (federated account marker)
set -e
kc() { runagent -m scratchpad1 podman exec -i keycloak /opt/keycloak/bin/kcadm.sh "$@"; }
kc config credentials --server http://127.0.0.1:18080 --realm master --user admin --password "${KC_ADMIN_PASSWORD}" </dev/null >/dev/null
for pair in ldap.dom.test:employeeNumber ad.dom.test:msDS-ExternalDirectoryObjectId; do
    R=${pair%%:*} A=${pair#*:}
    CID=$(kc get components -r $R --query type=org.keycloak.storage.UserStorageProvider --fields id --format csv --noquotes </dev/null)
    if kc get components -r $R --query parent=$CID </dev/null | jq -e '.[] | select(.name=="entra oid")' >/dev/null; then
        echo "$R: mapper exists"; continue
    fi
    kc create components -r $R -f - </dev/null <<JSON
{"name":"entra oid","providerId":"user-attribute-ldap-mapper",
 "providerType":"org.keycloak.storage.ldap.mappers.LDAPStorageMapper","parentId":"$CID",
 "config":{"user.model.attribute":["entra_oid"],"ldap.attribute":["$A"],
   "read.only":["false"],"always.read.value.from.ldap":["true"],
   "is.mandatory.in.ldap":["false"],"is.binary.attribute":["false"]}}
JSON
    echo "$R: mapper entra_oid <-> $A created"
done
for R in ldap.dom.test ad.dom.test; do
    for u in e.user1 e.u2 davide.principi kctest1; do
        kc get users -r $R -q username=$u -q exact=true </dev/null | jq -c --arg r $R '.[] | {realm: $r, username, oid: .attributes.entra_oid}'
    done
done
