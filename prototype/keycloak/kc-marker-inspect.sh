#!/bin/bash
kc() { runagent -m scratchpad1 podman exec -i keycloak /opt/keycloak/bin/kcadm.sh "$@" </dev/null; }
kc config credentials --server http://127.0.0.1:18080 --realm master --user admin --password "${KC_ADMIN_PASSWORD}" >/dev/null
for R in ldap.dom.test ad.dom.test; do
    echo "===== $R"
    CID=$(kc get components -r $R --query type=org.keycloak.storage.UserStorageProvider --fields id --format csv --noquotes)
    echo "federation $CID"
    kc get components -r $R --query parent=$CID | jq -r '.[] | "  \(.name) [\(.providerId)] \(.config|tostring)"'
    echo "-- idp mappers"
    kc get identity-provider/instances/entra/mappers -r $R | jq -r '.[] | "  \(.name) \(.config|tostring)"'
    echo "-- user profile entra attrs"
    kc get users/profile -r $R | jq -c '.attributes[] | select(.name|startswith("entra"))'
    echo "-- users with entra_oid"
    for u in $(kc get users -r $R --fields username --format csv --noquotes); do
        kc get users -r $R -q username=$u -q exact=true | jq -c '.[] | select(.attributes.entra_oid) | {username, federationLink, oid: .attributes.entra_oid, ldapid: .attributes.LDAP_ID, entry: .attributes.LDAP_ENTRY_DN}'
    done
done
