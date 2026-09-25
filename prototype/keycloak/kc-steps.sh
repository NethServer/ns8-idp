#!/bin/bash
# Step 1: AD realm, no password change prompt for users created by Keycloak
# Step 2: both realms, deny password logins to federated (Entra ID) users
set -e
kc() { runagent -m scratchpad1 podman exec -i keycloak /opt/keycloak/bin/kcadm.sh "$@"; }
urlenc() { jq -rn --arg s "$1" '$s|@uri'; }
kc config credentials --server http://127.0.0.1:18080 --realm master --user admin --password "${KC_ADMIN_PASSWORD}" </dev/null >/dev/null

echo "== step 1: pwdLastSet=-1 at creation (ad.dom.test)"
R=ad.dom.test
CID=$(kc get components -r $R --query type=org.keycloak.storage.UserStorageProvider --fields id --format csv --noquotes </dev/null)
kc create components -r $R -f - <<JSON
{"name":"no password change at creation","providerId":"hardcoded-ldap-attribute-mapper",
 "providerType":"org.keycloak.storage.ldap.mappers.LDAPStorageMapper","parentId":"$CID",
 "config":{"ldap.attribute.name":["pwdLastSet"],"ldap.attribute.value":["-1"]}}
JSON

# Append to flow $2 of realm $1 a conditional subflow that denies
# access to users with the entra_oid attribute
add_deny() {
    local R=$1 parent=$2 sub="$3"
    kc create "authentication/flows/$(urlenc "$parent")/executions/flow" -r $R -f - </dev/null <<JSON
{"alias":"$sub","type":"basic-flow","description":"Deny password logins to federated users","provider":"registration-page-form"}
JSON
    local subid=$(kc get "authentication/flows/$(urlenc "$parent")/executions" -r $R </dev/null | jq -r --arg a "$sub" '.[] | select(.displayName==$a) | .id')
    kc update "authentication/flows/$(urlenc "$parent")/executions" -r $R -f - </dev/null <<JSON
{"id":"$subid","requirement":"CONDITIONAL"}
JSON
    for p in conditional-user-attribute deny-access-authenticator; do
        kc create "authentication/flows/$(urlenc "$sub")/executions/execution" -r $R -f - </dev/null <<JSON
{"provider":"$p"}
JSON
    done
    kc get "authentication/flows/$(urlenc "$sub")/executions" -r $R </dev/null | jq -c '.[] | {id, providerId}' | while read -r e; do
        id=$(echo "$e" | jq -r .id); p=$(echo "$e" | jq -r .providerId)
        kc update "authentication/flows/$(urlenc "$sub")/executions" -r $R -f - </dev/null <<JSON
{"id":"$id","requirement":"REQUIRED"}
JSON
        if [ "$p" = conditional-user-attribute ]; then
            kc create "authentication/executions/$id/config" -r $R -f - </dev/null <<JSON
{"alias":"$sub - has entra_oid","config":{"attribute_name":"entra_oid","attribute_expected_value":".+","regex":"true","not":"false"}}
JSON
        else
            kc create "authentication/executions/$id/config" -r $R -f - </dev/null <<JSON
{"alias":"$sub - message","config":{"denyErrorMessage":"This account signs in with Microsoft Entra ID"}}
JSON
        fi
    done
}

for R in ldap.dom.test ad.dom.test; do
    echo "== step 2: $R"
    kc create "authentication/flows/browser/copy" -r $R -s "newName=ns8 browser" </dev/null
    kc create "authentication/flows/$(urlenc "direct grant")/copy" -r $R -s "newName=ns8 direct grant" </dev/null
    add_deny $R "ns8 browser forms" "ns8 browser deny federated"
    add_deny $R "ns8 direct grant" "ns8 direct grant deny federated"
    kc update realms/$R -s "browserFlow=ns8 browser" -s "directGrantFlow=ns8 direct grant" </dev/null
    kc get realms/$R --fields browserFlow,directGrantFlow </dev/null | jq -c .
    kc get "authentication/flows/$(urlenc "ns8 browser")/executions" -r $R </dev/null | jq -r '.[] | "  \("  " * .level)\(.displayName) [\(.requirement)]"'
    kc get "authentication/flows/$(urlenc "ns8 direct grant")/executions" -r $R </dev/null | jq -r '.[] | "  \("  " * .level)\(.displayName) [\(.requirement)]"'
done
