#!/bin/bash
# Move the "deny federated" subflows after the password check
set -e
kc() { runagent -m scratchpad1 podman exec -i keycloak /opt/keycloak/bin/kcadm.sh "$@" </dev/null; }
urlenc() { jq -rn --arg s "$1" '$s|@uri'; }
kc config credentials --server http://127.0.0.1:18080 --realm master --user admin --password "${KC_ADMIN_PASSWORD}" >/dev/null
lower() { # realm flow subflow-name times
    local id=$(kc get "authentication/flows/$(urlenc "$2")/executions" -r $1 | jq -r --arg n "$3" '.[] | select(.displayName==$n) | .id')
    for i in $(seq 1 $4); do kc create "authentication/executions/$id/lower-priority" -r $1 >/dev/null; done
}
for R in ldap.dom.test ad.dom.test; do
    lower $R "ns8 browser" "ns8 browser deny federated" 1
    lower $R "ns8 direct grant" "ns8 direct grant deny federated" 2
    echo "== $R"
    kc get "authentication/flows/$(urlenc "ns8 browser")/executions" -r $R | jq -r '.[] | select(.level>=1 and .level<=2) | "  \("  " * .level)\(.displayName) [\(.requirement)]"' | grep -vE "Organization|Condition - user configured|OTP|WebAuthn|Recovery|credential"
    kc get "authentication/flows/$(urlenc "ns8 direct grant")/executions" -r $R | jq -r '.[] | select(.level==0) | "  \(.displayName) [\(.requirement)]"'
done
