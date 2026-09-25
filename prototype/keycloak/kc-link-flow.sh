#!/bin/bash
# First broker login with account linking by Entra ID oid, for both realms
set -e
kc() { runagent -m scratchpad1 podman exec -i keycloak /opt/keycloak/bin/kcadm.sh "$@"; }
urlenc() { jq -rn --arg s "$1" '$s|@uri'; }
kc config credentials --server http://127.0.0.1:18080 --realm master --user admin --password "${KC_ADMIN_PASSWORD}" </dev/null >/dev/null
F="ns8 first broker login"
for pair in ldap.dom.test:employeeNumber ad.dom.test:msDS-ExternalDirectoryObjectId; do
    R=${pair%%:*} A=${pair#*:}
    echo "===== $R"
    if ! kc get authentication/flows -r $R </dev/null | jq -e --arg f "$F" '.[] | select(.alias==$f)' >/dev/null; then
        kc create "authentication/flows/$(urlenc "first broker login")/copy" -r $R -s "newName=$F" </dev/null
    fi
    execs=$(kc get "authentication/flows/$(urlenc "$F")/executions" -r $R </dev/null)
    sub=$(jq -r '.[] | select(.displayName|test("User creation or linking")) | .displayName' <<<"$execs")
    if ! jq -e '.[] | select(.providerId=="ns8-idp-link-by-attribute")' <<<"$execs" >/dev/null; then
        kc create "authentication/flows/$(urlenc "$sub")/executions/execution" -r $R -s provider=ns8-idp-link-by-attribute </dev/null
        execs=$(kc get "authentication/flows/$(urlenc "$F")/executions" -r $R </dev/null)
        id=$(jq -r '.[] | select(.providerId=="ns8-idp-link-by-attribute") | .id' <<<"$execs")
        jq -c --arg id "$id" '.[] | select(.id==$id) | .requirement="ALTERNATIVE"' <<<"$execs" \
            | kc update "authentication/flows/$(urlenc "$F")/executions" -r $R -f -
        kc create "authentication/executions/$id/config" -r $R -f - </dev/null <<JSON
{"alias":"$R link by oid","config":{"userAttribute":"entra_oid","ldapAttribute":"$A"}}
JSON
        # Move it before "Create User If Unique"
        for _ in 1 2 3 4; do
            first=$(kc get "authentication/flows/$(urlenc "$sub")/executions" -r $R </dev/null | jq -r '[.[] | select(.level==0)][0].providerId')
            [ "$first" = ns8-idp-link-by-attribute ] && break
            kc create "authentication/executions/$id/raise-priority" -r $R -b '{}' </dev/null
        done
    fi
    kc get identity-provider/instances/entra -r $R </dev/null \
      | jq -c --arg f "$F" --arg sec "$(cat /root/entra-secret)" '.firstBrokerLoginFlowAlias=$f | .config.clientSecret=$sec' \
      | kc update identity-provider/instances/entra -r $R -f -
    kc get identity-provider/instances/entra -r $R </dev/null | jq -c '{alias, enabled, firstBrokerLoginFlowAlias}'
    kc get "authentication/flows/$(urlenc "$F")/executions" -r $R </dev/null \
      | jq -r '.[] | "  \("  " * .level)\(.priority) \(.displayName) [\(.requirement)]\(if .authenticationConfig then " config" else "" end)"'
done
