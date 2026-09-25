#!/bin/bash
# Switch the federated account marker to ns8_idp (employeeType) + ns8_idp_id (employeeNumber)
set -e
kc() { runagent -m scratchpad1 podman exec -i keycloak /opt/keycloak/bin/kcadm.sh "$@"; }
urlenc() { jq -rn --arg s "$1" '$s|@uri'; }
py() { (cd /; runagent -m scratchpad1 python3 kc-marker-v2.py "$1"); }
install -o scratchpad1 -g scratchpad1 -m 644 /root/kc-marker-v2.py /home/scratchpad1/.config/state/
kc config credentials --server http://127.0.0.1:18080 --realm master --user admin --password "${KC_ADMIN_PASSWORD}" </dev/null >/dev/null

echo "== LDAP: copy the marker to employeeType/employeeNumber"
py copy

for R in ldap.dom.test ad.dom.test; do
    echo "===== $R"
    # User profile: declare the new attributes (Keycloak drops undeclared ones)
    kc get users/profile -r $R </dev/null | jq -c '
        .attributes |= (map(select(.name != "ns8_idp" and .name != "ns8_idp_id"))
          + [{"name":"ns8_idp","displayName":"Identity provider","multivalued":false,"validations":{},"permissions":{"view":["admin"],"edit":["admin"]}},
             {"name":"ns8_idp_id","displayName":"Identity provider user ID","multivalued":false,"validations":{},"permissions":{"view":["admin"],"edit":["admin"]}}])' \
      | kc update users/profile -r $R -f -

    # LDAP mappers: replace "entra oid" with "idp" and "idp id"
    CID=$(kc get components -r $R --query type=org.keycloak.storage.UserStorageProvider --fields id --format csv --noquotes </dev/null)
    old=$(kc get components -r $R --query parent=$CID </dev/null | jq -r '.[] | select(.name=="entra oid") | .id')
    [ -n "$old" ] && kc delete components/$old -r $R </dev/null
    for m in "idp:ns8_idp:employeeType" "idp id:ns8_idp_id:employeeNumber"; do
        IFS=: read -r name uattr lattr <<<"$m"
        kc get components -r $R --query parent=$CID </dev/null | jq -e --arg n "$name" '.[] | select(.name==$n)' >/dev/null && continue
        kc create components -r $R -f - </dev/null <<JSON
{"name":"$name","providerId":"user-attribute-ldap-mapper",
 "providerType":"org.keycloak.storage.ldap.mappers.LDAPStorageMapper","parentId":"$CID",
 "config":{"user.model.attribute":["$uattr"],"ldap.attribute":["$lattr"],
   "read.only":["false"],"always.read.value.from.ldap":["true"],
   "is.mandatory.in.ldap":["false"],"is.binary.attribute":["false"]}}
JSON
    done

    # Identity provider mappers: oid -> ns8_idp_id, provider alias -> ns8_idp
    kc get identity-provider/instances/entra/mappers -r $R </dev/null | jq -c '.[] | select(.name=="oid") | .config["user.attribute"]="ns8_idp_id"' \
      | while read -r m; do kc update "identity-provider/instances/entra/mappers/$(jq -r .id <<<"$m")" -r $R -f - <<<"$m"; done
    if ! kc get identity-provider/instances/entra/mappers -r $R </dev/null | jq -e '.[] | select(.name=="idp alias")' >/dev/null; then
        kc create identity-provider/instances/entra/mappers -r $R -f - </dev/null <<'JSON'
{"name":"idp alias","identityProviderAlias":"entra","identityProviderMapper":"hardcoded-attribute-idp-mapper",
 "config":{"syncMode":"INHERIT","attribute":"ns8_idp","attribute.value":"entra"}}
JSON
    fi

    # Deny conditions: any account with ns8_idp is federated
    for flow in "ns8 browser" "ns8 direct grant"; do
        kc get "authentication/flows/$(urlenc "$flow")/executions" -r $R </dev/null \
          | jq -r '.[] | select(.providerId=="conditional-user-attribute") | .authenticationConfig' | while read -r c; do
            kc get authentication/config/$c -r $R </dev/null | jq -c '.config.attribute_name="ns8_idp" | .alias=(.alias|sub("has entra_oid";"has ns8_idp"))' \
              | kc update authentication/config/$c -r $R -f -
        done
    done

    # Link step: match ID and provider
    c=$(kc get "authentication/flows/$(urlenc "ns8 first broker login")/executions" -r $R </dev/null | jq -r '.[] | select(.providerId=="ns8-idp-link-by-attribute") | .authenticationConfig')
    kc get authentication/config/$c -r $R </dev/null \
      | jq -c '.alias=(.alias|sub("by oid";"by provider ID")) | .config={"userAttribute":"ns8_idp_id","providerAttribute":"ns8_idp","ldapAttribute":"employeeNumber"}' \
      | kc update authentication/config/$c -r $R -f -

    # Retire entra_oid
    kc get users/profile -r $R </dev/null | jq -c '.attributes |= map(select(.name != "entra_oid"))' | kc update users/profile -r $R -f -
    kc create clear-user-cache -r $R </dev/null
done

echo "== LDAP: remove the old AD attribute"
py clear-old
for R in ldap.dom.test ad.dom.test; do kc create clear-user-cache -r $R </dev/null; done

echo "== state"
py show
for R in ldap.dom.test ad.dom.test; do
    echo "-- $R"
    CID=$(kc get components -r $R --query type=org.keycloak.storage.UserStorageProvider --fields id --format csv --noquotes </dev/null)
    kc get components -r $R --query parent=$CID </dev/null | jq -r '.[] | select(.name|test("idp|entra")) | "  mapper \(.name): \(.config["user.model.attribute"][0]) <-> \(.config["ldap.attribute"][0])"'
    kc get identity-provider/instances/entra/mappers -r $R </dev/null | jq -r '.[] | select(.name=="oid" or .name=="idp alias") | "  idp mapper \(.name): \(.config|tostring)"'
    for flow in "ns8 browser" "ns8 direct grant" "ns8 first broker login"; do
        kc get "authentication/flows/$(urlenc "$flow")/executions" -r $R </dev/null \
          | jq -r '.[] | select(.providerId=="conditional-user-attribute" or .providerId=="ns8-idp-link-by-attribute") | .authenticationConfig' \
          | while read -r c; do echo "  $flow: $(kc get authentication/config/$c -r $R </dev/null | jq -c '{alias, config}')"; done
    done
    for u in e.user1 e.u2 e.u3 dprincipi kctest1; do
        kc get users -r $R -q username=$u -q exact=true </dev/null | jq -r '.[] | "  \(.username): ns8_idp=\(.attributes.ns8_idp[0] // "-") ns8_idp_id=\(.attributes.ns8_idp_id[0] // "-") entra_oid=\(.attributes.entra_oid[0] // "-")"'
    done
done
rm -f /home/scratchpad1/.config/state/kc-marker-v2.py
