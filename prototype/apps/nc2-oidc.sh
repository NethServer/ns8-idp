#!/bin/bash
# Nextcloud SSO on nextcloud2 (ad.dom.test), same setup as scenario 1
set -e
kc() { runagent -m scratchpad1 podman exec -i keycloak /opt/keycloak/bin/kcadm.sh "$@"; }
occ() { runagent -m nextcloud2 podman exec --user www-data nextcloud-app php ./occ "$@" </dev/null 2>/dev/null | grep -v '^\[nextcloud\]' || true; }
R=ad.dom.test NC=https://nextcloud1.dp.nethserver.net
kc config credentials --server http://127.0.0.1:18080 --realm master --user admin --password "${KC_ADMIN_PASSWORD}" </dev/null >/dev/null

kc create clients -r $R -f - <<JSON
{"clientId":"nextcloud","name":"Nextcloud","protocol":"openid-connect","publicClient":false,"standardFlowEnabled":true,"directAccessGrantsEnabled":true,
 "redirectUris":["$NC/apps/user_oidc/code","$NC/index.php/apps/user_oidc/code"],"webOrigins":["$NC"],"rootUrl":"$NC",
 "attributes":{"post.logout.redirect.uris":"$NC/*"},
 "protocolMappers":[{"name":"ldap_uuid","protocol":"openid-connect","protocolMapper":"oidc-usermodel-attribute-mapper",
   "config":{"user.attribute":"LDAP_ID","claim.name":"ldap_uuid","jsonType.label":"String","id.token.claim":"true","access.token.claim":"true","userinfo.token.claim":"true","introspection.token.claim":"true"}}]}
JSON
CID=$(kc get clients -r $R -q clientId=nextcloud --fields id --format csv --noquotes </dev/null)
kc get clients/$CID/client-secret -r $R </dev/null | jq -r .value > /root/kc-nextcloud2-secret; chmod 600 /root/kc-nextcloud2-secret

occ app:install user_oidc
occ user_oidc:provider keycloak --clientid=nextcloud --clientsecret="$(cat /root/kc-nextcloud2-secret)" \
    --discoveryuri=https://keycloak.dp.nethserver.net/realms/$R/.well-known/openid-configuration \
    --unique-uid=0 --mapping-uid=ldap_uuid --mapping-display-name=name --mapping-email=email --scope="openid email profile"
occ config:system:set user_oidc auto_provision --type=boolean --value=false
occ ldap:set-config s01 ldapLoginFilter "(&(&(|(objectclass=person)))(|(sAMAccountName=%uid)(userPrincipalName=%uid)(objectGUID=%uid)))"
occ ldap:show-config s01 | grep "ldapLoginFilter "
occ user_oidc:provider --output=json | jq -c '.[] | {id, identifier, clientId}'
