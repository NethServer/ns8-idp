#!/bin/bash
# Realm ad.dom.test: read-only AD federation through ldapproxy (scenario 1 on AD)
set -e
kc() { runagent -m scratchpad1 podman exec -i keycloak /opt/keycloak/bin/kcadm.sh "$@"; }
R=ad.dom.test
kc config credentials --server http://127.0.0.1:18080 --realm master --user admin --password "${KC_ADMIN_PASSWORD}" </dev/null >/dev/null
BINDPW=$(api-cli run cluster/list-user-domains </dev/null | jq -r '.domains[] | select(.name=="ad.dom.test") | .bind_password')

kc create realms -s realm=$R -s enabled=true -s displayName=$R </dev/null
RID=$(kc get realms/$R --fields id --format csv --noquotes </dev/null)
kc create components -r $R -f - <<JSON
{"name":"$R","providerId":"ldap","providerType":"org.keycloak.storage.UserStorageProvider","parentId":"$RID",
 "config":{
  "enabled":["true"],"vendor":["ad"],"editMode":["READ_ONLY"],
  "connectionUrl":["ldap://127.0.0.1:20002"],"authType":["simple"],
  "bindDn":["ldapservice@ad.dom.test"],"bindCredential":["$BINDPW"],
  "usersDn":["CN=Users,DC=ad,DC=dom,DC=test"],"searchScope":["2"],
  "usernameLDAPAttribute":["sAMAccountName"],"rdnLDAPAttribute":["cn"],"uuidLDAPAttribute":["objectGUID"],
  "userObjectClasses":["person, organizationalPerson, user"],
  "customUserSearchFilter":["(objectCategory=person)"],
  "importEnabled":["true"],"syncRegistrations":["false"],"trustEmail":["true"],
  "pagination":["true"],"useTruststoreSpi":["never"],"connectionPooling":["true"]}}
JSON
CID=$(kc get components -r $R --query type=org.keycloak.storage.UserStorageProvider --fields id --format csv --noquotes </dev/null)
echo "LDAP component: $CID"
kc create components -r $R -f - <<JSON
{"name":"groups","providerId":"group-ldap-mapper","providerType":"org.keycloak.storage.ldap.mappers.LDAPStorageMapper","parentId":"$CID",
 "config":{"groups.dn":["DC=ad,DC=dom,DC=test"],"group.name.ldap.attribute":["cn"],"group.object.classes":["group"],
  "preserve.group.inheritance":["false"],"membership.ldap.attribute":["member"],"membership.attribute.type":["DN"],
  "membership.user.ldap.attribute":["cn"],"mode":["READ_ONLY"],
  "user.roles.retrieve.strategy":["LOAD_GROUPS_BY_MEMBER_ATTRIBUTE"],"drop.non.existing.groups.during.sync":["false"]}}
JSON
echo "== mappers"
kc get components -r $R --query parent=$CID </dev/null | jq -r '.[] | "\(.name): \(.providerId) \(.config["ldap.attribute"][0] // "")"'
echo "== sync"
kc create "user-storage/$CID/sync?action=triggerFullSync" -r $R -o </dev/null | jq -c .
kc get users -r $R </dev/null | jq -r '.[] | "\(.username)\t\(.attributes.LDAP_ID[0] // "-")\t\(.email // "-")"'
