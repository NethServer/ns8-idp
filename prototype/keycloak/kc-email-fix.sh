#!/bin/bash
# Let the Entra email claim reach the user (and LDAP mail) again
set -e
kc() { runagent -m scratchpad1 podman exec -i keycloak /opt/keycloak/bin/kcadm.sh "$@"; }
R=ldap.dom.test
kc config credentials --server http://127.0.0.1:18080 --realm master --user admin --password "${KC_ADMIN_PASSWORD}" </dev/null >/dev/null
kc get users/profile -r $R </dev/null \
  | jq '.attributes |= map(if .name == "email" then .permissions.edit = ["admin","user"] else . end)' \
  | kc update users/profile -r $R -f -
mid=$(kc get identity-provider/instances/entra/mappers -r $R </dev/null | jq -r '.[] | select(.name=="email") | .id')
kc get "identity-provider/instances/entra/mappers/$mid" -r $R </dev/null \
  | jq '.config.syncMode = "FORCE"' \
  | kc update "identity-provider/instances/entra/mappers/$mid" -r $R -f -
kc get users/profile -r $R </dev/null | jq -c '.attributes[] | select(.name=="email") | {name, required, edit: .permissions.edit}'
kc get "identity-provider/instances/entra/mappers/$mid" -r $R </dev/null | jq -c '{name, syncMode: .config.syncMode}'
date +"now: %T UTC"
