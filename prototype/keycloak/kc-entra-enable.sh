#!/bin/bash
# Set the Entra client secret from /root/entra-secret and enable the IdP
set -e
kc() { runagent -m scratchpad1 podman exec -i keycloak /opt/keycloak/bin/kcadm.sh "$@"; }
R=ldap.dom.test
[ -s /root/entra-secret ] || { echo "secret file missing"; exit 1; }
kc config credentials --server http://127.0.0.1:18080 --realm master --user admin --password "${KC_ADMIN_PASSWORD}" </dev/null >/dev/null
kc get identity-provider/instances/entra -r $R </dev/null \
    | jq --rawfile s /root/entra-secret '.enabled=true | .config.clientSecret=($s|rtrimstr("\n"))' \
    | kc update identity-provider/instances/entra -r $R -f -
kc get identity-provider/instances/entra -r $R </dev/null | jq -c '{alias,enabled,secret_length:(.config.clientSecret|length)}'
jar=$(mktemp)
curl -s -c "$jar" -b "$jar" -L "https://nextcloud.dp.nethserver.net/apps/user_oidc/login/1" | grep -oE 'Microsoft Entra ID|broker/entra/login' | sort -u
rm -f "$jar"
