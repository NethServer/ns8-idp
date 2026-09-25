#!/bin/bash
# Start an OAuth device authorization for client hermes-agent (realm ad.dom.test)
set -e
kc() { runagent -m scratchpad1 podman exec -i keycloak /opt/keycloak/bin/kcadm.sh "$@" </dev/null; }
R=ad.dom.test KC=https://keycloak.dp.nethserver.net/realms/ad.dom.test/protocol/openid-connect
kc config credentials --server http://127.0.0.1:18080 --realm master --user admin --password "${KC_ADMIN_PASSWORD}" >/dev/null
id=$(kc get clients -r $R -q clientId=hermes-agent --fields id --format csv --noquotes)
kc update clients/$id -r $R -s 'attributes."oauth2.device.authorization.grant.enabled"=true'
kc get clients/$id -r $R | jq -c '{clientId, device_grant: .attributes["oauth2.device.authorization.grant.enabled"]}'
curl -s $KC/auth/device -d client_id=hermes-agent --data-urlencode client_secret="$(cat /root/kc-hermes-agent-secret)" -d scope=openid \
  | tee /root/device-auth.json | jq -c '{user_code, verification_uri_complete, expires_in, interval}'
chmod 600 /root/device-auth.json
