#!/bin/bash
# Identity provider removed (simulated by disabling it): what federated
# accounts with an administrator-set password can do
kc() { runagent -m scratchpad1 podman exec -i keycloak /opt/keycloak/bin/kcadm.sh "$@"; }
kc config credentials --server http://127.0.0.1:18080 --realm master --user admin --password "${KC_ADMIN_PASSWORD}" </dev/null >/dev/null
R=ad.dom.test
setidp() { # enabled(true|false)
    kc get identity-provider/instances/entra -r $R </dev/null \
      | jq -c --argjson en "$1" --arg sec "$(cat /root/entra-secret)" '.enabled=$en | .config.clientSecret=$sec' \
      | kc update identity-provider/instances/entra -r $R -f -
    kc get identity-provider/instances/entra -r $R </dev/null | jq -c '{alias, enabled}'
}
grant() {
    curl -s "https://keycloak.dp.nethserver.net/realms/$R/protocol/openid-connect/token" -d grant_type=password \
        -d client_id=nextcloud --data-urlencode client_secret="$(cat /root/kc-nextcloud2-secret)" \
        -d username=e.user1 --data-urlencode "password=${FED_PASSWORD_AD}" \
      | sed 's/<[^>]*>/ /g' | grep -oE '"access_token"|This [a-z]+ signs in with Microsoft Entra ID|"error_description":"[^"]*"' | head -1
}
form() { NC=https://nextcloud1.dp.nethserver.net bash /root/sso-login.sh e.user1 "${FED_PASSWORD_AD}" 2>&1 | grep -oE 'This account signs in with Microsoft Entra ID|Invalid username or password|"id":"[^"]*"' | head -1; }
button() { curl -s -L "https://keycloak.dp.nethserver.net/realms/$R/protocol/openid-connect/auth?client_id=nextcloud&response_type=code&scope=openid&redirect_uri=$(jq -rn '"https://nextcloud1.dp.nethserver.net/apps/user_oidc/code"|@uri')" | grep -q social-entra && echo yes || echo no; }

echo "== provider enabled";  echo "  button=$(button) grant=$(grant) form=$(form)"
echo "== disable";           setidp false
echo "== provider disabled"; echo "  button=$(button) grant=$(grant) form=$(form)"
echo "== enable";            setidp true
echo "== provider enabled";  echo "  button=$(button) grant=$(grant) form=$(form)"
