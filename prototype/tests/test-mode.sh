#!/bin/bash
# Login behavior of realm ad.dom.test and its applications, in the current mode
KC=https://keycloak.dp.nethserver.net/realms/ad.dom.test NC=https://nextcloud1.dp.nethserver.net RC=https://roundcube1.dp.nethserver.net
host() { sed -E 's|^https?://([^/?]*).*|\1|'; }
first_foreign() { # follow redirects from $1, print the first host outside our domain
    curl -s -o /dev/null -L --max-redirs 10 -c /tmp/tm.jar -b /tmp/tm.jar -w '%{url_effective} %{http_code}' "$1" | awk '{print $1, $2}'
}
authurl="$KC/protocol/openid-connect/auth?client_id=nextcloud&response_type=code&scope=openid&redirect_uri=$(jq -rn --arg s "$NC/apps/user_oidc/code" '$s|@uri')"
printf '%-40s %s\n' "Keycloak auth endpoint lands on" "$(first_foreign "$authurl" | host)"
page=$(curl -s -L "$authurl" -c /tmp/tm.jar -b /tmp/tm.jar)
printf '%-40s %s\n' "Keycloak password form offered" "$(grep -q 'kc-form-login' <<<"$page" && echo yes || echo no)"
printf '%-40s %s\n' "Keycloak Entra ID button offered" "$(grep -q 'social-entra' <<<"$page" && echo yes || echo no)"
rm -f /tmp/tm.jar
printf '%-40s %s\n' "Nextcloud /login lands on" "$(first_foreign "$NC/login" | host)"
printf '%-40s %s\n' "Nextcloud OCS kctest1 password" \
    "$(curl -s -u "kctest1:${TEST_PASSWORD}" -H 'OCS-APIRequest: true' "$NC/ocs/v2.php/cloud/user?format=json" | jq -r '.ocs.data.id // .ocs.meta.message')"
rm -f /tmp/tm.jar
printf '%-40s %s\n' "Roundcube / lands on" "$(first_foreign "$RC/" | host)"
rm -f /tmp/tm.jar
printf '%-40s %s\n' "Roundcube password form offered" "$(curl -s "$RC/" | grep -q 'name="_pass"' && echo yes || echo no)"
printf '%-40s %s\n' "Direct grant kctest1 (native)" \
    "$(curl -s "$KC/protocol/openid-connect/token" -d grant_type=password -d client_id=nextcloud \
        --data-urlencode client_secret="$(cat /root/kc-nextcloud2-secret)" -d username=kctest1 --data-urlencode "password=${TEST_PASSWORD}" \
        | sed 's/<[^>]*>/ /g' | grep -oE '"access_token"|This [a-z]+ signs in with Microsoft Entra ID|"error_description":"[^"]*"' | head -1)"
printf '%-40s %s\n' "Nextcloud WebDAV kctest1 password" \
    "$(curl -s -o /dev/null -w 'HTTP %{http_code}' -u "kctest1:${TEST_PASSWORD}" -X PROPFIND -H 'Depth: 0' "$NC/remote.php/webdav/")"
printf '%-40s %s\n' "mail4 IMAP kctest1 password" \
    "$(curl -s -k --login-options AUTH=PLAIN -u "kctest1:${TEST_PASSWORD}" imaps://rl1.dp.nethserver.net:993/ -X NAMESPACE -o /dev/null -w 'exit=%{exitcode}')"
