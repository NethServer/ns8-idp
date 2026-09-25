#!/bin/bash
# Password logins: denied to federated users, allowed to native LDAP/AD users
grant() { # realm secretfile user password
    curl -s "https://keycloak.dp.nethserver.net/realms/$1/protocol/openid-connect/token" -d grant_type=password \
        -d client_id=nextcloud --data-urlencode client_secret="$(cat $2)" \
        --data-urlencode username="$3" --data-urlencode password="$4" \
      | jq -r 'if .access_token then "token issued" else "\(.error): \(.error_description)" end'
}
form() { # nextcloud-url user password
    NC=$1 bash /root/sso-login.sh "$2" "$3" 2>&1 | grep -oE 'This account signs in with Microsoft Entra ID|Invalid username or password|"id":"[^"]*"' | head -1
}
printf '%-48s %s\n' "ldap.dom.test grant   e.user1 (federated)" "$(grant ldap.dom.test /root/kc-nextcloud-secret e.user1 "${FED_PASSWORD_LDAP}")"
printf '%-48s %s\n' "ldap.dom.test grant   kctest1 (native)"    "$(grant ldap.dom.test /root/kc-nextcloud-secret kctest1 "${TEST_PASSWORD}")"
printf '%-48s %s\n' "ad.dom.test   grant   e.user1 (federated)" "$(grant ad.dom.test /root/kc-nextcloud2-secret e.user1 "${FED_PASSWORD_AD}")"
printf '%-48s %s\n' "ad.dom.test   grant   kctest1 (native)"    "$(grant ad.dom.test /root/kc-nextcloud2-secret kctest1 "${TEST_PASSWORD}")"
printf '%-48s %s\n' "ldap.dom.test form    e.user1 (federated)" "$(form https://nextcloud.dp.nethserver.net e.user1 "${FED_PASSWORD_LDAP}")"
printf '%-48s %s\n' "ldap.dom.test form    kctest1 (native)"    "$(form https://nextcloud.dp.nethserver.net kctest1 "${TEST_PASSWORD}")"
printf '%-48s %s\n' "ad.dom.test   form    e.user1 (federated)" "$(form https://nextcloud1.dp.nethserver.net e.user1 "${FED_PASSWORD_AD}")"
printf '%-48s %s\n' "ad.dom.test   form    kctest1 (native)"    "$(form https://nextcloud1.dp.nethserver.net kctest1 "${TEST_PASSWORD}")"
printf '%-48s %s\n' "mail4 IMAP password   e.user1 (federated)" \
    "$(curl -s -k --login-options AUTH=PLAIN -u "e.user1:${FED_PASSWORD_AD}" imaps://rl1.dp.nethserver.net:993/ -X NAMESPACE -o /dev/null -w 'exit=%{exitcode}')"
