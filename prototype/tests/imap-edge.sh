#!/bin/bash
# Edge cases for Dovecot OAuth2 passdb
KC=https://keycloak.dp.nethserver.net/realms/ldap.dom.test/protocol/openid-connect/token
IMAP=imaps://rl1.dp.nethserver.net:993/
tok() { # client user
    curl -s "$KC" -d grant_type=password -d client_id="$1" --data-urlencode client_secret="$(cat /root/kc-$1-secret)" \
        --data-urlencode username="$2" --data-urlencode "password=${TEST_PASSWORD}" | jq -r .access_token
}
imap() { # label user token
    printf '%-44s ' "$1"
    curl -s -k --login-options AUTH=XOAUTH2 -u "$2:" --oauth2-bearer "$3" "$IMAP" -X NAMESPACE -o /dev/null -w 'exit=%{exitcode}\n'
}
t1=$(tok dovecot kctest1)
imap "token(kctest1,dovecot) as kctest1@domain" kctest1@dp.nethserver.net "$t1"
imap "token(kctest1,dovecot) as kctest2" kctest2 "$t1"
imap "token(kctest1,nextcloud) as kctest1" kctest1 "$(tok nextcloud kctest1)"
imap "garbage token as kctest1" kctest1 "not-a-token"
printf '%-44s ' "SMTP submission XOAUTH2 (587, STARTTLS)"
printf 'Subject: xoauth2 test\r\n\r\nhello\r\n' | curl -v -s -k --ssl-reqd smtp://rl1.dp.nethserver.net:587 \
    --login-options AUTH=XOAUTH2 -u kctest1: --oauth2-bearer "$t1" \
    --mail-from kctest1@dp.nethserver.net --mail-rcpt kctest1@dp.nethserver.net -T - -w 'exit=%{exitcode}\n'
