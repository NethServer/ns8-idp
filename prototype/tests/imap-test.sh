#!/bin/bash
# Usage: imap-test.sh USER PASSWORD [CLIENT_ID]
# Get a Keycloak access token by password grant, then try IMAPS logins
# with XOAUTH2, OAUTHBEARER and plain password.
set -u
user=$1 pass=$2 client=${3:-dovecot}
KC=https://keycloak.dp.nethserver.net/realms/${REALM:-ldap.dom.test}/protocol/openid-connect/token
IMAP=imaps://rl1.dp.nethserver.net:993/
secret=$(cat "${SECRET_FILE:-/root/kc-${client}-secret}")
token=$(curl -s "$KC" -d grant_type=password -d client_id="$client" --data-urlencode client_secret="$secret" \
    --data-urlencode username="$user" --data-urlencode password="$pass" | jq -r .access_token)
[ "$token" = null ] && { echo "token request failed"; exit 1; }
echo "token for $user from client $client: ${#token} bytes"
for mech in XOAUTH2 OAUTHBEARER; do
    printf '%-12s ' "$mech"
    curl -s -k --login-options "AUTH=$mech" -u "$user:" --oauth2-bearer "$token" "$IMAP" -X 'NAMESPACE' -w 'exit=%{exitcode}\n' -o /dev/null 2>&1 | tail -1
done
printf '%-12s ' "PASSWORD"
curl -s -k --login-options "AUTH=PLAIN" -u "$user:$pass" "$IMAP" -X 'NAMESPACE' -w 'exit=%{exitcode}\n' -o /dev/null 2>&1 | tail -1
