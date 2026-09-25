#!/bin/bash
# Wait for the device authorization, then exchange the token for a
# Dovecot-only token and access e.user1's mailbox with it
KC=https://keycloak.dp.nethserver.net/realms/ad.dom.test/protocol/openid-connect
S=$(cat /root/kc-hermes-agent-secret)
DC=$(jq -r .device_code /root/device-auth.json)
claims() { cut -d. -f2 | tr '_-' '/+' | { read p; while [ $(( ${#p} % 4 )) -ne 0 ]; do p="$p="; done; echo "$p"; } | base64 -d \
    | jq -c '{iss, azp, aud, sub, preferred_username, email, scope, iat: (.iat|todate), exp: (.exp|todate)}'; }
for i in $(seq 1 120); do
    R=$(curl -s $KC/token -d grant_type=urn:ietf:params:oauth:grant-type:device_code \
        -d client_id=hermes-agent --data-urlencode client_secret="$S" -d device_code="$DC")
    err=$(echo "$R" | jq -r '.error // empty')
    [ -z "$err" ] && break
    [ "$err" != authorization_pending ] && [ "$err" != slow_down ] && { echo "device flow failed: $R"; exit 1; }
    sleep 5
done
[ -n "$err" ] && { echo "timed out waiting for the device login"; exit 1; }
rm -f /root/device-auth.json
T1=$(echo "$R" | jq -r .access_token)
echo "== user token (device flow), claims:"; echo "$T1" | claims

R2=$(curl -s $KC/token -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange -d client_id=hermes-agent \
    --data-urlencode client_secret="$S" --data-urlencode subject_token="$T1" \
    -d subject_token_type=urn:ietf:params:oauth:token-type:access_token -d audience=dovecot)
T2=$(echo "$R2" | jq -r '.access_token // empty')
[ -z "$T2" ] && { echo "token exchange failed: $R2"; exit 1; }
echo "== exchanged token (audience dovecot), claims:"; echo "$T2" | claims
echo "== exchanged token:"; echo "$T2"
user=$(echo "$T2" | cut -d. -f2 | tr '_-' '/+' | { read p; while [ $(( ${#p} % 4 )) -ne 0 ]; do p="$p="; done; echo "$p"; } | base64 -d | jq -r .preferred_username)

IMAP=imaps://rl1.dp.nethserver.net:993
echo "== IMAP as $user: folders"
curl -s -k --login-options AUTH=XOAUTH2 -u "$user:" --oauth2-bearer "$T2" "$IMAP/" -w 'exit=%{exitcode}\n'
echo "== IMAP as $user: INBOX status"
curl -s -k --login-options AUTH=XOAUTH2 -u "$user:" --oauth2-bearer "$T2" "$IMAP/" -X 'STATUS INBOX (MESSAGES UNSEEN)' -w 'exit=%{exitcode}\n'
echo "== IMAP as $user: last 5 message headers"
n=$(curl -s -k --login-options AUTH=XOAUTH2 -u "$user:" --oauth2-bearer "$T2" "$IMAP/INBOX" -X 'EXAMINE INBOX' | grep -oE '[0-9]+ EXISTS' | cut -d' ' -f1)
if [ "${n:-0}" -gt 0 ]; then
    from=$(( n > 5 ? n - 4 : 1 ))
    curl -s -k --login-options AUTH=XOAUTH2 -u "$user:" --oauth2-bearer "$T2" "$IMAP/INBOX" \
        -X "FETCH $from:$n (BODY.PEEK[HEADER.FIELDS (DATE FROM SUBJECT)])" | tr -d '\r' | grep -E '^(Date|From|Subject):'
else
    echo "INBOX is empty"
fi
