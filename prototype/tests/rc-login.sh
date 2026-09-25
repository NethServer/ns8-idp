#!/bin/bash
# Usage: rc-login.sh USER PASSWORD
# Simulate a browser OAuth login: Roundcube -> Keycloak login form -> Roundcube
set -u
RC=https://roundcube1.dp.nethserver.net
jar=$(mktemp) page=$(mktemp); trap 'rm -f "$jar" "$page"' EXIT
curl -s -c "$jar" -b "$jar" -o /dev/null "$RC/?_task=login"
curl -s -c "$jar" -b "$jar" -L -o "$page" "$RC/?_task=login&_action=oauth"
action=$(grep -o 'action="[^"]*login-actions/authenticate[^"]*"' "$page" | head -1 | sed 's/action="//; s/"$//; s/&amp;/\&/g')
[ -z "$action" ] && { echo "Keycloak login form not found"; head -c 600 "$page"; exit 1; }
curl -s -c "$jar" -b "$jar" -L -o "$page" -w 'final URL: %{url_effective} (%{http_code})\n' \
    --data-urlencode "username=$1" --data-urlencode "password=$2" -d credentialId= "$action"
grep -oE 'Invalid username or password|"username":"[^"]*"' "$page" | head -1
grep -oE '"(unread_counts|mailboxes)"' "$page" | sort -u | tr '\n' ' '; echo
# Optional: send a message to RCPT through the Roundcube session
[ -z "${3:-}" ] && exit 0
curl -s -c "$jar" -b "$jar" -L -o "$page" "$RC/?_task=mail&_action=compose"
token=$(grep -oE '"request_token":"[^"]+"' "$page" | head -1 | cut -d'"' -f4)
cid=$(grep -oE '"compose_id":"[^"]+"' "$page" | head -1 | cut -d'"' -f4)
from=$(grep -A3 '<select name="_from"' "$page" | grep -oE 'value="[0-9]+"' | head -1 | grep -oE '[0-9]+')
echo "compose id=$cid identity=$from"
curl -s -c "$jar" -b "$jar" -o "$page" "$RC/?_task=mail&_action=send&_framed=1" \
    -d _token="$token" -d _id="$cid" -d _from="$from" --data-urlencode _to="$3" \
    --data-urlencode "_subject=OAuth send test $(date +%T)" -d _is_html=0 --data-urlencode "_message=Sent by Roundcube with an OAuth token"
grep -oE 'sent_successfully|messagesent|smtp[a-z_]*error[^"]*|"[^"]*(error|failed)[^"]*"' "$page" | sort -u | head -5
