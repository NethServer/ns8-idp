#!/bin/bash
# 1. Password login through the Roundcube form (unchanged path)
# 2. OAuth login, wait past the 5 minutes access token lifetime, then use
#    the session again: Roundcube must refresh the token for IMAP.
set -u
RC=https://roundcube1.dp.nethserver.net
jar=$(mktemp) page=$(mktemp); trap 'rm -f "$jar" "$page"' EXIT

echo "== password login (kctest2)"
curl -s -c "$jar" -b "$jar" -o "$page" "$RC/?_task=login"
token=$(grep -oE 'name="_token" value="[^"]+"' "$page" | head -1 | cut -d'"' -f4)
curl -s -c "$jar" -b "$jar" -L -o "$page" -w 'final URL: %{url_effective} (%{http_code})\n' "$RC/?_task=login" \
    -d _token="$token" -d _task=login -d _action=login -d _user=kctest2 --data-urlencode "_pass=${TEST_PASSWORD}"
grep -qE '"mailboxes"' "$page" && echo "password login OK" || echo "password login FAILED"
: > "$jar"

echo "== OAuth login (kctest1), then wait 360s"
curl -s -c "$jar" -b "$jar" -o /dev/null "$RC/?_task=login"
curl -s -c "$jar" -b "$jar" -L -o "$page" "$RC/?_task=login&_action=oauth"
action=$(grep -o 'action="[^"]*login-actions/authenticate[^"]*"' "$page" | head -1 | sed 's/action="//; s/"$//; s/&amp;/\&/g')
curl -s -c "$jar" -b "$jar" -L -o "$page" -w 'final URL: %{url_effective} (%{http_code})\n' \
    --data-urlencode "username=kctest1" --data-urlencode "password=${TEST_PASSWORD}" -d credentialId= "$action"
token=$(grep -oE '"request_token":"[^"]+"' "$page" | head -1 | cut -d'"' -f4)
date +"login at %T"
sleep 360
date +"list at %T"
curl -s -c "$jar" -b "$jar" -H "X-Roundcube-Request: $token" -H 'X-Requested-With: XMLHttpRequest' \
    "$RC/?_task=mail&_action=list&_mbox=INBOX&_remote=1" -o "$page" -w 'list request: %{http_code}\n'
grep -oE '"(action|pagecount|messagecount)":[^,]*|OAuth token (refresh|expired)[^"]*|session_error|"redirect":"[^"]*"' "$page" | head -5
