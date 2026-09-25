#!/bin/bash
# Usage: sso-login.sh USER PASSWORD
# Simulate a browser OIDC code flow: Nextcloud -> Keycloak login form -> Nextcloud
set -u
NC=${NC:-https://nextcloud.dp.nethserver.net}
jar=$(mktemp); trap 'rm -f "$jar" /tmp/sso-page.html' EXIT
curl -s -c "$jar" -b "$jar" -L -o /tmp/sso-page.html "$NC/apps/user_oidc/login/1"
action=$(grep -o 'id="kc-form-login"[^>]*action="[^"]*"' /tmp/sso-page.html | sed 's/.*action="//; s/"$//; s/&amp;/\&/g')
if [ -z "$action" ]; then
    action=$(grep -o 'action="[^"]*login-actions/authenticate[^"]*"' /tmp/sso-page.html | head -1 | sed 's/action="//; s/"$//; s/&amp;/\&/g')
fi
[ -z "$action" ] && { echo "Keycloak login form not found"; head -c 600 /tmp/sso-page.html; exit 1; }
echo "Keycloak form: ${action%%\?*}"
curl -s -c "$jar" -b "$jar" -L -o /tmp/sso-page.html -w 'final URL: %{url_effective} (%{http_code})\n' \
    --data-urlencode "username=$1" --data-urlencode "password=$2" -d credentialId= "$action"
grep -oE 'This account signs in with Microsoft Entra ID|Invalid username or password|Account is disabled|[Ii]nternal [Ss]erver [Ee]rror' /tmp/sso-page.html | head -1
curl -s -b "$jar" -H 'OCS-APIRequest: true' "$NC/ocs/v2.php/cloud/user?format=json" | jq -c '.ocs.data | {id, displayname, email, groups}'
# Optional: read a file through the SSO session
if [ -n "${3:-}" ]; then
    token=$(curl -s -b "$jar" "$NC/csrftoken" | jq -r .token)
    curl -s -b "$jar" -H "requesttoken: $token" -w ' [GET %{http_code}]\n' "$NC/remote.php/webdav/$3"
fi
