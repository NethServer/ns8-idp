#!/bin/bash
# Check the account created by Keycloak at the first login of e.u3
kc() { runagent -m scratchpad1 podman exec -i keycloak /opt/keycloak/bin/kcadm.sh "$@" </dev/null; }
kc config credentials --server http://127.0.0.1:18080 --realm master --user admin --password "${KC_ADMIN_PASSWORD}" >/dev/null
R=ad.dom.test U=e.u3
echo "== events"
since=$(( ($(date +%s) - 1800) * 1000 ))
kc get events -r $R -q max=50 | jq -r --argjson s $since '.[] | select(.time >= $s) | [(.time/1000|strftime("%H:%M:%S")), .type, .clientId, (.details.username // ""), (.details.identity_provider // ""), (.error // "")] | @tsv' | tac
echo "== provider log"
runagent -m scratchpad1 podman logs --since 30m keycloak 2>&1 | grep -E "linked to|replacing|link refused|No account with"
echo "== keycloak user"
id=$(kc get users -r $R -q username=$U -q exact=true --fields id --format csv --noquotes)
kc get users/$id -r $R | jq -c '{username, email, firstName, lastName, oid: .attributes.entra_oid, federationLink}'
kc get users/$id/federated-identity -r $R | jq -c '.[] | {identityProvider, userName}'
echo "== AD entry"
cat > /home/scratchpad1/.config/state/kc-show.py <<'EOF'
import ldap3
conn = ldap3.Connection(ldap3.Server('ldap://127.0.0.1:20002'), 'keycloak-svc@ad.dom.test',
    open('ad-svc.pw').read().strip(), auto_bind=True)
conn.search('CN=Users,DC=ad,DC=dom,DC=test', '(sAMAccountName=e.u3)',
    attributes=['cn', 'displayName', 'mail', 'msDS-ExternalDirectoryObjectId', 'userAccountControl', 'pwdLastSet', 'userPrincipalName', 'whenCreated'])
print(conn.entries[0] if conn.entries else 'not found')
EOF
chown scratchpad1: /home/scratchpad1/.config/state/kc-show.py
(cd /; runagent -m scratchpad1 python3 kc-show.py); rm -f /home/scratchpad1/.config/state/kc-show.py
echo "== NS8 list-domain-users"
api-cli run cluster/list-domain-users --data '{"domain":"ad.dom.test"}' | jq -c '.users[] | select(.user=="e.u3")'
echo "== password logins (random password: expect the Entra ID denial, not invalid credentials)"
curl -s "https://keycloak.dp.nethserver.net/realms/$R/protocol/openid-connect/token" -d grant_type=password -d client_id=nextcloud \
    --data-urlencode client_secret="$(cat /root/kc-nextcloud2-secret)" -d username=$U --data-urlencode 'password=Wrong-Pw,1' \
  | sed 's/<[^>]*>/ /g' | grep -oE '"access_token"|This [a-z]+ signs in with Microsoft Entra ID|"error_description":"[^"]*"' | head -1
echo "== nextcloud2"
runagent -m nextcloud2 podman exec --user www-data nextcloud-app php ./occ user:list --output=json 2>/dev/null </dev/null | jq -r 'to_entries[] | select(.value|test("e.u3|User3")) | "\(.key)\t\(.value)"'
