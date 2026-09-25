#!/bin/bash
# Prove that the federated marker is read from LDAP: clear it, test, restore
kc() { runagent -m scratchpad1 podman exec -i keycloak /opt/keycloak/bin/kcadm.sh "$@" </dev/null; }
kc config credentials --server http://127.0.0.1:18080 --realm master --user admin --password "${KC_ADMIN_PASSWORD}" >/dev/null
grant() {
    curl -s "https://keycloak.dp.nethserver.net/realms/ad.dom.test/protocol/openid-connect/token" -d grant_type=password \
        -d client_id=nextcloud --data-urlencode client_secret="$(cat /root/kc-nextcloud2-secret)" \
        --data-urlencode username=e.user1 --data-urlencode password="${FED_PASSWORD_AD}" -w ' HTTP %{http_code}' \
      | sed 's/<[^>]*>/ /g' | tr -s ' \n' ' ' | grep -oE 'This account signs in with Microsoft Entra ID|"access_token"|"error_description":"[^"]*"|HTTP [0-9]+' | paste -sd' '
}
oid() { kc get users -r ad.dom.test -q username=e.user1 -q exact=true | jq -c '.[0].attributes.entra_oid'; }
cat > /home/scratchpad1/.config/state/kc-marker-clear.py <<'EOF'
import ldap3
conn = ldap3.Connection(ldap3.Server('ldap://127.0.0.1:20002'), 'keycloak-svc@ad.dom.test',
    open('ad-svc.pw').read().strip(), auto_bind=True)
print('clear', conn.modify('CN=e.user1,CN=Users,DC=ad,DC=dom,DC=test',
    {'msDS-ExternalDirectoryObjectId': [(ldap3.MODIFY_DELETE, [])]}))
EOF
chown scratchpad1: /home/scratchpad1/.config/state/kc-marker-clear.py
echo "marker set:      $(grant) | oid=$(oid)"
(cd /; runagent -m scratchpad1 python3 kc-marker-clear.py)
echo "cleared, cached: $(grant) | oid=$(oid)"
kc create clear-user-cache -r ad.dom.test
echo "cleared, evict:  $(grant) | oid=$(oid)"
(cd /; runagent -m scratchpad1 python3 kc-marker-backfill.py ad.dom.test e.user1 ${E_USER1_OID})
kc create clear-user-cache -r ad.dom.test
echo "restored, evict: $(grant) | oid=$(oid)"
rm -f /home/scratchpad1/.config/state/kc-marker-clear.py
