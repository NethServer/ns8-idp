#!/bin/bash
# Prepare the oid linking tests on ad.dom.test
set -e
kc() { runagent -m scratchpad1 podman exec -i keycloak /opt/keycloak/bin/kcadm.sh "$@"; }
kc config credentials --server http://127.0.0.1:18080 --realm master --user admin --password "${KC_ADMIN_PASSWORD}" </dev/null >/dev/null
R=ad.dom.test

echo "== (a) remove the Keycloak link of e.user1"
id=$(kc get users -r $R -q username=e.user1 -q exact=true --fields id --format csv --noquotes </dev/null)
kc get users/$id/federated-identity -r $R </dev/null | jq -c '.[] | {identityProvider, userId, userName}' | tee /root/e.user1-link.json
kc delete users/$id/federated-identity/entra -r $R </dev/null
echo "links now: $(kc get users/$id/federated-identity -r $R </dev/null | jq -c length)"

echo "== (b) provision dprincipi in advance, no password, with the davide.principi oid"
api-cli run module/samba1/add-user --data '{"user":"dprincipi","display_name":"Davide Principi (provisioned)"}' | jq -c .
(cd /; runagent -m scratchpad1 python3 kc-marker-backfill.py ad.dom.test dprincipi ${DPRINCIPI_OID})
cat > /home/scratchpad1/.config/state/kc-show.py <<'EOF'
import ldap3
conn = ldap3.Connection(ldap3.Server('ldap://127.0.0.1:20002'), 'keycloak-svc@ad.dom.test',
    open('ad-svc.pw').read().strip(), auto_bind=True)
conn.search('CN=Users,DC=ad,DC=dom,DC=test', '(sAMAccountName=dprincipi)',
    attributes=['msDS-ExternalDirectoryObjectId', 'userAccountControl', 'pwdLastSet', 'displayName', 'userPrincipalName'])
e = conn.entries[0]
print('dprincipi', e['msDS-ExternalDirectoryObjectId'].value, 'UAC', e.userAccountControl.value, 'pwdLastSet', e.pwdLastSet.value, e.userPrincipalName.value, sep='  ')
EOF
chown scratchpad1: /home/scratchpad1/.config/state/kc-show.py
(cd /; runagent -m scratchpad1 python3 kc-show.py); rm -f /home/scratchpad1/.config/state/kc-show.py
echo "dprincipi known to Keycloak before login: $(kc get users -r $R -q username=dprincipi -q exact=true -q briefRepresentation=true </dev/null | jq length) (search imports it on demand)"
echo "davide.principi in Keycloak $R: $(kc get users -r $R -q username=davide.principi -q exact=true </dev/null | jq length)"
