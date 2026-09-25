#!/bin/bash
# Recent logins of realm ad.dom.test and the Entra ID marker of federated accounts
kc() { runagent -m scratchpad1 podman exec -i keycloak /opt/keycloak/bin/kcadm.sh "$@" </dev/null; }
kc config credentials --server http://127.0.0.1:18080 --realm master --user admin --password "${KC_ADMIN_PASSWORD}" >/dev/null
R=ad.dom.test
echo "== events (last 40 min)"
since=$(( ($(date +%s) - 2400) * 1000 ))
kc get events -r $R -q max=100 | jq -r --argjson s $since '.[] | select(.time >= $s) | [(.time/1000|strftime("%H:%M:%S")), .type, .clientId, (.details.username // ""), (.details.identity_provider // ""), (.error // "")] | @tsv' | tac
echo "== keycloak users with entra_oid"
kc get users -r $R -q max=200 | jq -r '.[] | select(.attributes.entra_oid) | [.username, .attributes.entra_oid[0], ((.createdTimestamp/1000)|strftime("%Y-%m-%d %H:%M"))] | @tsv'
echo "== AD entries with msDS-ExternalDirectoryObjectId"
cat > /home/scratchpad1/.config/state/kc-list-marker.py <<'EOF'
import ldap3
conn = ldap3.Connection(ldap3.Server('ldap://127.0.0.1:20002'), 'keycloak-svc@ad.dom.test',
    open('ad-svc.pw').read().strip(), auto_bind=True)
conn.search('CN=Users,DC=ad,DC=dom,DC=test', '(msDS-ExternalDirectoryObjectId=*)',
    attributes=['sAMAccountName', 'msDS-ExternalDirectoryObjectId', 'whenCreated', 'userAccountControl', 'displayName', 'mail'])
for e in conn.entries:
    print(e.sAMAccountName.value, e['msDS-ExternalDirectoryObjectId'].value, e.whenCreated.value, 'UAC', e.userAccountControl.value, e.displayName.value, e.mail.value, sep='\t')
EOF
chown scratchpad1: /home/scratchpad1/.config/state/kc-list-marker.py
(cd /; runagent -m scratchpad1 python3 kc-list-marker.py)
rm -f /home/scratchpad1/.config/state/kc-list-marker.py
echo "== NS8 list-domain-users (federated names)"
api-cli run cluster/list-domain-users --data '{"domain":"ad.dom.test"}' | jq -r '.users[] | select(.user|test("^(e\\.|davide)")) | "\(.user)\t\(.display_name)\tlocked=\(.locked)"'
