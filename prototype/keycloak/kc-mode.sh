#!/bin/bash
# Usage: kc-mode.sh mixed|federated
# Switch the login mode of realm ad.dom.test and of its SSO applications
# (nextcloud2, roundcubemail2)
set -e
MODE=$1 R=ad.dom.test
[ "$MODE" = mixed ] || [ "$MODE" = federated ] || { echo "usage: $0 mixed|federated"; exit 2; }
kc() { runagent -m scratchpad1 podman exec -i keycloak /opt/keycloak/bin/kcadm.sh "$@"; }
occ() { runagent -m nextcloud2 podman exec --user www-data nextcloud-app php ./occ "$@" </dev/null 2>/dev/null | grep -v '^\[nextcloud\]' || true; }
urlenc() { jq -rn --arg s "$1" '$s|@uri'; }
kc config credentials --server http://127.0.0.1:18080 --realm master --user admin --password "${KC_ADMIN_PASSWORD}" </dev/null >/dev/null

# Native accounts (no Entra ID marker) that lose SSO logins in federated mode
cat > /home/scratchpad1/.config/state/kc-count-native.py <<'EOF'
import ldap3
conn = ldap3.Connection(ldap3.Server('ldap://127.0.0.1:20002'), 'keycloak-svc@ad.dom.test',
    open('ad-svc.pw').read().strip(), auto_bind=True)
conn.search('CN=Users,DC=ad,DC=dom,DC=test',
    '(&(objectClass=user)(objectCategory=person)(!(employeeType=*))'
    '(!(userAccountControl:1.2.840.113556.1.4.803:=2))(!(sAMAccountName=keycloak-svc))(!(sAMAccountName=ldapservice*)))',
    attributes=['sAMAccountName'])
names = sorted(e.sAMAccountName.value for e in conn.entries)
print(f'{len(names)} native accounts: {" ".join(names)}')
EOF
chown scratchpad1: /home/scratchpad1/.config/state/kc-count-native.py
(cd /; runagent -m scratchpad1 python3 kc-count-native.py | sed "s/^/$MODE mode, /")
rm -f /home/scratchpad1/.config/state/kc-count-native.py

# Deny-all direct grant flow, used in federated mode
if ! kc get authentication/flows -r $R </dev/null | jq -e '.[] | select(.alias=="ns8 direct grant deny all")' >/dev/null; then
    kc create authentication/flows -r $R -f - </dev/null <<'JSON'
{"alias":"ns8 direct grant deny all","description":"Password logins are disabled","providerId":"basic-flow","topLevel":true,"builtIn":false}
JSON
    kc create "authentication/flows/$(urlenc "ns8 direct grant deny all")/executions/execution" -r $R -s provider=deny-access-authenticator </dev/null
    id=$(kc get "authentication/flows/$(urlenc "ns8 direct grant deny all")/executions" -r $R </dev/null | jq -r '.[0].id')
    kc update "authentication/flows/$(urlenc "ns8 direct grant deny all")/executions" -r $R -f - </dev/null <<JSON
{"id":"$id","requirement":"REQUIRED"}
JSON
    kc create "authentication/executions/$id/config" -r $R -f - </dev/null <<'JSON'
{"alias":"deny all - message","config":{"denyErrorMessage":"This realm signs in with Microsoft Entra ID"}}
JSON
fi

execs=$(kc get "authentication/flows/$(urlenc "ns8 browser")/executions" -r $R </dev/null)
redir=$(jq -r '.[] | select(.level==0 and .providerId=="identity-provider-redirector") | .id' <<<"$execs")
redir_cfg=$(jq -r '.[] | select(.level==0 and .providerId=="identity-provider-redirector") | .authenticationConfig // empty' <<<"$execs")
forms=$(jq -r '.[] | select(.level==0 and .displayName=="ns8 browser forms") | .id' <<<"$execs")

if [ "$MODE" = federated ]; then
    [ -z "$redir_cfg" ] && kc create "authentication/executions/$redir/config" -r $R -f - </dev/null <<'JSON'
{"alias":"default entra","config":{"defaultProvider":"entra"}}
JSON
    forms_req=DISABLED dg_flow="ns8 direct grant deny all" nc_multi=0 rc_redirect=true
else
    [ -n "$redir_cfg" ] && kc delete "authentication/config/$redir_cfg" -r $R </dev/null
    forms_req=ALTERNATIVE dg_flow="ns8 direct grant" nc_multi=1 rc_redirect=false
fi
# Send the whole execution: without "priority" Keycloak resets it to 0 and
# moves the forms before the Cookie step, breaking SSO sessions
jq -c --arg id "$forms" --arg req "$forms_req" '.[] | select(.id==$id) | .requirement=$req | .priority=(if .priority==0 then 30 else .priority end)' <<<"$execs" \
    | kc update "authentication/flows/$(urlenc "ns8 browser")/executions" -r $R -f -
kc update realms/$R -f - </dev/null <<JSON
{"directGrantFlow":"$dg_flow","attributes":{"ns8_login_mode":"$MODE"}}
JSON

occ config:app:set user_oidc allow_multiple_user_backends --value=$nc_multi >/dev/null
runagent -m roundcubemail2 bash -c "sed -i \"s/^\\\$config\\['oauth_login_redirect'\\] = .*/\\\$config['oauth_login_redirect'] = $rc_redirect;/\" ~/.config/state/config/config.oauth.php && systemctl --user restart roundcubemail-app"

echo "== state"
kc get realms/$R </dev/null | jq -c '{directGrantFlow, mode: .attributes.ns8_login_mode}'
kc get "authentication/flows/$(urlenc "ns8 browser")/executions" -r $R </dev/null | jq -r '.[] | select(.level==0) | "  \(.priority) \(.displayName) [\(.requirement)] \(if .authenticationConfig then "config" else "" end)"'
echo "  nextcloud2 allow_multiple_user_backends=$(occ config:app:get user_oidc allow_multiple_user_backends)"
echo "  roundcubemail2 $(runagent -m roundcubemail2 bash -c "grep oauth_login_redirect ~/.config/state/config/config.oauth.php")"
