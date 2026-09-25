#!/bin/bash
kc() { runagent -m scratchpad1 podman exec -i keycloak /opt/keycloak/bin/kcadm.sh "$@" </dev/null; }
kc config credentials --server http://127.0.0.1:18080 --realm master --user admin --password "${KC_ADMIN_PASSWORD}" >/dev/null
echo "== password denial"
bash /root/test-deny.sh 2>&1 | grep -v "parse error"
echo "== federated only warning count"
sed -n '/^cat > .*kc-count-native.py/,/^EOF/p' /root/kc-mode.sh | sed '1d;$d' > /home/scratchpad1/.config/state/kc-count-native.py
chown scratchpad1: /home/scratchpad1/.config/state/kc-count-native.py
(cd /; runagent -m scratchpad1 python3 kc-count-native.py); rm -f /home/scratchpad1/.config/state/kc-count-native.py
echo "== remove the Keycloak link of e.user1 (ad.dom.test) for the browser test"
id=$(kc get users -r ad.dom.test -q username=e.user1 -q exact=true --fields id --format csv --noquotes)
kc delete users/$id/federated-identity/entra -r ad.dom.test
echo "links now: $(kc get users/$id/federated-identity -r ad.dom.test | jq -c length)"
