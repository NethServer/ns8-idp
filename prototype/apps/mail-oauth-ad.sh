#!/bin/bash
# Mail OAuth on the AD stack: mail4 (Dovecot) + roundcubemail2, realm ad.dom.test
set -e
kc() { runagent -m scratchpad1 podman exec -i keycloak /opt/keycloak/bin/kcadm.sh "$@"; }
R=ad.dom.test RC=https://roundcube1.dp.nethserver.net KCURL=https://keycloak.dp.nethserver.net/realms/$R
kc config credentials --server http://127.0.0.1:18080 --realm master --user admin --password "${KC_ADMIN_PASSWORD}" </dev/null >/dev/null

AUD='{"name":"aud-dovecot","protocol":"openid-connect","protocolMapper":"oidc-audience-mapper","config":{"included.client.audience":"dovecot","access.token.claim":"true","id.token.claim":"false","introspection.token.claim":"true"}}'

echo "== Keycloak clients"
kc create clients -r $R -f - <<JSON
{"clientId":"dovecot","name":"Dovecot IMAP (token introspection)","protocol":"openid-connect","publicClient":false,
 "standardFlowEnabled":false,"directAccessGrantsEnabled":true,"protocolMappers":[$AUD]}
JSON
kc create clients -r $R -f - <<JSON
{"clientId":"roundcube","name":"Roundcube webmail","protocol":"openid-connect","publicClient":false,
 "standardFlowEnabled":true,"directAccessGrantsEnabled":false,
 "redirectUris":["$RC/index.php/login/oauth"],"webOrigins":["$RC"],"rootUrl":"$RC",
 "attributes":{"post.logout.redirect.uris":"$RC/*","pkce.code.challenge.method":"S256"},"protocolMappers":[$AUD]}
JSON
for c in dovecot roundcube; do
    id=$(kc get clients -r $R -q clientId=$c --fields id --format csv --noquotes </dev/null)
    ( umask 077; kc get clients/$id/client-secret -r $R </dev/null | jq -r .value > /root/kc-$c-ad-secret )
done

echo "== Dovecot (mail4)"
runagent -m mail4 podman exec -i dovecot sh -c 'cat > /etc/dovecot/local.conf.d/passdb.conf' <<'CONF'

auth_mechanisms = $auth_mechanisms oauthbearer xoauth2

passdb {
  driver = oauth2
  mechanisms = xoauth2 oauthbearer
  args = /etc/dovecot/local.conf.d/oauth2.conf.ext
}
CONF
runagent -m mail4 podman exec -i dovecot sh -c 'cat > /etc/dovecot/local.conf.d/oauth2.conf.ext && chmod 600 /etc/dovecot/local.conf.d/oauth2.conf.ext' <<CONF
introspection_mode = post
introspection_url = https://dovecot:$(cat /root/kc-dovecot-ad-secret)@keycloak.dp.nethserver.net/realms/$R/protocol/openid-connect/token/introspect
active_attribute = active
active_value = true
username_attribute = preferred_username
CONF
runagent -m mail4 podman exec dovecot sh -c 'doveconf -n >/dev/null && doveadm reload && doveconf -n | grep ^auth_mechanisms' </dev/null

echo "== Roundcube (roundcubemail2)"
cat > /tmp/rc-oauth.php <<PHP
<?php
// OAuth2/OIDC login against Keycloak (NethServer/dev#8080 prototype)
// Behind Traefik: build https:// URLs (the OAuth redirect_uri included)
\$config['use_https'] = true;
\$config['oauth_provider'] = 'generic';
\$config['oauth_provider_name'] = 'Keycloak';
\$config['oauth_client_id'] = 'roundcube';
\$config['oauth_client_secret'] = '$(cat /root/kc-roundcube-ad-secret)';
\$config['oauth_config_uri'] = '$KCURL/.well-known/openid-configuration';
\$config['oauth_scope'] = 'openid profile email';
\$config['oauth_identity_fields'] = ['preferred_username'];
\$config['oauth_login_redirect'] = false;
PHP
runagent -m roundcubemail2 podman exec -i roundcubemail-app php -l < /tmp/rc-oauth.php
runagent -m roundcubemail2 sh -c 'cat > $AGENT_STATE_DIR/config/config.oauth.php && chmod 644 $AGENT_STATE_DIR/config/config.oauth.php' < /tmp/rc-oauth.php
rm -f /tmp/rc-oauth.php
runagent -m roundcubemail2 systemctl --user restart roundcubemail-app.service </dev/null
sleep 8
curl -s "$RC/?_task=login" | grep -oE 'Login with Keycloak' | head -1
