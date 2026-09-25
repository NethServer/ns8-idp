<?php
// OAuth2/OIDC login against Keycloak (NethServer/dev#8080 prototype)
// Behind Traefik: build https:// URLs (the OAuth redirect_uri included)
$config['use_https'] = true;
$config['oauth_provider'] = 'generic';
$config['oauth_provider_name'] = 'Keycloak';
$config['oauth_client_id'] = 'roundcube';
$config['oauth_client_secret'] = 'CLIENT_SECRET';
$config['oauth_config_uri'] = 'https://keycloak.dp.nethserver.net/realms/ad.dom.test/.well-known/openid-configuration';
$config['oauth_scope'] = 'openid profile email';
$config['oauth_identity_fields'] = ['preferred_username'];
$config['oauth_login_redirect'] = false;
