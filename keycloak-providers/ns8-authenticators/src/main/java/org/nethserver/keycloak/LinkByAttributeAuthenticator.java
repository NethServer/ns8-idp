package org.nethserver.keycloak;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.authenticators.broker.AbstractIdpAuthenticator;
import org.keycloak.authentication.authenticators.broker.util.SerializedBrokeredIdentityContext;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.FederatedIdentityModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

/**
 * First broker login step: link the brokered identity to the existing
 * account that has the same immutable identifier (for example the Entra ID
 * oid), without a password check. The identifier is the user attribute set
 * by an identity provider mapper.
 */
public class LinkByAttributeAuthenticator extends AbstractIdpAuthenticator {

    private static final Logger logger = Logger.getLogger(LinkByAttributeAuthenticator.class);

    static final String CONF_USER_ATTRIBUTE = "userAttribute";
    static final String CONF_PROVIDER_ATTRIBUTE = "providerAttribute";
    static final String CONF_LDAP_ATTRIBUTE = "ldapAttribute";
    static final String DEFAULT_USER_ATTRIBUTE = "ns8_idp_id";

    @Override
    protected void authenticateImpl(AuthenticationFlowContext context, SerializedBrokeredIdentityContext serializedCtx,
            BrokeredIdentityContext brokerContext) {
        KeycloakSession session = context.getSession();
        RealmModel realm = context.getRealm();
        String userAttribute = config(context, CONF_USER_ATTRIBUTE, DEFAULT_USER_ATTRIBUTE);
        String providerAttribute = config(context, CONF_PROVIDER_ATTRIBUTE, null);
        String ldapAttribute = config(context, CONF_LDAP_ATTRIBUTE, null);
        String alias = serializedCtx.getIdentityProviderId();

        List<String> values = serializedCtx.getAttribute(userAttribute);
        String value = values == null || values.isEmpty() ? null : values.get(0);
        if (value == null || value.isBlank()) {
            logger.debugf("No %s attribute from identity provider %s: skipped", userAttribute, alias);
            context.attempted();
            return;
        }

        List<UserModel> matches = find(session, realm, userAttribute, value);
        if (matches.isEmpty() && ldapAttribute != null) {
            matches = find(session, realm, ldapAttribute, value).stream()
                    .filter(u -> value.equals(u.getFirstAttribute(userAttribute)))
                    .collect(Collectors.toList());
        }
        // An identifier is unique only within its identity provider
        if (providerAttribute != null) {
            matches = matches.stream()
                    .filter(u -> alias.equals(u.getFirstAttribute(providerAttribute)))
                    .collect(Collectors.toList());
        }
        if (matches.isEmpty()) {
            logger.infof("No account with %s=%s from %s: skipped", userAttribute, value, alias);
            context.attempted();
            return;
        }
        if (matches.size() > 1) {
            logger.warnf("%d accounts with %s=%s: link refused", matches.size(), userAttribute, value);
            context.failure(AuthenticationFlowError.USER_CONFLICT);
            return;
        }

        UserModel user = matches.get(0);
        FederatedIdentityModel link = session.users().getFederatedIdentity(realm, user, alias);
        if (link != null && !link.getUserId().equals(brokerContext.getId())) {
            logger.infof("Account %s: replacing the %s link %s with %s", user.getUsername(), alias,
                    link.getUserId(), brokerContext.getId());
            session.users().removeFederatedIdentity(realm, user, alias);
        }
        logger.infof("Account %s linked to %s identity %s by %s", user.getUsername(), alias,
                brokerContext.getId(), userAttribute);
        context.setUser(user);
        context.success();
    }

    private static List<UserModel> find(KeycloakSession session, RealmModel realm, String attribute, String value) {
        try (Stream<UserModel> users = session.users().searchForUserByUserAttributeStream(realm, attribute, value)) {
            return users.filter(u -> u.getFirstAttribute(attribute) == null || value.equals(u.getFirstAttribute(attribute)))
                    .collect(Collectors.toList());
        }
    }

    private static String config(AuthenticationFlowContext context, String key, String def) {
        AuthenticatorConfigModel cfg = context.getAuthenticatorConfig();
        Map<String, String> map = cfg == null ? null : cfg.getConfig();
        String v = map == null ? null : map.get(key);
        return v == null || v.isBlank() ? def : v.trim();
    }

    @Override
    protected void actionImpl(AuthenticationFlowContext context, SerializedBrokeredIdentityContext serializedCtx,
            BrokeredIdentityContext brokerContext) {
        authenticateImpl(context, serializedCtx, brokerContext);
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }
}
