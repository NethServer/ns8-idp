package org.nethserver.keycloak;

import java.util.List;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

public class LinkByAttributeAuthenticatorFactory implements AuthenticatorFactory {

    public static final String PROVIDER_ID = "ns8-idp-link-by-attribute";
    private static final LinkByAttributeAuthenticator SINGLETON = new LinkByAttributeAuthenticator();

    private static final List<ProviderConfigProperty> CONFIG = ProviderConfigurationBuilder.create()
            .property().name(LinkByAttributeAuthenticator.CONF_USER_ATTRIBUTE)
                .label("User attribute")
                .helpText("Attribute set by an identity provider mapper, holding an immutable identifier (e.g. the Entra ID oid)")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue(LinkByAttributeAuthenticator.DEFAULT_USER_ATTRIBUTE).add()
            .property().name(LinkByAttributeAuthenticator.CONF_PROVIDER_ATTRIBUTE)
                .label("Provider attribute")
                .helpText("Optional: attribute holding the identity provider alias; the account must match the current provider")
                .type(ProviderConfigProperty.STRING_TYPE).add()
            .property().name(LinkByAttributeAuthenticator.CONF_LDAP_ATTRIBUTE)
                .label("LDAP attribute")
                .helpText("Optional: LDAP attribute mapped to the user attribute, for accounts not imported yet")
                .type(ProviderConfigProperty.STRING_TYPE).add()
            .build();

    private static final AuthenticationExecutionModel.Requirement[] REQUIREMENTS = {
            AuthenticationExecutionModel.Requirement.ALTERNATIVE,
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.DISABLED,
    };

    @Override
    public Authenticator create(KeycloakSession session) {
        return SINGLETON;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "NS8 link existing account by attribute";
    }

    @Override
    public String getHelpText() {
        return "Links the brokered identity to the account with the same immutable identifier, without a password check";
    }

    @Override
    public String getReferenceCategory() {
        return null;
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENTS;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG;
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }
}
