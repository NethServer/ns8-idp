package org.nethserver.keycloak.access;

import org.keycloak.Config;
import org.keycloak.authentication.RequiredActionFactory;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

public final class ClientAccessActionFactory implements RequiredActionFactory {
    public static final String ID = "ns8-client-access";
    private static final RequiredActionProvider INSTANCE = new ClientAccessAction();
    @Override public RequiredActionProvider create(KeycloakSession session) { return INSTANCE; }
    @Override public String getId() { return ID; }
    @Override public String getDisplayText() { return "NS8 client access group"; }
    @Override public void init(Config.Scope config) { }
    @Override public void postInit(KeycloakSessionFactory factory) { }
    @Override public void close() { }
}
