package org.nethserver.keycloak.access;

import java.util.List;
import jakarta.ws.rs.core.Response;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.mappers.AbstractOIDCProtocolMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper;
import org.keycloak.protocol.oidc.mappers.OIDCIDTokenMapper;
import org.keycloak.protocol.oidc.mappers.UserInfoTokenMapper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.IDToken;
import org.keycloak.services.ErrorResponseException;

/** Deny token issuance, refresh and user info to users that are not current
 * members of the access group of the client: for example the redemption of
 * an authorization code issued before a group removal. It adds no claim.
 */
public final class GroupTokenGate extends AbstractOIDCProtocolMapper
        implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper {
    public static final String ID = "ns8-client-group-token-gate";
    @Override public String getId() { return ID; }
    @Override public String getDisplayType() { return "NS8 client access group at token issuance"; }
    @Override public String getDisplayCategory() { return TOKEN_MAPPER_CATEGORY; }
    @Override public String getHelpText() { return "Refuse token issuance when current LDAP group membership is absent"; }
    @Override public List<ProviderConfigProperty> getConfigProperties() { return List.of(); }
    private void check(KeycloakSession session, UserSessionModel userSession, ClientSessionContext ctx) {
        if (!GroupAccess.allowed(session, session.getContext().getRealm(), ctx.getClientSession().getClient(), userSession.getUser())) {
            throw new ErrorResponseException("access_denied", "Required client group membership is absent", Response.Status.FORBIDDEN);
        }
    }
    @Override public AccessToken transformAccessToken(AccessToken token, ProtocolMapperModel model,
            KeycloakSession session, UserSessionModel userSession, ClientSessionContext ctx) {
        check(session, userSession, ctx);
        return token;
    }
    @Override public IDToken transformIDToken(IDToken token, ProtocolMapperModel model,
            KeycloakSession session, UserSessionModel userSession, ClientSessionContext ctx) {
        check(session, userSession, ctx);
        return token;
    }
    @Override public AccessToken transformUserInfoToken(AccessToken token, ProtocolMapperModel model,
            KeycloakSession session, UserSessionModel userSession, ClientSessionContext ctx) {
        check(session, userSession, ctx);
        return token;
    }
}
