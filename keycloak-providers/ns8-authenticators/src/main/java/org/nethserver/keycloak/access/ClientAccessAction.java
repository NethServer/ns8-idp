package org.nethserver.keycloak.access;

import jakarta.ws.rs.core.Response;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionProvider;

/** Deny the login to a client with an access policy, if the user is not
 * a current member of its group. Keycloak evaluates the triggers of the
 * enabled required actions when any authentication completes: password,
 * SSO cookie and federated IdP logins alike, so the realm flows stay as
 * they are. The action is added to the authentication session only, not
 * to the user.
 */
public final class ClientAccessAction implements RequiredActionProvider {
    @Override
    public void evaluateTriggers(RequiredActionContext context) {
        if (!allowed(context)) {
            context.getAuthenticationSession().addRequiredAction(ClientAccessActionFactory.ID);
        }
    }

    @Override
    public void requiredActionChallenge(RequiredActionContext context) {
        if (allowed(context)) {
            context.success();
        } else {
            // An error page without a form: the login cannot continue
            context.challenge(context.form().setError("accessDenied")
                .createErrorPage(Response.Status.FORBIDDEN));
        }
    }

    @Override
    public void processAction(RequiredActionContext context) {
        requiredActionChallenge(context);
    }

    private static boolean allowed(RequiredActionContext context) {
        return GroupAccess.allowed(context.getSession(), context.getRealm(),
            context.getAuthenticationSession().getClient(), context.getUser());
    }

    @Override public void close() { }
}
