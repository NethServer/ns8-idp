package org.nethserver.keycloak.access;

import org.keycloak.models.ClientModel;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.cache.UserCache;
import org.keycloak.models.utils.StorageUnavailableUserModelDelegate;

/** Access policy of a client: only the current members of one LDAP group
 * of the user domain may sign in. Clients without the policy attribute
 * are not restricted: the required action runs for every client.
 */
public final class GroupAccess {
    public static final String POLICY = "ns8.access_policy";
    public static final String POLICY_GROUP = "group";
    public static final String GROUP_ID = "ns8.access_group_id";
    public static final String GROUP_PATH = "ns8.access_group_path";

    private GroupAccess() { }

    public static boolean restricted(ClientModel client) {
        return client == null || POLICY_GROUP.equals(client.getAttribute(POLICY));
    }

    public static boolean allowed(KeycloakSession session, RealmModel realm, ClientModel client, UserModel user) {
        if (!restricted(client)) {
            return true;
        }
        try {
            var groupId = client.getAttribute(GROUP_ID);
            var group = groupId == null || groupId.isEmpty() ? null : realm.getGroupById(groupId);
            if (group == null || user == null) {
                return false;
            }
            // The user cache keeps the group memberships of LDAP users for
            // its whole lifespan: evict this user only, and load it again
            // through the LDAP federation to read its current memberships.
            var cache = session.getProvider(UserCache.class);
            if (cache != null) {
                cache.evict(realm, user);
            }
            var live = session.users().getUserById(realm, user.getId());
            if (live == null || live instanceof StorageUnavailableUserModelDelegate || !live.isEnabled()
                    || !liveMembership(realm, live)) {
                return false;
            }
            return live.getGroupsStream().anyMatch(g -> g.getId().equals(groupId));
        } catch (RuntimeException ex) {
            // LDAP errors must not fall back to local memberships
            return false;
        }
    }

    /** The memberships come from LDAP only if the user is federated by an
     * LDAP provider with a read-only group mapper. The provider itself may
     * be writable, as in realms with federated IdPs. */
    private static boolean liveMembership(RealmModel realm, UserModel user) {
        var link = user.getFederationLink();
        ComponentModel federation = link == null ? null : realm.getComponent(link);
        return federation != null && "ldap".equals(federation.getProviderId())
            && realm.getComponentsStream(federation.getId(),
                "org.keycloak.storage.ldap.mappers.LDAPStorageMapper")
                .anyMatch(m -> "group-ldap-mapper".equals(m.getProviderId())
                    && "READ_ONLY".equals(m.getConfig().getFirst("mode"))
                    && "LOAD_GROUPS_BY_MEMBER_ATTRIBUTE".equals(
                        m.getConfig().getFirst("user.roles.retrieve.strategy")));
    }
}
