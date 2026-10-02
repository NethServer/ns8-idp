#
# Copyright (C) 2026 Nethesis S.r.l.
# SPDX-License-Identifier: GPL-3.0-or-later
#

"""Federated identity providers of the realms, like Microsoft Entra ID.

A realm with a federated IdP has write access to its user domain: the
first login of an unknown federated user creates the account in LDAP.
Federated accounts carry a marker in LDAP, the IdP alias in
employeeType and the immutable user ID at the IdP in employeeNumber:
it links the federated identity to the account, and denies password
logins to the account in Keycloak.

Only Active Directory user domains are supported: OpenLDAP accounts
need numeric IDs that Keycloak cannot allocate.
"""

import json
import os
import secrets
import sys
import urllib.error
import urllib.parse
import urllib.request

import agent
import agent.tasks
import cluster.userdomains

# Realm attribute: "read-only" (default) or "writable"
ACCESS_ATTRIBUTE = "ns8_user_domain_access"
# Secrets of the federation, by user domain: the service account and the
# federated IdP credentials. Keycloak returns IdP secrets masked, so a
# copy is needed to update an IdP.
SECRETS_FILE = "federation.json"

MAPPER_TYPE = "org.keycloak.storage.ldap.mappers.LDAPStorageMapper"
# User attributes of the federated account marker, and their LDAP
# attributes
MARKER = {
    "ns8_idp": "employeeType",
    "ns8_idp_id": "employeeNumber",
}

BROWSER_FLOW = "ns8 browser"
BROWSER_FORMS_FLOW = "ns8 browser forms"
DIRECT_GRANT_FLOW = "ns8 direct grant"
FIRST_BROKER_LOGIN_FLOW = "ns8 first broker login"
LINK_AUTHENTICATOR = "ns8-idp-link-by-attribute"

ENTRA_LOGIN_URL = "https://login.microsoftonline.com"

def _path(name):
    return urllib.parse.quote(name, safe="")

#
# User domain access
#

def user_domain_access(kc, realm):
    attributes = kc.get(f"/{realm}").get("attributes") or {}
    return attributes.get(ACCESS_ATTRIBUTE, "read-only")

def set_user_domain_access(kc, realm, access):
    kc.put(f"/{realm}", {"attributes": {ACCESS_ATTRIBUTE: access}})

def domain_provider(domain):
    """Return the module ID of the account provider of a user domain."""
    rdb = agent.redis_connect(use_replica=True)
    providers = cluster.userdomains.list_domains(rdb)[domain]["providers"]
    return providers[0]["id"]

def _load_secrets():
    try:
        with open(SECRETS_FILE) as fp:
            return json.load(fp)
    except FileNotFoundError:
        return {}

def _save_secrets(data):
    old_umask = os.umask(0o077)
    try:
        with agent.safe_open(SECRETS_FILE) as fp:
            json.dump(data, fp)
    finally:
        os.umask(old_umask)

def _update_domain_secrets(domain, key, value):
    """Set, or remove with a None value, one secret of a user domain."""
    data = _load_secrets()
    entry = data.setdefault(domain, {})
    if value is None:
        entry.pop(key, None)
    else:
        entry[key] = value
    if not entry:
        data.pop(domain)
    _save_secrets(data)

def load_service_account(domain):
    """Return the service account of a writable user domain, or None."""
    return _load_secrets().get(domain, {}).get("service_account")

def load_idp_settings(domain, alias):
    """Return the stored settings of a federated IdP, or None."""
    return _load_secrets().get(domain, {}).get("idps", {}).get(alias)

def save_idp_settings(domain, alias, settings):
    """Store, or remove with None, the settings of a federated IdP."""
    idps = _load_secrets().get(domain, {}).get("idps", {})
    if settings is None:
        idps.pop(alias, None)
    else:
        idps[alias] = settings
    _update_domain_secrets(domain, "idps", idps or None)

def service_account_name():
    # sAMAccountName is at most 20 characters
    return f"{os.environ['MODULE_ID']}-svc"[:20]

def ensure_service_account(domain):
    """Create the service account of the module in the user domain, as
    a member of Domain Admins, and return it. If it exists already, its
    password is reset."""
    account = load_service_account(domain)
    if account:
        return account
    provider_id = domain_provider(domain)
    user = service_account_name()
    # The AD password complexity requires several character classes
    password = secrets.token_urlsafe(24) + "aA1!"
    data = {
        "user": user,
        "display_name": f"Keycloak service account of {os.environ['MODULE_ID']}",
        "password": password,
        "locked": False,
        "groups": ["Domain Admins"],
        "no_password_expiration": True,
        "must_change_password": False,
    }
    print(f"Creating service account {user} in user domain {domain}", file=sys.stderr)
    response = agent.tasks.run(agent_id=f"module/{provider_id}", action="add-user", data=data,
        extra={"isNotificationHidden": True})
    if response["exit_code"] != 0:
        # The account may exist from a previous run: reset it
        print(f"Resetting service account {user}", file=sys.stderr)
        response = agent.tasks.run(agent_id=f"module/{provider_id}", action="alter-user", data=data,
            extra={"isNotificationHidden": True})
        agent.assert_exp(response["exit_code"] == 0, f"cannot set service account {user}")
    account = {"user": user, "bind_dn": f"{user}@{domain}", "password": password}
    _update_domain_secrets(domain, "service_account", account)
    return account

def remove_service_account(domain):
    account = load_service_account(domain)
    if not account:
        return
    print(f"Removing service account {account['user']} from user domain {domain}", file=sys.stderr)
    response = agent.tasks.run(agent_id=f"module/{domain_provider(domain)}", action="remove-user",
        data={"user": account["user"]}, extra={"isNotificationHidden": True})
    if response["exit_code"] != 0:
        print(agent.SD_WARNING + f"Cannot remove service account {account['user']}", file=sys.stderr)
    _update_domain_secrets(domain, "service_account", None)

#
# Writable LDAP federation, Active Directory
#

def _mappers(kc, realm, component_id):
    return {m["name"]: m for m in kc.get(f"/{realm}/components", params={"parent": component_id, "type": MAPPER_TYPE})}

def _ensure_mapper(kc, realm, component_id, mappers, name, provider_id, config):
    if name in mappers:
        mapper = mappers[name]
        mapper["config"].update(config)
        kc.put(f"/{realm}/components/{mapper['id']}", mapper)
    else:
        kc.post(f"/{realm}/components", {
            "name": name,
            "providerId": provider_id,
            "providerType": MAPPER_TYPE,
            "parentId": component_id,
            "config": config,
        })

def ensure_writable_mappers(kc, realm, component_id):
    """LDAP mappers that write accounts like the NS8 AD accounts: the
    user name in cn, the full name in displayName, no givenName and sn,
    and the federated account marker."""
    mappers = _mappers(kc, realm, component_id)
    for name in ("username", "email"):
        if name in mappers:
            _ensure_mapper(kc, realm, component_id, mappers, name, mappers[name]["providerId"], {"read.only": ["false"]})
    for name in ("first name", "last name"):
        if name in mappers:
            kc.delete(f"/{realm}/components/{mappers[name]['id']}")
    _ensure_mapper(kc, realm, component_id, mappers, "full name", "full-name-ldap-mapper", {
        "ldap.full.name.attribute": ["displayName"],
        "read.only": ["false"],
        "write.only": ["false"],
    })
    _ensure_mapper(kc, realm, component_id, mappers, "cn", "user-attribute-ldap-mapper", {
        "ldap.attribute": ["cn"],
        "user.model.attribute": ["username"],
        "read.only": ["false"],
        "always.read.value.from.ldap": ["false"],
        "is.mandatory.in.ldap": ["true"],
    })
    # Without it, Samba requires a password change at the first login
    _ensure_mapper(kc, realm, component_id, mappers, "no password change at creation", "hardcoded-ldap-attribute-mapper", {
        "ldap.attribute.name": ["pwdLastSet"],
        "ldap.attribute.value": ["-1"],
    })
    for user_attribute, ldap_attribute in MARKER.items():
        _ensure_mapper(kc, realm, component_id, mappers, user_attribute, "user-attribute-ldap-mapper", {
            "user.model.attribute": [user_attribute],
            "ldap.attribute": [ldap_attribute],
            "read.only": ["false"],
            # The marker is also written by other tools, like
            # import-users: always read it from LDAP
            "always.read.value.from.ldap": ["true"],
            "is.mandatory.in.ldap": ["false"],
        })

def ensure_read_only_mappers(kc, realm, component_id):
    """Make the LDAP mappers read-only, before the federation becomes
    read-only."""
    for mapper in _mappers(kc, realm, component_id).values():
        if mapper["config"].get("read.only") == ["false"]:
            mapper["config"]["read.only"] = ["true"]
            kc.put(f"/{realm}/components/{mapper['id']}", mapper)

def ensure_user_profile(kc, realm):
    """Declare the marker attributes, which Keycloak would otherwise
    drop, and make first and last names optional: NS8 AD accounts have
    only displayName."""
    profile = kc.get(f"/{realm}/users/profile")
    names = {a["name"] for a in profile["attributes"]}
    for attribute in profile["attributes"]:
        if attribute["name"] in ("firstName", "lastName"):
            attribute.pop("required", None)
    for name, display_name in (("ns8_idp", "Identity provider"), ("ns8_idp_id", "Identity provider user ID")):
        if name not in names:
            profile["attributes"].append({
                "name": name,
                "displayName": display_name,
                "multivalued": False,
                "validations": {},
                "permissions": {"view": ["admin"], "edit": ["admin"]},
            })
    kc.put(f"/{realm}/users/profile", profile)

#
# Authentication flows
#

def _flows(kc, realm):
    return {f["alias"]: f for f in kc.get(f"/{realm}/authentication/flows")}

def _executions(kc, realm, flow):
    return kc.get(f"/{realm}/authentication/flows/{_path(flow)}/executions")

def _move_last(kc, realm, parent_flow, execution_id):
    """Move an execution after its siblings: Keycloak adds new
    executions on top of a flow, before the user is identified."""
    for _ in range(20):
        siblings = [e for e in _executions(kc, realm, parent_flow) if e["level"] == 0]
        if siblings[-1]["id"] == execution_id:
            return
        kc.post(f"/{realm}/authentication/executions/{execution_id}/lower-priority", {})

def _set_requirement(kc, realm, flow, execution_id, requirement):
    execution = next(e for e in _executions(kc, realm, flow) if e["id"] == execution_id)
    execution["requirement"] = requirement
    kc.put(f"/{realm}/authentication/flows/{_path(flow)}/executions", execution)

def ensure_flows(kc, realm):
    """Create the NS8 copies of the browser, direct grant and first
    broker login flows, and bind them to the realm."""
    flows = _flows(kc, realm)
    for builtin, copy in (("browser", BROWSER_FLOW), ("direct grant", DIRECT_GRANT_FLOW),
            ("first broker login", FIRST_BROKER_LOGIN_FLOW)):
        if copy not in flows:
            kc.post(f"/{realm}/authentication/flows/{_path(builtin)}/copy", {"newName": copy})

    # Link the federated identity to the account with the same marker,
    # before any account creation
    executions = _executions(kc, realm, FIRST_BROKER_LOGIN_FLOW)
    if not any(e.get("providerId") == LINK_AUTHENTICATOR for e in executions):
        subflow = next(e["displayName"] for e in executions if "User creation or linking" in e["displayName"])
        kc.post(f"/{realm}/authentication/flows/{_path(subflow)}/executions/execution", {"provider": LINK_AUTHENTICATOR})
        link = next(e for e in _executions(kc, realm, FIRST_BROKER_LOGIN_FLOW) if e.get("providerId") == LINK_AUTHENTICATOR)
        _set_requirement(kc, realm, FIRST_BROKER_LOGIN_FLOW, link["id"], "ALTERNATIVE")
        kc.post(f"/{realm}/authentication/executions/{link['id']}/config", {
            "alias": "link by marker",
            "config": {"userAttribute": "ns8_idp_id", "providerAttribute": "ns8_idp", "ldapAttribute": MARKER["ns8_idp_id"]},
        })
        for _ in range(20):
            first = next(e for e in _executions(kc, realm, subflow) if e["level"] == 0)
            if first["id"] == link["id"]:
                break
            kc.post(f"/{realm}/authentication/executions/{link['id']}/raise-priority", {})

    kc.put(f"/{realm}", {"browserFlow": BROWSER_FLOW, "directGrantFlow": DIRECT_GRANT_FLOW})

def reset_flows(kc, realm):
    """Bind the built-in flows again. The NS8 copies are kept."""
    kc.put(f"/{realm}", {"browserFlow": "browser", "directGrantFlow": "direct grant"})

def _deny_subflow_name(flow, alias):
    return f"{flow} deny {alias}"

def ensure_password_denial(kc, realm, alias, display_name):
    """Deny password logins to the accounts federated by the IdP alias:
    otherwise they could log in without the IdP, bypassing its
    multi-factor authentication and conditional access."""
    # Rebuild the subflows: a previous run may have left them incomplete
    remove_password_denial(kc, realm, alias)
    for parent in (BROWSER_FORMS_FLOW, DIRECT_GRANT_FLOW):
        name = _deny_subflow_name(parent, alias)
        kc.post(f"/{realm}/authentication/flows/{_path(parent)}/executions/flow", {
            "alias": name,
            "type": "basic-flow",
            "description": f"Deny password logins to the accounts of {alias}",
            "provider": "registration-page-form",
        })
        subflow = next(e for e in _executions(kc, realm, parent) if e["displayName"] == name)
        _set_requirement(kc, realm, parent, subflow["id"], "CONDITIONAL")
        _move_last(kc, realm, parent, subflow["id"])
        for provider in ("conditional-user-attribute", "deny-access-authenticator"):
            kc.post(f"/{realm}/authentication/flows/{_path(name)}/executions/execution", {"provider": provider})
        for execution in _executions(kc, realm, name):
            _set_requirement(kc, realm, name, execution["id"], "REQUIRED")
            # Configuration aliases are unique in the realm
            if execution["providerId"] == "conditional-user-attribute":
                config_alias = f"{name} condition"
                config = {"attribute_name": "ns8_idp", "attribute_expected_value": alias, "regex": "false", "not": "false"}
            else:
                config_alias = f"{name} message"
                config = {"denyErrorMessage": f"This account signs in with {display_name}"}
            kc.post(f"/{realm}/authentication/executions/{execution['id']}/config", {
                "alias": config_alias, "config": config,
            })

def remove_password_denial(kc, realm, alias):
    for parent in (BROWSER_FORMS_FLOW, DIRECT_GRANT_FLOW):
        name = _deny_subflow_name(parent, alias)
        for execution in _executions(kc, realm, parent):
            if execution["displayName"] == name:
                kc.delete(f"/{realm}/authentication/executions/{execution['id']}")

#
# Microsoft Entra ID
#

def entra_endpoints(tenant_id):
    base = f"{ENTRA_LOGIN_URL}/{tenant_id}"
    return {
        "issuer": f"{base}/v2.0",
        "authorizationUrl": f"{base}/oauth2/v2.0/authorize",
        "tokenUrl": f"{base}/oauth2/v2.0/token",
        "jwksUrl": f"{base}/discovery/v2.0/keys",
        "logoutUrl": f"{base}/oauth2/v2.0/logout",
    }

def check_entra_credentials(tenant_id, client_id, client_secret):
    """Request a token with the client credentials grant. Return None
    on success, or the error code of Entra ID."""
    form = urllib.parse.urlencode({
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": "https://graph.microsoft.com/.default",
    }).encode()
    try:
        with urllib.request.urlopen(entra_endpoints(tenant_id)["tokenUrl"], data=form, timeout=30):
            return None
    except urllib.error.HTTPError as ex:
        try:
            return json.loads(ex.read()).get("error", f"http_{ex.code}")
        except ValueError:
            return f"http_{ex.code}"
    except urllib.error.URLError as ex:
        return f"connection_failed: {ex.reason}"

def entra_idp_rep(alias, display_name, entra):
    config = entra_endpoints(entra["tenant_id"])
    config.update({
        "clientId": entra["client_id"],
        "clientSecret": entra["client_secret"],
        "clientAuthMethod": "client_secret_post",
        "useJwksUrl": "true",
        "validateSignature": "true",
        # Entra ID custom claims are in the ID token, not in the
        # Microsoft Graph user info
        "disableUserInfo": "true",
        "defaultScope": "openid profile email",
        "pkceEnabled": "true",
        "pkceMethod": "S256",
        "syncMode": "IMPORT",
    })
    return {
        "alias": alias,
        "displayName": display_name,
        "providerId": "oidc",
        "enabled": True,
        # The email claim of Entra ID is not verified
        "trustEmail": False,
        "firstBrokerLoginFlowAlias": FIRST_BROKER_LOGIN_FLOW,
        "config": config,
    }

def entra_idp_mappers(alias):
    def attribute(name, claim, user_attribute, sync_mode="INHERIT"):
        return {"name": name, "identityProviderAlias": alias,
            "identityProviderMapper": "oidc-user-attribute-idp-mapper",
            "config": {"syncMode": sync_mode, "claim": claim, "user.attribute": user_attribute}}
    return [
        # LDAP user names cannot contain the domain of the UPN
        {"name": "username", "identityProviderAlias": alias,
            "identityProviderMapper": "oidc-username-idp-mapper",
            "config": {"syncMode": "INHERIT", "template": "${CLAIM.preferred_username | localpart}"}},
        attribute("email", "email", "email", sync_mode="FORCE"),
        attribute("first name", "given_name", "firstName"),
        attribute("last name", "family_name", "lastName"),
        # The oid claim is the immutable user ID in the tenant
        attribute("idp id", "oid", "ns8_idp_id"),
        {"name": "idp alias", "identityProviderAlias": alias,
            "identityProviderMapper": "hardcoded-attribute-idp-mapper",
            "config": {"syncMode": "INHERIT", "attribute": "ns8_idp", "attribute.value": alias}},
    ]

def federated_idps(kc, realm):
    return kc.get(f"/{realm}/identity-provider/instances")

def redirect_uri(realm, alias):
    return f"https://{os.environ['IDP_HOSTNAME']}/realms/{realm}/broker/{alias}/endpoint"
