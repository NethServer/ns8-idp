#
# Copyright (C) 2026 Nethesis S.r.l.
# SPDX-License-Identifier: GPL-3.0-or-later
#

"""Keycloak checks of the test suite. It runs in the idp module
environment, with the ns8-agent credentials, and prints JSON:

    kccheck.py sync REALM
    kccheck.py claims REALM CLIENT_ID USERNAME
    kccheck.py login REALM CLIENT_ID USERNAME PASSWORD
"""

import base64
import json
import sys
import urllib.error
import urllib.parse
import urllib.request

import kcadmin

kc = kcadmin.agent_client()

def user_rep(realm, username):
    return kc.get(f"/{realm}/users", params={"username": username, "exact": "true"})[0]

def find_client(realm, client_id):
    return kc.find_client(realm, client_id)

def sync(realm):
    """Synchronize users and groups from LDAP, and list them."""
    storage = kc.get(f"/{realm}/components", params={"type": "org.keycloak.storage.UserStorageProvider"})[0]
    kc.post(f"/{realm}/user-storage/{storage['id']}/sync?action=triggerFullSync")
    for mapper in kc.get(f"/{realm}/components", params={"parent": storage["id"]}):
        if mapper["providerId"] == "group-ldap-mapper":
            kc.post(f"/{realm}/user-storage/{storage['id']}/mappers/{mapper['id']}/sync?direction=fedToKeycloak")
    return {
        "connection_url": storage["config"]["connectionUrl"][0],
        "users": sorted(u["username"] for u in kc.get(f"/{realm}/users")),
        "groups": sorted(g["name"] for g in kc.get(f"/{realm}/groups")),
    }

def claims(realm, client_id, username):
    """Claims of an example access token, without a login."""
    user = user_rep(realm, username)
    client = find_client(realm, client_id)
    token = kc.get(f"/{realm}/clients/{client['id']}/evaluate-scopes/generate-example-access-token",
        params={"userId": user["id"], "scope": "openid"})
    token["LDAP_ID"] = user["attributes"]["LDAP_ID"][0]
    return token

def login(realm, client_id, username, password):
    """Log in with a password. The direct access grant is enabled only
    for the login."""
    client = find_client(realm, client_id)
    client_path = f"/{realm}/clients/{client['id']}"
    secret = kc.get(f"{client_path}/client-secret")["value"]
    client["directAccessGrantsEnabled"] = True
    kc.put(client_path, client)
    form = urllib.parse.urlencode({
        "grant_type": "password",
        "client_id": client_id,
        "client_secret": secret,
        "username": username,
        "password": password,
        "scope": "openid",
    }).encode()
    try:
        url = kcadmin.base_url() + f"/realms/{realm}/protocol/openid-connect/token"
        with urllib.request.urlopen(url, data=form) as resp:
            payload = json.load(resp)["access_token"].split(".")[1]
            return {"status": 200, "claims": json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))}
    except urllib.error.HTTPError as ex:
        return {"status": ex.code, "error": json.loads(ex.read()).get("error")}
    finally:
        client["directAccessGrantsEnabled"] = False
        kc.put(client_path, client)

commands = {"sync": sync, "claims": claims, "login": login}
json.dump(commands[sys.argv[1]](*sys.argv[2:]), fp=sys.stdout)
