#
# Copyright (C) 2026 Nethesis S.r.l.
# SPDX-License-Identifier: GPL-3.0-or-later
#

"""Minimal client of the Keycloak admin REST API.

Requests go to the Keycloak HTTP port published by the idp pod on the
host loopback interface.
"""

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request

import agent

AGENT_CLIENT_ID = "ns8-agent"
AGENT_SECRET_FILE = "ns8-agent.json"

class KeycloakError(Exception):
    def __init__(self, method, url, status, body):
        self.status = status
        self.body = body
        super().__init__(f"{method} {url}: HTTP {status} {body[:500]}")

def base_url():
    return "http://127.0.0.1:" + os.environ["TCP_PORT"]

def wait_ready(timeout=300):
    """Wait until Keycloak answers the master realm discovery document."""
    url = base_url() + "/realms/master/.well-known/openid-configuration"
    deadline = time.monotonic() + timeout
    while True:
        try:
            with urllib.request.urlopen(url, timeout=10):
                return
        except (urllib.error.URLError, ConnectionError, TimeoutError) as ex:
            # Keycloak answers 503 while it bootstraps: any other HTTP
            # error is final
            if isinstance(ex, urllib.error.HTTPError) and ex.code != 503:
                raise
            if time.monotonic() > deadline:
                raise TimeoutError(f"Keycloak is not ready at {url}: {ex}") from ex
        time.sleep(2)

class Client:
    """Admin API client authenticated with the client_credentials grant
    of a master realm confidential client."""

    def __init__(self, client_id, client_secret):
        self.client_id = client_id
        self.client_secret = client_secret
        self._token = None
        self._token_expiry = 0

    def _send(self, method, url, body=None, headers=None, retries=5):
        req = urllib.request.Request(url, data=body, headers=headers or {}, method=method)
        for attempt in range(retries + 1):
            try:
                with urllib.request.urlopen(req, timeout=60) as resp:
                    return resp.status, dict(resp.headers), resp.read()
            except urllib.error.HTTPError as ex:
                # A 503 is returned for a short time after startup
                if ex.code != 503 or attempt == retries:
                    raise KeycloakError(method, url, ex.code, ex.read().decode(errors="replace")) from None
            except (urllib.error.URLError, ConnectionError):
                if attempt == retries:
                    raise
            time.sleep(2)

    def token(self):
        if self._token and time.monotonic() < self._token_expiry:
            return self._token
        form = urllib.parse.urlencode({
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
        }).encode()
        _, _, body = self._send("POST",
            base_url() + "/realms/master/protocol/openid-connect/token",
            body=form,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        payload = json.loads(body)
        self._token = payload["access_token"]
        # Renew the token a bit before it expires
        self._token_expiry = time.monotonic() + max(payload.get("expires_in", 60) - 15, 5)
        return self._token

    def renew_token(self):
        """Obtain a new token, for example to use roles granted after
        the current token was issued."""
        self._token = None

    def request(self, method, path, data=None, params=None):
        """Call the admin API. The path is relative to /admin/realms, e.g.
        "/master/clients". Return the decoded JSON response, or the
        Location header value for a 201 response without body."""
        url = base_url() + "/admin/realms" + path
        if params:
            url += "?" + urllib.parse.urlencode(params)
        headers = {"Authorization": "Bearer " + self.token()}
        body = None
        if data is not None:
            body = json.dumps(data).encode()
            headers["Content-Type"] = "application/json"
        status, rheaders, rbody = self._send(method, url, body=body, headers=headers)
        if rbody:
            return json.loads(rbody)
        if status == 201:
            return rheaders.get("Location")
        return None

    def get(self, path, params=None):
        return self.request("GET", path, params=params)

    def post(self, path, data=None):
        return self.request("POST", path, data=data)

    def put(self, path, data=None):
        return self.request("PUT", path, data=data)

    def delete(self, path, data=None):
        return self.request("DELETE", path, data=data)

    def find_client(self, realm, client_id):
        """Return the representation of a client, or None."""
        for rep in self.get(f"/{realm}/clients", params={"clientId": client_id}):
            if rep["clientId"] == client_id:
                return rep
        return None

def agent_client():
    """Return a Client authenticated as ns8-agent."""
    with open(AGENT_SECRET_FILE) as fp:
        creds = json.load(fp)
    return Client(creds["client_id"], creds["client_secret"])

def save_agent_secret(client_secret):
    old_umask = os.umask(0o077)
    try:
        with agent.safe_open(AGENT_SECRET_FILE) as fp:
            json.dump({"client_id": AGENT_CLIENT_ID, "client_secret": client_secret}, fp)
    finally:
        os.umask(old_umask)

def managed_realms(kc):
    """Return the names of the realms managed by the module: all realms
    except master."""
    try:
        reps = kc.get("", params={"briefRepresentation": "true"})
    except KeycloakError as ex:
        # ns8-agent sees only the realms it created: with none, the
        # list request is forbidden
        if ex.status == 403:
            return []
        raise
    return [rep["realm"] for rep in reps if rep["realm"] != "master"]
