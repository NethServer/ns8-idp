"""Real Keycloak contract check against an isolated test-only server.

Environment: TEST_KEYCLOAK_URL, TEST_ADMIN_USER, TEST_ADMIN_PASSWORD.
No token, password, client secret or identity information is printed.
"""
import base64
import hashlib
import html.parser
import http.cookiejar
import json
import os
import secrets
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from test_claims import idprealm

BASE = os.environ["TEST_KEYCLOAK_URL"]
REALM = "ns8-claims-qualification"
CALLBACK = BASE + "/test-callback"


def request(method, url, data=None, headers=None):
    req = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            return response.status, json.load(response) if response.headers.get("Content-Length") != "0" else None
    except urllib.error.HTTPError as error:
        if error.code == 204:
            return 204, None
        raise


def form(path, values):
    req = urllib.request.Request(BASE + path, data=urllib.parse.urlencode(values).encode())
    with urllib.request.urlopen(req, timeout=15) as response:
        return json.load(response)


class API:
    def __init__(self):
        self.token = form("/realms/master/protocol/openid-connect/token", {
            "grant_type": "password", "client_id": "admin-cli",
            "username": os.environ["TEST_ADMIN_USER"], "password": os.environ["TEST_ADMIN_PASSWORD"],
        })["access_token"]

    def call(self, method, path, payload=None):
        req = urllib.request.Request(BASE + "/admin/realms" + path,
            data=None if payload is None else json.dumps(payload).encode(),
            headers={"Authorization": "Bearer " + self.token, "Content-Type": "application/json"}, method=method)
        with urllib.request.urlopen(req, timeout=15) as response:
            text = response.read()
            return json.loads(text) if text else None

    def get(self, path): return self.call("GET", path)
    def post(self, path, payload=None): return self.call("POST", path, payload)
    def put(self, path, payload=None): return self.call("PUT", path, payload)
    def delete(self, path): return self.call("DELETE", path)
    def find_client(self, realm, client):
        clients = self.get(f"/{realm}/clients?clientId=" + urllib.parse.quote(client))
        if not clients: return None
        return self.get(f"/{realm}/clients/{clients[0]['id']}")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl): return None


class LoginForm(html.parser.HTMLParser):
    action = None
    fields = None
    error_text = ""
    def __init__(self):
        super().__init__(); self.fields = {}; self.error_text = ""
    def handle_data(self, text):
        self.error_text += text
    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "form" and attrs.get("id") == "kc-form-login": self.action = attrs["action"]
        if tag == "input" and attrs.get("type") == "hidden" and attrs.get("name"):
            self.fields[attrs["name"]] = attrs.get("value", "")


def authorize(secret, verifier, username, password):
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    state = secrets.token_urlsafe(20)
    params = {"client_id": "app1", "redirect_uri": CALLBACK, "response_type": "code", "scope": "openid",
              "code_challenge_method": "S256", "code_challenge": challenge, "state": state}
    # Browsers treat loopback as a secure context and send these Secure login
    # cookies over localhost HTTP. CookieJar does not; match the browser only
    # in this isolated loopback fixture, not in any supported client code.
    assert urllib.parse.urlsplit(BASE).hostname in ("127.0.0.1", "localhost")
    policy = http.cookiejar.DefaultCookiePolicy()
    policy.secure_protocols = ("https", "wss", "http")
    jar = http.cookiejar.CookieJar(policy)
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar), NoRedirect())
    url = BASE + f"/realms/{REALM}/protocol/openid-connect/auth?" + urllib.parse.urlencode(params)
    with opener.open(url, timeout=15) as response:
        parser = LoginForm(); parser.feed(response.read().decode())
    assert parser.action, "login form not found"
    req = urllib.request.Request(parser.action, data=urllib.parse.urlencode({**parser.fields, "username": username, "password": password}).encode(), headers={"Origin": BASE, "Referer": url})
    try:
        opener.open(req, timeout=15)
        raise AssertionError("authorization did not redirect")
    except urllib.error.HTTPError as response:
        if response.code != 302:
            error_parser = LoginForm(); error_parser.feed(response.read().decode())
            known = [m for m in ("Cookie not found", "Invalid username or password", "Invalid parameter", "Invalid redirect", "Session not active", "Invalid code") if m.lower() in error_parser.error_text.lower()]
            raise AssertionError("Browser authorization returned HTTP " + str(response.code) + ": " + ", ".join(known))
        redirect = response.headers["Location"]
    assert redirect.startswith(CALLBACK + "?")
    query = urllib.parse.parse_qs(urllib.parse.urlsplit(redirect).query)
    assert query["state"] == [state]
    return form(f"/realms/{REALM}/protocol/openid-connect/token", {
        "grant_type": "authorization_code", "client_id": "app1", "client_secret": secret,
        "redirect_uri": CALLBACK, "code": query["code"][0], "code_verifier": verifier,
    })


def decoded(token):
    value = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)))


def verify_signed_access(token):
    header = json.loads(base64.urlsafe_b64decode(token.split(".")[0] + "=="))
    assert header["alg"] == "RS256"
    jwks = request("GET", BASE + f"/realms/{REALM}/protocol/openid-connect/certs")[1]
    key = next(key for key in jwks["keys"] if key["kid"] == header["kid"])
    with tempfile.TemporaryDirectory() as tmp:
        cert = Path(tmp) / "cert.der"; pub = Path(tmp) / "pub.pem"; sig = Path(tmp) / "sig"; body = Path(tmp) / "body"
        cert.write_bytes(base64.b64decode(key["x5c"][0]))
        with pub.open("wb") as output:
            subprocess.run(["openssl", "x509", "-inform", "DER", "-in", str(cert), "-pubkey", "-noout"], stdout=output, check=True)
        parts = token.split(".")
        sig.write_bytes(base64.urlsafe_b64decode(parts[2] + "=" * (-len(parts[2]) % 4)))
        body.write_bytes((parts[0] + "." + parts[1]).encode())
        subprocess.run(["openssl", "dgst", "-sha256", "-verify", str(pub), "-signature", str(sig), str(body)], stdout=subprocess.DEVNULL, check=True)
    claims = decoded(token)
    assert claims["iss"] == BASE + "/realms/" + REALM
    assert "api1" in claims["aud"]
    assert claims["exp"] > time.time()
    assert claims["typ"] == "Bearer"
    assert claims["c1_principal_kind"] == "human"


def denied_grant(grant, secret, username=None, password=None):
    params = {"grant_type": grant, "client_id": "app1", "client_secret": secret}
    if username: params.update(username=username, password=password)
    try:
        form(f"/realms/{REALM}/protocol/openid-connect/token", params)
        raise AssertionError("prohibited grant succeeded")
    except urllib.error.HTTPError as response:
        assert response.code in (400, 401)
        payload = json.loads(response.read())
        assert payload["error"] in ("unauthorized_client", "invalid_client")


kc = API()
# Use a brand-new isolated realm; refuse to overwrite anything existing.
assert not any(r["realm"] == REALM for r in kc.get(""))
kc.post("", {"realm": REALM, "enabled": True, "sslRequired": "none"})
try:
    password = secrets.token_urlsafe(32)
    kc.post(f"/{REALM}/users", {"username": "alice", "enabled": True, "firstName": "Alice", "lastName": "Example",
        "email": "alice@example.org", "emailVerified": True,
        "credentials": [{"type": "password", "value": password, "temporary": False}]})
    kwargs = {"redirect_uris": [CALLBACK], "audience": ["api1"], "access_token_claims": {"c1_principal_kind": "human"}}
    secret = idprealm.ensure_client(kc, REALM, "app1", **kwargs)
    client = kc.find_client(REALM, "app1")
    models = f"/{REALM}/clients/{client['id']}/protocol-mappers/models"
    before = kc.get(models)
    assert secret == idprealm.ensure_client(kc, REALM, "app1", **kwargs)
    assert before == kc.get(models)
    tokens = authorize(secret, secrets.token_urlsafe(48), "alice", password)
    verify_signed_access(tokens["access_token"])
    assert "c1_principal_kind" not in decoded(tokens["id_token"])
    refreshed = form(f"/realms/{REALM}/protocol/openid-connect/token", {"grant_type": "refresh_token", "client_id": "app1", "client_secret": secret, "refresh_token": tokens["refresh_token"]})
    verify_signed_access(refreshed["access_token"])
    denied_grant("password", secret, "alice", password)
    denied_grant("client_credentials", secret)
    kc.post(models, {"name": "admin-audience", "protocol": "openid-connect", "protocolMapper": "oidc-audience-mapper",
        "config": {"included.custom.audience": "admin-added", "access.token.claim": "true"}})
    admin_mapper = next(m for m in kc.get(models) if m["name"] == "admin-audience")
    client = kc.find_client(REALM, "app1"); client["enabled"] = False
    kc.put(f"/{REALM}/clients/{client['id']}", client)
    assert secret == idprealm.ensure_client(kc, REALM, "app1", **kwargs)
    assert not kc.find_client(REALM, "app1")["enabled"]
    assert admin_mapper in kc.get(models)
    idprealm.ensure_client(kc, REALM, "app1", redirect_uris=[CALLBACK], access_token_claims={})
    assert admin_mapper in kc.get(models)
    assert not any(m["name"].startswith(idprealm.CLAIM_MAPPER_PREFIX) for m in kc.get(models))
    print(json.dumps({"signed_access_token": "PASS", "id_token_claim_excluded": "PASS", "code_pkce": "PASS", "refresh": "PASS", "password_grant_denied": "PASS", "client_credentials_denied": "PASS", "mapper_idempotency": "PASS", "unrelated_mapper_preserved": "PASS", "secret_preserved": "PASS", "disabled_state_preserved": "PASS", "owned_claim_removal": "PASS"}))
finally:
    kc.delete("/" + REALM)
