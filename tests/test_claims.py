"""Contract/regression checks without a running NS8 agent or Keycloak."""
import copy
import importlib.util
import json
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
# Import the production module, with only unavailable SDK packages stubbed.
agent = types.ModuleType("agent")
agent.__path__ = []
agent.ldapproxy = types.ModuleType("agent.ldapproxy")
with patch.dict(sys.modules, {"agent": agent, "agent.ldapproxy": agent.ldapproxy,
                             "kcadmin": types.ModuleType("kcadmin")}):
    spec = importlib.util.spec_from_file_location("idprealm", ROOT / "imageroot/pypkg/idprealm.py")
    idprealm = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(idprealm)

class ValidationError(Exception):
    pass

def fail(*args):
    raise ValidationError(args[-1])

class Keycloak:
    def __init__(self, current=None, mappers=()):
        self.current = copy.deepcopy(current)
        self.mappers = copy.deepcopy(list(mappers))
        self.writes = []
        self.secret = "existing-test-secret"

    def find_client(self, *args):
        return copy.deepcopy(self.current)

    def get(self, path):
        if path.endswith("client-secret"):
            return {"value": self.secret}
        return copy.deepcopy(self.mappers)

    def put(self, path, rep):
        self.writes.append(("put", path, copy.deepcopy(rep)))
        if "/protocol-mappers/" in path:
            self.mappers = [copy.deepcopy(rep) if m["id"] == rep["id"] else m for m in self.mappers]
        else:
            self.current = copy.deepcopy(rep)

    def post(self, path, rep=None):
        self.writes.append(("post", path, copy.deepcopy(rep)))
        if path.endswith("client-secret"):
            self.secret = "explicitly-rotated-test-secret"
            return {"value": self.secret}
        if path.endswith("/clients"):
            self.current = {**copy.deepcopy(rep), "id": "client-1"}
            self.secret = rep["secret"]
            self.mappers = [{**m, "id": str(i)} for i, m in enumerate(rep["protocolMappers"])]
        else:
            self.mappers.append({**copy.deepcopy(rep), "id": "new-" + str(len(self.mappers))})

    def delete(self, path):
        self.writes.append(("delete", path, None))
        self.mappers = [m for m in self.mappers if not path.endswith("/" + m["id"])]

class ClaimsTests(unittest.TestCase):
    def setUp(self):
        self.validation = patch.object(idprealm, "fail_validation", fail)
        self.validation.start()
        self.addCleanup(self.validation.stop)

    def register(self, kc, **kw):
        return idprealm.ensure_client(kc, "example.org", "app1", redirect_uris=["https://app.example.org/callback"], **kw)

    def test_reserved_names_and_nested_names_rejected_before_writes(self):
        for name in idprealm.RESERVED_CLAIMS | {"realm_access.roles", "foo.sub", "iss.x", "Foo_claim"}:
            with self.subTest(name=name):
                kc = Keycloak()
                with self.assertRaises(ValidationError):
                    self.register(kc, access_token_claims={name: "human"})
                self.assertFalse(kc.writes)

    def test_bounds_and_arbitrary_mapper_json_rejected(self):
        for claims in ([], {"app_kind": {"protocolMapper": "script"}},
                       {"app_kind": True}, {"app_kind": "x\nhacked=y"},
                       {"app_kind": "x" * 129}, {"app_kind": ""},
                       {f"app_claim{i}": "human" for i in range(9)}):
            with self.assertRaises(ValidationError):
                idprealm.validate_access_token_claims(claims)

    def test_human_client_is_never_machine_or_password_client(self):
        kc = Keycloak()
        self.register(kc, access_token_claims={"app_kind": "human"})
        for key in ("directAccessGrantsEnabled", "serviceAccountsEnabled", "implicitFlowEnabled", "publicClient"):
            self.assertFalse(kc.current[key])
        mapper = kc.mappers[0]
        self.assertEqual(mapper["protocolMapper"], "oidc-hardcoded-claim-mapper")
        self.assertEqual(mapper["config"]["claim.value"], "human")
        self.assertEqual(mapper["config"]["access.token.claim"], "true")
        self.assertEqual(mapper["config"]["id.token.claim"], "false")
        self.assertEqual(mapper["config"]["userinfo.token.claim"], "false")

    def test_retry_preserves_mapper_ids_secret_and_disabled_state(self):
        kc = Keycloak()
        first = self.register(kc, access_token_claims={"app_kind": "human"}, audience=["api"])
        kc.current["enabled"] = False
        mapper_ids = [m["id"] for m in kc.mappers]
        kc.writes.clear()
        second = self.register(kc, access_token_claims={"app_kind": "human"}, audience=["api"])
        self.assertEqual(first, second)
        self.assertFalse(kc.current["enabled"])
        self.assertEqual(mapper_ids, [m["id"] for m in kc.mappers])
        self.assertFalse([w for w in kc.writes if "protocol-mappers" in w[1]])
        self.assertFalse([w for w in kc.writes if w[1].endswith("client-secret")])

    def test_omission_preserves_claims_empty_removes_only_owned(self):
        kc = Keycloak()
        self.register(kc, access_token_claims={"app_kind": "human"})
        unrelated = {"id": "admin", "name": "admin-audience", "protocol": "openid-connect",
                     "protocolMapper": "oidc-audience-mapper", "config": {"included.custom.audience": "keep"}}
        kc.mappers.append(copy.deepcopy(unrelated))
        self.register(kc)
        self.assertEqual(len(kc.mappers), 2)
        self.register(kc, access_token_claims={})
        self.assertEqual(kc.mappers, [unrelated])

    def test_value_update_preserves_mapper_identity(self):
        kc = Keycloak()
        self.register(kc, access_token_claims={"app_kind": "human"})
        before = kc.mappers[0]["id"]
        self.register(kc, access_token_claims={"app_kind": "user"})
        self.assertEqual(before, kc.mappers[0]["id"])
        self.assertEqual(kc.mappers[0]["config"]["claim.value"], "user")

    def test_mapper_name_collision_fails_before_client_update(self):
        kc = Keycloak()
        self.register(kc)
        kc.mappers.append({"id": "admin", **idprealm.access_token_claim_mapper("app_kind", "admin")})
        kc.writes.clear()
        with self.assertRaises(ValidationError):
            self.register(kc, access_token_claims={"app_kind": "human"})
        self.assertFalse(kc.writes)

    def test_client_owner_cannot_be_taken_over(self):
        kc = Keycloak({"id": "other", "attributes": {idprealm.MODULE_ATTRIBUTE: "other1"}})
        with self.assertRaises(ValidationError):
            self.register(kc, access_token_claims={"app_kind": "human"})
        self.assertFalse(kc.writes)

    def test_explicit_rotation_and_existing_mapper_ownership(self):
        kc = Keycloak()
        old = self.register(kc, audience=["api"])
        self.assertNotEqual(old, self.register(kc, audience=["api"], rotate_secret=True))
        self.register(kc, audience=[])
        self.assertFalse(kc.mappers)

    def test_partial_mapper_removal_failure_retains_ownership_for_retry(self):
        kc = Keycloak()
        self.register(kc, access_token_claims={"app_kind": "human"})
        with patch.object(kc, "delete", side_effect=RuntimeError("interrupted")):
            with self.assertRaises(RuntimeError):
                self.register(kc, access_token_claims={})
        self.assertIn(idprealm.CLAIM_MAPPER_PREFIX + "app_kind", json.loads(kc.current["attributes"][idprealm.CLAIM_NAMES_ATTRIBUTE]))
        self.register(kc, access_token_claims={})
        self.assertFalse(kc.mappers)
        self.assertEqual(json.loads(kc.current["attributes"][idprealm.CLAIM_NAMES_ATTRIBUTE]), [])

    def test_corrupt_ownership_fails_without_writes(self):
        kc = Keycloak()
        self.register(kc)
        kc.current["attributes"][idprealm.CLAIM_NAMES_ATTRIBUTE] = "{}"
        kc.writes.clear()
        with self.assertRaises(ValidationError): self.register(kc, access_token_claims={})
        self.assertFalse(kc.writes)

    def test_keycloak_normalized_audience_is_owned_and_legacy_is_recognized(self):
        mapper = {**idprealm.audience_mapper("api"), "id": "legacy", "consentRequired": False}
        self.assertTrue(idprealm.is_audience_mapper(mapper))
        mapper["config"].pop("userinfo.token.claim")
        self.assertTrue(idprealm.is_audience_mapper(mapper))
        mapper["config"]["included.custom.audience"] = "admin-change"
        self.assertFalse(idprealm.is_audience_mapper(mapper))

    def test_input_schema_accepts_custom_claim_and_rejects_reserved(self):
        import jsonschema
        schema = json.loads((ROOT / "imageroot/actions/register-client/validate-input.json").read_text())
        jsonschema.Draft7Validator.check_schema(schema)
        validator = jsonschema.Draft7Validator(schema)
        validator.validate({"domain": "example.org", "access_token_claims": {"app_kind": "human"}})
        for name in idprealm.RESERVED_CLAIMS | {"realm_access.roles"}:
            with self.subTest(name=name):
                self.assertTrue(list(validator.iter_errors({"domain": "example.org", "access_token_claims": {name: "human"}})))

if __name__ == "__main__":
    unittest.main()
