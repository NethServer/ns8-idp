"""Action ownership and input/output contract regression tests."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import runpy
import sys
import types
import unittest
from unittest.mock import Mock, patch

import jsonschema

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]


class ClientAccessTests(unittest.TestCase):
    def schema(self, action, direction='input'):
        return json.loads((ROOT / 'imageroot/actions' / action / f'validate-{direction}.json').read_text())

    def test_group_names_and_null(self):
        schema = self.schema('alter-realm-client')
        for group in ('services_vaultwarden', 'engineering', 'R&D', None):
            jsonschema.validate({'domain':'ad.test','client_id':'app1','access_group':group}, schema)
        for group in ('', 'a/b', 'a\nb', 'a\rb', 17):
            with self.subTest(group=group), self.assertRaises(jsonschema.ValidationError):
                jsonschema.validate({'domain':'ad.test','client_id':'app1','access_group':group}, schema)

    def test_token_lifespan_limits(self):
        schema = self.schema('register-client')
        for value in (None, 60, 600, 86400):
            jsonschema.validate({'domain':'ad.test','access_token_lifespan':value}, schema)
        jsonschema.validate({'domain':'ad.test'}, schema)
        for value in (True, '600', 59, 86401, 600.5):
            with self.subTest(value=value), self.assertRaises(jsonschema.ValidationError):
                jsonschema.validate({'domain':'ad.test','access_token_lifespan':value}, schema)

    def run_status(self, caller, request):
        realm = types.ModuleType('idprealm')
        realm.require_keycloak = Mock()
        def invalid(field, value, code):
            raise ValueError(code)
        realm.fail_validation = invalid
        realm.module_clients = Mock(return_value=[{'id':'a','clientId':'app1','enabled':False}, {'id':'b','clientId':'app2','enabled':True}])
        kcadmin = types.ModuleType('kcadmin')
        kcadmin.agent_client = Mock(return_value=object())
        kcadmin.managed_realms = Mock(return_value=['ad.test'])
        access = types.ModuleType('idpaccess')
        access.access_state = Mock(return_value={'enforced':True,'group':'engineering','group_path':'/engineering','issues':[]})
        output = io.StringIO()
        with patch.dict(sys.modules, {'idprealm':realm,'kcadmin':kcadmin,'idpaccess':access}), \
                patch.dict(os.environ, {'AGENT_TASK_USER':caller}), \
                patch.object(sys, 'stdin', io.StringIO(json.dumps(request))), contextlib.redirect_stdout(output):
            runpy.run_path(str(ROOT / 'imageroot/actions/get-client-access/20read'), run_name='__main__')
        state = json.loads(output.getvalue())
        jsonschema.validate(state, self.schema('get-client-access','output'))
        return state, access.access_state.call_args.args[2]

    def test_module_reads_only_own_client_and_reports_disabled_separately(self):
        state, client = self.run_status('module/app1', {'domain':'ad.test'})
        self.assertEqual(client['clientId'], 'app1')
        self.assertTrue(state['enforced'])
        self.assertFalse(state['enabled'])

    def test_module_cannot_select_another_client(self):
        with self.assertRaisesRegex(ValueError, 'client_id_not_allowed'):
            self.run_status('module/app1', {'domain':'ad.test','client_id':'app2'})

    def test_nonmodule_caller_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'caller_not_a_module'):
            self.run_status('user/someone', {'domain':'ad.test'})

    def test_administrator_selects_client(self):
        state, client = self.run_status('', {'domain':'ad.test','client_id':'app2'})
        self.assertEqual(client['clientId'], 'app2')
        self.assertTrue(state['enabled'])

    def test_administrator_must_select_client(self):
        with self.assertRaisesRegex(ValueError, 'client_id_required'):
            self.run_status('', {'domain':'ad.test'})

    def test_unmanaged_realm_and_missing_client(self):
        with self.assertRaisesRegex(ValueError, 'realm_not_found'):
            self.run_status('module/app1', {'domain':'other.test'})
        with self.assertRaisesRegex(ValueError, 'client_not_found'):
            self.run_status('module/missing', {'domain':'ad.test'})


if __name__ == '__main__':
    unittest.main(verbosity=2)
