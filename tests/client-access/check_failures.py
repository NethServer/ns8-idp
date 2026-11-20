#!/usr/bin/env python3
"""Additional client-policy behavior checks on disposable services.
"""
import contextlib
import copy
import io
import os
import runpy
import sys
import types
import json
from pathlib import Path
import secrets
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from run import ROOT, LoginTests, cmd, idpaccess, idprealm, requests


class DraftEvidence(LoginTests):
    def new_client(self, name):
        idprealm.ensure_client(self.kc, 'ad.test', name,
            redirect_uris=[self.vw_url+'/identity/connect/oidc-signin'])
        client = self.kc.find_client('ad.test', name)
        self.addCleanup(lambda: self.kc.delete('/ad.test/clients/'+client['id']))
        return client

    def redeem(self, target, verifier, client='vaultwarden1', secret=None):
        return requests.post(self.url+'/realms/ad.test/protocol/openid-connect/token', data={
            'grant_type':'authorization_code', 'client_id':client,
            'client_secret':secret or self.secret,
            'code':parse_qs(urlsplit(target).query)['code'][0],
            'redirect_uri':self.vw_url+'/identity/connect/oidc-signin',
            'code_verifier':verifier}, timeout=20)

    def test_17_preflight_vs_mid_update_failure(self):
        client=self.new_client('review-failure')
        with self.assertRaises(idpaccess.PolicyError):
            idpaccess.set_policy(self.kc,'ad.test',copy.deepcopy(client),'missing-review-group')
        after=self.kc.find_client('ad.test','review-failure')
        self.assertTrue(after['enabled'])
        self.assertFalse(idpaccess.restricted(after))
        # Fail the real policy procedure after it has disabled the real client.
        with patch.object(idpaccess,'_ensure_token_gate',side_effect=RuntimeError('injected mapper write failure')):
            with self.assertRaisesRegex(RuntimeError,'injected'):
                idpaccess.set_policy(self.kc,'ad.test',after,'services_vaultwarden')
        failed=self.kc.find_client('ad.test','review-failure')
        self.assertFalse(failed['enabled'])
        self.assertTrue(idpaccess.restricted(failed))
        self.assertIn('token_gate_missing',idpaccess.access_state(self.kc,'ad.test',failed)['issues'])
        idpaccess.reconcile(self.kc,'ad.test',[failed])
        repaired=self.kc.find_client('ad.test','review-failure')
        self.assertFalse(repaired['enabled'])
        self.assertTrue(idpaccess.access_state(self.kc,'ad.test',repaired)['enforced'])

    def test_18_grants_detected_and_registration_resets(self):
        client=self.new_client('review-grants')
        idpaccess.set_policy(self.kc,'ad.test',client,'services_vaultwarden')
        client=self.kc.find_client('ad.test','review-grants')
        flags=('directAccessGrantsEnabled','implicitFlowEnabled','serviceAccountsEnabled')
        self.assertTrue(all(client[k] is False for k in flags))
        for flag in flags: client[flag]=True
        self.kc.put('/ad.test/clients/'+client['id'],client)
        state=idpaccess.access_state(self.kc,'ad.test',self.kc.find_client('ad.test','review-grants'))
        self.assertFalse(state['enforced'])
        self.assertEqual(set(state['issues']),{k+'_set' for k in flags})
        idpaccess.reconcile(self.kc,'ad.test',[self.kc.find_client('ad.test','review-grants')])
        self.assertFalse(idpaccess.access_state(self.kc,'ad.test',self.kc.find_client('ad.test','review-grants'))['enforced'])
        idprealm.ensure_client(self.kc,'ad.test','review-grants',redirect_uris=[self.vw_url+'/identity/connect/oidc-signin'])
        client=self.kc.find_client('ad.test','review-grants')
        self.assertTrue(all(client[k] is False for k in flags))
        self.assertTrue(idpaccess.access_state(self.kc,'ad.test',client)['enforced'])

    def test_19_real_token_defaults_and_reset(self):
        self.assertEqual(self.kc.get('/ad.test')['accessTokenLifespan'],300)
        client=self.new_client('review-token')
        secret=self.kc.get('/ad.test/clients/'+client['id']+'/client-secret')['value']
        _,_,target,verifier=self.auth('allowed',client='review-token')
        response=self.redeem(target,verifier,client='review-token',secret=secret)
        self.assertEqual(response.status_code,200)
        self.assertGreaterEqual(response.json()['expires_in'],295)
        self.assertLessEqual(response.json()['expires_in'],300)
        idprealm.ensure_client(self.kc,'ad.test','review-token',
            redirect_uris=[self.vw_url+'/identity/connect/oidc-signin'],access_token_lifespan=600)
        idprealm.ensure_client(self.kc,'ad.test','review-token',
            redirect_uris=[self.vw_url+'/identity/connect/oidc-signin'],access_token_lifespan=None)
        _,_,target,verifier=self.auth('allowed',client='review-token')
        response=self.redeem(target,verifier,client='review-token',secret=secret)
        self.assertEqual(response.status_code,200)
        self.assertGreaterEqual(response.json()['expires_in'],295)
        self.assertLessEqual(response.json()['expires_in'],300)
    def test_21_local_only_account_denied(self):
        username='reviewlocal'
        self.kc.post('/ad.test/users',{'username':username,'enabled':True,'email':'reviewlocal@example.test',
            'emailVerified':True,'firstName':'Review','lastName':'Local','credentials':[{'type':'password','value':self.password,'temporary':False}]})
        user=self.kc.get('/ad.test/users',params={'username':username,'exact':'true'})[0]
        self.addCleanup(lambda:self.kc.delete('/ad.test/users/'+user['id']))
        # Even manually assigning the imported group locally is insufficient.
        group=self.kc.get('/ad.test/group-by-path/services_vaultwarden')
        self.kc.put('/ad.test/users/'+user['id']+'/groups/'+group['id'])
        _,_,target,_=self.auth(username,client='other1')
        self.assertIn('code=',target or '')
        _,response,target,_=self.auth(username)
        self.assertIsNone(target)
        self.assertEqual(response.status_code,403)

    def test_22_nested_and_deleted_ldap_groups(self):
        group='review-parent'
        cmd('podman','exec',self.samba,'samba-tool','group','add',group)
        self.addCleanup(lambda:cmd('podman','exec',self.samba,'samba-tool','group','delete',group,check=False))
        client=self.new_client('review-group')
        cmd('podman','exec',self.samba,'samba-tool','group','addmembers',group,'services_vaultwarden')
        idpaccess.set_policy(self.kc,'ad.test',client,group)
        _,response,target,_=self.auth('allowed',client='review-group')
        self.assertIsNone(target)
        self.assertEqual(response.status_code,403)
        cmd('podman','exec',self.samba,'samba-tool','group','addmembers',group,'allowed')
        session,_,target,_=self.auth('allowed',client='review-group')
        self.assertIn('code=',target or '')
        cmd('podman','exec',self.samba,'samba-tool','group','delete',group)
        _,response,target,_=self.auth('allowed',session=session,client='review-group',require_cookie=True)
        self.assertIsNone(target)
        self.assertEqual(response.status_code,403)
        # Run the actual get-client-access action against the real Keycloak.
        # Only NS8 caller identity/transport plumbing is substituted.
        kcadmin=types.ModuleType('kcadmin')
        kcadmin.agent_client=lambda:self.kc
        kcadmin.managed_realms=lambda kc:['ad.test']
        output=io.StringIO()
        with patch.dict(sys.modules,{'kcadmin':kcadmin}), \
                patch.dict(os.environ,{'AGENT_TASK_USER':'module/review-group'}), \
                patch.object(idprealm,'require_keycloak',return_value=None), \
                patch.object(sys,'stdin',io.StringIO('{"domain":"ad.test"}')), \
                contextlib.redirect_stdout(output):
            runpy.run_path(str(ROOT/'imageroot/actions/get-client-access/20read'),run_name='__main__')
        state=json.loads(output.getvalue())
        # Report what the administrative health check says after real LDAP deletion.
        self.assertTrue(state['enforced'],state)
        self.assertEqual(state['issues'],[])
        print('LDAP-deleted group: login denied, structural access_state remains enforced=true',flush=True)


if __name__=='__main__':
    suite=unittest.TestSuite(DraftEvidence(name) for name in sorted(DraftEvidence.__dict__) if name.startswith('test_'))
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(not result.wasSuccessful())
