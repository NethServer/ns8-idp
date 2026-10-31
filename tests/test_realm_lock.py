#!/usr/bin/env python3
"""Deterministic action lock-placement and real event-handler execution checks.
NS8 services are fakes; file locking and the unchanged action scripts are real.
Set IDP_UPSTREAM_ROOT to the pinned ns8-idp checkout for negative controls.
"""
import contextlib
import fcntl
import importlib.util
import io
import json
import multiprocessing
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import types
import unittest

sys.dont_write_bytecode = True

ROOT=Path(__file__).resolve().parents[1]
UPSTREAM=Path(os.environ.get('IDP_UPSTREAM_ROOT', ROOT))


def action_worker(script, lockfile, pipe):
    agent=types.ModuleType('agent')
    agent.__path__=[]
    ldap=types.ModuleType('agent.ldapproxy')
    agent.ldapproxy=ldap
    @contextlib.contextmanager
    def lock(name):
        assert name=='realms'
        with open(lockfile,'a') as fd:
            fcntl.flock(fd,fcntl.LOCK_EX)
            yield
    agent.exclusive_file_lock=lock
    agent.redis_connect=lambda **kw:types.SimpleNamespace(hget=lambda *a:'ad.test')
    agent.get_smarthost_settings=lambda r:{'enabled':False}
    ldap.Ldapproxy=lambda:types.SimpleNamespace(get_domains_list=lambda:['ad.test'])
    kcadmin=types.ModuleType('kcadmin')
    client={'id':'client','clientId':'review1','attributes':{'ns8.module_id':'review1'}}
    kc=types.SimpleNamespace(put=lambda *a:None)
    def connect():
        pipe.send('keycloak-access')
        return kc
    kcadmin.agent_client=connect
    kcadmin.managed_realms=lambda kc:['ad.test']
    sys.modules.update({'agent':agent,'agent.ldapproxy':ldap,'kcadmin':kcadmin})
    spec=importlib.util.spec_from_file_location('idprealm',ROOT/'imageroot/pypkg/idprealm.py')
    realm=importlib.util.module_from_spec(spec)
    sys.modules['idprealm']=realm
    spec.loader.exec_module(realm)
    realm.require_keycloak=lambda:None
    realm.module_clients=lambda *a:[client]
    realm.ensure_federation=lambda *a:None
    policy=types.ModuleType('idpaccess')
    policy.reconcile=lambda *a:None
    sys.modules['idpaccess']=policy
    sys.stdin=io.StringIO(json.dumps({'domain':'ad.test','client_id':'review1','enabled':False}))
    pipe.send('started')
    try:
        runpy.run_path(str(script),run_name='__main__')
        pipe.send('done')
    except BaseException as exc:
        pipe.send(('error',type(exc).__name__,str(exc)))
    finally:
        pipe.close()


class ActionBoundaries(unittest.TestCase):
    def check_lock(self, script, expected_locked):
        ctx=multiprocessing.get_context('fork')
        with tempfile.TemporaryDirectory() as tmp:
            lockfile=Path(tmp)/'realms'
            with lockfile.open('a') as fd:
                fcntl.flock(fd,fcntl.LOCK_EX)
                parent,child=ctx.Pipe()
                process=ctx.Process(target=action_worker,args=(script,lockfile,child))
                process.start()
                try:
                    self.assertTrue(parent.poll(10),'worker failed to start')
                    self.assertEqual(parent.recv(),'started')
                    # With the shared lock held, an action must not access Keycloak.
                    if expected_locked:
                        self.assertFalse(parent.poll(.3),'Keycloak accessed while realms lock is held')
                    else:
                        self.assertTrue(parent.poll(5),'negative control did not bypass held lock')
                        self.assertEqual(parent.recv(),'keycloak-access')
                    fcntl.flock(fd,fcntl.LOCK_UN)
                    if expected_locked:
                        self.assertTrue(parent.poll(5))
                        self.assertEqual(parent.recv(),'keycloak-access')
                    self.assertTrue(parent.poll(5))
                    self.assertEqual(parent.recv(),'done')
                    process.join(5)
                    self.assertEqual(process.exitcode,0)
                finally:
                    if process.is_alive(): process.terminate(); process.join()
                    parent.close(); child.close()

    def test_actions_wait_for_shared_lock(self):
        for relative in ('bin/keycloak-post-start','actions/alter-realm-client/20alter'):
            with self.subTest(action=relative):
                self.check_lock(ROOT/'imageroot'/relative,True)

    @unittest.skipUnless(os.environ.get('IDP_UPSTREAM_ROOT'), 'set IDP_UPSTREAM_ROOT to the unpatched checkout')
    def test_upstream_negative_controls_bypass_shared_lock(self):
        for relative in ('bin/keycloak-post-start','actions/alter-realm-client/20alter'):
            with self.subTest(action=relative):
                self.check_lock(UPSTREAM/'imageroot'/relative,False)

    def test_real_event_handlers_invoke_reconciliation_when_running(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp=Path(tmp)
            (tmp/'systemctl').write_text('#!/bin/sh\nexit "$REVIEW_SERVICE_STATUS"\n')
            (tmp/'keycloak-post-start').write_text('#!/bin/sh\nprintf reconciled > "$REVIEW_MARKER"\n')
            for name in ('systemctl','keycloak-post-start'): (tmp/name).chmod(0o755)
            handlers=('module-domain-changed/10reconcile','user-domain-changed/10reconcile',
                'module-removed/10reconcile','smarthost-changed/10apply_smarthost')
            for handler in handlers:
                for service_status in ('0','1'):
                    with self.subTest(handler=handler,service_status=service_status):
                        marker=tmp/'called'
                        marker.unlink(missing_ok=True)
                        env=dict(os.environ,PATH=str(tmp)+':'+os.environ['PATH'],
                            REVIEW_MARKER=str(marker),REVIEW_SERVICE_STATUS=service_status)
                        subprocess.run(['bash',str(UPSTREAM/'imageroot/events'/handler)],env=env,check=True)
                        self.assertEqual(marker.exists(),service_status=='0')


if __name__=='__main__': unittest.main(verbosity=2)
