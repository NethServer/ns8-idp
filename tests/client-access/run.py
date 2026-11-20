#!/usr/bin/env python3
"""Disposable Samba AD + ns8-idp OIDC client access protocol tests.
Requires Podman. Only loopback ports are published; no production resources.
"""
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import time
import unittest
from html.parser import HTMLParser
from urllib.parse import parse_qs, urlencode, urljoin, urlsplit

import requests
import types

ROOT = Path(__file__).resolve().parents[2]
# The NS8 agent libraries are not needed by the Keycloak functions used
# here: stub them to load the module code unchanged.
for name in ('agent', 'agent.ldapproxy', 'agent.tasks', 'cluster', 'cluster.userdomains', 'kcadmin'):
    sys.modules.setdefault(name, types.ModuleType(name))
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / 'imageroot/pypkg'))
import idpaccess
import idpfed
import idprealm


class Form(HTMLParser):
    """Forms, with their hidden and prefilled inputs, and links of a page."""
    def __init__(self, html):
        super().__init__()
        self.action = None
        self.forms = {}
        self.links = []
        self._form = None
        self.feed(html)
    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'form':
            self._form = {'action': attrs.get('action'), 'inputs': {}}
            self.forms[attrs.get('id') or ''] = self._form
            if attrs.get('id') == 'kc-form-login':
                self.action = attrs['action']
        elif tag == 'input' and self._form is not None and attrs.get('name'):
            self._form['inputs'][attrs['name']] = attrs.get('value') or ''
        elif tag == 'a' and attrs.get('href'):
            self.links.append(attrs['href'])
    def handle_endtag(self, tag):
        if tag == 'form':
            self._form = None


def cmd(*args, check=True, **kwargs):
    return subprocess.run(args, check=check, capture_output=True, text=True, **kwargs)


def port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


class Admin:
    def __init__(self, url, password):
        self.url = url
        self.password = password
        self.token = None
    def request(self, method, path, data=None, params=None):
        if self.token is None:
            response = requests.post(self.url + '/realms/master/protocol/openid-connect/token', data={
                'grant_type': 'password', 'client_id': 'admin-cli', 'username': 'admin', 'password': self.password}, timeout=20)
            response.raise_for_status()
            self.token = response.json()['access_token']
        response = requests.request(method, self.url + '/admin/realms' + path, json=data,
            params=params, headers={'Authorization': 'Bearer ' + self.token}, timeout=25)
        if response.status_code == 401:
            self.token = None
            return self.request(method, path, data, params)
        if response.status_code >= 400:
            raise RuntimeError(f'{method} {path}: {response.status_code} {response.text[:400]}')
        return response.json() if response.content else response.headers.get('Location')
    def get(self, p, params=None): return self.request('GET', p, params=params)
    def post(self, p, data=None): return self.request('POST', p, data)
    def put(self, p, data=None): return self.request('PUT', p, data)
    def delete(self, p, data=None): return self.request('DELETE', p, data)
    def find_client(self, realm, cid):
        return next((c for c in self.get('/' + realm + '/clients', params={'clientId': cid}) if c['clientId'] == cid), None)


def wait_http(url, containers, seconds=180):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        try:
            if requests.get(url, timeout=2).status_code == 200:
                return
        except requests.RequestException:
            pass
        for name in containers:
            state = cmd('podman', 'inspect', '-f', '{{.State.Running}}', name)
            if state.stdout.strip() != 'true':
                logs = cmd('podman', 'logs', name).stdout + cmd('podman', 'logs', name).stderr
                raise RuntimeError(f'{name} exited: {logs[-5000:]}')
        time.sleep(2)
    raise TimeoutError(url)


class LoginTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.suffix = secrets.token_hex(4)
        cls.network = 'vw-sso-' + cls.suffix
        cls.samba = 'vw-ad-' + cls.suffix
        cls.keycloak = 'vw-kc-' + cls.suffix
        cls.names = []
        cls.password = secrets.token_urlsafe(24) + 'Aa1!'
        cls.kc_port, cls.vw_port = port(), port()
        cls.url = f'http://127.0.0.1:{cls.kc_port}'
        cls.vw_url = f'http://127.0.0.1:{cls.vw_port}'
        cls.addClassCleanup(cls.cleanup)
        cmd('podman', 'network', 'create', cls.network)
        env = dict(os.environ, AD_PASSWORD=cls.password)
        cmd('podman', 'run', '-d', '--name', cls.samba, '--hostname', 'dc.ad.test',
            '--network', cls.network, '--network-alias', 'samba', '--env', 'AD_PASSWORD',
            'localhost/ns8-vaultwarden-test-samba', env=env)
        cls.names.append(cls.samba)
        env = dict(os.environ, KC_BOOTSTRAP_ADMIN_USERNAME='admin', KC_BOOTSTRAP_ADMIN_PASSWORD=cls.password)
        cmd('podman', 'run', '-d', '--name', cls.keycloak, '--network', cls.network,
            '-p', f'127.0.0.1:{cls.kc_port}:8080', '--env', 'KC_BOOTSTRAP_ADMIN_USERNAME',
            '--env', 'KC_BOOTSTRAP_ADMIN_PASSWORD', os.environ.get('IDP_RUNTIME_IMAGE', 'localhost/ns8-idp-client-access-test'),
            'start-dev', '--db=dev-file', '--features=scripts', '--hostname=' + cls.url,
            env=env)
        cls.names.append(cls.keycloak)
        wait_http(cls.url + '/realms/master/.well-known/openid-configuration', cls.names)
        cls.kc = Admin(cls.url, cls.password)
        cls.realm = 'ad.test'
        cls.kc.post('', {'realm': cls.realm, 'enabled': True, 'sslRequired': 'none',
            'registrationAllowed': False})
        rid = cls.kc.get('/ad.test')['id']
        # Same read-only AD LDAP schema and group mapper as ns8-idp, using the
        # private test network in place of the NS8 ldapproxy.
        conf = {k: [v] for k,v in {
            'enabled':'true', 'editMode':'READ_ONLY', 'connectionUrl':'ldap://samba:389',
            'authType':'simple', 'bindDn':'CN=Administrator,CN=Users,DC=ad,DC=test',
            'bindCredential':cls.password, 'importEnabled':'true', 'syncRegistrations':'false',
            'trustEmail':'true', 'vendor':'ad', 'usersDn':'DC=ad,DC=test',
            'searchScope':'2', 'usernameLDAPAttribute':'sAMAccountName', 'rdnLDAPAttribute':'cn',
            'uuidLDAPAttribute':'objectGUID', 'userObjectClasses':'person, organizationalPerson, user',
            'customUserSearchFilter':'(&(objectCategory=person)(!(sAMAccountName=Administrator)))',
            'pagination':'true', 'cachePolicy':'DEFAULT', 'connectionTimeout':'3000', 'readTimeout':'3000'
        }.items()}
        cls.kc.post('/ad.test/components', {'name':'ns8-ldap','providerId':'ldap',
            'providerType':'org.keycloak.storage.UserStorageProvider','parentId':rid,'config':conf})
        cls.component = cls.kc.get('/ad.test/components',params={'type':'org.keycloak.storage.UserStorageProvider'})[0]
        cls.kc.post('/ad.test/components', {'name':'groups','providerId':'group-ldap-mapper',
            'providerType':'org.keycloak.storage.ldap.mappers.LDAPStorageMapper',
            'parentId':cls.component['id'], 'config':{k:[v] for k,v in {
                'group.name.ldap.attribute':'cn', 'groups.dn':'DC=ad,DC=test',
                'group.object.classes':'group', 'preserve.group.inheritance':'false',
                'membership.ldap.attribute':'member', 'membership.attribute.type':'DN',
                'membership.user.ldap.attribute':'cn', 'mode':'READ_ONLY',
                'user.roles.retrieve.strategy':'LOAD_GROUPS_BY_MEMBER_ATTRIBUTE',
                'drop.non.existing.groups.during.sync':'false'
            }.items()}})
        mapper = next(c for c in cls.kc.get('/ad.test/components',params={'parent':cls.component['id']}) if c['name']=='groups')
        # Wait for domain provisioning, then import group objects once. Membership
        # itself is looked up on authentication, never maintained in this runner.
        end = time.monotonic()+90
        while True:
            try:
                cls.kc.post('/ad.test/user-storage/' + cls.component['id'] + '/mappers/' + mapper['id'] + '/sync?direction=fedToKeycloak')
                break
            except RuntimeError:
                if time.monotonic()>end: raise
                time.sleep(2)
        # Registration as by the register-client action, with the access token
        # lifespan requested by the Vaultwarden module
        redirect=[cls.vw_url+'/identity/connect/oidc-signin']
        cls.secret = idprealm.ensure_client(cls.kc, 'ad.test', 'vaultwarden1', redirect_uris=redirect,
            access_token_lifespan=600)
        idprealm.ensure_client(cls.kc, 'ad.test', 'other1', redirect_uris=redirect)
        cls.policy = idpaccess.set_policy(cls.kc, 'ad.test', cls.kc.find_client('ad.test','vaultwarden1'),
            'services_vaultwarden')
    @classmethod
    def cleanup(cls):
        out=ROOT/'tests/outputs/integration'
        out.mkdir(parents=True,exist_ok=True)
        for name in reversed(cls.names):
            logs=cmd('podman','logs',name,check=False)
            # Never retain passwords, authorization URLs/codes or tokens.
            lines=[l for l in (logs.stdout+logs.stderr).splitlines()
                if not any(v in l.lower() for v in ('password','token','code=','state=','bindcredential','secret'))]
            (out/(name.split('-')[1]+'.log')).write_text('\n'.join(lines))
            cmd('podman','rm','-f',name,check=False)
        cmd('podman','network','rm',cls.network,check=False)

    def auth(self, username, session=None, client='vaultwarden1', mobile=False, require_cookie=False):
        s=session or requests.Session()
        verifier=secrets.token_urlsafe(48)
        challenge=base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
        url=self.url+'/realms/ad.test/protocol/openid-connect/auth?'+urlencode({
            'client_id':client,'redirect_uri':self.vw_url+'/identity/connect/oidc-signin',
            'response_type':'code','scope':'openid profile email','state':secrets.token_urlsafe(24),
            'code_challenge':challenge,'code_challenge_method':'S256'})
        r=s.get(url,allow_redirects=False,timeout=20)
        for _ in range(20):
            # Keycloak treats loopback as a secure browser context and sets
            # Secure cookies even on HTTP. requests lacks that browser exception.
            # Only our ephemeral loopback fixture is allowed to relax this flag.
            for cookie in s.cookies:
                if cookie.domain == '127.0.0.1': cookie.secure = False
            if r.is_redirect:
                target=urljoin(r.url,r.headers['Location'])
                if target.startswith('bitwarden:') or (not mobile and target.startswith(self.vw_url)):
                    return s,r,target,verifier
                r=s.get(target,allow_redirects=False,timeout=20)
                continue
            form=Form(r.text)
            if form.action:
                if require_cookie:
                    self.fail('Expected reuse of the existing SSO cookie; password fallback would invalidate this test')
                r=s.post(form.action,data={'username':username,'password':self.password},allow_redirects=False,timeout=20)
                continue
            return s,r,None,verifier
        self.fail('Redirect loop')

    def test_01_allowed_and_denied(self):
        self.assertTrue(self.policy['enforced'], self.policy)
        # No private flow, no realm flow change, no cache change
        client=self.kc.find_client('ad.test','vaultwarden1')
        self.assertFalse(any((client.get('authenticationFlowBindingOverrides') or {}).values()))
        self.assertEqual(self.kc.get('/ad.test')['browserFlow'],'browser')
        comp=self.kc.get('/ad.test/components/'+self.component['id'])
        self.assertEqual(comp['config']['cachePolicy'],['DEFAULT'])
        for username,expected in [('allowed',True),('denied',False)]:
            with self.subTest(username=username):
                _,r,target,_=self.auth(username)
                self.assertEqual(bool(target and 'code=' in target),expected,
                    f'{username}: HTTP {r.status_code}, page {r.text[-1000:]}')

    def test_02_other_client_unrestricted(self):
        _,_,target,_=self.auth('denied',client='other1')
        self.assertIn('code=',target or '')


    def test_04_revocation_with_cookie_and_new_device(self):
        session,_,target,_=self.auth('allowed',client='other1')
        self.assertIn('code=',target or '')
        cmd('podman','exec',self.samba,'samba-tool','group','removemembers','services_vaultwarden','allowed')
        try:
            for label,s,mobile in [('existing cookie',session,False),('new browser',None,False)]:
                with self.subTest(label=label):
                    _,r,target,_=self.auth('allowed',session=s,mobile=mobile,require_cookie=s is not None)
                    self.assertIsNone(target,f'{label}: got a callback after revocation')
                    self.assertEqual(r.status_code,403)
            # Login to other applications still succeeds after removal.
            _,_,target,_=self.auth('allowed',session=session,client='other1',require_cookie=True)
            self.assertIn('code=',target or '')
        finally:
            cmd('podman','exec',self.samba,'samba-tool','group','addmembers','services_vaultwarden','allowed')
        _,_,target,_=self.auth('allowed')
        self.assertIn('code=',target or '')

    def test_05_missing_policy_denies(self):
        client=self.kc.find_client('ad.test','vaultwarden1')
        attrs=dict(client['attributes'])
        client['attributes'][idpaccess.GROUP_ID] = 'missing-group'
        self.kc.put('/ad.test/clients/'+client['id'],client)
        try:
            _,r,target,_=self.auth('allowed')
            self.assertIsNone(target)
            self.assertEqual(r.status_code,403)
        finally:
            client['attributes']=attrs
            self.kc.put('/ad.test/clients/'+client['id'],client)

    def test_06_policy_idempotent_and_restart_persistent(self):
        state=idpaccess.set_policy(self.kc,'ad.test',self.kc.find_client('ad.test','vaultwarden1'),'services_vaultwarden')
        self.assertTrue(state['enforced'])
        cmd('podman','restart',self.keycloak)
        wait_http(self.url+'/realms/ad.test/.well-known/openid-configuration',self.names)
        self.kc.token=None
        _,_,target,_=self.auth('allowed')
        self.assertIn('code=',target or '')
        _,r,target,_=self.auth('denied')
        self.assertIsNone(target)
        self.assertEqual(r.status_code,403)
    def test_07_directory_unavailable_denies(self):
        session,_,target,_=self.auth('allowed',client='other1')
        self.assertIn('code=',target or '')
        # With LDAP unavailable, Keycloak may invalidate cookie authentication
        # and show a fresh login form. That is safe; completing it must still
        # produce neither an authorization code nor a token.
        cmd('podman','pause',self.samba)
        try:
            _,r,target,_=self.auth('allowed',session=session)
            self.assertIsNone(target)
            self.assertGreaterEqual(r.status_code,400)
        finally:
            cmd('podman','unpause',self.samba)

    def test_08_code_and_refresh_cannot_bypass_revocation(self):
        _,_,target,verifier=self.auth('allowed')
        self.assertIn('code=',target or '')
        # Issue one live refresh token before removing group membership.
        _,_,second,second_verifier=self.auth('allowed')
        token_url=self.url+'/realms/ad.test/protocol/openid-connect/token'
        def redeem(callback, pkce):
            return requests.post(token_url,data={
                'grant_type':'authorization_code','client_id':'vaultwarden1',
                'client_secret':self.secret,'code':parse_qs(urlsplit(callback).query)['code'][0],
                'redirect_uri':self.vw_url+'/identity/connect/oidc-signin','code_verifier':pkce},timeout=20)
        live=redeem(second,second_verifier)
        self.assertEqual(live.status_code,200)
        refresh=live.json()['refresh_token']
        cmd('podman','exec',self.samba,'samba-tool','group','removemembers','services_vaultwarden','allowed')
        try:
            stale=redeem(target,verifier)
            self.assertEqual(stale.status_code,403)
            self.assertNotIn('access_token',stale.json())
            refreshed=requests.post(token_url,data={
                'grant_type':'refresh_token','client_id':'vaultwarden1',
                'client_secret':self.secret,'refresh_token':refresh},timeout=20)
            self.assertEqual(refreshed.status_code,403)
            self.assertNotIn('access_token',refreshed.json())
        finally:
            cmd('podman','exec',self.samba,'samba-tool','group','addmembers','services_vaultwarden','allowed')

    def test_09_cached_user_revocation_and_regrant(self):
        # The LDAP cache stays enabled: warm it with a login to another client,
        # then check that membership changes apply to the next login at once.
        comp=self.kc.get('/ad.test/components/'+self.component['id'])
        self.assertEqual(comp['config']['cachePolicy'],['DEFAULT'])
        session,_,target,_=self.auth('allowed',client='other1')
        self.assertIn('code=',target or '')
        cmd('podman','exec',self.samba,'samba-tool','group','removemembers','services_vaultwarden','allowed')
        try:
            _,r,target,_=self.auth('allowed',session=session,require_cookie=True)
            self.assertIsNone(target)
            self.assertEqual(r.status_code,403)
        finally:
            cmd('podman','exec',self.samba,'samba-tool','group','addmembers','services_vaultwarden','allowed')
        _,_,target,_=self.auth('allowed',session=session,require_cookie=True)
        self.assertIn('code=',target or '')
        cmd('podman','exec',self.samba,'samba-tool','group','addmembers','services_vaultwarden','denied')
        try:
            _,_,target,_=self.auth('denied')
            self.assertIn('code=',target or '')
        finally:
            cmd('podman','exec',self.samba,'samba-tool','group','removemembers','services_vaultwarden','denied')
        _,r,target,_=self.auth('denied')
        self.assertIsNone(target)


    def broker_auth(self, password, session=None, client='vaultwarden1', federated=False):
        """Sign in through the external IdP. Return (session, last response,
        callback URL or None, visited URLs)."""
        s=session or requests.Session()
        url=self.url+'/realms/ad.test/protocol/openid-connect/auth?'+urlencode({
            'client_id':client,'redirect_uri':self.vw_url+'/identity/connect/oidc-signin',
            'response_type':'code','scope':'openid profile email','state':secrets.token_urlsafe(24)})
        r=s.get(url,allow_redirects=False,timeout=20)
        visited=[url]
        for _ in range(30):
            for cookie in s.cookies:
                if cookie.domain == '127.0.0.1': cookie.secure = False
            if r.is_redirect:
                target=urljoin(r.url,r.headers['Location'])
                visited.append(target)
                if target.startswith(self.vw_url):
                    return s,r,target,visited
                r=s.get(target,allow_redirects=False,timeout=20)
                continue
            page=Form(r.text)
            if '/realms/ext/' in r.url and page.action:
                r=s.post(page.action,data={'username':'fedx','password':password},allow_redirects=False,timeout=20)
                continue
            if '/realms/ad.test/' in r.url and page.action:
                if federated:
                    self.fail('The password form of the realm is shown in federated login mode')
                link=next(l for l in page.links if '/broker/ext/' in l)
                r=s.get(urljoin(r.url,link.replace('&amp;','&')),allow_redirects=False,timeout=20)
                continue
            form=next((f for i,f in page.forms.items() if 'profile' in i or 'update' in i),None)
            if form:
                # First broker login: review the profile received from the IdP
                r=s.post(urljoin(r.url,form['action']),data=form['inputs'],allow_redirects=False,timeout=20)
                continue
            return s,r,None,visited
        self.fail('Redirect loop')

    def test_11_writable_federation_and_federated_idp(self):
        """Realm with a federated IdP, configured with the unchanged upstream
        functions: writable LDAP federation, NS8 flows, password denial and
        both login modes. A second realm of the same Keycloak stands in for
        Microsoft Entra ID."""
        kc=self.kc
        comp=kc.get('/ad.test/components/'+self.component['id'])
        original=dict(comp['config'])
        comp['config'].update({'editMode':['WRITABLE'],'syncRegistrations':['true']})
        kc.put('/ad.test/components/'+comp['id'],comp)
        ext_password=secrets.token_urlsafe(18)+'Aa1!'
        kc.post('',{'realm':'ext','enabled':True,'sslRequired':'none'})
        ext_secret=secrets.token_urlsafe(32)
        kc.post('/ext/clients',{'clientId':'ad-broker','protocol':'openid-connect','publicClient':False,
            'secret':ext_secret,'standardFlowEnabled':True,
            'redirectUris':[self.url+'/realms/ad.test/broker/ext/endpoint']})
        kc.post('/ext/users',{'username':'fedx','enabled':True,'email':'fedx@example.test','emailVerified':True,
            'firstName':'Fed','lastName':'User','credentials':[{'type':'password','value':ext_password,'temporary':False}]})
        try:
            idpfed.ensure_writable_mappers(kc,'ad.test',comp['id'])
            idpfed.ensure_user_profile(kc,'ad.test')
            idpfed.ensure_flows(kc,'ad.test')
            idpfed.ensure_password_denial(kc,'ad.test','ext','External')
            # Keycloak calls the token endpoint from its own container
            internal='http://127.0.0.1:8080/realms/ext/protocol/openid-connect'
            rep=idpfed.entra_idp_rep('ext','External',{'tenant_id':'x','client_id':'ad-broker','client_secret':ext_secret})
            rep['config'].update({'issuer':self.url+'/realms/ext',
                'authorizationUrl':self.url+'/realms/ext/protocol/openid-connect/auth',
                'tokenUrl':internal+'/token','jwksUrl':internal+'/certs',
                'logoutUrl':self.url+'/realms/ext/protocol/openid-connect/logout'})
            kc.post('/ad.test/identity-provider/instances',rep)
            for mapper in idpfed.entra_idp_mappers('ext'):
                if mapper['name']=='idp id':
                    mapper['config']['claim']='sub'
                kc.post('/ad.test/identity-provider/instances/ext/mappers',mapper)
            # The policy is still complete with the writable federation
            state=idpaccess.access_state(kc,'ad.test',kc.find_client('ad.test','vaultwarden1'))
            self.assertTrue(state['enforced'],state)
            with self.subTest('native accounts with the writable federation'):
                _,_,target,_=self.auth('allowed')
                self.assertIn('code=',target or '')
                _,r,target,_=self.auth('denied')
                self.assertIsNone(target)
                self.assertEqual(r.status_code,403)
            with self.subTest('first federated login creates the account and is denied'):
                session,r,target,_=self.broker_auth(ext_password)
                self.assertIsNone(target,'federated non-member got an authorization code')
                self.assertEqual(r.status_code,403,r.text[-500:])
                out=cmd('podman','exec',self.samba,'samba-tool','user','show','fedx').stdout
                self.assertIn('employeeType: ext',out)
            with self.subTest('same SSO session, unrestricted client'):
                _,r,target,_=self.broker_auth(ext_password,session=session,client='other1')
                self.assertIn('code=',target or '',r.text[-500:])
            cmd('podman','exec',self.samba,'samba-tool','group','addmembers','services_vaultwarden','fedx')
            with self.subTest('member after group change, existing SSO session'):
                _,r,target,_=self.broker_auth(ext_password,session=session)
                self.assertIn('code=',target or '',r.text[-500:])
            with self.subTest('federated login mode applies to the restricted client'):
                idpfed.apply_login_mode(kc,'ad.test','federated')
                try:
                    _,r,target,visited=self.broker_auth(ext_password,federated=True)
                    self.assertTrue(any('/realms/ext/' in u for u in visited))
                    self.assertIn('code=',target or '',r.text[-500:])
                finally:
                    idpfed.apply_login_mode(kc,'ad.test','mixed')
            cmd('podman','exec',self.samba,'samba-tool','group','removemembers','services_vaultwarden','fedx')
            with self.subTest('fresh federated login after removal'):
                _,r,target,_=self.broker_auth(ext_password)
                self.assertIsNone(target)
                self.assertEqual(r.status_code,403)
        finally:
            for idp in kc.get('/ad.test/identity-provider/instances'):
                idpfed.remove_password_denial(kc,'ad.test',idp['alias'])
                kc.delete('/ad.test/identity-provider/instances/'+idp['alias'])
            idpfed.reset_flows(kc,'ad.test')
            idpfed.ensure_read_only_mappers(kc,'ad.test',comp['id'])
            comp=kc.get('/ad.test/components/'+comp['id'])
            comp['config'].update({'editMode':original['editMode'],'syncRegistrations':original['syncRegistrations']})
            kc.put('/ad.test/components/'+comp['id'],comp)
            kc.delete('/ext')
        _,_,target,_=self.auth('allowed')
        self.assertIn('code=',target or '')

    def test_12_access_token_lifespan_is_optional(self):
        kc=self.kc
        lifespan=lambda cid: (kc.find_client('ad.test',cid).get('attributes') or {}).get('access.token.lifespan') or None
        self.assertEqual(lifespan('vaultwarden1'),'600')
        self.assertIsNone(lifespan('other1'))
        redirect=[self.vw_url+'/identity/connect/oidc-signin']
        # A registration without the setting keeps it
        idprealm.ensure_client(kc,'ad.test','vaultwarden1',redirect_uris=redirect)
        self.assertEqual(lifespan('vaultwarden1'),'600')
        _,_,target,verifier=self.auth('allowed')
        token=requests.post(self.url+'/realms/ad.test/protocol/openid-connect/token',data={
            'grant_type':'authorization_code','client_id':'vaultwarden1','client_secret':self.secret,
            'code':parse_qs(urlsplit(target).query)['code'][0],
            'redirect_uri':self.vw_url+'/identity/connect/oidc-signin','code_verifier':verifier},timeout=20).json()
        self.assertGreaterEqual(token['expires_in'],595)
        self.assertLessEqual(token['expires_in'],600)
        # None restores the realm default
        idprealm.ensure_client(kc,'ad.test','vaultwarden1',redirect_uris=redirect,access_token_lifespan=None)
        self.assertIsNone(lifespan('vaultwarden1'))
        idprealm.ensure_client(kc,'ad.test','vaultwarden1',redirect_uris=redirect,access_token_lifespan=600)
        self.assertEqual(lifespan('vaultwarden1'),'600')
        # Registrations keep the policy
        self.assertTrue(idpaccess.access_state(kc,'ad.test',kc.find_client('ad.test','vaultwarden1'))['enforced'])

    def test_13_policy_removal_and_new_policy(self):
        kc=self.kc
        idpaccess.clear_policy(kc,'ad.test',kc.find_client('ad.test','vaultwarden1'))
        try:
            client=kc.find_client('ad.test','vaultwarden1')
            self.assertFalse(idpaccess.restricted(client))
            self.assertFalse(any(m.get('protocolMapper')==idpaccess.TOKEN_GATE
                for m in kc.get('/ad.test/clients/'+client['id']+'/protocol-mappers/models')))
            self.assertFalse(any(k.startswith('ns8.access') for k in client.get('attributes',{})))
            _,_,target,_=self.auth('denied')
            self.assertIn('code=',target or '')
        finally:
            state=idpaccess.set_policy(kc,'ad.test',kc.find_client('ad.test','vaultwarden1'),'services_vaultwarden')
        self.assertTrue(state['enforced'])
        _,r,target,_=self.auth('denied')
        self.assertIsNone(target)
        with self.assertRaises(idpaccess.PolicyError) as ctx:
            idpaccess.set_policy(kc,'ad.test',kc.find_client('ad.test','other1'),'no_such_group')
        self.assertEqual(ctx.exception.code,'group_not_found')
        self.assertFalse(idpaccess.restricted(kc.find_client('ad.test','other1')))
        self.assertTrue(kc.find_client('ad.test','other1')['enabled'])


    def test_15_reconcile_restores_missing_parts(self):
        kc=self.kc
        client=kc.find_client('ad.test','vaultwarden1')
        for mapper in idpaccess._token_gates(kc,'ad.test',client):
            kc.delete('/ad.test/clients/'+client['id']+'/protocol-mappers/models/'+mapper['id'])
        action=next(a for a in kc.get('/ad.test/authentication/required-actions') if a['providerId']==idpaccess.ACTION)
        action['enabled']=False
        kc.put('/ad.test/authentication/required-actions/'+action['alias'],action)
        state=idpaccess.access_state(kc,'ad.test',kc.find_client('ad.test','vaultwarden1'))
        self.assertFalse(state['enforced'])
        self.assertEqual(set(state['issues']),{'token_gate_missing','required_action_disabled'})
        idpaccess.reconcile(kc,'ad.test',idprealm.module_clients(kc,'ad.test'))
        self.assertTrue(idpaccess.access_state(kc,'ad.test',kc.find_client('ad.test','vaultwarden1'))['enforced'])
        _,r,target,_=self.auth('denied')
        self.assertIsNone(target)

    def test_16_client_removed_and_registered_again(self):
        """Module removal deletes its client; a new module instance with the
        same ID registers a new client, without policy until set again."""
        kc=self.kc
        kc.delete('/ad.test/clients/'+kc.find_client('ad.test','vaultwarden1')['id'])
        redirect=[self.vw_url+'/identity/connect/oidc-signin']
        idprealm.ensure_client(kc,'ad.test','vaultwarden1',redirect_uris=redirect,access_token_lifespan=600)
        client=kc.find_client('ad.test','vaultwarden1')
        client['secret']=self.secret
        kc.put('/ad.test/clients/'+client['id'],client)
        self.assertFalse(idpaccess.access_state(kc,'ad.test',kc.find_client('ad.test','vaultwarden1'))['enforced'])
        state=idpaccess.set_policy(kc,'ad.test',kc.find_client('ad.test','vaultwarden1'),'services_vaultwarden')
        self.assertTrue(state['enforced'])
        _,r,target,_=self.auth('denied')
        self.assertIsNone(target)
        _,_,target,_=self.auth('allowed')
        self.assertIn('code=',target or '')


if __name__=='__main__':
    unittest.main(verbosity=2)
