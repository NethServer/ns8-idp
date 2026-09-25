#!/usr/bin/env python3
# Write the Entra oid marker to LDAP; argv: realm uid oid
import sys, ldap3
DOMAINS = {
    'ldap.dom.test': ('ldap://127.0.0.1:20005', 'uid=keycloak-svc,ou=People,dc=ldap,dc=dom,dc=test',
                      'ldap-svc.pw', 'ou=People,dc=ldap,dc=dom,dc=test', 'uid', 'employeeNumber'),
    'ad.dom.test': ('ldap://127.0.0.1:20002', 'keycloak-svc@ad.dom.test',
                    'ad-svc.pw', 'CN=Users,DC=ad,DC=dom,DC=test', 'sAMAccountName', 'msDS-ExternalDirectoryObjectId'),
}
realm, uid, oid = sys.argv[1:4]
url, bind_dn, pwfile, base, uattr, mattr = DOMAINS[realm]
conn = ldap3.Connection(ldap3.Server(url), bind_dn, open(pwfile).read().strip(), auto_bind=True)
conn.search(base, f'({uattr}={uid})', attributes=[mattr])
dn = conn.entries[0].entry_dn
ok = conn.modify(dn, {mattr: [(ldap3.MODIFY_REPLACE, [oid])]})
print(realm, dn, mattr, oid, 'OK' if ok else conn.result, file=sys.stderr)
