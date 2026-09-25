#!/usr/bin/env python3
# Federated account marker v2: employeeType = provider alias, employeeNumber = provider ID
# argv: copy | clear-old | show
import sys, ldap3
DOMAINS = {
    'ldap.dom.test': ('ldap://127.0.0.1:20005', 'uid=keycloak-svc,ou=People,dc=ldap,dc=dom,dc=test',
                      'ldap-svc.pw', 'ou=People,dc=ldap,dc=dom,dc=test', 'uid', 'employeeNumber'),
    'ad.dom.test': ('ldap://127.0.0.1:20002', 'keycloak-svc@ad.dom.test',
                    'ad-svc.pw', 'CN=Users,DC=ad,DC=dom,DC=test', 'sAMAccountName', 'msDS-ExternalDirectoryObjectId'),
}
cmd = sys.argv[1]
for realm, (url, bind_dn, pwfile, base, uattr, old) in DOMAINS.items():
    conn = ldap3.Connection(ldap3.Server(url), bind_dn, open(pwfile).read().strip(), auto_bind=True)
    if cmd == 'copy':
        conn.search(base, f'(&({old}=*)(!(employeeType=*)))', attributes=[uattr, old])
        for e in conn.entries:
            oid = e[old].value
            ok = conn.modify(e.entry_dn, {'employeeNumber': [(ldap3.MODIFY_REPLACE, [oid])],
                                          'employeeType': [(ldap3.MODIFY_REPLACE, ['entra'])]})
            print(realm, e[uattr].value, 'entra', oid, 'OK' if ok else conn.result)
    elif cmd == 'clear-old' and old != 'employeeNumber':
        conn.search(base, f'({old}=*)', attributes=[uattr])
        for e in conn.entries:
            ok = conn.modify(e.entry_dn, {old: [(ldap3.MODIFY_DELETE, [])]})
            print(realm, e[uattr].value, 'cleared', old, 'OK' if ok else conn.result)
    elif cmd == 'show':
        extra = [old] if old != 'employeeNumber' else []
        conn.search(base, '(employeeType=*)', attributes=[uattr, 'employeeType', 'employeeNumber'] + extra)
        for e in conn.entries:
            print(realm, e[uattr].value, e.employeeType.value, e.employeeNumber.value,
                  *(f'{a}={e[a].value}' for a in extra), sep='\t')
