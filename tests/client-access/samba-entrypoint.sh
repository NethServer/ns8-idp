#!/bin/bash
set -Eeuo pipefail
# Disposable test domain; the random password is passed by the test runner.
rm -f /etc/samba/smb.conf
# Authentication-only fixture: rootless LXC cannot set SYSVOL Windows ACLs.
# Provision the real AD database but skip SYSVOL ACL setup; no SMB share is tested.
python3 - <<'PROVISION'
import os
import samba.provision
from samba.netcmd.main import samba_tool
samba.provision.setsysvolacl = lambda *args, **kwargs: None
result = samba_tool('domain', 'provision',
    '--realm=AD.TEST', '--domain=AD', '--server-role=dc',
    '--dns-backend=SAMBA_INTERNAL', '--adminpass=' + os.environ['AD_PASSWORD'])
if result: raise SystemExit(result)
PROVISION
samba-tool user create allowed "$AD_PASSWORD" --mail-address=allowed@example.test
samba-tool user create denied "$AD_PASSWORD" --mail-address=denied@example.test
samba-tool group add services_vaultwarden
samba-tool group addmembers services_vaultwarden allowed
# Test transport equivalent to the NS8 ldapproxy; internal test network only.
sed -i '/\[global\]/a\        ldap server require strong auth = no' /etc/samba/smb.conf
exec samba --foreground --no-process-group
