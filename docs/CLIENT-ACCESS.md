# Client access draft: design and validation

The optional policy is implemented by a required action and a token mapper
in the existing `ns8-authenticators` JAR. No browser flow is copied or
rewritten. A per-client browser-flow copy was rejected because realm changes
would not propagate and broker authentication bypasses that flow. A wrapper
that references the realm flow was rejected because Keycloak recursively
deletes referenced subflows. Realm-wide LDAP NO_CACHE was rejected because
it would affect unrelated clients.

This ports the reviewed Vaultwarden prototype to the regular ns8-idp layout.
Overlay images, separate grant scripts and first-prototype migration are
excluded. The general realm-lock fix is submitted separately in
[NethServer/ns8-idp#15](https://github.com/NethServer/ns8-idp/pull/15).
Until that lands, this draft also needs those same two critical sections;
merge #15 first. Fixed token claims in #4 remain an independent feature and
will need a registration/mapper compatibility check if combined.

## Reproduce

Use Python 3 with requests/jsonschema, Podman and a Linux host capable of
running its containers. Tests use ephemeral test networks, random credentials
and loopback ports; they do not access a production installation.

```sh
python3 -m unittest discover -s tests -p test_client_access.py -v
python3 -m unittest discover -s tests -p test_realm_lock.py -v
podman build -f tests/client-access/Samba.Containerfile -t localhost/ns8-vaultwarden-test-samba tests/client-access
podman build -f tests/client-access/Containerfile -t localhost/ns8-idp-client-access-test .
python3 tests/client-access/run.py
python3 tests/client-access/check_failures.py
```

`run.py` covers allowed/denied and unrestricted clients, cached membership
revocation/regrant, SSO-cookie reuse, code/refresh denial, LDAP failure,
restart, writable LDAP and a broker realm, policy removal/reapplication,
reconciliation and client deletion/re-registration, plus real token lifespan.
`check_failures.py` covers preflight versus mid-update failures, grant-flag
diagnostics, token default/reset, local-only accounts and direct/nested/deleted
groups. The broker is a second Keycloak realm, not a live Entra ID tenant.

The required action relies on Keycloak's trigger evaluation at completed
authentication, and the LDAP failure check uses
`StorageUnavailableUserModelDelegate` (not a stable public API). Revalidate
these paths on Keycloak updates. The current compile target is inherited
from upstream (26.7.5), while the runtime image is upstream's 26.7.4.

## Remaining before general release

- Decide whether client authorization belongs here or in applications, and
  review the LDAP workload caused by targeted eviction.
- Add a policy field/error translations to the realm/client UI.
- Validate upgrade, backup/restore, complete existing NS8 realm/federation
  suites, alternative LDAP schemas, future MFA and grant compatibility.
- Run the upstream NS8/QEMU suite on the integrated module; the older
  Vaultwarden QEMU run covers the overlay prototype, not this new patch.

No production deployment, live Entra, physical mobile app or complete
feature/upgrade compatibility is claimed by this draft.
