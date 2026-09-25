# SSO prototype files

Scripts and configuration of the Keycloak SSO prototype described in
[INSTRUCTIONS.md](../INSTRUCTIONS.md) (NethServer/dev#8080). They ran as
`root` on a single test node, `rl1.dp.nethserver.net`, and are kept as a
record of the Keycloak admin API calls and application settings that this
module has to automate. They are not part of the module image.

## Test environment

| Module | Role |
|---|---|
| `scratchpad1` | hosts the Keycloak container (`imageroot/systemd/user/keycloak.service`) |
| `openldap1` | user domain `ldap.dom.test`, realm `ldap.dom.test` |
| `samba1` | user domain `ad.dom.test`, realm `ad.dom.test` |
| `nextcloud1`, `nextcloud2` | Nextcloud bound to `ldap.dom.test` and `ad.dom.test` |
| `mail4`, `roundcubemail2` | Mail and Roundcube bound to `ad.dom.test` |

Host names (`*.dp.nethserver.net`), module names and realm names are
hard-coded. Client secrets are read from files in `/root`
(`kc-nextcloud-secret`, `kc-dovecot-secret`, `entra-secret`, …), and the
Keycloak service accounts' LDAP passwords from `ldap-svc.pw` and
`ad-svc.pw` in the `scratchpad1` state directory.

Passwords and test user IDs are replaced by environment variables:

| Variable | Value |
|---|---|
| `KC_ADMIN_PASSWORD` | Keycloak `master` realm `admin` password |
| `TEST_PASSWORD` | password of the native test users `kctest1`, `kctest2` |
| `FED_PASSWORD_AD` | password set by the administrator for the federated `e.user1` in `ad.dom.test` |
| `FED_PASSWORD_LDAP` | same, in `ldap.dom.test` |
| `E_USER1_OID` | Entra ID `oid` of `e.user1` |
| `DPRINCIPI_OID` | Entra ID `oid` of the user linked to the provisioned `dprincipi` |

Scripts that run `podman exec -i` through `runagent` read standard input,
so copy them to the node and run them as files, not with `ssh 'bash -s'`.

## Layout

- `keycloak/` – realm setup, in the order of the prototype:
  `kc-ad-realm.sh` (AD realm and federation), `kc-ldap-writable.sh`
  (writable federation, scenario 2), `kc-ad-scenario2.sh`,
  `kc-ad-names.sh`, `kc-entra-enable.sh`, `kc-email-fix.sh`,
  `kc-upper-mapper.sh` (AD uppercase `ldap_uuid` claim), `kc-steps.sh` and
  `kc-steps-order.sh` (deny password logins to federated users),
  `kc-marker-mapper.sh` and `kc-marker-backfill.py` (first marker version,
  `entra_oid`), `kc-marker-v2.sh` and `kc-marker-v2.py` (current marker,
  `ns8_idp` and `ns8_idp_id`), `kc-link-flow.sh` (first broker login flow
  with the link step), `kc-mode.sh` (mixed and federated only modes).
  `kc-inspect-user.sh`, `kc-marker-inspect.sh` and `kc-check-logins.sh`
  only read.
- `apps/` – application side: `nc2-oidc.sh` (Nextcloud `user_oidc` and
  its Keycloak client), `mail-oauth-ad.sh` (Dovecot and Roundcube), and
  the configuration files `dovecot/passdb.conf`,
  `dovecot/oauth2.conf.ext`, `roundcube/config.oauth.php`, with the
  client secrets replaced by `CLIENT_SECRET`.
- `tests/` – login simulations with `curl` (`sso-login.sh`,
  `rc-login.sh`, `imap-test.sh`, …) and the checks of each prototype
  step (`test-deny.sh`, `test-mode.sh`, `kc-idp-disabled.sh`, …).
- `kc-posix-fixup/` – the OpenLDAP fix-up job of scenario 2, option A:
  script, user service and timer of the `scratchpad1` module.
- `realms/` – final state of both realms, from the Keycloak partial
  export (`POST /admin/realms/{realm}/partial-export` with clients, without
  users, groups and roles). Keycloak masks the secrets as `**********`,
  and the Entra ID tenant and client IDs are replaced by `TENANT_ID` and
  `CLIENT_ID`. The prototype node no longer exists: this is the
  reference for flows, mappers, clients and user profile.
- `agent/` – token exchange and OAuth device authorization tests with a
  `hermes-agent` client: an agent obtains a Dovecot-only token for a
  user. Not described in INSTRUCTIONS.md yet.

The custom Keycloak providers are in
[`../keycloak-providers`](../keycloak-providers):

- `ns8-authenticators` – the link by marker step, a Maven project. The
  prototype built it with
  `podman run --rm -v "$PWD":/src:Z -w /src docker.io/library/maven:3.9-eclipse-temurin-21 mvn -q -B package`.
- `ns8-mappers` – the AD uppercase `ldap_uuid` JavaScript mapper, which
  requires Keycloak `--features=scripts`. Package it with
  `zip -r ns8-mappers.jar META-INF ldap-id-upper.js`.

Both JAR files go in the Keycloak providers directory, mounted from
`kc-providers` in the module state.
