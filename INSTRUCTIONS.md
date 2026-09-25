# Single sign-on

Design notes and prototype results for this module, copied from
`docs/sso.md` of NethServer/ns8-core. The prototype files are in
this repository: `imageroot/systemd/user/keycloak.service` (the
Keycloak unit of the prototype), `keycloak-providers/` (the
custom Keycloak providers) and `prototype/` (setup scripts, application
configuration and tests, see its README).

This page collects the design notes for Single Sign-On (SSO) in NS8,
based on [Keycloak](https://www.keycloak.org/) as OpenID Connect (OIDC)
identity provider. It is a work in progress: the implementation is not
available yet. See NethServer/dev#8080 for the broad picture.

## Scenarios

**Scenario 1 – SSO over an existing user domain.** Users and groups stay
in an NS8 user domain (for example an OpenLDAP internal domain). Keycloak
reads the LDAP database with the read-only credentials published by the
core (see [User domains](https://nethserver.github.io/ns8-core/core/user_domains)) and handles
only authentication: login form, sessions and tokens. Applications still
read accounts and groups from LDAP, and existing account mappings must be
preserved: an application user account must not change because the login
mechanism changed.

**Scenario 2 – Federation with a cloud identity provider.** Keycloak is
federated with Microsoft Entra ID or Google Workspace and has read-write
access to an internal LDAP user domain. Users and groups can optionally be
provisioned in advance through the cloud provider APIs and loaded with the
`import-users` action of the account provider. When a user logs in for
the first time with a federated identity and has no LDAP account yet, the
account is created on the fly. In any case the LDAP database contains the
user and group entries, so applications work as in scenario 1: LDAP for
accounts, OIDC for logins.

Both scenarios have been validated with a prototype, on an OpenLDAP
internal domain and on a Samba Active Directory internal domain. The
prototype is described in the appendixes: [scenario
1](#appendix-scenario-1-prototype), [scenario
2](#appendix-scenario-2-prototype) and [Active
Directory](#appendix-active-directory-prototype). Scenario 2 has been
validated with Entra ID only.

## Architecture

The user domain remains the account database. A separate Keycloak
application provides authentication on top of it:

```text
  browser: login form
        |
        v
  +-------------------------+   LDAP bind (password check),   +--------------------+
  | Keycloak application    |   users and groups search       | User domain (LDAP) |
  | - realm per user domain | ------------------------------> | e.g. OpenLDAP      |
  | - LDAP federation       |                                 | users, groups,     |
  | - OIDC clients          |                                 | entryUUID          |
  +-------------------------+                                 +--------------------+
     ^ OIDC code flow ^ token introspection                           ^
     |                |                                               |
  +-----------+  +------------------------+                           |
  | Nextcloud |  | Mail (Dovecot, Postfix)|  <-- XOAUTH2/OAUTHBEARER   |
  | Roundcube |  +------------------------+      from Roundcube and    |
  +-----------+                                  mail clients          |
        |                                                             |
        +------- all applications: accounts and groups from LDAP -----+
```

- The Keycloak application is an account consumer of the user domain,
  like any other application. It discovers the LDAP service and its
  credentials with the core service discovery APIs.
- A Keycloak realm corresponds to a user domain. The realm has an LDAP
  federation provider: user passwords are checked with an LDAP bind, so
  the account provider password policy (lockout, expiration) still
  applies.
- Each application is an OIDC client of the realm. It keeps reading
  users and groups from LDAP, and maps the OIDC identity to the LDAP
  account through a token claim with a stable identifier.
- Password logins keep working alongside SSO where applications support
  them: WebDAV and app passwords in Nextcloud, IMAP/SMTP password
  authentication, the Roundcube login form.

### Identity mapping

The key point for scenario 1 is that the claim used by each application
matches the identifier the application already uses for LDAP accounts:

| Application | Existing LDAP account key | Token claim | Keycloak source |
|---|---|---|---|
| Nextcloud (`user_ldap`), OpenLDAP | `entryUUID` (default internal user name) | `ldap_uuid` | user attribute `LDAP_ID` |
| Nextcloud (`user_ldap`), AD | `objectGUID`, as uppercase string | `ldap_uuid` | user attribute `LDAP_ID`, converted to uppercase |
| Dovecot | `uid` or `sAMAccountName` (login is normalized with `auth_username_format = %Ln`) | `preferred_username` | LDAP user name attribute |
| Roundcube | `username@maildomain` (stored user name) | `preferred_username` | LDAP user name attribute, then Roundcube appends `username_domain` |

The Keycloak `sub` claim is an internal Keycloak identifier: it must not
be used as account key by applications.

For AD domains, Keycloak stores `objectGUID` in `LDAP_ID` as a lowercase
string (`03dbc254-159a-…`), while Nextcloud user IDs are uppercase
(`03DBC254-159A-…`), and the Nextcloud database compares them as
case-sensitive strings (`utf8mb4_bin` collation). Keycloak has no
built-in claim transformation: the `ldap_uuid` claim needs a custom
protocol mapper.

### Tokens for mail services

Mail clients (and Roundcube, acting as a mail client) authenticate to
IMAP and SMTP with the `XOAUTH2` or `OAUTHBEARER` SASL mechanisms, sending
an access token instead of a password. Dovecot validates the token with
the Keycloak introspection endpoint. Postfix delegates SASL to Dovecot, so
SMTP submission works the same way.

Keycloak 26 answers `active: false` to an introspection request if the
introspecting client (`dovecot`) is not listed in the token audience. Any
client issuing tokens for mail services needs an audience mapper that adds
`dovecot` to the `aud` claim. As a benefit, tokens issued for other
applications (for example Nextcloud) are rejected by Dovecot.

## Scenario 1 feasibility

The prototype confirms that scenario 1 is feasible with the proposed
architecture, an NS8 user domain plus a separate Keycloak application,
for both OpenLDAP and Active Directory domains:

- no change to LDAP data or to the account provider modules;
- existing Nextcloud accounts, files and shares are preserved, because
  the Nextcloud user ID is still the `entryUUID` (the `objectGUID` for
  AD);
- existing Roundcube user records and settings are preserved;
- users created in the user domain can log in on the first try;
- a user locked in NS8 cannot log in through Keycloak;
- password logins keep working in parallel.

### Required changes

The following changes emerged from the prototype. They are not
implemented yet.

**Keycloak application (new module)**

- Persistent database. The prototype uses the embedded `dev-file` H2
  database, which Keycloak does not recommend for production: a separate
  PostgreSQL container is the likely alternative.
- Bind a user domain and create one realm for it, with an LDAP
  federation provider configured from service discovery (preferably
  through ldapproxy) and a group mapper.
- Exclude hidden users and groups from the LDAP federation, with the
  `Ldapproxy` filter clause helpers.
- Expose an API for applications to register OIDC clients: redirect URIs,
  protocol mappers, audience, client secret retrieval. See the
  [Keycloak API calls](#keycloak-api-calls) in the appendix.
- Publish the realm issuer URL with service discovery, so applications
  can find the identity provider of their user domain.
- Traefik route and TLS certificate for the Keycloak host name.
- For AD domains, provide a protocol mapper that converts `LDAP_ID` to
  uppercase. The prototype uses a JavaScript mapper, which requires the
  `scripts` preview feature: a small Java mapper is preferable for
  production.

**Nextcloud (`ns8-nextcloud`)**

- Install and configure the `user_oidc` app, with the `ldap_uuid` claim as
  user ID and `auto_provision` disabled.
- Add `(entryUUID=%uid)` to the LDAP login filter written by `setup-ldap`.
  `user_oidc` resolves users that are not yet known to `user_ldap` by
  running the LDAP login filter with the claim value. Without it, a user
  that Nextcloud has not mapped yet gets an HTTP 400 error at the first
  login. The change must be implemented in the module: the
  `nextcloud-app` unit runs `setup-ldap` at every start, overwriting any
  manual change of the LDAP configuration.
- For AD domains, add `(objectGUID=%uid)` to the login filter instead.
  `objectGUID` is binary, but Samba also accepts the GUID string, in
  both upper and lower case, as filter value.
- Unrelated bug found during the tests: `configure-module` without the
  `internal_smarthost` attribute leaves Nextcloud in a restart loop
  (`KeyError` in `setup-smtp`). The UI always sends the attribute.

**Mail (`ns8-mail`)**

- Add the `oauth2` passdb for the `xoauth2` and `oauthbearer`
  mechanisms, with introspection client credentials and
  `username_attribute = preferred_username`.
- Add `mechanisms = plain login` to the LDAP passdbs. Otherwise every
  token login is also attempted as an LDAP bind with the token as
  password. This is harmless while the password policy has no
  `pwdMaxFailure`, but those failures would count toward a lockout
  threshold. Putting the `oauth2` passdb first is not enough alone: a
  rejected token would still fall through to LDAP, unless the passdb has
  `result_failure = return-fail` and `result_internalfail = return`.
- Keep `debug` disabled in the `oauth2` passdb configuration: it logs the
  introspection URL, which contains the client secret, and full tokens.

**Roundcube (`ns8-roundcubemail`)**

- Write the OAuth configuration, using OIDC discovery.
- Generate `https://` URLs behind Traefik, with `use_https` or
  `proxy_whitelist`. Otherwise the OAuth `redirect_uri` starts with
  `http://` and Keycloak rejects it.

### Open issues

- **Single logout.** Logging out of an application ends the Keycloak
  session, but other applications are not notified: back-channel logout
  URLs are not configured. `user_oidc` provides a back-channel logout
  endpoint; Roundcube support is to be checked.
- **Account lock and existing sessions.** Locking a user in NS8 prevents
  new Keycloak logins, but existing Keycloak sessions and refresh tokens
  are probably still valid until they expire. To be tested.
- **Session idle time.** Keycloak refresh tokens last 30 minutes of
  inactivity by default: longer idle sessions probably need a new login.
- **Availability.** Keycloak becomes a dependency for SSO logins.
  Password logins remain available as a fallback where applications
  support them.
- **Desktop and mobile mail clients.** Support for a custom OAuth
  identity provider varies among mail clients. Not tested.

## Scenario 2 feasibility

The prototype confirms that scenario 2 is feasible with Entra ID, on
both OpenLDAP and Active Directory internal domains. A user that did not
exist in NS8 logged in with Entra ID: Keycloak created the account in the
user domain at the first login, and the user logged in to Nextcloud and
Roundcube with it, exactly like the users of scenario 1.

### How accounts are created

The Keycloak realm of the user domain has an identity provider for
Entra ID, and its LDAP federation provider is writable, with the
*Sync registrations* option enabled. At the first login with an Entra
ID identity, the *first broker login* flow of Keycloak creates the user,
and the LDAP federation provider writes it to the LDAP database.

- The Keycloak application is granted the `domadm` role on the account
  provider (`openldap@any:domadm`, see [Import/Export users
  APIs](https://nethserver.github.io/ns8-core/core/user_domains#importexport-users-apis)).
  With it, the application creates its own LDAP service account as a
  member of `domain admins`, the group with write access to the OpenLDAP
  database. Keycloak binds with this account.
- NS8 lists only users with both the `posixAccount` and `inetOrgPerson`
  object classes, so `uidNumber`, `gidNumber` and `homeDirectory` are
  mandatory. Keycloak can write only static values for them: it cannot
  allocate a unique `uidNumber` when it creates an LDAP entry. The same
  applies to `gidNumber` of groups.
- Options for creating accounts at the first login: (A) Keycloak writes
  the entry with placeholder values, and an NS8 job replaces them; (B) a
  custom Keycloak authenticator in the first broker login flow creates
  the account with the NS8 logic; (C) accounts are created only by a
  provisioning job. The prototype implements option A: a job running
  every minute assigns the next free `uidNumber`, the home directory and
  the `displayName` attribute, like the OpenLDAP `add-user` command does.
  Until the job runs, the new account has placeholder values: this did
  not affect the tested applications.

On Active Directory domains account creation is simpler:

- The Keycloak application is granted `samba@any:domadm`, and its
  service account is a member of `Domain Admins`.
- NS8 lists AD users with `(objectClass=user)(objectCategory=person)`: no
  numeric ID is required, so no placeholder and no fix-up job are
  needed. Keycloak uses its Active Directory mode for the LDAP federation
  provider.
- NS8 AD accounts have `cn` equal to the user name and the full name in
  `displayName`, with no `givenName` and `sn`. The prototype configures
  the Keycloak mappers accordingly: the *full name* mapper reads and
  writes `displayName`, and the user name is also written to `cn`.
- Keycloak does not set `userPrincipalName`, unlike the NS8 `add-user`
  action. The tested applications also accept `sAMAccountName`.

### Identity attributes

| Keycloak user | Entra ID claim | Notes |
|---|---|---|
| user name (OpenLDAP `uid`, AD `sAMAccountName` and `cn`) | `preferred_username`, local part | the UPN `john@contoso.example` becomes `john` |
| first and last name (OpenLDAP `cn`, `sn`; AD `displayName`) | `given_name`, `family_name` | mandatory for `inetOrgPerson` |
| email (LDAP `mail`) | `email` | present only if the Entra ID user has the Email property |
| `entra_oid` attribute | `oid` | immutable user ID in the tenant |
| `entra_groups` attribute | `groups` | security group IDs, not names |
| federated identity link | `sub` | pairwise: it differs for each Entra ID application |

- LDAP user names must match `^[a-zA-Z][-._a-zA-Z0-9]*$`, so the UPN
  must be converted. Keeping its local part may produce collisions, for
  example between users of different domains of the same tenant.
- If the user name already exists in Keycloak or LDAP, the default first
  broker login flow asks the user to confirm the account link by logging
  in with the existing account password (not tested). This is safe.
  Automatic linking by email address is unsafe with Entra ID, because
  the `email` claim is not verified; the immutable `oid` is preferable
  for linking identities provisioned in advance.
- If the Entra ID user has no Email property, Keycloak shows the *Update
  account information* form and the user can type any address. The
  address is written to LDAP `mail`, without verification.

### Passwords of federated accounts

Federated accounts are created without a password, on both OpenLDAP and
Active Directory, so the two account providers behave the same way:

- By default the account has no usable password: services that check
  passwords with an LDAP bind (Samba file shares, IMAP and SMTP clients
  without OAuth, WebDAV) do not work for it.
- An administrator can set a password later, with the usual NS8 actions
  (`alter-user`) or the cluster-admin UI, for users that need those
  services. Verified on both account providers: after that, LDAP binds
  and Samba shares work with the new password.
- Keycloak refuses password logins to federated users, including those
  with a password set by the administrator. Otherwise such users could
  log in to Keycloak, and so to every SSO application, without Entra ID,
  bypassing its multi-factor authentication and conditional access. The
  prototype implements this with a conditional step in the browser and
  direct grant authentication flows: after the password check, access
  is denied to users with the `entra_oid` attribute. Logins through
  Entra ID do not run the password step, so they are not affected.
  Password-based services outside Keycloak remain outside the Entra ID
  policies, by design.

On Active Directory, the *MSAD account controls* mapper of Keycloak
requires a password change at login when the entry has `pwdLastSet`
equal to 0 or missing, which is the Samba default for a new account
without password. Keycloak then shows the *Update password* form at the
first login, and writes the chosen password to AD. To avoid it, the
prototype writes `pwdLastSet: -1` when Keycloak creates the account:
Samba stores the current time instead, and the password change is not
required. The account is created with `userAccountControl: 544`, normal
account with the *password not required* flag: empty passwords are
refused anyway, over LDAP, SMB and Kerberos. When an administrator sets a
password, Samba clears the flag (`userAccountControl: 512`). Disabling
the *Update password* required action of the realm would also avoid the
form, but it would remove the password change of native AD users with
an expired password.

### Required changes

**Keycloak application**

- Grant `openldap@any:domadm` and `samba@any:domadm`, and create the LDAP
  service account. Hide it from users lists with the NS8 hidden users
  feature, and exclude it from the Keycloak user federation.
- Enable the password modify extended operation (`LDAPv3 password
  modify`) in the LDAP federation provider. Otherwise Keycloak writes
  the `userPassword` attribute with the clear-text value, and OpenLDAP
  stores it as is (`olcPPolicyHashCleartext` is `FALSE`). A writable
  federation provider also lets Keycloak change the password of LDAP
  users.
- Implement the account creation option (A or B above) for OpenLDAP. For
  AD, write `pwdLastSet: -1` at account creation and configure the name
  mappers as described above.
- Deny password logins to federated users in the browser and direct
  grant flows. Keycloak 26 adds new executions at the top of a flow,
  where the user is not identified yet: the step must be moved after the
  password check.
- Configure the identity provider, the claim mappers and the user profile
  attributes (`entra_oid`, `entra_groups`). Keycloak 26 drops attributes
  that are not declared in the user profile.
- Keep the email attribute editable by users in the user profile. If it
  is editable by admins only, the value received from Entra ID is
  discarded at the first login. To prevent users from changing their
  LDAP attributes in the Keycloak account console, other means are
  needed, for example removing the `manage-account` role.

### Open issues

- **Groups.** Entra ID group memberships are not written to LDAP yet.
  Group IDs are available at login; group names require Microsoft Graph
  API calls, or on-premises synchronized groups.
- **Users unknown until the first login.** If accounts are created only
  at the first login, a federated user does not exist in the user domain
  before that, so no application knows it. For example Dovecot does not
  find the user (`doveadm user` answers *user doesn't exist*), and
  Postfix rejects messages for it with a permanent error (`550 5.1.1
  User unknown`): the sender receives a bounce, and the message is not
  delivered later. Likewise, the user cannot receive Nextcloud shares
  and is not a member of any group. Provisioning in advance is required
  if applications must know users before their first login.
- **Provisioning in advance.** Reading users and groups with the
  Microsoft Graph API and loading them with `import-users` is not tested.
  Accounts provisioned in advance must be linked to the Entra ID
  identity at the first login, preferably by `oid`.
- **Deprovisioning.** A user disabled or deleted in Entra ID keeps the
  LDAP account, and can use existing sessions until they expire. A
  provisioning job should lock the LDAP account.
- **Forms at the first login.** Any form shown at the first federated
  login (*Update account information*, *Update password*) makes the
  login round trip longer. Once, after about one minute spent on the
  *Update password* form, Nextcloud refused the login with "Received
  state has expired"; a second attempt worked. Not investigated.
- **Google Workspace.** Not tested. See [Federated account
  marker](#federated-account-marker) for its user ID.
- **Entra ID plans.** With the free plan, applications can be assigned
  to single users only, not to groups.

## Single configuration

This section describes an alternative to the two scenarios. Its main
parts have been prototyped on the scenario 2 setup: see [Appendix: single
configuration prototype](#appendix-single-configuration-prototype).

Instead of choosing between scenario 1 and scenario 2, the Keycloak
application always uses the same configuration: a writable LDAP
federation on an internal user domain, where native and federated
accounts coexist. A cloud identity provider like Entra ID is an optional
source of accounts: it acts like an external administrator that adds
federated accounts at their first login. Federated accounts can still be
provisioned in advance, in a single run of `import-users`.
Password-based services, for example Samba file shares, keep working for
every account with an LDAP password.

When an identity provider is configured, a flag of the realm selects the
login mode:

- **Federated only.** The realm serves only accounts of the identity
  provider: login forms redirect straight to the Entra ID login.
- **Mixed.** The Keycloak login form accepts the password of native
  accounts and shows a "Microsoft Entra ID" button for federated
  accounts.

The scenario 2 prototype already works as the mixed mode: native LDAP
users log in with their password next to federated users, and the
switch of an existing realm to writable mode does not affect them. The
following sections list what is missing.

### Federated account marker

Federated accounts are recognized by the `entra_oid` attribute, which
exists only in the Keycloak database. As a consequence:

- NS8 cannot tell native and federated accounts apart, for example in
  the users list or in `import-users`;
- if the Keycloak database is lost, the password login denial and the
  links to the Entra ID identities are lost too;
- accounts provisioned in advance cannot carry the marker.

The marker must be stored in LDAP, with `user-attribute-ldap-mapper`
components in Keycloak. It must also tell which identity provider the
account belongs to: an Entra ID `oid` and a Google Workspace user ID are
unrelated values, and a realm may have both providers, or move from one
to the other. The marker has two parts:

| User attribute | LDAP attribute | Value |
|---|---|---|
| `ns8_idp` | `employeeType` | identity provider alias, for example `entra` or `google` |
| `ns8_idp_id` | `employeeNumber` | immutable user ID at the provider: Entra ID `oid`, Google `sub` |

- Both attributes exist in the `inetOrgPerson` class of OpenLDAP and in
  the `user` class of AD, with any schema version, so both account
  providers have the same mapper configuration. They are not used by the
  NS8 modules.
- The OpenLDAP ACLs give write access on every attribute to `domain
  admins`, so the Keycloak service account can set them.
- `ns8_idp` is written by a *Hardcoded Attribute* mapper of each identity
  provider, `ns8_idp_id` by a claim mapper: `oid` for Entra ID, `sub`
  for Google.
- AD also has `msDS-ExternalDirectoryObjectId`, the attribute used by
  Entra Connect (`User_<objectId>`). It is left alone: it is specific to
  Entra ID, and it is missing from older schemas.

Google Workspace (not tested) fits the same model: its `sub` claim is
permanent, is the same for all the applications of the tenant, and
equals the user `id` of the Admin SDK Directory API. Accounts can then
be provisioned in advance from the Directory API, as from Microsoft
Graph.

The mappers always read the values from LDAP, so the password login
denial no longer depends on the Keycloak database: it applies to every
account with `ns8_idp`. Keycloak sees a value changed outside Keycloak,
for example by `import-users`, only when the user leaves its cache: the
LDAP federation needs a cache policy with a short lifespan, or the
writer must clear the user cache.

### Linking accounts provisioned in advance

The Keycloak federated identity link is based on the Entra ID `sub`
claim, which is pairwise: it cannot be read with Microsoft Graph, so
links cannot be created in advance with the Keycloak admin API. The
default first broker login flow does not help either:

- it asks to confirm the link with the existing account password, and
  accounts provisioned in advance have none;
- automatic linking by user name or email address is unsafe, as
  described in [Identity attributes](#identity-attributes).

The first broker login flow needs a step that finds the existing user by
marker, with the same `ns8_idp` and `ns8_idp_id` as the identity being
linked, and links it without a password check. Keycloak has no built-in
authenticator for it: the prototype implements it as a small Java
provider, which can be packaged with the other custom providers, like the
AD uppercase mapper and the account creation of option B.

Linking by marker also restores the links if the Keycloak database is
lost, or if the Entra ID application changes and the pairwise `sub`
changes with it. Both cases worked in the prototype: the link removed
from the Keycloak database was restored at the next login, without any
form.

Linking an account provisioned in advance runs the profile checks of the
realm. The prototype account had no `mail`, which the realm user profile
requires, so Keycloak showed the *Update account information* form after
the link: the address typed by the user was written to LDAP without
verification, and the form also replaced the provisioned `displayName`
with the first and last name. The identity provider mappers do not help
at this point, because they update an existing account only at the
following logins. Accounts provisioned in advance should include `mail`.

For provisioning in advance, `import-users` of both account providers
must also:

- accept the marker attribute; today `add-user` and `import-users` do
  not handle any of the attributes above;
- create accounts without a password: today they set a random one if
  it is missing, so accounts provisioned in advance would differ from
  the accounts created by Keycloak. Verified with the Samba `add-user`
  action: without `password` the account gets `userAccountControl: 512`
  and a current `pwdLastSet`;
- receive records from a Microsoft Graph or Google Directory API
  exporter, not available yet.

### Conversion of native accounts

In mixed mode, an Entra ID user name can match an existing native
account. If the user confirms the link with the native password, the
mappers set the marker, and from then on Keycloak denies password
logins to that account. The policy is to be defined: either the
conversion of a native account to a federated one is allowed, or the
first broker login flow refuses the link.

### Federated only mode

Tested on the AD realm, with Nextcloud and Roundcube:

- In Keycloak, the *Identity Provider Redirector* step of the browser
  flow has `entra` as default provider, the password forms subflow is
  disabled, and the realm direct grant flow denies every login. Opening
  the Keycloak login page goes straight to the Entra ID login.
- Applications must know the mode, for example from service discovery,
  next to the realm issuer URL. Otherwise their login pages still show a
  password form and a Keycloak button. Nextcloud: `occ config:app:set
  user_oidc allow_multiple_user_backends --value=0`. Roundcube:
  `oauth_login_redirect = true`. With both settings, the application
  login pages redirect to Entra ID, and a login in Nextcloud also opens
  Roundcube without asking anything.
- Password logins outside Keycloak keep working: Nextcloud WebDAV and
  OCS API, IMAP.
- No native account, for example an NS8 administrator, can log in to
  the SSO applications through Keycloak. The Keycloak `master` realm is
  still available to Keycloak administrators.

### Mode changes

With a single configuration, changing the mode is an ordinary
administrative operation, and each change needs a defined behavior:

- **From mixed to federated only.** Native accounts without an Entra ID
  identity lose SSO logins. The UI should at least show a warning with
  the number of affected accounts: with the marker in LDAP, they are the
  enabled accounts without it, service accounts excluded. In the
  prototype AD domain they were 8, including `Administrator`.
- **Identity provider removed.** Federated accounts without a password
  cannot log in anymore: either an administrator sets their passwords,
  or they are locked. In addition, the password login denial must be
  turned off together with the provider: it depends only on the marker,
  so with the provider disabled, a federated account with a password set
  by the administrator could not log in to any SSO application.
- **Entra ID application or tenant changed.** The `sub` claim changes and
  all links break. Linking by `oid` restores them at the next login.

### Permanent write access

The writable federation is always configured, even if no identity
provider is ever added. Consequences:

- Every installation grants the Keycloak application `domadm`, and its
  service account is a member of `domain admins` or `Domain Admins`. On
  Samba, `Domain Admins` has full control of the domain. A narrower
  delegation is to be evaluated: OpenLDAP ACLs, or AD permissions limited
  to user creation and password reset in the users container.
- Keycloak self-registration must stay disabled, and users created from
  the Keycloak admin console skip the NS8 `add-user` logic.
- The account console can change LDAP attributes, unless the
  `manage-account` role is removed.
- Keycloak can change the passwords of native users, for example with
  the *Update password* required action when a password expires. It
  binds as the service account, so the change is an administrative
  reset. Whether the OpenLDAP password policy (quality, history,
  `pwdMustChange`) and the Samba password complexity still apply is to
  be tested.

### Account creation

With the writable federation always configured, account creation at the
first login is always active. Option B of [How accounts are
created](#how-accounts-are-created), a custom authenticator that creates
the account with the NS8 logic, becomes more attractive than the fix-up
job of option A: on AD it would also set `userPrincipalName`, like the
NS8 `add-user` action.

The open issues of scenario 2 (groups, deprovisioning, Google
Workspace, forms at the first login) are unchanged. Deprovisioning
matters more in mixed mode: a federated user disabled in Entra ID keeps
the LDAP password set by an administrator, if any, with no relation to
the Entra ID account state.

## Appendix: scenario 1 prototype

The prototype ran on a single NS8 node with these modules:

| Module | Role |
|---|---|
| `openldap1` | internal user domain `ldap.dom.test` |
| `scratchpad1` | empty module hosting the Keycloak 26.7 container |
| `nextcloud1` | Nextcloud 33, `ns8-nextcloud` 1.7.5 |
| `mail3` | Dovecot 2.3.21, Postfix |
| `roundcubemail1` | Roundcube 1.7.4, `ns8-roundcubemail` 2.1.10 |

In the following snippets host names are replaced by `*.example.org`, and
secrets by placeholders.

### Keycloak container

Keycloak runs in production mode behind Traefik, on the host network,
with a persistent volume. The unit is a systemd user unit of the module:

```ini
[Unit]
Description=Keycloak prototype

[Service]
Environment=PODMAN_SYSTEMD_UNIT=%n
ExecStartPre=/bin/rm -f %t/keycloak.pid %t/keycloak.ctr-id
ExecStart=/usr/bin/podman run --conmon-pidfile %t/keycloak.pid \
    --cidfile %t/keycloak.ctr-id --cgroups=no-conmon --replace -d \
    --name keycloak --network=host \
    --env-file %h/.config/state/keycloak.env \
    --volume keycloak-data:/opt/keycloak/data \
    quay.io/keycloak/keycloak:26.7 start \
    --http-enabled=true --http-port=18080 \
    --proxy-headers=xforwarded --proxy-trusted-addresses=127.0.0.1 \
    --hostname=https://keycloak.example.org
ExecStop=/usr/bin/podman stop --ignore --cidfile %t/keycloak.ctr-id -t 30
ExecStopPost=/usr/bin/podman rm --ignore -f --cidfile %t/keycloak.ctr-id
PIDFile=%t/keycloak.pid
Type=forking
Restart=always
TimeoutStartSec=120

[Install]
WantedBy=default.target
```

The environment file contains `KC_BOOTSTRAP_ADMIN_USERNAME`,
`KC_BOOTSTRAP_ADMIN_PASSWORD` and `KC_DB=dev-file`. In a user unit, `%h`
is the module home directory, while `%S` points to `~/.local/state`,
not to the module state directory.

The Traefik route forwards `keycloak.example.org` to
`http://127.0.0.1:18080`, with a Let's Encrypt certificate.

### Keycloak API calls

The prototype configured Keycloak with `kcadm.sh`, running inside the
container:

```sh
podman exec -i keycloak /opt/keycloak/bin/kcadm.sh ...
```

`podman exec` needs `-i` to pass a JSON document on standard input
(`-f -`). The calls below list the functions that the Keycloak
application needs to implement, with the matching Admin REST API
endpoints under `/admin/realms`.

**1. Log in.** `kcadm.sh config credentials --server http://127.0.0.1:18080
--realm master --user admin --password ...`. It obtains an admin token
from the `master` realm.

**2. Create a realm for the user domain.** `POST /admin/realms`

```sh
kcadm.sh create realms -s realm=ldap.dom.test -s enabled=true
```

**3. Add the LDAP federation provider.** `POST /admin/realms/{realm}/components`

Values come from `cluster/list-user-domains` (or `agent.ldapproxy`).
`parentId` is the realm ID, returned by `kcadm.sh get realms/{realm}`.
Read-only edit mode is enough for scenario 1:

```sh
kcadm.sh create components -r ldap.dom.test \
  -s name=ldap.dom.test -s providerId=ldap \
  -s providerType=org.keycloak.storage.UserStorageProvider \
  -s parentId=REALM_ID \
  -s 'config.enabled=["true"]' -s 'config.vendor=["other"]' \
  -s 'config.editMode=["READ_ONLY"]' \
  -s 'config.connectionUrl=["ldap://10.5.4.1:20003"]' \
  -s 'config.authType=["simple"]' \
  -s 'config.bindDn=["cn=ldapservice,dc=ldap,dc=dom,dc=test"]' \
  -s 'config.bindCredential=["BIND_PASSWORD"]' \
  -s 'config.usersDn=["ou=People,dc=ldap,dc=dom,dc=test"]' \
  -s 'config.searchScope=["1"]' \
  -s 'config.usernameLDAPAttribute=["uid"]' \
  -s 'config.rdnLDAPAttribute=["uid"]' \
  -s 'config.uuidLDAPAttribute=["entryUUID"]' \
  -s 'config.userObjectClasses=["inetOrgPerson, posixAccount"]' \
  -s 'config.importEnabled=["true"]' -s 'config.syncRegistrations=["false"]' \
  -s 'config.trustEmail=["true"]' -s 'config.pagination=["false"]'
```

With vendor `other`, Keycloak creates the default mappers for user name,
first and last name (`cn`, `sn`), email and timestamps. The `LDAP_ID`
user attribute holds the `entryUUID` value. Keycloak lowercases user
names (`MixedCaseUser` becomes `mixedcaseuser`).

**4. Add the group mapper.** Same endpoint, with the LDAP component ID as
parent:

```sh
kcadm.sh create components -r ldap.dom.test \
  -s name=groups -s providerId=group-ldap-mapper \
  -s providerType=org.keycloak.storage.ldap.mappers.LDAPStorageMapper \
  -s parentId=LDAP_COMPONENT_ID \
  -s 'config."groups.dn"=["ou=Groups,dc=ldap,dc=dom,dc=test"]' \
  -s 'config."group.name.ldap.attribute"=["cn"]' \
  -s 'config."group.object.classes"=["posixGroup"]' \
  -s 'config."preserve.group.inheritance"=["false"]' \
  -s 'config."membership.ldap.attribute"=["memberUid"]' \
  -s 'config."membership.attribute.type"=["UID"]' \
  -s 'config."membership.user.ldap.attribute"=["uid"]' \
  -s 'config.mode=["READ_ONLY"]' \
  -s 'config."user.roles.retrieve.strategy"=["LOAD_GROUPS_BY_MEMBER_ATTRIBUTE"]'
```

**5. Synchronize users and groups.** Optional: users are also imported
at their first login.

- `POST /admin/realms/{realm}/user-storage/{id}/sync?action=triggerFullSync`
- `POST /admin/realms/{realm}/user-storage/{id}/mappers/{mapperId}/sync?direction=fedToKeycloak`

**6. Register an application client.** `POST /admin/realms/{realm}/clients`

Example for Nextcloud: a confidential client with the authorization code
flow and a protocol mapper that exposes `LDAP_ID` as the `ldap_uuid`
claim:

```json
{
  "clientId": "nextcloud",
  "protocol": "openid-connect",
  "publicClient": false,
  "standardFlowEnabled": true,
  "redirectUris": [
    "https://nextcloud.example.org/apps/user_oidc/code",
    "https://nextcloud.example.org/index.php/apps/user_oidc/code"
  ],
  "webOrigins": ["https://nextcloud.example.org"],
  "attributes": {
    "post.logout.redirect.uris": "https://nextcloud.example.org/*"
  },
  "protocolMappers": [{
    "name": "ldap_uuid",
    "protocol": "openid-connect",
    "protocolMapper": "oidc-usermodel-attribute-mapper",
    "config": {
      "user.attribute": "LDAP_ID",
      "claim.name": "ldap_uuid",
      "jsonType.label": "String",
      "id.token.claim": "true",
      "access.token.claim": "true",
      "userinfo.token.claim": "true",
      "introspection.token.claim": "true"
    }
  }]
}
```

The Roundcube client has redirect URI
`https://webmail.example.org/index.php/login/oauth` and the audience
mapper of step 7 instead of the `ldap_uuid` mapper. The `dovecot` client
is confidential with no login flow: it is used only to authenticate
introspection requests.

**7. Add an audience mapper.** `POST /admin/realms/{realm}/clients/{id}/protocol-mappers/models`

Needed by clients whose tokens are sent to Dovecot:

```json
{
  "name": "aud-dovecot",
  "protocol": "openid-connect",
  "protocolMapper": "oidc-audience-mapper",
  "config": {
    "included.client.audience": "dovecot",
    "access.token.claim": "true",
    "id.token.claim": "false",
    "introspection.token.claim": "true"
  }
}
```

**8. Retrieve the client secret.** `GET /admin/realms/{realm}/clients/{id}/client-secret`.
To rotate it, use `POST` on the same endpoint.

The client `{id}` is the internal client ID, returned by
`GET /admin/realms/{realm}/clients?clientId=nextcloud`.

### Nextcloud

After `configure-module` with the `host` and `domain` attributes (plus
`internal_smarthost`, because of the bug described above), the prototype
ran these `occ` commands:

```sh
occ app:install user_oidc
occ user_oidc:provider keycloak \
    --clientid=nextcloud --clientsecret=CLIENT_SECRET \
    --discoveryuri=https://keycloak.example.org/realms/ldap.dom.test/.well-known/openid-configuration \
    --unique-uid=0 --mapping-uid=ldap_uuid \
    --mapping-display-name=name --mapping-email=email \
    --scope="openid email profile"
occ config:system:set user_oidc auto_provision --type=boolean --value=false
occ ldap:set-config s01 ldapLoginFilter \
    "(&(|(objectclass=inetOrgPerson))(|(uid=%uid)(mail=%uid)(entryUUID=%uid)))"
```

- `--unique-uid=0` uses the claim value as Nextcloud user ID, instead of a
  hash of provider and claim.
- With `auto_provision` disabled, `user_oidc` logs in only users that
  already exist in another backend, here `user_ldap`.
- The login page shows a "Log in with keycloak" button next to the
  password form. `occ config:app:set user_oidc allow_multiple_user_backends
  --value=0` redirects to Keycloak directly (not tested).

### Dovecot

Two files in the `dovecot-custom` volume, mounted at
`/etc/dovecot/local.conf.d/`. Any `*.conf` file there is appended to
Dovecot's `local.conf`. `passdb.conf`:

```text
auth_mechanisms = $auth_mechanisms oauthbearer xoauth2

passdb {
  driver = oauth2
  mechanisms = xoauth2 oauthbearer
  args = /etc/dovecot/local.conf.d/oauth2.conf.ext
}
```

`oauth2.conf.ext` (mode `600`, because it contains the client secret):

```text
introspection_mode = post
introspection_url = https://dovecot:CLIENT_SECRET@keycloak.example.org/realms/ldap.dom.test/protocol/openid-connect/token/introspect
active_attribute = active
active_value = true
username_attribute = preferred_username
```

Notes:

- Do not set `tokeninfo_url` to the Keycloak token endpoint: Dovecot
  sends it a `GET` request, Keycloak answers `405` and Dovecot does not
  proceed to introspection.
- The default `username_attribute` is `email`. It does not match the
  login name, which Dovecot reduces to the bare `uid`.
- Dovecot returns only the user name from the `oauth2` passdb, so the
  `prefetch` userdb falls through to the LDAP userdb: users are still
  resolved from LDAP.
- Apply changes with `doveadm reload`.
- Dovecot delays authentication after failures from the same remote IP.
  Roundcube and Postfix submission connect from the same IP for all
  users: after a few failed logins in a row, the delay exceeded the
  Postfix wait time and SMTP authentication failed with `454 4.7.0
  Temporary authentication failure`. This is not specific to OAuth.

### Roundcube

An additional file in the module configuration directory,
`~/.config/state/config/config.oauth.php`. The container entrypoint
includes every `*.php` file of that directory at startup, and the module
rewrites only its own files. The file must be readable by the web server
user inside the container (mode `644`, like the other files).

```php
<?php
// Behind Traefik: build https:// URLs (the OAuth redirect_uri included)
$config['use_https'] = true;
$config['oauth_provider'] = 'generic';
$config['oauth_provider_name'] = 'Keycloak';
$config['oauth_client_id'] = 'roundcube';
$config['oauth_client_secret'] = 'CLIENT_SECRET';
$config['oauth_config_uri'] = 'https://keycloak.example.org/realms/ldap.dom.test/.well-known/openid-configuration';
$config['oauth_scope'] = 'openid profile email';
$config['oauth_identity_fields'] = ['preferred_username'];
$config['oauth_login_redirect'] = false;
```

Restart the `roundcubemail-app` unit to load a new file. Check the syntax
first with `php -l`: a PHP syntax error breaks the whole application.

Roundcube appends `username_domain` to the `preferred_username` value,
so the stored user name (for example `john@example.org`) is the same as
for password logins. Roundcube uses `OAUTHBEARER` for both IMAP and SMTP,
and refreshes the access token when it expires.

### Test results

The login flows were tested with `curl`, simulating a browser (cookie
jar, Keycloak login form submission), and in a real browser.

| Test | Result |
|---|---|
| Nextcloud login through Keycloak | user ID is the LDAP `entryUUID`, LDAP groups present |
| Nextcloud login of a user never seen by Nextcloud | works at the first try, with the `entryUUID` login filter; HTTP 400 without it |
| Nextcloud WebDAV with LDAP password | works, same account and home directory as SSO |
| Keycloak login of a user locked in NS8 | rejected ("Invalid username or password") |
| IMAP `XOAUTH2` and `OAUTHBEARER` | works, also with `user@domain` login names |
| IMAP token of another user, token of another client, invalid token | rejected |
| SMTP submission with `XOAUTH2` | works |
| IMAP and SMTP password logins | unchanged |
| Roundcube login through Keycloak | works; existing Roundcube user record reused |
| Roundcube send message | works, Postfix logs `sasl_method=OAUTHBEARER` |
| Roundcube session after the access token expiration (5 minutes) | token refreshed, session still valid |
| Logout from Nextcloud and from Roundcube | Keycloak session ended |

## Appendix: scenario 2 prototype

The scenario 2 prototype extends the scenario 1 one: same node, same
realm `ldap.dom.test`, with an Entra ID tenant on the free plan.

### Entra ID application

In the Entra admin center, *App registrations*:

1. New registration, single tenant, redirect URI of type *Web*:
   `https://keycloak.example.org/realms/ldap.dom.test/broker/entra/endpoint`.
   `entra` is the alias of the identity provider in Keycloak. Each realm
   needs its own redirect URI.
2. *Certificates & secrets*: create a client secret.
3. *Token configuration*: add the optional ID token claims `email`,
   `upn`, `given_name`, `family_name`, and a groups claim with *Security
   groups*, emitted as *Group ID*.
4. *API permissions*: add the Microsoft Graph delegated permissions
   `openid`, `profile`, `email`, `offline_access` (group *OpenId
   permissions*), and grant admin consent.
5. *Enterprise applications*, the same application: set *Assignment
   required* and assign the users allowed to log in.

The secret can be checked without a user login, requesting a token with
the client credentials grant:

```sh
curl -s https://login.microsoftonline.com/TENANT_ID/oauth2/v2.0/token \
    -d grant_type=client_credentials -d client_id=CLIENT_ID \
    --data-urlencode client_secret=CLIENT_SECRET \
    -d scope=https://graph.microsoft.com/.default
```

### Keycloak identity provider

**1. Declare the extra user attributes.** `PUT /admin/realms/{realm}/users/profile`.
Add to the `attributes` array of the current profile:

```json
{"name": "entra_oid", "multivalued": false,
 "permissions": {"view": ["admin"], "edit": ["admin"]}},
{"name": "entra_groups", "multivalued": true,
 "permissions": {"view": ["admin"], "edit": ["admin"]}}
```

**2. Create the identity provider.** `POST /admin/realms/{realm}/identity-provider/instances`

A generic OIDC provider, bound to the tenant issuer. Entra ID custom
claims are in the ID token, not in the Microsoft Graph user info
endpoint, so user info is disabled:

```json
{
  "alias": "entra",
  "displayName": "Microsoft Entra ID",
  "providerId": "oidc",
  "enabled": true,
  "trustEmail": false,
  "firstBrokerLoginFlowAlias": "first broker login",
  "config": {
    "clientId": "CLIENT_ID",
    "clientSecret": "CLIENT_SECRET",
    "clientAuthMethod": "client_secret_post",
    "issuer": "https://login.microsoftonline.com/TENANT_ID/v2.0",
    "authorizationUrl": "https://login.microsoftonline.com/TENANT_ID/oauth2/v2.0/authorize",
    "tokenUrl": "https://login.microsoftonline.com/TENANT_ID/oauth2/v2.0/token",
    "jwksUrl": "https://login.microsoftonline.com/TENANT_ID/discovery/v2.0/keys",
    "logoutUrl": "https://login.microsoftonline.com/TENANT_ID/oauth2/v2.0/logout",
    "useJwksUrl": "true",
    "validateSignature": "true",
    "disableUserInfo": "true",
    "defaultScope": "openid profile email",
    "pkceEnabled": "true",
    "pkceMethod": "S256",
    "syncMode": "IMPORT"
  }
}
```

The admin API returns the client secret masked (`**********`): take
care not to write back the masked value when updating the provider.

**3. Add the claim mappers.** `POST /admin/realms/{realm}/identity-provider/instances/entra/mappers`

```json
{"name": "username", "identityProviderAlias": "entra",
 "identityProviderMapper": "oidc-username-idp-mapper",
 "config": {"syncMode": "INHERIT", "template": "${CLAIM.preferred_username | localpart}"}}
```

Then one `oidc-user-attribute-idp-mapper` for each claim, with
`config.claim` and `config["user.attribute"]`: `email` → `email`,
`given_name` → `firstName`, `family_name` → `lastName`, `oid` →
`entra_oid`, `groups` → `entra_groups`. The prototype sets `syncMode`
to `FORCE` on the email mapper, so a change in Entra ID is copied to
LDAP at the next login.

**4. Enable events (optional).** `PUT /admin/realms/{realm}/events/config`
with `eventsEnabled`, `eventsExpiration` and `adminEventsEnabled`.
Keycloak does not log successful logins by default; stored events are
returned by `GET /admin/realms/{realm}/events`.

### Writable LDAP federation

**1. Create the service account.** With the `domadm` role, the module
agent runs the `add-user` action of the account provider:

```sh
api-cli run module/openldap1/add-user --data - <<'JSON'
{"user": "keycloak-svc", "display_name": "Keycloak service account",
 "password": "RANDOM_PASSWORD", "groups": ["domain admins"],
 "no_password_expiration": true}
JSON
```

**2. Update the LDAP federation provider.** `PUT /admin/realms/{realm}/components/{id}`,
changing these `config` values of the scenario 1 provider:

```json
{
  "connectionUrl": ["ldap://127.0.0.1:20005"],
  "bindDn": ["uid=keycloak-svc,ou=People,dc=ldap,dc=dom,dc=test"],
  "bindCredential": ["RANDOM_PASSWORD"],
  "editMode": ["WRITABLE"],
  "syncRegistrations": ["true"],
  "usePasswordModifyExtendedOp": ["true"]
}
```

`127.0.0.1:20005` is the ldapproxy port of the domain, as returned by
`Ldapproxy().get_domain()` in the module environment.

**3. Allow writes of user attributes.** The default mappers created with
the provider in read-only mode have `config["read.only"] = ["true"]`.
Set it to `false` for the `username`, `first name`, `last name` and
`email` mappers, otherwise the new LDAP entry misses mandatory
attributes.

**4. Add the posixAccount attributes.** `POST /admin/realms/{realm}/components`,
one `hardcoded-ldap-attribute-mapper` for each attribute, with the LDAP
federation provider ID as `parentId`:

```json
{"name": "posix uidNumber", "providerId": "hardcoded-ldap-attribute-mapper",
 "providerType": "org.keycloak.storage.ldap.mappers.LDAPStorageMapper",
 "parentId": "LDAP_COMPONENT_ID",
 "config": {"ldap.attribute.name": ["uidNumber"], "ldap.attribute.value": ["1000"]}}
```

The values are `gidNumber` = `1001` (the `locals` group, like
`add-user`), `uidNumber` = `1000` and `homeDirectory` = `/home/nobody`.
The placeholder `uidNumber` is lower than the numbers assigned by
`add-user`, so it does not change the next free number.

### Fix-up job

A systemd user timer of the module runs this script every minute (see
[`kc-posix-fixup`](#kc-posix-fixup-script) below). It searches entries
with the placeholder `uidNumber`, and for each one:

- replaces `uidNumber` with the next free number, in a single modify
  operation that deletes the placeholder value: if the entry was already
  fixed in the meantime, the operation fails;
- sets `homeDirectory` to `/home/<uid>`;
- sets `displayName` to `cn` and `sn`, if missing.

#### kc-posix-fixup script

```python
#!/usr/bin/env python3
import os, sys, ldap3

PLACEHOLDER_UID = 1000
PEOPLE_DN = 'ou=People,dc=ldap,dc=dom,dc=test'
BIND_DN = 'uid=keycloak-svc,' + PEOPLE_DN

with open(os.path.join(os.environ['AGENT_STATE_DIR'], 'ldap-svc.pw')) as fp:
    bind_password = fp.read()
conn = ldap3.Connection(ldap3.Server('ldap://127.0.0.1:20005'), BIND_DN,
    bind_password, auto_bind=True, raise_exceptions=False)

conn.search(PEOPLE_DN, f'(&(objectClass=posixAccount)(uidNumber={PLACEHOLDER_UID}))',
    attributes=['uid', 'cn', 'sn', 'displayName'])
pending = list(conn.entries)
if not pending:
    sys.exit(0)
conn.search(PEOPLE_DN, '(&(objectClass=posixAccount)(uidNumber=*))', attributes=['uidNumber'])
next_uid = max([int(e.uidNumber.value) for e in conn.entries] + [PLACEHOLDER_UID]) + 1

for entry in pending:
    uid = entry.uid.value
    changes = {
        'uidNumber': [(ldap3.MODIFY_DELETE, [str(PLACEHOLDER_UID)]), (ldap3.MODIFY_ADD, [str(next_uid)])],
        'homeDirectory': [(ldap3.MODIFY_REPLACE, [f'/home/{uid}'])],
    }
    if not entry.displayName.value:
        changes['displayName'] = [(ldap3.MODIFY_REPLACE,
            [' '.join(filter(None, [entry.cn.value, entry.sn.value])) or uid])]
    if conn.modify(entry.entry_dn, changes):
        next_uid += 1
```

### Deny password logins to federated users

The built-in flows are copied, and the copies become the realm defaults:

- `POST /admin/realms/{realm}/authentication/flows/browser/copy` with
  `{"newName": "ns8 browser"}`
- `POST /admin/realms/{realm}/authentication/flows/direct%20grant/copy`
  with `{"newName": "ns8 direct grant"}`
- `PUT /admin/realms/{realm}` with `browserFlow` and `directGrantFlow`
  set to the new flow names.

A conditional subflow is added to the `ns8 browser forms` subflow and to
the `ns8 direct grant` flow:

1. `POST /admin/realms/{realm}/authentication/flows/{flow}/executions/flow`
   with `{"alias": "ns8 browser deny federated", "type": "basic-flow",
   "provider": "registration-page-form"}`; then set its requirement to
   `CONDITIONAL` with `PUT …/flows/{flow}/executions`.
2. `POST …/flows/{subflow}/executions/execution` with
   `{"provider": "conditional-user-attribute"}` and with
   `{"provider": "deny-access-authenticator"}`; set both to `REQUIRED`.
3. `POST /admin/realms/{realm}/authentication/executions/{id}/config` for
   the condition:
   ```json
   {"alias": "has entra_oid",
    "config": {"attribute_name": "entra_oid", "attribute_expected_value": ".+",
               "regex": "true", "not": "false"}}
   ```
   and for the deny step:
   ```json
   {"alias": "message",
    "config": {"denyErrorMessage": "This account signs in with Microsoft Entra ID"}}
   ```
4. `POST /admin/realms/{realm}/authentication/executions/{id}/lower-priority`
   on the subflow, until it follows the password step (*Username Password
   Form* in the browser flow, *Password* in the direct grant flow).

The browser flow then shows "This account signs in with Microsoft Entra
ID" to a federated user who types a password. The direct grant answers
HTTP 401 with an HTML page instead of a JSON error. Keycloak records a
`LOGIN_ERROR` event with `error="access_denied"`.

### Test results

| Test | Result |
|---|---|
| Keycloak login with Entra ID, read-only LDAP federation | user created in the Keycloak database only; claims mapped as expected |
| Keycloak login with Entra ID, writable LDAP federation | LDAP entry created by the service account, linked to the Keycloak user (`LDAP_ID`) |
| Fix-up job | `uidNumber`, `homeDirectory`, `displayName` assigned within a minute |
| NS8 `cluster/list-domain-users` | the new user is listed |
| Email property added in Entra ID, next login | email copied to Keycloak and LDAP `mail` |
| Nextcloud login | user ID is the new `entryUUID`; name, email and primary group from LDAP |
| Roundcube login | works, IMAP `OAUTHBEARER`, mailbox created |
| Scenario 1 LDAP users after the switch to writable mode | login unchanged |
| Administrator sets a password to the federated user (`alter-user`) | LDAP bind works with it |
| Federated user, Keycloak password form and direct grant | denied |
| Native LDAP user, Keycloak password form and direct grant | allowed |

## Appendix: Active Directory prototype

Both scenarios were repeated on the Samba AD internal domain
`ad.dom.test`, on the same node, with a dedicated set of applications:

| Module | Role |
|---|---|
| `samba1` | internal user domain `ad.dom.test` |
| `nextcloud2` | Nextcloud bound to `ad.dom.test` |
| `mail4` | Mail 1.8.0 bound to `ad.dom.test` |
| `roundcubemail2` | Roundcube for `mail4` |

Keycloak has a second realm, `ad.dom.test`. Nextcloud, Dovecot and
Roundcube were configured as in the scenario 1 appendix, with clients of
the new realm. The Entra ID identity provider, its mappers and the user
profile attributes were copied from the first realm; the Entra ID
application needs an additional redirect URI for the realm:
`https://keycloak.example.org/realms/ad.dom.test/broker/entra/endpoint`.

### LDAP federation in Active Directory mode

Samba requires TLS for simple binds, and its self-signed certificate
does not match the host name. Keycloak connects instead to the
clear-text port of ldapproxy (`127.0.0.1:20002` in the prototype), which
connects to Samba with TLS. The component is created as in scenario 1,
with these `config` values:

```json
{
  "vendor": ["ad"],
  "editMode": ["READ_ONLY"],
  "connectionUrl": ["ldap://127.0.0.1:20002"],
  "bindDn": ["ldapservice@ad.dom.test"],
  "usersDn": ["CN=Users,DC=ad,DC=dom,DC=test"],
  "searchScope": ["2"],
  "usernameLDAPAttribute": ["sAMAccountName"],
  "rdnLDAPAttribute": ["cn"],
  "uuidLDAPAttribute": ["objectGUID"],
  "userObjectClasses": ["person, organizationalPerson, user"],
  "customUserSearchFilter": ["(objectCategory=person)"],
  "pagination": ["true"]
}
```

The group mapper uses `group.object.classes = group`,
`membership.ldap.attribute = member` and `membership.attribute.type =
DN`.

For scenario 2 the component is changed to `WRITABLE`, with *Sync
registrations*, and binds as the service account
`keycloak-svc@ad.dom.test`, created by the module agent with the samba1
`add-user` action and member of `Domain Admins`. The password modify
extended operation is not used: Keycloak sets AD passwords with the
`unicodePwd` attribute.

Name mappers, to match the NS8 AD accounts:

- the `full name` mapper (`full-name-ldap-mapper`) has
  `ldap.full.name.attribute = displayName`, read and write;
- an additional `user-attribute-ldap-mapper` writes the user name to
  `cn`;
- the default `first name` (`givenName`) and `last name` (`sn`) mappers
  are removed: NS8 AD accounts have neither, and with them Keycloak
  saw users with no first and last name. As the user profile required
  them, Keycloak refused logins with "Account is not fully set up".
  First and last name are also made optional in the user profile.

To create accounts without the *Update password* form, a
`hardcoded-ldap-attribute-mapper` writes `pwdLastSet` = `-1`.

### Uppercase ldap_uuid claim

The prototype deploys a JavaScript protocol mapper. Keycloak loads
providers from `/opt/keycloak/providers`: the Keycloak container unit
mounts a directory of the module state there, and starts Keycloak with
`--features=scripts`. The provider is a JAR file with two entries:

`META-INF/keycloak-scripts.json`:

```json
{
  "mappers": [{
    "name": "LDAP_ID uppercase",
    "fileName": "ldap-id-upper.js",
    "description": "LDAP_ID user attribute converted to uppercase"
  }]
}
```

`ldap-id-upper.js`:

```js
// LDAP_ID (objectGUID string) in uppercase, like Nextcloud user_ldap
var ldapId = user.getFirstAttribute("LDAP_ID");
exports = ldapId ? ldapId.toUpperCase() : null;
```

The mapper type is `script-ldap-id-upper.js`. It replaces the
`oidc-usermodel-attribute-mapper` of the Nextcloud client, with the same
`claim.name` (`ldap_uuid`) and token options.

The Nextcloud login filter becomes:

```text
(&(&(|(objectclass=person)))(|(sAMAccountName=%uid)(userPrincipalName=%uid)(objectGUID=%uid)))
```

### Test results

| Test | Result |
|---|---|
| Nextcloud login of an AD user, `LDAP_ID` claim as is | HTTP 400: lowercase claim, uppercase Nextcloud user ID |
| Same test with the uppercase mapper | works, Nextcloud user ID is the uppercase `objectGUID` |
| Nextcloud login of an AD user never seen by Nextcloud | works at the first try, with the `objectGUID` login filter |
| IMAP `XOAUTH2`, `OAUTHBEARER`, password; Roundcube login and send | works, as on OpenLDAP |
| Entra ID first login, before the `pwdLastSet` mapper | *Update password* form; the chosen password is written to AD |
| Entra ID first login, with the `pwdLastSet` mapper | no password form; account enabled, `userAccountControl: 544`, listed by NS8 |
| Empty password for the new account (LDAP, SMB, Kerberos) | refused |
| Administrator sets a password (`alter-user`) | `userAccountControl: 512`, Samba share access works |
| Federated user, Keycloak password form and direct grant | denied, also with the password set by the administrator |
| Nextcloud and Roundcube login of the federated user | works; Nextcloud user ID is the uppercase `objectGUID` |

## Appendix: single configuration prototype

The prototype extends the scenario 2 setup of both realms. The login
mode tests ran on the AD realm, the only one with Nextcloud, Mail and
Roundcube still installed.

### Marker mappers

The user profile declares `ns8_idp` and `ns8_idp_id`, like `entra_oid`
in the scenario 2 appendix. Two LDAP mappers, `POST
/admin/realms/{realm}/components` with the LDAP federation provider ID
as `parentId`, are the same for OpenLDAP and AD:

```json
{"name": "idp", "providerId": "user-attribute-ldap-mapper",
 "providerType": "org.keycloak.storage.ldap.mappers.LDAPStorageMapper",
 "parentId": "LDAP_COMPONENT_ID",
 "config": {"user.model.attribute": ["ns8_idp"],
            "ldap.attribute": ["employeeType"],
            "read.only": ["false"], "always.read.value.from.ldap": ["true"],
            "is.mandatory.in.ldap": ["false"]}}
```

The second mapper, `idp id`, maps `ns8_idp_id` to `employeeNumber`. The
`entra` identity provider has its `oid` claim mapper changed to write
`ns8_idp_id`, and a new mapper writes its alias:

```json
{"name": "idp alias", "identityProviderAlias": "entra",
 "identityProviderMapper": "hardcoded-attribute-idp-mapper",
 "config": {"syncMode": "INHERIT", "attribute": "ns8_idp",
            "attribute.value": "entra"}}
```

The deny condition of the password flows checks `ns8_idp`. The
prototype first used `entra_oid` in `msDS-ExternalDirectoryObjectId` for
AD, then switched to this form. Existing federated accounts got the new
LDAP values before the new mappers were created: an account without
them loses the marker. `POST /admin/realms/{realm}/clear-user-cache`
makes Keycloak read LDAP values changed by other writers.

### Login mode switch

Federated only mode, in the realm:

1. `POST …/authentication/executions/{id}/config` on the *Identity
   Provider Redirector* execution of the browser flow, with
   `{"alias": "default entra", "config": {"defaultProvider": "entra"}}`.
   Mixed mode deletes this configuration.
2. The `ns8 browser forms` subflow set to `DISABLED` (`ALTERNATIVE` in
   mixed mode).
3. `directGrantFlow` set to a flow that has only a `deny-access-authenticator`
   step (`ns8 direct grant` in mixed mode).
4. A realm attribute, `ns8_login_mode`, records the mode.

Updating an execution with `PUT …/flows/{flow}/executions` requires the
whole execution representation. If `priority` is missing, Keycloak
resets it to 0 and moves the execution to the top of its flow: the forms
subflow ran before the *Cookie* step, and every login required the
password again.

### Link by marker authenticator

The provider `ns8-idp-link-by-attribute` is a JAR file in the Keycloak
providers directory. It extends `AbstractIdpAuthenticator` and runs in
the first broker login flow. Its configuration names the ID attribute
(`ns8_idp_id`), the provider attribute (`ns8_idp`) and the LDAP ID
attribute (`employeeNumber`):

- it reads the `ns8_idp_id` attribute that the identity provider mapper
  set on the brokered identity; without it, the step is skipped;
- it searches the realm users with the same `ns8_idp_id`, then, if none
  is found, with the LDAP attribute, for accounts not imported in
  Keycloak yet;
- it keeps only the accounts whose `ns8_idp` equals the alias of the
  identity provider of the login;
- with exactly one match it removes any older link of the same identity
  provider, sets the user and succeeds, so Keycloak links the identity
  to the existing account; with more matches it fails.

The built-in *first broker login* flow is copied as `ns8 first broker
login`, and the step is added as the first alternative of its *User
creation or linking* subflow, before *Create User If Unique*. The
`entra` identity provider uses the new flow
(`firstBrokerLoginFlowAlias`). Keycloak logs a warning at startup,
because authenticators are an internal SPI that may change between
releases.

### Test results

| Test | Result |
|---|---|
| Marker removed from LDAP, user cache cleared | password login allowed; denied again after the marker is restored |
| Federated only mode: Keycloak, Nextcloud, Roundcube login pages | all redirect to Entra ID; no password form, no Keycloak button |
| Federated only mode: Entra ID login in Nextcloud, then Roundcube | Roundcube opens without asking anything (Keycloak session) |
| Federated only mode: native user, direct grant | denied |
| Federated only mode: native user, WebDAV, OCS API, IMAP password | works |
| Back to mixed mode | password form and Entra ID button again, SSO session reused |
| Identity provider disabled: federated user with administrator password | denied: no SSO login left |
| Entra ID first login of a user unknown to NS8 | account created in AD with the marker, no form; listed by NS8 |
| Marker moved to `employeeType` and `employeeNumber` | password login denial and native account count unchanged |
| Same marker, Keycloak link of `e.user1` removed, Entra ID login | link restored by `ns8_idp_id` and `ns8_idp`, no form |
| Same marker, Entra ID first login of a user unknown to NS8 | account created in AD with `employeeType: entra` and the `oid` in `employeeNumber`, no form; listed by NS8 |
| Keycloak link of `e.user1` removed, Entra ID login | link restored by `oid`, no form |
| `dprincipi` provisioned with the `oid` of Entra ID user `davide.principi` | Entra ID login linked to `dprincipi`, no password; *Update account information* form because `mail` was missing |
