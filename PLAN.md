# Implementation plan

Implementation plan of the idp module. The design notes and the
prototype results are in `INSTRUCTIONS.md`.

## Service composition

Keycloak and PostgreSQL run in a Podman pod with its own network
namespace. Four systemd user units compose the service:

| Unit | Type | Role |
|---|---|---|
| `idp.service` | forking | The pod. Publishes only `127.0.0.1:${TCP_PORT}:8080` |
| `postgres.service` | notify | PostgreSQL, listening on `127.0.0.1` in the pod |
| `keycloak-init.service` | oneshot | First-run and recovery jobs, see below |
| `keycloak.service` | notify | The Keycloak server |

Start order: `idp.service`, `postgres.service`,
`keycloak-init.service`, `keycloak.service`. Every unit except the pod
has `BindsTo=idp.service`, and only `idp.service` is enabled.
`keycloak.service` has `Requires=` and `After=keycloak-init.service`:
when the init job fails, Keycloak does not start and the error is in the
init unit journal. A skipped init job, because of its condition, is not a
failure.

`configure-module/80start_services` enables `idp.service` and restarts
the pod, PostgreSQL and Keycloak units by name. The init job runs when
needed, pulled in by `keycloak.service`.

The pod uses `--network=pasta`. With `--network=private`, Podman 5.8
refuses the published port: "PortMappings can only be used with Bridge,
slirp4netns, or pasta networking".

With Pasta, connections from the host loopback interface to the
published port reach the pod with the host public address as source,
not `127.0.0.1` (verified on rl1). For this reason:

- Keycloak trusts the proxy headers from any source
  (`KC_PROXY_HEADERS=xforwarded` without
  `KC_PROXY_TRUSTED_ADDRESSES`). The port is published only on the host
  loopback interface, so only local processes, like Traefik, reach it.
- Every Keycloak server, including the temporary one of the init job,
  runs with `--hostname=https://${IDP_HOSTNAME}`. Without an HTTPS
  hostname, the master realm refuses plain HTTP requests from a public
  address ("HTTPS required").

A Unix socket in a shared volume was discarded: the PostgreSQL JDBC
driver has no native Unix socket support yet (pgjdbc/pgjdbc#4188 is a
draft), and the workaround needs the junixsocket library in the
Keycloak providers.

Keycloak reaches ldapproxy at `host.containers.internal:<port>`, once
ldapproxy listens on all IPv4 addresses (NethServer/dev#8188). Apps
behind Traefik on the same node need `--add-host=<fqdn>:host-gateway`
on the pod.

The Traefik `module-removed` event handler removes the module routes,
so `destroy-module` has no route cleanup step.

### Readiness

Both server units are `Type=notify`, so a unit is active only when its
server accepts connections, and units ordered after it wait for that:

- PostgreSQL uses the Debian image (`postgres:18.6-trixie`), built with
  systemd support, and runs with `--sdnotify=container`. Tested on
  rl1: the unit becomes active on the final server start, not on the
  temporary server of the first-run initialization.
- Keycloak runs with `--sdnotify=healthy` and a Podman health check on
  `/health/ready` of the management port 9000, inside the container.
  The image has no curl, so the check is a bash `/dev/tcp` request. The
  management port is not published by the pod. The startup check loops
  internally until Keycloak is ready (`--health-startup-timeout=150s`):
  Podman runs it once per start, so the journal has no failed check
  units while Keycloak starts.

Keycloak answers 503 to requests received while it bootstraps. The
HTTP helper retries on connection errors and 503 responses for a short
time; any other error is final.

The JVM exits with status 143 on SIGTERM: `keycloak.service` declares
`SuccessExitStatus=143`, so a normal stop is not a failure.

### Keycloak image

The module builds its own Keycloak image, `idp-keycloak`, from
`keycloak-providers/Containerfile` (published as `IDP_KEYCLOAK_IMAGE`):

1. A Maven stage builds the `ns8-authenticators` jar and packs the
   `ns8-mappers` scripts jar.
2. A builder stage copies the jars into the providers directory and
   runs `kc.sh build` with the build-time options: database, features,
   health endpoints and cache.
3. The final stage copies only the build output (`lib/quarkus`) and the
   providers onto the upstream image, so the base layers stay shared:
   484 MB against 480 MB of the upstream image.

Every server, including `bootstrap-admin` and the temporary server of
the init job, runs with `--optimized`. Measured on rl1: a Keycloak
restart takes about 20 s instead of 40 s, and the credential recovery
of the init job about 1 minute instead of 2.

Renovate groups the base image tag and the `org.keycloak` Maven
dependencies of the providers in one update, so the providers are
always built against the Keycloak version of the image.

Besides 5432, 8080 and 9000, the Keycloak JVM listens on a random
high port inside the pod. It is not published; its purpose is not
verified yet.

### Configuration

Runtime options are environment variables (`KC_*`), shared by
`keycloak.service` and the init job:

- `etc/keycloak.env`, shipped with the module: database connection,
  cache, HTTP and proxy options.
- `state/passwords.env`, generated by `create-module` with mode 0600:
  `POSTGRES_PASSWORD` and `KC_DB_PASSWORD`.
- `--hostname=https://${IDP_HOSTNAME}` on the command line, from the
  module environment.

`KC_CACHE=local` is set both at build time and at runtime: `kc.sh
show-config` does not list it among the persisted build options.

## Module configuration

`configure-module` takes the Keycloak host name (`host`) and
`lets_encrypt`. Its steps:

1. `10validate_host`: a changed host name must not be already routed by
   Traefik, otherwise the action fails with the `host_already_used`
   validation error.
2. `20route`: route the whole host name to the Keycloak port, with
   HTTP to HTTPS redirection. With `lets_encrypt_check`, if the Let's
   Encrypt certificate is not obtained, the action fails and Traefik
   keeps the previous route. With `lets_encrypt_cleanup`, disabling
   Let's Encrypt removes the certificate.
3. `30configure`: save `IDP_HOSTNAME`. It runs after the route step,
   so a failed route leaves the settings and the running services
   unchanged. The Let's Encrypt flag is not saved by the module: Traefik
   stores it in the route.
4. `80start_services`: restart the services, so Keycloak runs with the
   new `--hostname`.

`get-configuration` returns the same fields, reading `lets_encrypt`
from the Traefik route with `agent.get_route()`. The Settings page of the UI
has the host name field and the Let's Encrypt switch. It warns when Let's
Encrypt is being disabled, and shows the Traefik messages when the
certificate cannot be obtained.

## Keycloak administration

Module actions, event handlers and helper scripts configure Keycloak
through the admin REST API, with plain HTTP requests to
`http://127.0.0.1:${TCP_PORT}` from the host. The `kcadmin` Python
module under `imageroot/pypkg/` obtains tokens with the
`client_credentials` grant from the master realm and wraps the admin API
calls.

`kcadm.sh` with `podman exec` is not used: it needs the same admin
credentials, starts a JVM for every call and loses its login session
when the container is recreated. `kc.sh import` does not update existing
realms and needs a stopped server.

### The ns8-agent client

The module owns the `ns8-agent` confidential client in the master
realm, with the service account enabled. Its secret is stored in
`state/ns8-agent.json`, written with `agent.safe_open()` and never in
Redis.

The service account has only the `create-realm` role of the master
realm. When it creates a realm, Keycloak grants it the admin roles of
that realm (the roles of the `<realm>-realm` client in master), so it
manages exactly the realms created by the module. It has no rights on
the master realm itself. Every realm other than master belongs to the
module, so the realms visible to `ns8-agent` are the managed realms.
Verified on rl1: after creating a realm, `GET /admin/realms` returns
it, and master realm requests are forbidden. While `ns8-agent` has no
realm, `GET /admin/realms` is forbidden: the helper reads that as an
empty list.

### Init job

`keycloak-init.service` runs `bin/keycloak-init` with
`ConditionPathExists=!%E/state/ns8-agent.json`. The same job covers the
first start and credential recovery:

1. Run `kc.sh bootstrap-admin service` in a one-shot container in the
   pod, with a random client ID and secret (`--client-secret:env=`).
   Tested on rl1: on an empty database it creates the master realm and
   the temporary client in about 70 s (with the stock image, before the
   optimized build). It also logs an error about the
   existing client ID and exits with 0, so its exit code is not
   trusted.
2. Start a temporary Keycloak server in the pod, on port 8080, and wait
   until it answers.
3. With a token of the temporary client, create `ns8-agent`, or reset
   its secret if it exists. Assign it the `create-realm` role and the
   roles of the `<realm>-realm` client of every existing realm: a new
   client does not inherit the rights of the realms created by an old
   one.
4. Check a token of `ns8-agent`, then save its secret to
   `state/ns8-agent.json`. The file marks the job as done.
5. Delete the temporary client and stop the temporary server.

On later starts the helper uses the `ns8-agent` credentials. A failed
token request is an error: the helper does not fall back to other
credentials.

To recover lost credentials, for example after a partial restore,
remove `state/ns8-agent.json` and restart `keycloak.service`. Tested on
rl1, with one existing realm: the job reset the `ns8-agent` secret and
granted the realm roles again in about 2 minutes, and in about 1
minute with the optimized image. A dedicated action for
this is left to a future iteration. The path that creates `ns8-agent`
again, when the client itself is missing, is not tested yet.

## SMTP settings

Keycloak has no server-wide SMTP configuration: each realm stores its
own `smtpServer` settings. `tls_verify` has no realm equivalent. The
sender address is `IDP_SMTP_FROM`, or `no-reply@${IDP_HOSTNAME}` when
unset.

Events can be lost, so the SMTP settings are applied again every time
Keycloak starts:

- `bin/keycloak-post-start` applies the node smarthost settings to every
  realm managed by `ns8-agent`.
- `keycloak.service` runs it with `ExecStartPost=-runagent
  keycloak-post-start`, after the health check passes. The `-` prefix
  keeps a failure from failing the unit, which `Restart=always` would
  turn into a restart loop.
- `configure-module` starts the services, so the script runs implicitly
  after the first start and after every configuration change.
- The `smarthost-changed` event handler only runs the script. If
  Keycloak is not running, the script exits with success: the next
  start applies the settings.

## Tests

The Robot Framework suite in `tests/` runs in the two scenarios of the
NS8 test workflow, selected by the `SCENARIO` variable:

- `install`: install the module image under test, configure it without
  Let's Encrypt, and verify it.
- `update`: install the latest stable release, configure it, update it
  to the image under test with `update-module`, and verify it. The
  suite is skipped while idp has no stable release.

The verification checks that the pod units are active, that Keycloak
runs the image of the module, that the OIDC discovery document is
served through Traefik with the configured issuer, and that the
`ns8-agent` credentials are accepted by the admin API.

`update-module.d/80restart` reloads the units and restarts the running
services, so an update takes effect immediately. A module that is not
configured yet stays stopped.

## Open points

- `etc/state-include.conf` and the PostgreSQL dump for backup and
  restore.
- Realm creation per user domain and LDAP federation.
- Keycloak admin console exposure on the public host name.
- Do not run `systemd-analyze --user verify` in a module session: on
  rl1 it replaced the socket of the user manager with a dead one, and
  Podman could not create health check timers until the user manager
  was restarted.
