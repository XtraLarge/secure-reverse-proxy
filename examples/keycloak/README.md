# Optional Keycloak dev/test stack

This example keeps the main repository deployment slim and adds Keycloak only for
local end-to-end testing.

It starts:

- `proxy` - this repository's Apache OIDC reverse proxy
- `redis` - OIDC session cache
- `keycloak` - local OIDC provider with a pre-imported realm
- `whoami` - a tiny backend to verify authenticated proxying

The example uses the wildcard dev domain `*.127.0.0.1.nip.io`, which resolves to
`127.0.0.1` without editing `/etc/hosts`.

## Quick start

```bash
cd examples/keycloak
./prepare.sh
docker compose up -d --build
```

Then open:

- `https://keycloak.127.0.0.1.nip.io:8443/` - Keycloak via the proxy
- `https://whoami.127.0.0.1.nip.io:8443/` - OIDC-protected test backend
- `https://toc.127.0.0.1.nip.io:8443/` - generated TOC page

Default login:

- user: `demo`
- password: `demo`

Keycloak admin:

- user: `admin`
- password: `admin`

## What `prepare.sh` does

- copies `.env.example` to `.env` if needed
- generates a self-signed wildcard certificate for `127.0.0.1.nip.io`
- stores it under `ssl/127.0.0.1.nip.io/`

## How the OIDC loop works

The proxy publishes `keycloak.127.0.0.1.nip.io:8443` as an unauthenticated reverse
proxy to the local Keycloak container, so the browser always sees a realistic HTTPS
issuer URL.

`mod_auth_openidc` fetches the discovery document internally from
`http://keycloak:8080/...` on the Docker network. Keycloak is started with its public
hostname set to `https://keycloak.127.0.0.1.nip.io:8443`, so the returned issuer and
authorization endpoints still match the browser-facing URL.

## Keycloak client requirements

When configuring the `Proxy` client in Keycloak for use with `mod_auth_openidc`:

**PKCE must be disabled.**
`mod_auth_openidc` does not send a `code_challenge` by default. If PKCE is
enforced on the Keycloak client (`pkce.code.challenge.method = S256`), the
authorization request will be rejected with:

```
Missing parameter: code_challenge_method
```

Set `pkce.code.challenge.method` to empty/unset in the client attributes.

**Redirect URIs must be explicit, not just wildcards.**
Keycloak 26 does not match `https://*.example.com/protected` as a wildcard for
exact callback URLs in some configurations. Add the exact callback URL
(`https://myapp.example.com/protected`) explicitly alongside any wildcard entries.

**Token endpoint routing inside the container.**
`mod_auth_openidc` reads all endpoint URLs from the OIDC discovery document.
If Keycloak is started with `--hostname=https://iam.example.com`, those endpoints
will reference `iam.example.com`. The proxy container must be able to reach that
host for the token exchange step.

If `iam.example.com` is served by the same Apache container (as a `VHost_Proxy`
pointing to `http://keycloak:8080/`), add an `extra_hosts` entry in your
Compose file so the container resolves `iam.example.com` to its own VLan/bridge IP
instead of going through external DNS (which might point to a different server):

```yaml
services:
  proxy:
    extra_hosts:
      - "iam.example.com:10.0.0.1"  # container's own network IP
```

This avoids a loopback deadlock and lets the self-referential token exchange
complete via a proper TCP connection on the external interface.

## Important limits

- This is a dev/test setup only.
- The certificate is self-signed. Your browser will warn until you trust it.
- Keep `.env` local. Do not commit real secrets.
- The example default for `INTERNAL_NETWORKS` intentionally excludes `172.16.0.0/12`,
  because Docker bridge traffic often comes from that range and would otherwise bypass OIDC during local tests.
- The example default for `GEOIP_ALLOW_COUNTRIES` is `|DE`, which means:
  empty GeoIP country code or `DE` are accepted. This keeps local Docker-based tests
  in the OIDC flow even when private bridge addresses have no country match.
