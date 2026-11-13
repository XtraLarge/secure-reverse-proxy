# secure-reverse-proxy

[🇩🇪 Deutsche Version](README.de.md)

> Apache reverse proxy with built-in OIDC single sign-on, a web-based admin UI, and a live table-of-contents page for all your services.

[![Container Image](https://img.shields.io/badge/ghcr.io-xtralarge%2Fsecure--reverse--proxy-blue?logo=github)](https://github.com/XtraLarge/secure-reverse-proxy/pkgs/container/secure-reverse-proxy)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## What it does

One container sits in front of all your internal services.
Users authenticate once via your OIDC provider (Keycloak, Authentik, Dex, …) and
then access each proxied service without logging in again.

After login they land on the **Table of Contents** — a live overview of every service,
with per-row reachability status, the effective country lock and column filters.

---

## Features

| | |
|---|---|
| **Single sign-on** | `mod_auth_openidc` — works with any OIDC/OAuth2 provider |
| **Per-service access control** | Each vhost restricts access by username (`preferred_username` claim) or group membership (`groups` claim), or both |
| **GeoIP country lock** | External traffic is restricted to a configurable list of countries; the lock can be switched per site in the admin UI |
| **GeoLock page** | `geolock.<domain>` — temporarily allow extra countries (e.g. while travelling), protected by OIDC login + PIN and reachable worldwide |
| **Table of contents** | Overview page (`toc.<domain>`) with live internal/external reachability checks and the effective GeoIP lock per entry |
| **Admin UI** | Browser-based vhost editor at `admin.<domain>` — add, edit and reload vhosts without SSH; always requires login |
| **Keycloak user management** | Create, edit and manage Keycloak users from the admin UI (`admin.<domain>/admin-kc.lua`) |
| **Backchannel logout** | Logout propagates to the OIDC provider and clears the Redis session |
| **Redis session cache** | One session shared across all subdomains of a domain |
| **Secrets as files** | Every secret can be passed as `<VAR>_FILE`; secrets are removed from the environment before Apache starts |
| **Let's Encrypt / ACME** | Automatic certificate provisioning and renewal via certbot |
| **WebSocket support** | Pass-through WebSocket connections to backends |
| **mod_macro templates** | Reusable vhost patterns — one line per service |
| **Passphrase rotation** | OIDC session encryption key is auto-generated and rotated daily |

---

## Quick start

### 1. Clone and configure

```bash
git clone https://github.com/XtraLarge/secure-reverse-proxy.git
cd secure-reverse-proxy
```

**Option A — interactive setup (recommended):**

```bash
bash scripts/setup.sh
```

The script asks for all required values, auto-generates secrets for Redis and
the OIDC session passphrase, and creates the directory structure for you.

**Option B — manual:**

```bash
cp .env.example .env
```

Edit `.env` — the minimum required values are:

```dotenv
OIDC_PROVIDER_METADATA_URL=https://sso.example.com/realms/myrealm/.well-known/openid-configuration
OIDC_CLIENT_SECRET=your-client-secret
OIDC_COOKIE_DOMAIN=example.com
```

### 2. Add TLS certificates

```bash
mkdir -p ssl/example.com
cp /path/to/cert.pem      ssl/example.com/cert.pem
cp /path/to/key.pem       ssl/example.com/key.pem
cp /path/to/fullchain.pem ssl/example.com/fullchain.pem
```

### 3. Create a site configuration

```bash
mkdir -p sites
cp conf/sites-available/example.conf sites/example.com.conf
# edit sites/example.com.conf — replace example.com with your domain
# and 'alice' with the user(s) allowed to use the admin UI
```

### 4. Start

```bash
docker compose up -d
```

Open `https://toc.example.com` — you will be redirected to your OIDC provider
and land on the table of contents after login.

---

> **Local test without a real domain or OIDC provider?**
> See [`examples/keycloak/`](examples/keycloak/README.md) for a self-contained
> stack with Keycloak, a test user, and a sample proxied backend.

---

## Directory layout

```
secure-reverse-proxy/
├── docker-compose.yml
├── .env                        ← settings and secrets (gitignored)
├── ssl/                        ← TLS certificates (gitignored)
│   └── <domain>/
│       ├── cert.pem
│       ├── key.pem
│       └── fullchain.pem
├── sites/                      ← your vhost configs (gitignored)
│   └── <domain>.conf
├── AddOn/                      ← optional per-vhost Apache snippets (gitignored)
│   └── <domain>/
│       ├── <site>.preconfig    ← included before ProxyPass
│       └── <site>.postconfig   ← included after ProxyPass
└── config/                     ← runtime config (gitignored)
    ├── basic.htpasswd          ← Basic Auth user database
    ├── extra-countries.conf    ← extra allowed countries (written by the GeoLock page)
    ├── geolock/                ← per-site GeoLock overrides (written by the admin UI)
    │   └── <domain>/<site>.conf
    └── oidc-clients/           ← per-domain OIDC credentials (written by admin UI)
        └── <domain>.conf       ← OIDCClientID / OIDCClientSecret overrides
```

`ssl/`, `sites/`, `AddOn/` and `config/` are bind-mounted into the container and
are never committed to git.

---

## Environment variables

Copy `.env.example` to `.env` and fill in your values.

### OIDC

| Variable | Required | Default | Description |
|---|---|---|---|
| `OIDC_PROVIDER_METADATA_URL` | ✓ | — | OIDC discovery endpoint |
| `OIDC_CLIENT_ID` | — | `Proxy` | Client ID registered in your IdP |
| `OIDC_CLIENT_SECRET` | ✓ | — | Client secret |
| `OIDC_COOKIE_DOMAIN` | ✓ | — | Base domain for session cookies, e.g. `example.com` |
| `OIDC_SCOPE` | — | `openid email` | OAuth2 scopes (must include `openid`) |
| `OIDC_REMOTE_USER_CLAIM` | — | `email` | Claim mapped to `REMOTE_USER` |
| `OIDC_REDIRECT_PATH` | — | `/protected` | OIDC callback path |
| `OIDC_DEFAULT_LOGOUT_URL` | — | auto | Post-logout redirect URL |
| `OIDC_CRYPTO_PASSPHRASE` | — | auto-generated | Session encryption key; auto-generated and rotated daily if not set |
| `OIDC_PROVIDER_TOKEN_ENDPOINT_AUTH` | — | `client_secret_basic` | Token endpoint auth method |

### Redis

| Variable | Required | Default | Description |
|---|---|---|---|
| `REDIS_HOST` | — | `redis` | Redis hostname |
| `REDIS_PORT` | — | `6379` | Redis port |
| `REDIS_DB` | — | `1` | Redis database index |
| `REDIS_PASSWORD` | — | — | Redis password; strongly recommended (leave empty only for tests) |

### Access control

| Variable | Required | Default | Description |
|---|---|---|---|
| `INTERNAL_NETWORKS` | — | — | Comma-separated CIDRs that bypass the country lock and the login of normal sites (e.g. `10.0.0.0/8,192.168.0.0/16`). **Not** for the admin UI and the GeoLock page: they always require login. |
| `GEOIP_ALLOW_COUNTRIES` | — | `DE` | Pipe-separated ISO 3166-1 alpha-2 country codes allowed for external traffic (e.g. `DE\|AT\|CH`) |
| `GEOIP_ACCOUNT_ID` / `GEOIP_LICENSE_KEY` | — | — | MaxMind credentials to download a current GeoLite2-Country database on start and weekly; without them the bundled database is used |

> Internal clients only count as internal if they reach the proxy directly. If your
> internal DNS resolves the service names to your public IP (NAT hairpin), the proxy
> sees the router's public address and treats them as external. Use split DNS (the
> service names resolve to the proxy's internal IP) so that `INTERNAL_NETWORKS` applies.

### GeoLock page

| Variable | Required | Default | Description |
|---|---|---|---|
| `GEOLOCK_PIN` | — | — | PIN required on `geolock.<domain>` (stored only as a hash). Without it the page shows "not configured". Use more than 4 digits. |
| `GEOLOCK_COUNTRIES` | — | — | Extra countries (pipe-separated) written to `config/extra-countries.conf` on the **first** start only, i.e. when the file does not exist yet. Afterwards the GeoLock page owns the file. |

### TLS / ACME

| Variable | Required | Default | Description |
|---|---|---|---|
| `ACME_EMAIL` | — | — | If set, certbot requests Let's Encrypt certificates for all domains automatically |
| `ACME_DOMAINS` | — | auto | Comma-separated root domains; default: detected from the site configs |
| `ACME_SERVER` | — | Let's Encrypt | ACME directory URL (e.g. the staging endpoint for tests) |

### Keycloak user management

| Variable | Required | Default | Description |
|---|---|---|---|
| `KEYCLOAK_ADMIN_URL` | — | auto-derived | Keycloak Admin REST API base URL, e.g. `https://sso.example.com/admin/realms/myrealm`. Auto-derived from `OIDC_PROVIDER_METADATA_URL` if not set. |
| `KEYCLOAK_REALM` | — | `master` | Realm the proxy clients and users live in |
| `KEYCLOAK_ROLE_PREFIX` | — | — | Only show/manage roles with this name prefix (e.g. `proxy-`). Empty = all roles. |
| `KEYCLOAK_API_CLIENT_ID` | — | — | Confidential client with a service account (client credentials) used by the admin UI and the redirect-URI sync. Give it only the needed `realm-management` roles (in realm `master`: client `master-realm`): `view-users`, `query-users`, `manage-users`, `query-groups`, `view-clients`, `query-clients`, `manage-clients`, `view-realm`. |
| `KEYCLOAK_API_CLIENT_SECRET` | — | — | Secret of that client (or `KEYCLOAK_API_CLIENT_SECRET_FILE`) |
| `KEYCLOAK_ADMIN_USER` / `KEYCLOAK_ADMIN_PASS` | — | — | Legacy: admin password grant via `admin-cli`. Only used if no service account is configured — prefer the service account. |

### Secrets as files

Every secret can be passed as a file instead: set `<VAR>_FILE=/run/secrets/<name>` and leave `<VAR>` unset (`OIDC_CLIENT_SECRET`, `OIDC_CRYPTO_PASSPHRASE`, `REDIS_PASSWORD`, `KEYCLOAK_API_CLIENT_SECRET`, `KEYCLOAK_ADMIN_PASS`, `GEOLOCK_PIN`, `GEOIP_LICENSE_KEY`, `ACME_EMAIL`). The entrypoint renders all configs and then removes the secrets from the environment before Apache and the background services start, so workers, Lua and CGI never see them. Rendered files containing secrets are root-only (0600).

### Logging

| Variable | Required | Default | Description |
|---|---|---|---|
| `LOG_FILE` | — | `/var/log/apache2/apache.log` | Consolidated log file; `off` disables local file logging |
| `SYSLOG_REMOTE` | — | — | Remote syslog target, e.g. `udp://10.0.0.20:514` |
| `LOG_RETENTION_DAYS` | — | `14` | Days to keep rotated log files |

### Other

| Variable | Required | Default | Description |
|---|---|---|---|
| `APACHE_SERVER_NAME` | — | `localhost` | Global Apache `ServerName` (suppresses `AH00558`) |
| `TOC_TITLE` | — | domain name | Title shown on the TOC page |
| `TOC_ACCOUNT_URL` | — | auto-derived | Link to the user's IdP account page (change password) in the TOC top bar. Derived from a Keycloak `OIDC_PROVIDER_METADATA_URL` (`…/realms/REALM/account/`); without either, no link is shown. |
| `HTTPS_PORT` | — | `443` | External HTTPS port; only change it if the proxy is exposed on a non-standard port |

---

## TLS certificates

### Manual certificates

Place certificate files under `ssl/<domain>/`:

```
ssl/example.com/
├── cert.pem        # server certificate
├── key.pem         # private key
└── fullchain.pem   # full chain (cert + intermediates)
```

The entrypoint detects certificates at startup and configures SSL automatically for
each domain that has a matching cert directory.

### Let's Encrypt (automatic)

Set `ACME_EMAIL` in `.env`. The entrypoint runs certbot on startup and installs
a weekly cron job for renewal. Certificates are stored in the `letsencrypt` volume.

```dotenv
ACME_EMAIL=admin@example.com
```

Expose port 80 so certbot can complete the HTTP-01 challenge.

---

## Site configuration

Create one `.conf` file per domain in `sites/`. Use the macros provided —
see [`conf/sites-available/example.conf`](conf/sites-available/example.conf) for
a full annotated reference.

### Domain frame

Every configuration file needs `Domain_Init` at the top and `Domain_Final` at
the bottom:

```apache
USE Domain_Init example.com www 'alice|bob'

# ... your vhosts here ...

USE Domain_Final example.com www
```

`Domain_Init <domain> <default-subdomain> '<admin-users>'` automatically creates:

- `https://example.com` → redirect to `https://www.example.com`
- `https://toc.example.com` → table of contents
- `https://logout.example.com` → OIDC logout and confirmation page
- `https://admin.example.com` → admin UI, only for the listed admin users
- `https://geolock.example.com` → GeoLock page, only for the listed admin users

The admin users are a pipe-separated list of `preferred_username` values,
matched case-insensitively. The admin and GeoLock vhosts are part of the frame
on purpose, so editing the domain body cannot remove them by accident — do not
add `Admin_VHost` or `GeoLock_VHost` yourself.

`Domain_Final` catches all undefined subdomains and redirects them to the
default subdomain.

For a secondary domain whose cookie domain differs from `OIDC_COOKIE_DOMAIN`,
use `Domain_Init_Simple <domain> <default-subdomain>` (no TOC, logout, admin or
OIDC directives).

### Vhost macros

```apache
# Redirect alias (no auth)
Use VHost_Alias  <site>  <domain>  <target-url>

# Reverse proxy — specific OIDC users only (pipe-separated, case-insensitive)
Use VHost_Proxy_OIDC_User  <site>  <domain>  <backend-url>/  'alice|bob'

# Reverse proxy — OIDC users and/or groups (pipe-separated, '' skips one side)
Use VHost_Proxy_OIDC  <site>  <domain>  <backend-url>/  'alice'  'editors|admins'

# Reverse proxy — any authenticated OIDC user
Use VHost_Proxy_OIDC_Any  <site>  <domain>  <backend-url>/

# Reverse proxy — HTTP Basic auth
Use VHost_Proxy_Basic  <site>  <domain>  <backend-url>/  user  'username'

# Reverse proxy — HTTP Basic auth + WebSocket (e.g. Frigate, Home Assistant)
Use VHost_Proxy_WS_Basic  <site>  <domain>  <backend-url>/  user  'username'

# Reverse proxy — no proxy login, country lock applies (backend handles its own auth)
Use VHost_Proxy  <site>  <domain>  <backend-url>/

# Reverse proxy — no proxy login and no country lock: reachable worldwide
Use VHost_Proxy_Open  <site>  <domain>  <backend-url>/
```

All `VHost_Proxy*` macros except `VHost_Proxy_Open` apply the country lock to
external clients. Clients from `INTERNAL_NETWORKS` skip both the country lock and
the proxy login.

### Example

```apache
USE Domain_Init example.com www 'alice'

Use VHost_Alias            www      example.com  https://www-backend.internal/
Use VHost_Proxy_OIDC_User  app      example.com  http://10.0.0.5:8080/   'alice|bob'
Use VHost_Proxy_OIDC       wiki     example.com  http://10.0.0.8:3000/   ''  'editors'
Use VHost_Proxy_OIDC_Any   monitor  example.com  http://10.0.0.6:3000/
Use VHost_Proxy            files    example.com  http://10.0.0.9:8080/
Use VHost_Proxy_Open       idp      example.com  https://10.0.0.7:8443/

USE Domain_Final example.com www
```

This creates the following vhosts (external access; internal networks skip
the country lock and the login of normal sites):

| URL | Auth | Country lock | Backend |
|---|---|---|---|
| `https://www.example.com` | — | — | redirect to `https://www-backend.internal/` |
| `https://app.example.com` | OIDC (alice or bob only) | yes | `http://10.0.0.5:8080/` |
| `https://wiki.example.com` | OIDC (group: editors) | yes | `http://10.0.0.8:3000/` |
| `https://monitor.example.com` | OIDC (any user) | yes | `http://10.0.0.6:3000/` |
| `https://files.example.com` | backend's own login | yes | `http://10.0.0.9:8080/` |
| `https://idp.example.com` | backend's own login | no | `https://10.0.0.7:8443/` |
| `https://toc.example.com` | OIDC (any user) | yes | built-in TOC page |
| `https://admin.example.com` | OIDC (alice only), also from internal networks | yes | built-in admin UI |
| `https://geolock.example.com` | OIDC (alice only) + PIN | no | built-in GeoLock page |
| `https://logout.example.com` | — | — | built-in logout page |

### GeoLock per site

The country lock (`GEOIP_ALLOW_COUNTRIES`, plus the countries added at `geolock.<domain>`) is a separate layer in every site macro. Each macro keeps its default (`VHost_Proxy_Open`: off, all others: on); the admin UI can switch it per site to *on* or *off* without changing the auth type. The setting is stored in `config/geolock/<domain>/<site>.conf`:

```apache
SetEnvIf Request_URI ^ GEOLOCK=on        # on: enforce the lock, also without auth
SetEnvIf Request_URI ^ AllowCountry=1    # off: lift the lock, authentication stays
```

*On* blocks other countries before authentication. With the default setting the
lock is part of the vhost's `Require` rules, so a preconfig with
`Require all granted` would lift it — set the site explicitly to *on* where the
lock must hold regardless of preconfigs.

Internal networks are never country-locked. A preconfig can still lift the lock for single paths, e.g. `SetEnvIf Request_URI "^/api/" AllowCountry=1`.

### What sites/, AddOn/ and config/ may contain

These directories are writable by the admin UI (www-data), while Apache's master runs
as root. So Apache never parses them directly: before every start and reload the
container copies them into a root-only snapshot (`/run/apache2/cfg`), checks the copy
with `proxy-config-guard.sh` and only then reads it. A rejected configuration stops the
start (fail closed) or skips the reload — Apache keeps the previous configuration — and
the findings are logged; the admin UI shows them before saving.

- `sites/*.conf`: only `Use <macro> …` lines (and `LogLevel`). The first two macro
  parameters must be plain site/domain names (no paths, no `..`).
- `AddOn/`: vhost directives, but no `LoadModule`/`LoadFile`, logs only to
  `/var/log/apache2/` or syslog (no piped logs), no `RewriteMap` programs, no SSL program
  hooks, no server-level directives (`User`, `PidFile`, `Mutex`, …), `Include` only of
  other AddOn files and the public runtime includes (`internal-networks.conf`,
  `internal-env.conf`, `iam-admin-oidc.conf`).
- `config/`: `oidc-clients/<domain>.conf` only `OIDC*` directives,
  `extra-countries.conf` and `geolock/…` only `SetEnvIf`.
- everywhere: no `${…}`, no `Define`/`UnDefine`, no own `<Macro>`, no symlinks or
  special files.

### Per-vhost AddOn snippets

For per-vhost Apache directives (SSL proxy settings, custom headers, WebSocket
rewrite rules), create files in `AddOn/<domain>/`:

```
AddOn/example.com/
├── app.preconfig     ← included before ProxyPass for app.example.com
└── app.postconfig    ← included after ProxyPass for app.example.com
```

**HTTPS backend with self-signed certificate:**

```apache
# AddOn/example.com/app.preconfig
SSLProxyVerify none
SSLProxyCheckPeerCN off
SSLProxyCheckPeerName off
SSLProxyCheckPeerExpire off
```

**WebSocket backend:**

Use `VHost_Proxy_WS_Basic` (or `VHost_Proxy_OIDC_*` with a `.preconfig` snippet) —
`upgrade=ANY` is already set in the macro, no extra RewriteRule needed:

```apache
# Basic auth + WebSocket (Frigate, Node-RED, …)
Use VHost_Proxy_WS_Basic  camera  example.com  http://10.0.0.9:5000/  user  'alice'

# OIDC + WebSocket (Home Assistant, …)
# Add to AddOn/example.com/ha.preconfig:
#   ProxyPassMatch ^/api/websocket ws://10.0.0.7:8123/api/websocket
```

More examples: [`examples/addons/`](examples/addons/README.md)

---

## Built-in pages

### Table of contents (`toc.<domain>`)

After login, users land here. Every vhost of the domain that the user is
allowed to use is listed with:

- **Status / Ext** — reachability checked every minute from inside (via the
  proxy's own internal address) and from outside (via the public IP of the
  domain); green = up, yellow = unexpected answer, red = down
- **GeoIP** — `ja`/`nein`: whether external access is limited to the allowed
  countries; the tooltip shows where the value comes from (macro default, admin
  UI setting, or fixed frame vhost)
- **Secured** — the authentication type (OpenID Connect, Basic, PIN, …)

The note above the table names the allowed countries and any temporarily
unlocked extra countries. Every column can be filtered.

From `INTERNAL_NETWORKS` the TOC opens without login.

### Admin UI (`admin.<domain>`)

Only the admin users listed in `Domain_Init` can log in — **always via OIDC, also
from internal networks**. State-changing requests are only accepted with a
logged-in user and an `Origin`/`Referer` of the admin host itself (protection
against cross-site requests, no form tokens needed).

The admin UI lets you:

- **View** the expanded Apache configuration for each vhost
- **Add and edit** vhost configurations directly in the browser
- **Switch the GeoLock per site** (default / on / off, see above)
- **Unlock the GeoLock page** after too many wrong PINs
- **Reload** the Apache configuration without restarting the container: the
  config is tested first, Keycloak redirect URIs are synced, then Apache reloads
  gracefully; a broken config is not applied
- **Create and rotate Keycloak clients** per domain — the proxy-`<domain>` client,
  `admin`/`user` roles, and `<domain>-admins`/`<domain>-users` groups are set up
  automatically; the per-domain credentials are stored in `config/oidc-clients/<domain>.conf`.
  This uses the service account from `KEYCLOAK_API_CLIENT_ID` (or the legacy admin password).

### Keycloak user management (`admin.<domain>/admin-kc.lua`)

Requires `KEYCLOAK_ADMIN_URL` (or `OIDC_PROVIDER_METADATA_URL` in standard
Keycloak format). The logged-in admin's own OIDC access token is used, so the
admin's Keycloak roles decide what is possible.

Lets you:

- **List and search** Keycloak users
- **Create** users with a temporary password
- **Edit** name, email, and group assignments
- **Reset** passwords
- **Enable / disable** or **delete** users
- **Manage groups** — create and delete `<domain>-admins` / `<domain>-users` groups

**Required Keycloak roles** for the admin user (Client Roles → `realm-management`):

| Role | Purpose |
|---|---|
| `view-users` | List and view users |
| `manage-users` | Create, update, delete users and set passwords |
| `query-roles` | List realm roles |

### GeoLock page (`geolock.<domain>`)

Lets the admin users allow extra countries for a while, e.g. while travelling.
It requires the OIDC login of an admin user **and** the `GEOLOCK_PIN`. Unlike the
admin UI it is reachable from every country — otherwise it could not be used
from abroad. After 3 wrong PINs the page locks itself until it is unlocked in the admin UI. The extra countries are stored in
`config/extra-countries.conf` and apply to all sites with the country lock; the
change takes effect after a graceful reload.

### Logout page (`logout.<domain>`)

Triggers OIDC backchannel logout, clears the Redis session, and shows an
animated terminal-style confirmation before redirecting back to the domain.

---

## OIDC provider setup

### Keycloak

1. Open **Clients** → **Create client**
2. Set **Client ID** to the value of `OIDC_CLIENT_ID` (default: `Proxy`)
3. Enable **Client authentication** (confidential)
4. Under **Valid redirect URIs**, add: `https://*.example.com/protected`
5. Copy the **Client secret** to `OIDC_CLIENT_SECRET` in `.env`
6. Set `OIDC_PROVIDER_METADATA_URL` to:
   `https://<keycloak-host>/realms/<realm>/.well-known/openid-configuration`

For the admin UI's Keycloak functions, create a second confidential client with
**Service accounts roles** enabled, assign it the `realm-management` roles listed
under [Keycloak user management](#keycloak-user-management) and set
`KEYCLOAK_API_CLIENT_ID` / `KEYCLOAK_API_CLIENT_SECRET`.

For a fully prepared local test stack with realm import and sample users, see
[`examples/keycloak/`](examples/keycloak/README.md).

### Other providers

Any OIDC-compliant provider works (Authentik, Dex, Azure AD, Google, …).
Set `OIDC_PROVIDER_METADATA_URL` to the provider's discovery endpoint and
configure the redirect URI as `https://*.example.com/<OIDC_REDIRECT_PATH>`.
The Keycloak-specific admin functions are not available then.

---

## Running

```bash
# Start
docker compose up -d

# View logs
docker compose logs -f proxy

# Test Apache config without restarting
docker compose exec proxy apache2ctl configtest

# Reload Apache gracefully (needs cap_add KILL, see Container Registry below);
# the admin UI's "apply" does the same plus configtest and Keycloak sync
docker compose exec proxy apache2ctl -k graceful

# Full restart via tini (fresh entrypoint run)
docker compose exec proxy kill -TERM 1

# Stop
docker compose down
```

---

## Container Registry

The image is built by GitHub Actions on every push to `master` and published to
the GitHub Container Registry. (The old Docker Hub repository is no longer
updated.)

```bash
docker pull ghcr.io/xtralarge/secure-reverse-proxy:latest
```

To use the pre-built image instead of building locally, set `image:` in
`docker-compose.yml`:

```yaml
services:
  proxy:
    image: ghcr.io/xtralarge/secure-reverse-proxy:latest
    cap_add:
      - CHOWN
      - KILL              # graceful reload: root master must signal the www-data mod_cgid daemon
      - NET_BIND_SERVICE
      - SETGID
      - SETUID
```

> `CHOWN`, `SETGID` and `SETUID` are required so Apache can switch from `root`
> to `www-data` after binding to ports 80/443. Without them the proxy still starts,
> but CGI endpoints (e.g. `toc.<domain>/cgi/echo.pl`) will fail at runtime.

---

## Development / local build

```bash
docker build -t secure-reverse-proxy:local .
tests/run-tests.sh secure-reverse-proxy:local
```
