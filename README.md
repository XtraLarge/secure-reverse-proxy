# secure-reverse-proxy

[🇩🇪 Deutsche Version](README.de.md)

> Apache reverse proxy with built-in OIDC single sign-on, a web-based admin UI, and a live table-of-contents page for all your services.

[![Docker Image](https://img.shields.io/badge/Docker-xtralarge71%2Fsecure--reverse--proxy-blue?logo=docker)](https://hub.docker.com/r/xtralarge71/secure-reverse-proxy)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## What it does

One container sits in front of all your internal services.
Users authenticate once via your OIDC provider (Keycloak, Authentik, Dex, …) and
then access each proxied service without logging in again.

After login they land on the **Table of Contents** — a live overview of every service,
with per-row reachability status and a search filter.

![TOC page](docs/screenshots/toc.png)
<!-- TODO: screenshot of toc.<domain> after OIDC login -->

---

## Features

| | |
|---|---|
| **Single sign-on** | `mod_auth_openidc` — works with any OIDC/OAuth2 provider |
| **Per-service access control** | Each vhost restricts access by username (`preferred_username` claim) or group membership (`groups` claim), or both |
| **GeoIP country filter** | External traffic is restricted to a configurable list of countries |
| **Table of contents** | OIDC-protected overview page (`toc.<domain>`) with live reachability checks |
| **Admin UI** | Browser-based vhost editor at `admin.<domain>` — add, edit and reload vhosts without SSH |
| **Keycloak user management** | Create, edit and manage Keycloak users from the admin UI (`admin.<domain>/admin-kc.lua`) |
| **Backchannel logout** | Logout propagates to the OIDC provider and clears the Redis session |
| **Redis session cache** | One session shared across all subdomains of a domain |
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
├── .env                        ← secrets (gitignored)
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
    ├── extra-countries.conf    ← GeoIP country allow-list (written by geolock UI)
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
| `REDIS_PASSWORD` | — | — | Redis password; leave empty to disable auth |

### Access control

| Variable | Required | Default | Description |
|---|---|---|---|
| `INTERNAL_NETWORKS` | — | — | Comma-separated CIDRs that bypass GeoIP and OIDC auth (e.g. `10.0.0.0/8,192.168.0.0/16`) |
| `GEOIP_ALLOW_COUNTRIES` | — | `DE` | Pipe-separated ISO 3166-1 alpha-2 country codes allowed for external traffic (e.g. `DE\|AT\|CH`) |

### TLS / ACME

| Variable | Required | Default | Description |
|---|---|---|---|
| `ACME_EMAIL` | — | — | If set, certbot requests Let's Encrypt certificates for all domains automatically |

### Keycloak user management

| Variable | Required | Default | Description |
|---|---|---|---|
| `KEYCLOAK_ADMIN_URL` | — | auto-derived | Keycloak Admin REST API base URL, e.g. `https://sso.example.com/admin/realms/myrealm`. Auto-derived from `OIDC_PROVIDER_METADATA_URL` if not set. |
| `KEYCLOAK_ROLE_PREFIX` | — | — | Only show/manage roles with this name prefix (e.g. `proxy-`). Empty = all roles. |

### Other

| Variable | Required | Default | Description |
|---|---|---|---|
| `APACHE_SERVER_NAME` | — | `localhost` | Global Apache `ServerName` (suppresses `AH00558`) |
| `TOC_TITLE` | — | domain name | Title shown on the TOC page |

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
the bottom. `Domain_Init` automatically creates:

- `https://example.com` → redirect to `https://www.example.com`
- `https://toc.example.com` → OIDC-protected table of contents
- `https://logout.example.com` → OIDC logout and confirmation page

```apache
USE Domain_Init example.com www

# ... your vhosts here ...

USE Domain_Final example.com www
```

### Vhost macros

```apache
# Redirect alias (no auth)
Use VHost_Alias  <site>  <domain>  <target-url>

# Reverse proxy — specific OIDC users only (pipe-separated, case-insensitive)
Use VHost_Proxy_OIDC_User  <site>  <domain>  <backend-url>/  'alice|bob'

# Reverse proxy — specific OIDC groups only (pipe-separated, case-insensitive)
Use VHost_Proxy_OIDC_Group  <site>  <domain>  <backend-url>/  'editors|admins'

# Reverse proxy — any authenticated OIDC user
Use VHost_Proxy_OIDC_Any  <site>  <domain>  <backend-url>/

# Reverse proxy — HTTP Basic auth
Use VHost_Proxy_Basic  <site>  <domain>  <backend-url>/  user  'username'

# Reverse proxy — HTTP Basic auth + WebSocket (e.g. Frigate, Home Assistant)
Use VHost_Proxy_WS_Basic  <site>  <domain>  <backend-url>/  user  'username'

# Reverse proxy — no auth (backend handles its own auth)
Use VHost_Proxy  <site>  <domain>  <backend-url>/

# Admin UI (optional)
Use Admin_VHost  <domain>  'alice'
```

### Example

```apache
USE Domain_Init example.com www

Use VHost_Alias          www       example.com  https://www-backend.internal/
Use VHost_Proxy_OIDC_User  app       example.com  http://10.0.0.5:8080/   'alice|bob'
Use VHost_Proxy_OIDC_Group wiki      example.com  http://10.0.0.8:3000/   'editors'
Use VHost_Proxy_OIDC_Any   monitor   example.com  http://10.0.0.6:3000/
Use VHost_Proxy          idp       example.com  https://10.0.0.7:8443/
Use Admin_VHost          example.com  'alice'

USE Domain_Final example.com www
```

This creates the following vhosts:

| URL | Auth | Backend |
|---|---|---|
| `https://www.example.com` | — | `https://www-backend.internal/` |
| `https://app.example.com` | OIDC (alice or bob only) | `http://10.0.0.5:8080/` |
| `https://wiki.example.com` | OIDC (group: editors) | `http://10.0.0.8:3000/` |
| `https://monitor.example.com` | OIDC (any user) | `http://10.0.0.6:3000/` |
| `https://idp.example.com` | none | `https://10.0.0.7:8443/` |
| `https://toc.example.com` | OIDC (any user) | built-in TOC page |
| `https://admin.example.com` | OIDC (alice only) | built-in admin UI |
| `https://logout.example.com` | — | built-in logout page |

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

After login, users land here. All vhosts configured for the domain are listed
with their current reachability status (green/red dot). The list is filterable.

![TOC page](docs/screenshots/toc.png)
<!-- TODO: screenshot -->

### Admin UI (`admin.<domain>`)

Available when `Use Admin_VHost` is included in the site config.
Only the listed user(s) can log in.

The admin UI lets you:

- **View** the expanded Apache configuration for each vhost
- **Add and edit** vhost configurations directly in the browser
- **Reload** the Apache configuration without restarting the container
- **Create and rotate Keycloak clients** per domain — the proxy-`<domain>` client,
  `admin`/`user` roles, and `<domain>-admins`/`<domain>-users` groups are set up
  automatically; the per-domain credentials are stored in `config/oidc-clients/<domain>.conf`

![Admin UI](docs/screenshots/admin.png)
<!-- TODO: screenshot -->

### Keycloak user management (`admin.<domain>/admin-kc.lua`)

Requires `KEYCLOAK_ADMIN_URL` (or `OIDC_PROVIDER_METADATA_URL` in standard
Keycloak format). The logged-in admin's OIDC access token is used — no separate
service account needed.

Lets you:

- **List and search** Keycloak users
- **Create** users with a temporary password
- **Edit** name, email, and group assignments
- **Reset** passwords
- **Enable / disable** or **delete** users
- **Manage groups** — create and delete `<domain>-admins` / `<domain>-users` groups

![Keycloak user management](docs/screenshots/admin-kc.png)
<!-- TODO: screenshot -->

**Required Keycloak roles** for the admin user (Client Roles → `realm-management`):

| Role | Purpose |
|---|---|
| `view-users` | List and view users |
| `manage-users` | Create, update, delete users and set passwords |
| `query-roles` | List realm roles |

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

For a fully prepared local test stack with realm import and sample users, see
[`examples/keycloak/`](examples/keycloak/README.md).

### Other providers

Any OIDC-compliant provider works (Authentik, Dex, Azure AD, Google, …).
Set `OIDC_PROVIDER_METADATA_URL` to the provider's discovery endpoint and
configure the redirect URI as `https://*.example.com/<OIDC_REDIRECT_PATH>`.

---

## Running

```bash
# Start
docker compose up -d

# View logs
docker compose logs -f proxy

# Test Apache config without restarting
docker compose exec proxy apache2ctl configtest

# Reload Apache (full restart via tini — graceful reload not reliable in Docker)
docker compose exec proxy kill -TERM 1

# Stop
docker compose down
```

---

## Docker Hub

```bash
docker pull xtralarge71/secure-reverse-proxy:latest
```

To use the pre-built image instead of building locally, set `image:` in
`docker-compose.yml`:

```yaml
services:
  proxy:
    image: xtralarge71/secure-reverse-proxy:latest
    cap_add:
      - CHOWN
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
