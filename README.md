# apache-oidc-proxy

Apache reverse proxy with:
- **mod_auth_openidc** — OIDC/OAuth2 single sign-on
- **mod_macro** — reusable vhost templates
- **mod_geoip** — country-based access control
- **mod_lua** — dynamic table-of-contents page (`toc.<domain>`)
- **Redis** session cache (shared across all subdomains)

After login the user lands on `toc.<domain>` — a filterable table of all configured services with live reachability status. Logout triggers OIDC backchannel logout and shows an animated terminal page before redirecting back.

---

## Requirements

| Requirement | Notes |
|---|---|
| Docker + Docker Compose v2 | `docker compose` (not `docker-compose`) |
| Wildcard TLS certificate | One per domain, e.g. from Let's Encrypt |
| OIDC provider | Keycloak, Authentik, Dex, … |
| DNS | `*.example.com` → this host |

---

## Quick start

```bash
git clone https://github.com/XtraLarge/apache-oidc-proxy.git
cd apache-oidc-proxy
cp .env.example .env
# edit .env — see section below
mkdir -p ssl/<yourdomain> sites-enabled AddOn/<yourdomain>
# copy certs and create sites-enabled/<yourdomain>.conf
docker compose up -d
```

For a full local OIDC demo including Keycloak, see [`examples/keycloak/`](examples/keycloak/).
If you want Keycloak directly in the root compose stack, start with
`docker compose --profile keycloak up -d`.

---

## Directory layout

```
apache-oidc-proxy/
├── docker-compose.yml
├── .env                        ← secrets, gitignored
├── ssl/                        ← TLS certs, gitignored
│   └── <domain>/
│       ├── cert.pem
│       ├── key.pem
│       └── fullchain.pem
├── sites-enabled/              ← your vhost configs, gitignored
│   └── <domain>.conf
└── AddOn/                      ← optional per-vhost snippets, gitignored
    └── <domain>/
        ├── <site>.preconfig    ← included before ProxyPass
        └── <site>.postconfig   ← included after ProxyPass
```

The `ssl/`, `sites-enabled/` and `AddOn/` directories are bind-mounted into the container as read-only volumes and are **never committed to git**.

---

## TLS certificates

Place the certificate files for each domain into `ssl/<domain>/`:

```bash
ssl/
└── example.com/
    ├── cert.pem        # server certificate
    ├── key.pem         # private key
    └── fullchain.pem   # full chain (cert + intermediates)
```

### Let's Encrypt (certbot)

If your certs live at `/etc/letsencrypt/live/<domain>/`, mount or symlink them:

```bash
# Option A: symlink
mkdir -p ssl
ln -s /etc/letsencrypt/live/example.com ssl/example.com

# Option B: adjust the ssl volume in docker-compose.yml
volumes:
  - /etc/letsencrypt/live:/etc/apache2/ssl:ro
```

### Existing certificate directory (e.g. `/etc/apache2/ssl/Proxy/`)

If your certs are already at a path like `/etc/apache2/ssl/Proxy/<domain>/`, adjust the volume mount:

```yaml
volumes:
  - /etc/apache2/ssl/Proxy:/etc/apache2/ssl:ro
```

---

## Environment variables (`.env`)

Copy `.env.example` to `.env` and fill in your values.

| Variable | Required | Description |
|---|---|---|
| `OIDC_PROVIDER_METADATA_URL` | ✓ | OIDC discovery endpoint (`/.well-known/openid-configuration`) |
| `OIDC_CLIENT_ID` | — | Client ID registered in your IdP (default: `Proxy`) |
| `OIDC_CLIENT_SECRET` | ✓ | Client secret |
| `OIDC_CRYPTO_PASSPHRASE` | — | Optional session encryption key; if unset, the container auto-generates and rotates it daily |
| `OIDC_COOKIE_DOMAIN` | ✓ | Base domain for session cookies, e.g. `example.com` |
| `OIDC_DEFAULT_LOGOUT_URL` | — | Post-logout redirect (default: `https://logout.<DOMAIN>/help?text=Logout%20successful!`) |
| `OIDC_REMOTE_USER_CLAIM` | — | Claim mapped to `REMOTE_USER` (default: `email`) |
| `OIDC_SCOPE` | — | OAuth2 scopes (default: `openid email`) |
| `OIDC_REDIRECT_PATH` | — | OIDC callback path (default: `/protected`) |
| `APACHE_SERVER_NAME` | — | Global Apache `ServerName` used to suppress `AH00558` (default: `localhost`) |
| `REDIS_HOST` | — | Redis hostname (default: `redis`) |
| `REDIS_PORT` | — | Redis port (default: `6379`) |
| `REDIS_DB` | — | Redis database index (default: `1`) |
| `REDIS_PASSWORD` | — | Redis password — leave empty to disable auth |
| `GEOIP_ALLOW_COUNTRIES` | — | Pipe-separated ISO codes (default: `DE`) |
| `INTERNAL_NETWORKS` | — | Comma-separated CIDRs that bypass GeoIP + auth |
| `TOC_TITLE` | — | Title shown on the TOC page |
| `KEYCLOAK_IMAGE` | — | Optional bundled Keycloak image when using `--profile keycloak` |
| `KEYCLOAK_ADMIN` | — | Optional bundled Keycloak admin user |
| `KEYCLOAK_ADMIN_PASSWORD` | — | Optional bundled Keycloak admin password |
| `KEYCLOAK_HOST` | — | Public hostname bundled Keycloak should advertise |

---

## Site configuration

Create one `.conf` file per domain in `sites-enabled/`. Use the macros provided by the image — see `conf/sites-available/example.conf` for a full reference.

### Available macros

```apache
# Redirect alias (no auth)
Use VHost_Alias  <site>  <domain>  <target-url>

# Reverse proxy — specific OIDC users only (pipe-separated, case-insensitive)
Use VHost_Proxy_OIDC  <site>  <domain>  <backend-url>/  'alice|bob'

# Reverse proxy — any authenticated OIDC user (use sparingly)
Use VHost_Proxy_OIDC_Any  <site>  <domain>  <backend-url>/

# Reverse proxy — HTTP Basic auth
Use VHost_Proxy_Basic  <site>  <domain>  <backend-url>/  user  'username'

# Reverse proxy — no auth (backend handles it, e.g. identity provider, file server)
Use VHost_Proxy  <site>  <domain>  <backend-url>/
```

Every domain needs `Domain_Init` at the top and `Domain_Final` at the bottom:

```apache
USE Domain_Init example.com www

Use VHost_Proxy_OIDC  monitor  example.com  http://10.0.0.5:3000/  'alice|bob'
Use VHost_Proxy  files  example.com  http://10.0.0.6/

USE Domain_Final example.com www
```

`Domain_Init` automatically creates:
- `http(s)://example.com` → redirect to `https://www.example.com`
- `https://toc.example.com` → OIDC-protected table of contents (Lua)
- `https://logout.example.com` → OIDC logout + animated confirmation page

### HTTPS backends with self-signed certificates

The `PROXY` macro verifies backend TLS by default. For internal backends with self-signed certs, create an `AddOn/<domain>/<site>.preconfig` snippet:

```apache
# AddOn/example.com/backup.preconfig
SSLProxyVerify none
SSLProxyCheckPeerCN off
SSLProxyCheckPeerName off
SSLProxyCheckPeerExpire off
```

### WebSocket backends

Add WebSocket rewrite rules in an `AddOn/<domain>/<site>.preconfig`:

```apache
# AddOn/example.com/iot.preconfig — WebSocket support
ProxyPass /api/websocket ws://10.0.0.7:8123/api/websocket
ProxyPassReverse /api/websocket ws://10.0.0.7:8123/api/websocket
RewriteEngine on
RewriteCond %{HTTP:Upgrade} =websocket [NC]
RewriteRule /(.*)  ws://10.0.0.7:8123/$1 [P,L]
RewriteCond %{HTTP:Upgrade} !=websocket [NC]
RewriteRule /(.*)  http://10.0.0.7:8123/$1 [P,L]
```

For more production-like patterns, see the anonymized examples in
[`examples/addons/`](examples/addons/README.md), including:

- Office suite WOPI endpoints and WebSocket routing (`office.preconfig`)
- File sync WebSocket and large-upload tuning (`files.preconfig`)
- Identity provider forwarded headers (`idp.preconfig`)
- HTTPS backends with self-signed certs and WebSocket upgrade (`backup.preconfig`, `cluster.preconfig`)

---

## OIDC provider setup (Keycloak example)

1. Create a client with **Client ID** = `Proxy` (or whatever `OIDC_CLIENT_ID` is set to)
2. Set **Access Type** = `confidential`
3. Add redirect URIs: `https://*.example.com/protected`
4. Copy the client secret to `OIDC_CLIENT_SECRET` in `.env`
5. The `preferred_username` claim is used for user matching in `VHost_Proxy_OIDC`

For a fully prepared local Keycloak stack with realm import, test user and sample
proxy config, see [`examples/keycloak/README.md`](examples/keycloak/README.md).

## Optional bundled Keycloak in root compose

The root [`docker-compose.yml`](/root/codex/apache-oidc-proxy/repo/docker-compose.yml)
also contains a `keycloak` service behind the optional `keycloak` profile.
This keeps the default deployment slim, but makes Keycloak part of the same stack
when you want it there.

Start it with:

```bash
docker compose --profile keycloak up -d
```

The bundled service:

- imports realm files from [`keycloak/`](/root/codex/apache-oidc-proxy/repo/keycloak/)
- uses `KEYCLOAK_HOST` as its public browser-facing hostname
- stays on the internal `backend` network, so you would usually expose it through
  a normal `Use VHost_Proxy keycloak <domain> http://keycloak:8080/` vhost

---

## Running

```bash
# Start (pulls image from Docker Hub if not built locally)
docker compose up -d

# View logs
docker compose logs -f proxy

# Test Apache config without restarting
docker compose exec proxy apache2ctl configtest

# Reload Apache config (e.g. after changing sites-enabled/)
docker compose exec proxy apache2ctl graceful

# Stop
docker compose down
```

---

## Built-in pages

| URL | Description |
|---|---|
| `https://toc.<domain>/` | Table of contents — all configured services, filterable, with live status |
| `https://toc.<domain>/cgi/echo.pl` | Dumps all Apache environment variables (OIDC claims, headers, …) |
| `https://logout.<domain>/` | Triggers OIDC logout and redirects to the animated confirmation page |
| `https://logout.<domain>/help?text=<message>` | Animated terminal page, redirects to `https://<domain>` after display |

---

## Image on Docker Hub

```
docker pull xtralarge71/apache-oidc-proxy:latest
```

Set `image:` instead of `build:` in `docker-compose.yml` to use the pre-built image:

```yaml
services:
  proxy:
    image: xtralarge71/apache-oidc-proxy:latest
    cap_add:
      - CHOWN
      - NET_BIND_SERVICE
      - SETGID
      - SETUID
```

`CHOWN`, `SETGID` and `SETUID` are required so Apache can switch from `root` to
`www-data` and start `mod_cgid` cleanly. Without them, the proxy may still start,
but CGI-based debug endpoints such as `toc.<domain>/cgi/echo.pl` can fail at runtime.

---

## Development / local build

```bash
docker build -t apache-oidc-proxy:local .
# run tests
tests/run-tests.sh apache-oidc-proxy:local
```
