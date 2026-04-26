#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  apache-oidc-proxy — full stack setup
#
#  Generates a complete, self-contained docker-compose deployment with:
#    - Apache OIDC reverse proxy (built from this repo)
#    - Keycloak identity provider (with pre-configured realm + users)
#    - Redis session cache
#    - whoami test backend (OIDC-protected demo endpoint)
#    - Self-signed TLS wildcard certificate
#
#  Usage:
#    bash scripts/setup.sh                  # interactive
#    bash scripts/setup.sh --no-deploy      # generate files only, skip docker up
#    bash scripts/setup.sh --force          # overwrite existing output dir
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

BOLD='\033[1m'; DIM='\033[2m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
RED='\033[0;31m'; CYAN='\033[0;36m'; RESET='\033[0m'

say()    { printf "${CYAN}▸${RESET} %s\n" "$*"; }
ok()     { printf "${GREEN}✔${RESET} %s\n" "$*"; }
warn()   { printf "${YELLOW}⚠${RESET}  %s\n" "$*"; }
err()    { printf "${RED}✖${RESET}  %s\n" "$*" >&2; }
header() { printf "\n${BOLD}%s${RESET}\n%s\n" "$1" "$(printf '─%.0s' $(seq 1 ${#1}))"; }
die()    { err "$*"; exit 1; }

ask() {
  local _var="$1" _prompt="$2" _default="${3:-}"
  local _hint=""
  [[ -n "$_default" ]] && _hint=" ${DIM}[${_default}]${RESET}"
  printf "${BOLD}%s${RESET}%b: " "$_prompt" "$_hint"
  local _val; IFS= read -r _val </dev/tty
  [[ -z "$_val" ]] && _val="$_default"
  printf -v "$_var" '%s' "$_val"
}

gen_secret() { openssl rand -hex 32; }
# URL-safe password: letters + digits + a few symbols, no ambiguous chars
gen_pass()   { openssl rand -base64 24 | tr -d 'lIO0/+=' | head -c 20; }

# ── arguments ─────────────────────────────────────────────────────────────────
FORCE=0; NO_DEPLOY=0
for arg in "$@"; do
  case "$arg" in
    --force)     FORCE=1 ;;
    --no-deploy) NO_DEPLOY=1 ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

command -v openssl >/dev/null || die "openssl not found — required for cert + secret generation"
command -v python3 >/dev/null || die "python3 not found — required for realm JSON generation"

# ── banner ────────────────────────────────────────────────────────────────────
echo
printf "${BOLD}apache-oidc-proxy — setup${RESET}\n"
printf "${DIM}Repo: %s${RESET}\n" "$REPO_DIR"
echo

# ── interactive questions ─────────────────────────────────────────────────────
header "Domain & Ports"
ask DOMAIN "Base domain (e.g. example.com)" ""
while [[ -z "$DOMAIN" || ! "$DOMAIN" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*\.)+[A-Za-z]{2,}$ ]]; do
  warn "Enter a valid domain (e.g. example.com)"
  ask DOMAIN "Base domain" ""
done

ask ADMIN_USER  "Admin username"      "admin"
ask TOC_TITLE   "TOC page title"      "Service Overview"

header "Network"
say "The proxy container gets its own IP on an existing macvlan Docker network."
say "Example: network name 'VLan10', container IP '10.10.25.50'."
ask MACVLAN_NET  "Existing macvlan network name"       "VLan10"
ask PROXY_IP     "Container IP on that network"        ""
while [[ -z "$PROXY_IP" || ! "$PROXY_IP" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; do
  warn "Enter a valid IP address"
  ask PROXY_IP "Container IP" ""
done
say "If traffic arrives via port-forward/NAT (e.g. router maps :9443 → :443),"
say "set the external HTTPS port below (what browsers see in URLs)."
ask HTTPS_PORT "External HTTPS port seen by browsers" "443"

header "Output Directory"
ask OUT_DIR "Where to generate files" "${REPO_DIR}/deploy-${DOMAIN}"

header "Deploy"
ask DOCKER_HOST_OPT "Docker host for deploy (empty = local socket)" ""

# ── derived values ────────────────────────────────────────────────────────────
[[ "$HTTPS_PORT" == "443" ]] && PORT_SUFFIX="" || PORT_SUFFIX=":${HTTPS_PORT}"
REALM="proxy"
CLIENT_ID="Proxy"
KC_HOSTNAME="https://iam.${DOMAIN}${PORT_SUFFIX}"

say "Generating secrets..."
KC_ADMIN_PASS="$(gen_pass)"
OIDC_CLIENT_SECRET="$(gen_secret)"
REDIS_PASSWORD="$(gen_secret)"
OIDC_CRYPTO_PASSPHRASE="$(gen_secret)"
ADMIN_PASS="$(gen_pass)"
USER_PASS="$(gen_pass)"

# ── output directory ──────────────────────────────────────────────────────────
if [[ -d "$OUT_DIR" && "$FORCE" -eq 0 ]]; then
  warn "Directory '$OUT_DIR' already exists."
  printf "Overwrite? (y/N): "; read -r _yn </dev/tty
  [[ "$_yn" =~ ^[Yy]$ ]] || { say "Aborted."; exit 0; }
fi

mkdir -p "${OUT_DIR}/sites-enabled" \
         "${OUT_DIR}/AddOn" \
         "${OUT_DIR}/keycloak" \
         "${OUT_DIR}/ssl/${DOMAIN}"

# ── self-signed wildcard TLS cert ─────────────────────────────────────────────
header "TLS Certificate"
SSL_DIR="${OUT_DIR}/ssl/${DOMAIN}"

# Try with SAN extension first (openssl ≥ 1.1.1), fall back for older versions
if openssl req -x509 -nodes -newkey rsa:3072 -days 3650 \
    -keyout "${SSL_DIR}/key.pem" \
    -out    "${SSL_DIR}/cert.pem" \
    -subj   "/CN=*.${DOMAIN}" \
    -addext "subjectAltName=DNS:${DOMAIN},DNS:*.${DOMAIN}" \
    -quiet  2>/dev/null; then
  :
else
  openssl req -x509 -nodes -newkey rsa:3072 -days 3650 \
    -keyout "${SSL_DIR}/key.pem" \
    -out    "${SSL_DIR}/cert.pem" \
    -subj   "/CN=*.${DOMAIN}" 2>/dev/null
fi

cp "${SSL_DIR}/cert.pem" "${SSL_DIR}/fullchain.pem"
chmod 600 "${SSL_DIR}/key.pem"
ok "Self-signed wildcard cert for *.${DOMAIN} (10 years)"
warn "Browsers will show a security warning — replace with a real cert before production use."

# ── sites-enabled/DOMAIN.conf ────────────────────────────────────────────────
header "Site Configuration"

cat > "${OUT_DIR}/sites-enabled/${DOMAIN}.conf" <<SITEEOF
# Generated by setup.sh — do not edit by hand (re-run setup.sh to regenerate)

USE Domain_Init ${DOMAIN} toc

# Keycloak identity provider — proxied internally (no OIDC auth on this vhost)
Use VHost_Proxy  iam  ${DOMAIN}  http://keycloak:8080/

# Admin panel — requires Keycloak login matching admin username
Use Admin_VHost  ${DOMAIN}  ${ADMIN_USER}

# Demo backend — requires any valid Keycloak login
Use VHost_Proxy_OIDC_Any  demo  ${DOMAIN}  http://whoami:80/

USE Domain_Final ${DOMAIN} toc
SITEEOF
ok "sites-enabled/${DOMAIN}.conf"

# ── Keycloak realm import ─────────────────────────────────────────────────────
header "Keycloak Realm"

python3 - <<PYEOF
import json

realm = {
  "realm": "${REALM}",
  "displayName": "${TOC_TITLE}",
  "enabled": True,
  "registrationAllowed": False,
  "rememberMe": True,
  "resetPasswordAllowed": False,
  "loginWithEmailAllowed": False,
  "duplicateEmailsAllowed": False,
  "sslRequired": "external",
  "bruteForceProtected": True,
  "failureFactor": 5,
  "waitIncrementSeconds": 60,
  "maxFailureWaitSeconds": 900,
  "clients": [
    {
      "clientId": "${CLIENT_ID}",
      "name": "apache-oidc-proxy",
      "enabled": True,
      "protocol": "openid-connect",
      "publicClient": False,
      "secret": "${OIDC_CLIENT_SECRET}",
      "redirectUris": ["https://*.${DOMAIN}${PORT_SUFFIX}/protected"],
      "webOrigins":   ["https://*.${DOMAIN}${PORT_SUFFIX}"],
      "standardFlowEnabled":       True,
      "directAccessGrantsEnabled": False,
      "serviceAccountsEnabled":    False,
      "attributes": {
        "pkce.code.challenge.method": "",
        "post.logout.redirect.uris": "https://logout.${DOMAIN}${PORT_SUFFIX}/*"
      },
      "defaultClientScopes": ["web-origins", "acr", "profile", "email", "roles"],
      "optionalClientScopes": ["address", "phone", "offline_access", "microprofile-jwt"]
    }
  ],
  "groups": [
    {"name": "admins", "path": "/admins"},
    {"name": "users",  "path": "/users"}
  ],
  "users": [
    {
      "username": "${ADMIN_USER}",
      "enabled": True,
      "emailVerified": True,
      "firstName": "Admin",
      "lastName": "User",
      "email": "${ADMIN_USER}@${DOMAIN}",
      "credentials": [{"type": "password", "value": "${ADMIN_PASS}", "temporary": False}],
      "groups": ["/admins", "/users"]
    },
    {
      "username": "user",
      "enabled": True,
      "emailVerified": True,
      "firstName": "Demo",
      "lastName": "User",
      "email": "user@${DOMAIN}",
      "credentials": [{"type": "password", "value": "${USER_PASS}", "temporary": False}],
      "groups": ["/users"]
    }
  ]
}

with open("${OUT_DIR}/keycloak/realm-import.json", "w") as f:
    json.dump(realm, f, indent=2)
    f.write("\n")
PYEOF
ok "keycloak/realm-import.json"

# ── .env ─────────────────────────────────────────────────────────────────────
header "Environment File"

cat > "${OUT_DIR}/.env" <<ENVEOF
# Generated by scripts/setup.sh — $(date -u '+%Y-%m-%d %H:%M UTC')
# Keep this file secure (chmod 600).

# ── OpenID Connect Provider ───────────────────────────────────────────────────
# Internal Docker URL for metadata — Keycloak reachable via backend network
OIDC_PROVIDER_METADATA_URL=http://keycloak:8080/realms/${REALM}/.well-known/openid-configuration
OIDC_CLIENT_ID=${CLIENT_ID}
OIDC_CLIENT_SECRET=${OIDC_CLIENT_SECRET}
OIDC_PROVIDER_TOKEN_ENDPOINT_AUTH=client_secret_basic
OIDC_REMOTE_USER_CLAIM=preferred_username
OIDC_SCOPE=openid email profile
OIDC_CRYPTO_PASSPHRASE=${OIDC_CRYPTO_PASSPHRASE}

# ── Session & Cookie ──────────────────────────────────────────────────────────
OIDC_COOKIE_DOMAIN=${DOMAIN}
OIDC_DEFAULT_LOGOUT_URL=https://logout.${DOMAIN}${PORT_SUFFIX}/help?text=Logout%20successful!
OIDC_REDIRECT_PATH=/protected
HTTPS_PORT=${HTTPS_PORT}

# ── Redis Session Cache ───────────────────────────────────────────────────────
REDIS_HOST=redis
REDIS_PORT=6379
REDIS_DB=1
REDIS_PASSWORD=${REDIS_PASSWORD}

# ── GeoIP Access Control ──────────────────────────────────────────────────────
# Pipe-separated ISO country codes allowed through GeoIP check.
# Leading pipe = empty alternative matches missing/unknown GeoIP (e.g. localhost).
# Remove leading pipe to enforce country restriction strictly.
GEOIP_ALLOW_COUNTRIES=DE|AT|CH

# ── Internal Networks ─────────────────────────────────────────────────────────
INTERNAL_NETWORKS=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16

# ── TOC Page ──────────────────────────────────────────────────────────────────
TOC_TITLE=${TOC_TITLE}

# ── Keycloak ──────────────────────────────────────────────────────────────────
KEYCLOAK_REALM=${REALM}
KEYCLOAK_ADMIN=admin
KEYCLOAK_ADMIN_PASSWORD=${KC_ADMIN_PASS}
ENVEOF

chmod 600 "${OUT_DIR}/.env"
ok ".env (chmod 600)"

# ── docker-compose.yml ────────────────────────────────────────────────────────
header "Docker Compose File"

cat > "${OUT_DIR}/docker-compose.yml" <<COMPOSEEOF
# Generated by scripts/setup.sh
# Build and start: docker compose up -d --build
# Stop:            docker compose down
# Logs:            docker compose logs -f proxy

services:

  proxy:
    build:
      context: ${REPO_DIR}
    restart: unless-stopped
    env_file: .env
    environment:
      - APACHE_SERVER_NAME=localhost
    volumes:
      - ./ssl:/etc/apache2/ssl:ro
      - ./sites-enabled:/etc/apache2/sites-enabled:ro
      - ./AddOn:/etc/apache2/AddOn:ro
    extra_hosts:
      # iam.DOMAIN resolves to the proxy's own macvlan IP.
      # mod_auth_openidc token exchange stays internal: proxy → keycloak:8080.
      - "iam.${DOMAIN}:${PROXY_IP}"
    depends_on:
      redis:
        condition: service_healthy
      keycloak:
        condition: service_healthy
    networks:
      frontend:
        ipv4_address: ${PROXY_IP}
      backend: {}
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    cap_add:
      - CHOWN
      - NET_BIND_SERVICE
      - SETGID
      - SETUID

  redis:
    image: redis:7-alpine
    restart: unless-stopped
    environment:
      - REDIS_PASSWORD=\${REDIS_PASSWORD:-}
    command: >
      sh -c "exec redis-server --save '' --appendonly no
      --maxmemory 128mb --maxmemory-policy allkeys-lru
      \$\${REDIS_PASSWORD:+--requirepass \$\$REDIS_PASSWORD}"
    networks:
      - backend
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    healthcheck:
      test: ["CMD-SHELL", "redis-cli \$\${REDIS_PASSWORD:+-a \$\$REDIS_PASSWORD} ping"]
      interval: 10s
      timeout: 3s
      retries: 5

  keycloak:
    image: quay.io/keycloak/keycloak:26.1
    restart: unless-stopped
    command:
      - start-dev
      - --import-realm
      - --hostname=${KC_HOSTNAME}
      - --proxy-headers=xforwarded
    environment:
      - KEYCLOAK_ADMIN=\${KEYCLOAK_ADMIN:-admin}
      - KEYCLOAK_ADMIN_PASSWORD=\${KEYCLOAK_ADMIN_PASSWORD}
    volumes:
      - ./keycloak:/opt/keycloak/data/import:ro
    networks:
      - backend
    healthcheck:
      test: ["CMD-SHELL", "exec 3<>/dev/tcp/localhost/8080 && printf 'GET /realms/${REALM}/.well-known/openid-configuration HTTP/1.0\\r\\nHost: localhost\\r\\n\\r\\n' >&3 && timeout 3 cat <&3 | grep -q realm"]
      interval: 15s
      timeout: 10s
      retries: 12
      start_period: 30s

  whoami:
    image: traefik/whoami:v1.10
    restart: unless-stopped
    networks:
      - backend

networks:
  # The proxy container gets its own IP on the existing macvlan network.
  # No port-mapping needed — all traffic to PROXY_IP goes directly to Apache.
  frontend:
    external: true
    name: ${MACVLAN_NET}

  backend:
    driver: bridge
COMPOSEEOF
ok "docker-compose.yml"

# ── credentials.txt ───────────────────────────────────────────────────────────
header "Credentials"

cat > "${OUT_DIR}/credentials.txt" <<CREDEOF
# apache-oidc-proxy — generated credentials
# Domain:    ${DOMAIN}
# Generated: $(date -u '+%Y-%m-%d %H:%M UTC')
#
# IMPORTANT: Keep this file secure. Delete it after storing credentials safely.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 Keycloak Admin Console
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  URL:      https://iam.${DOMAIN}${PORT_SUFFIX}/admin/
  Username: admin
  Password: ${KC_ADMIN_PASS}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 OIDC Proxy — Admin Panel
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  URL:      https://admin.${DOMAIN}${PORT_SUFFIX}/
  Username: ${ADMIN_USER}
  Password: ${ADMIN_PASS}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 Regular User (demo access)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  URL:      https://demo.${DOMAIN}${PORT_SUFFIX}/
  Username: user
  Password: ${USER_PASS}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 Service URLs
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  TOC overview:  https://toc.${DOMAIN}${PORT_SUFFIX}/
  Logout:        https://logout.${DOMAIN}${PORT_SUFFIX}/

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 Internal secrets (also in .env)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  OIDC client secret:     ${OIDC_CLIENT_SECRET}
  Redis password:         ${REDIS_PASSWORD}
  OIDC crypto passphrase: ${OIDC_CRYPTO_PASSPHRASE}
CREDEOF

chmod 600 "${OUT_DIR}/credentials.txt"
ok "credentials.txt (chmod 600)"

# ── summary ───────────────────────────────────────────────────────────────────
header "Summary"
printf "Files generated in: ${BOLD}%s${RESET}\n\n" "$OUT_DIR"
say "DNS records — point these subdomains to ${PROXY_IP}:"
for sub in toc iam admin logout demo; do
  printf "  ${sub}.%s → %s\n" "$DOMAIN" "$PROXY_IP"
done
echo
say "The proxy container will have IP ${PROXY_IP} on '${MACVLAN_NET}'."
say "All traffic to that IP (port 80/443) goes directly to Apache — no port mapping."
echo
say "The TLS cert is self-signed — browsers will warn."
say "Replace ${BOLD}ssl/${DOMAIN}/${RESET} with a real cert before production use."
echo

# ── optional deploy ───────────────────────────────────────────────────────────
if [[ "$NO_DEPLOY" -eq 0 ]]; then
  printf "Deploy now? (y/N): "; read -r _do_deploy </dev/tty
  if [[ "$_do_deploy" =~ ^[Yy]$ ]]; then
    [[ -n "$DOCKER_HOST_OPT" ]] && export DOCKER_HOST="$DOCKER_HOST_OPT"

    say "Building image (this takes a minute)..."
    docker compose -f "${OUT_DIR}/docker-compose.yml" \
      --env-file "${OUT_DIR}/.env" build

    say "Starting stack..."
    docker compose -f "${OUT_DIR}/docker-compose.yml" \
      --env-file "${OUT_DIR}/.env" up -d

    echo
    ok "Stack started!"
    say "Keycloak needs ~30 seconds to start and import the realm."
    say "Credentials saved to: ${OUT_DIR}/credentials.txt"
    echo
    printf "${BOLD}Keycloak Admin:${RESET}  https://iam.%s%s/admin/\n" "$DOMAIN" "$PORT_SUFFIX"
    printf "${BOLD}TOC Overview:${RESET}    https://toc.%s%s/\n"        "$DOMAIN" "$PORT_SUFFIX"
  fi
fi

echo
printf "${BOLD}Credentials:${RESET} %s\n" "${OUT_DIR}/credentials.txt"
echo
