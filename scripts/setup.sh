#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  apache-oidc-proxy — interactive setup
#  Run this once to create your .env and the required directory structure.
#
#  Usage:
#    bash scripts/setup.sh          # interactive
#    bash scripts/setup.sh --force  # overwrite existing .env without asking
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

# ── helpers ───────────────────────────────────────────────────────────────────
BOLD='\033[1m'; DIM='\033[2m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
RED='\033[0;31m'; CYAN='\033[0;36m'; RESET='\033[0m'

say()   { printf "${CYAN}▸${RESET} %s\n" "$*"; }
ok()    { printf "${GREEN}✔${RESET} %s\n" "$*"; }
warn()  { printf "${YELLOW}⚠${RESET}  %s\n" "$*"; }
err()   { printf "${RED}✖${RESET}  %s\n" "$*" >&2; }
header(){ printf "\n${BOLD}%s${RESET}\n%s\n" "$1" "$(printf '─%.0s' $(seq 1 ${#1}))"; }

# Prompt: ask(varname "Question" "default")
# Sets the global variable named $1 to user input (or default on empty).
ask() {
  local _var="$1" _prompt="$2" _default="${3:-}"
  local _hint=""
  [[ -n "$_default" ]] && _hint=" ${DIM}[${_default}]${RESET}"
  printf "${BOLD}%s${RESET}%b: " "$_prompt" "$_hint"
  local _val
  IFS= read -r _val </dev/tty
  [[ -z "$_val" ]] && _val="$_default"
  printf -v "$_var" '%s' "$_val"
}

# ask_secret: like ask but input is hidden
ask_secret() {
  local _var="$1" _prompt="$2" _default="${3:-}"
  local _hint=""
  [[ -n "$_default" ]] && _hint=" ${DIM}[leave empty to auto-generate]${RESET}"
  printf "${BOLD}%s${RESET}%b: " "$_prompt" "$_hint"
  local _val
  IFS= read -rs _val </dev/tty; echo
  [[ -z "$_val" ]] && _val="$_default"
  printf -v "$_var" '%s' "$_val"
}

gen_secret() { openssl rand -hex 32 2>/dev/null || head -c 32 /dev/urandom | base64 | tr -d '+/=' | head -c 32; }

# ── argument handling ─────────────────────────────────────────────────────────
FORCE=0
for arg in "$@"; do [[ "$arg" == "--force" ]] && FORCE=1; done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ENV_FILE="$REPO_DIR/.env"

# ── banner ────────────────────────────────────────────────────────────────────
echo
printf "${BOLD}apache-oidc-proxy — setup${RESET}\n"
printf "${DIM}Working directory: %s${RESET}\n" "$REPO_DIR"
echo

# ── .env existence check ─────────────────────────────────────────────────────
if [[ -f "$ENV_FILE" && "$FORCE" -eq 0 ]]; then
  warn ".env already exists."
  printf "Overwrite? (y/N): "
  read -r yn </dev/tty
  if [[ ! "$yn" =~ ^[Yy]$ ]]; then
    say "Aborted — existing .env kept."
    exit 0
  fi
fi

# ── collect values ────────────────────────────────────────────────────────────

header "OIDC Provider"
ask OIDC_PROVIDER_METADATA_URL \
  "Discovery URL (e.g. https://keycloak.example.com/realms/master/.well-known/openid-configuration)" ""
while [[ -z "$OIDC_PROVIDER_METADATA_URL" ]]; do
  warn "This field is required."
  ask OIDC_PROVIDER_METADATA_URL "Discovery URL" ""
done

ask OIDC_CLIENT_ID     "Client ID"                           "proxy"
ask_secret OIDC_CLIENT_SECRET "Client secret (leave empty to generate)" ""
[[ -z "$OIDC_CLIENT_SECRET" ]] && { OIDC_CLIENT_SECRET="$(gen_secret)"; warn "Generated client secret."; }

ask OIDC_PROVIDER_TOKEN_ENDPOINT_AUTH \
  "Token endpoint auth (client_secret_basic / client_secret_post)" "client_secret_basic"
ask OIDC_REMOTE_USER_CLAIM "Remote-user claim (email / preferred_username / sub)" "email"
ask OIDC_SCOPE            "OAuth2 scopes (must include openid)"                   "openid email"

header "Session & Cookie"
ask OIDC_COOKIE_DOMAIN   "Base domain for session cookies (e.g. example.com)"    ""
while [[ -z "$OIDC_COOKIE_DOMAIN" ]]; do
  warn "This field is required."
  ask OIDC_COOKIE_DOMAIN "Base domain" ""
done

ask OIDC_DEFAULT_LOGOUT_URL \
  "Post-logout redirect URL" "https://logout.${OIDC_COOKIE_DOMAIN}/help?text=Logout%20successful!"
ask OIDC_REDIRECT_PATH   "OIDC redirect path (no real content served here)"       "/protected"

printf "\nGenerate a fixed crypto passphrase? (y/N, default N = auto-generate on start): "
read -r gen_pass </dev/tty
OIDC_CRYPTO_PASSPHRASE=""
if [[ "$gen_pass" =~ ^[Yy]$ ]]; then
  OIDC_CRYPTO_PASSPHRASE="$(gen_secret)"
  ok "Generated crypto passphrase."
fi

header "Redis Session Cache"
ask REDIS_HOST "Redis hostname"      "redis"
ask REDIS_PORT "Redis port"          "6379"
ask REDIS_DB   "Redis database index" "1"
ask_secret REDIS_PASSWORD "Redis password (leave empty to generate)" ""
[[ -z "$REDIS_PASSWORD" ]] && { REDIS_PASSWORD="$(gen_secret)"; ok "Generated Redis password."; }

header "GeoIP Access Control"
ask GEOIP_ALLOW_COUNTRIES \
  "Allowed countries (pipe-separated ISO codes, e.g. DE|AT|CH)" "DE"

header "Internal Networks"
ask INTERNAL_NETWORKS \
  "Trusted CIDRs that bypass auth (comma-separated)" \
  "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"

header "Table of Contents Page"
ask TOC_TITLE "Title shown on the TOC page" "Service Overview"

header "Keycloak admin integration (optional)"
say "If admin.lua should create Keycloak clients automatically, set KEYCLOAK_ADMIN_URL."
say "Leave empty to skip (can be added to .env later)."
ask KEYCLOAK_ADMIN_URL \
  "Keycloak Admin API base URL (e.g. https://keycloak.example.com/realms/master)" ""

# ── write .env ────────────────────────────────────────────────────────────────
header "Writing .env"

# Helper: write optional commented-out line or active line
_env_opt() {
  local key="$1" val="$2"
  if [[ -n "$val" ]]; then
    printf '%s=%s\n' "$key" "$val"
  else
    printf '#%s=\n' "$key"
  fi
}

cat >"$ENV_FILE" <<EOF
# ═══════════════════════════════════════════════════════════════════════════════
#  apache-oidc-proxy — environment configuration
#  Generated by scripts/setup.sh on $(date -u '+%Y-%m-%d %H:%M UTC')
# ═══════════════════════════════════════════════════════════════════════════════

# ── OpenID Connect Provider ───────────────────────────────────────────────────
OIDC_PROVIDER_METADATA_URL=${OIDC_PROVIDER_METADATA_URL}
OIDC_CLIENT_ID=${OIDC_CLIENT_ID}
OIDC_CLIENT_SECRET=${OIDC_CLIENT_SECRET}
OIDC_PROVIDER_TOKEN_ENDPOINT_AUTH=${OIDC_PROVIDER_TOKEN_ENDPOINT_AUTH}
OIDC_REMOTE_USER_CLAIM=${OIDC_REMOTE_USER_CLAIM}
OIDC_SCOPE=${OIDC_SCOPE}

# ── Per-domain OIDC client credentials (optional) ────────────────────────────
# OIDC_CLIENT_ID_EXAMPLE_COM=proxy-example.com
# OIDC_CLIENT_SECRET_EXAMPLE_COM=secret-for-example-com

# ── Session & Cookie ──────────────────────────────────────────────────────────
OIDC_COOKIE_DOMAIN=${OIDC_COOKIE_DOMAIN}
OIDC_DEFAULT_LOGOUT_URL=${OIDC_DEFAULT_LOGOUT_URL}
OIDC_REDIRECT_PATH=${OIDC_REDIRECT_PATH}
EOF

_env_opt OIDC_CRYPTO_PASSPHRASE "$OIDC_CRYPTO_PASSPHRASE" >>"$ENV_FILE"

cat >>"$ENV_FILE" <<EOF

# ── Redis Session Cache ───────────────────────────────────────────────────────
REDIS_HOST=${REDIS_HOST}
REDIS_PORT=${REDIS_PORT}
REDIS_DB=${REDIS_DB}
REDIS_PASSWORD=${REDIS_PASSWORD}

# ── GeoIP Access Control ──────────────────────────────────────────────────────
GEOIP_ALLOW_COUNTRIES=${GEOIP_ALLOW_COUNTRIES}

# ── Internal Networks ─────────────────────────────────────────────────────────
INTERNAL_NETWORKS=${INTERNAL_NETWORKS}

# ── TOC Page ──────────────────────────────────────────────────────────────────
TOC_TITLE=${TOC_TITLE}
EOF

if [[ -n "$KEYCLOAK_ADMIN_URL" ]]; then
  cat >>"$ENV_FILE" <<EOF

# ── Keycloak admin integration ────────────────────────────────────────────────
KEYCLOAK_ADMIN_URL=${KEYCLOAK_ADMIN_URL}
EOF
fi

chmod 600 "$ENV_FILE"
ok ".env written (chmod 600)"

# ── create directory structure ────────────────────────────────────────────────
header "Creating directories"

mkdir -p "$REPO_DIR/ssl"
mkdir -p "$REPO_DIR/sites-enabled"
mkdir -p "$REPO_DIR/AddOn"

ok "ssl/           — place TLS certificates here (ssl/<domain>/cert.pem etc.)"
ok "sites-enabled/ — place your vhost .conf files here"
ok "AddOn/         — optional per-vhost include snippets"

# ── copy example vhost conf ───────────────────────────────────────────────────
EXAMPLE_CONF="$REPO_DIR/conf/sites-available/example.conf"
DEST_CONF="$REPO_DIR/sites-enabled/sites.conf"
if [[ -f "$EXAMPLE_CONF" && ! -f "$DEST_CONF" ]]; then
  printf "\nCopy example vhost config to sites-enabled/sites.conf? (y/N): "
  read -r copy_ex </dev/tty
  if [[ "$copy_ex" =~ ^[Yy]$ ]]; then
    cp "$EXAMPLE_CONF" "$DEST_CONF"
    ok "sites-enabled/sites.conf created from example — edit to match your setup."
  fi
fi

# ── summary ───────────────────────────────────────────────────────────────────
header "Done"
say "Next steps:"
printf "  1. Add TLS certificates to ${BOLD}ssl/<domain>/${RESET}\n"
printf "  2. Edit ${BOLD}sites-enabled/sites.conf${RESET} (or create your own)\n"
printf "  3. Run:  ${BOLD}docker compose up -d${RESET}\n"
echo
