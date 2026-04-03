#!/bin/bash
set -euo pipefail

log() { echo "[entrypoint] $*"; }
die() { echo "[entrypoint] ERROR: $*" >&2; exit 1; }

# ── Required variables ────────────────────────────────────────────────────────
[[ -n "${OIDC_PROVIDER_METADATA_URL:-}" ]] \
    || die "OIDC_PROVIDER_METADATA_URL is required (e.g. https://keycloak/realms/master/.well-known/openid-configuration)"
[[ -n "${OIDC_CLIENT_SECRET:-}" ]] \
    || die "OIDC_CLIENT_SECRET is required"
[[ -n "${OIDC_CRYPTO_PASSPHRASE:-}" ]] \
    || die "OIDC_CRYPTO_PASSPHRASE is required — generate with: openssl rand -hex 32"
[[ -n "${OIDC_COOKIE_DOMAIN:-}" ]] \
    || die "OIDC_COOKIE_DOMAIN is required (e.g. example.com)"

# ── Defaults for optional variables ──────────────────────────────────────────
export OIDC_CLIENT_ID="${OIDC_CLIENT_ID:-Proxy}"
export OIDC_PROVIDER_TOKEN_ENDPOINT_AUTH="${OIDC_PROVIDER_TOKEN_ENDPOINT_AUTH:-client_secret_basic}"
export OIDC_REMOTE_USER_CLAIM="${OIDC_REMOTE_USER_CLAIM:-email}"
export OIDC_SCOPE="${OIDC_SCOPE:-openid email}"
export OIDC_REDIRECT_PATH="${OIDC_REDIRECT_PATH:-/protected}"
export OIDC_DEFAULT_LOGOUT_URL="${OIDC_DEFAULT_LOGOUT_URL:-https://logout.${OIDC_COOKIE_DOMAIN}/help?text=Logout%20successful!}"

export REDIS_HOST="${REDIS_HOST:-redis}"
export REDIS_PORT="${REDIS_PORT:-6379}"
export REDIS_DB="${REDIS_DB:-1}"

# Pipe-separated ISO country codes for GeoIP allow-list (used as regex alternation)
# Example: DE|AT|CH  →  allows Germany, Austria, Switzerland
export GEOIP_ALLOW_COUNTRIES="${GEOIP_ALLOW_COUNTRIES:-DE}"

# ── Generate internal networks include ────────────────────────────────────────
# INTERNAL_NETWORKS: comma-separated CIDRs that bypass GeoIP and auth entirely.
# These are injected into an Apache Include file used inside the auth macros.
INTERNAL_NETWORKS="${INTERNAL_NETWORKS:-10.0.0.0/8,172.16.0.0/12,192.168.0.0/16}"
NETWORKS_FILE="/etc/apache2/conf-runtime/internal-networks.conf"

log "Generating internal networks include: ${INTERNAL_NETWORKS}"
> "$NETWORKS_FILE"
IFS=',' read -ra NETS <<< "$INTERNAL_NETWORKS"
for net in "${NETS[@]}"; do
    net="$(echo "$net" | tr -d ' ')"
    echo "      Require ip ${net}" >> "$NETWORKS_FILE"
done

# ── Process config templates ──────────────────────────────────────────────────
# envsubst receives an explicit variable list so that Apache mod_macro syntax
# $(MACRO_PARAM) is left untouched — only ${ENV_VAR} placeholders are replaced.
SUBST_VARS='${OIDC_PROVIDER_METADATA_URL}'\
'${OIDC_PROVIDER_TOKEN_ENDPOINT_AUTH}'\
'${OIDC_CLIENT_ID}'\
'${OIDC_CLIENT_SECRET}'\
'${OIDC_REMOTE_USER_CLAIM}'\
'${OIDC_SCOPE}'\
'${OIDC_REDIRECT_PATH}'\
'${OIDC_CRYPTO_PASSPHRASE}'\
'${OIDC_DEFAULT_LOGOUT_URL}'\
'${OIDC_COOKIE_DOMAIN}'\
'${REDIS_HOST}'\
'${REDIS_PORT}'\
'${REDIS_DB}'\
'${GEOIP_ALLOW_COUNTRIES}'

for tmpl in /etc/apache2/macro/*.template /etc/apache2/conf-available/*.template; do
    [ -f "$tmpl" ] || continue
    out="${tmpl%.template}"
    log "Processing template: $(basename "$tmpl") -> $(basename "$out")"
    envsubst "$SUBST_VARS" < "$tmpl" > "$out"
done

# Enable the auth_openidc conf (generated from template above)
a2enconf auth_openidc 2>/dev/null || true

# ── Validate Apache config ────────────────────────────────────────────────────
log "Testing Apache configuration..."
apache2ctl configtest || die "Apache config test failed — check your site configs and env vars"

log "Starting Apache..."
exec "$@"
