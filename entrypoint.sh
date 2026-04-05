#!/bin/bash
set -euo pipefail

log() { echo "[entrypoint] $*"; }
die() { echo "[entrypoint] ERROR: $*" >&2; exit 1; }

# ── Required variables ────────────────────────────────────────────────────────
[[ -n "${OIDC_PROVIDER_METADATA_URL:-}" ]] \
    || die "OIDC_PROVIDER_METADATA_URL is required (e.g. https://keycloak/realms/master/.well-known/openid-configuration)"
[[ -n "${OIDC_CLIENT_SECRET:-}" ]] \
    || die "OIDC_CLIENT_SECRET is required"
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
export REDIS_PASSWORD="${REDIS_PASSWORD:-}"

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
    [[ "$net" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/([0-9]|[1-2][0-9]|3[0-2]))?$ ]] \
        || die "Invalid CIDR in INTERNAL_NETWORKS: '${net}'"
    echo "      Require ip ${net}" >> "$NETWORKS_FILE"
done

# ── Generate OIDC crypto passphrase include ───────────────────────────────────
# If OIDC_CRYPTO_PASSPHRASE is set, use it as the initial key.
# Otherwise auto-generate a random 32-byte hex key.
# The rotate-oidc-key.sh cron job (03:00 daily) shifts current → previous
# and generates a fresh key, so existing sessions keep working for one day.
PASSPHRASE_FILE="/etc/apache2/conf-runtime/oidc-passphrase.key"
PASSPHRASE_CONF="/etc/apache2/conf-runtime/oidc-passphrase.conf"

if [[ -n "${OIDC_CRYPTO_PASSPHRASE:-}" ]]; then
    log "Using provided OIDC_CRYPTO_PASSPHRASE as initial crypto key"
    CURRENT_KEY="${OIDC_CRYPTO_PASSPHRASE}"
else
    log "Auto-generating OIDC crypto passphrase (rotates daily at 03:00)"
    CURRENT_KEY="$(openssl rand -hex 32)"
fi
echo "${CURRENT_KEY}" > "$PASSPHRASE_FILE"
printf 'OIDCCryptoPassphrase  "%s"\n' "${CURRENT_KEY}" > "$PASSPHRASE_CONF"

# ── Generate Redis password include ──────────────────────────────────────────
REDIS_AUTH_FILE="/etc/apache2/conf-runtime/redis-auth.conf"
if [[ -n "${REDIS_PASSWORD}" ]]; then
    log "Configuring Redis password authentication"
    printf 'OIDCRedisCachePassword  %s\n' "${REDIS_PASSWORD}" > "$REDIS_AUTH_FILE"
else
    > "$REDIS_AUTH_FILE"
fi

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
'${OIDC_DEFAULT_LOGOUT_URL}'\
'${OIDC_COOKIE_DOMAIN}'\
'${REDIS_HOST}'\
'${REDIS_PORT}'\
'${REDIS_DB}'\
'${GEOIP_ALLOW_COUNTRIES}'

for tmpl in /etc/apache2/macro/*.template /etc/apache2/conf-available/*.template /var/www/**/*.template; do
    [ -f "$tmpl" ] || continue
    out="${tmpl%.template}"
    log "Processing template: $(basename "$tmpl") -> $(basename "$out")"
    envsubst "$SUBST_VARS" < "$tmpl" > "$out"
done

# Enable the auth_openidc conf (generated from template above)
a2enconf auth_openidc 2>/dev/null || true

# ── Start cron for daily key rotation ────────────────────────────────────────
/usr/sbin/cron -f &
log "cron daemon started (rotate-oidc-key.sh runs at 03:00 daily)"

# ── Validate Apache config ────────────────────────────────────────────────────
log "Testing Apache configuration..."
apache2ctl configtest || die "Apache config test failed — check your site configs and env vars"

log "Starting Apache..."
exec "$@"
