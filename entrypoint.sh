#!/bin/bash
set -euo pipefail
shopt -s globstar  # enables ** glob for recursive template scanning

log() { echo "[entrypoint] $*"; }
die() { echo "[entrypoint] ERROR: $*" >&2; exit 1; }

# Debian's Apache packaging expects runtime vars such as APACHE_RUN_DIR from
# /etc/apache2/envvars. Shell logic in this script still uses hardcoded paths
# where appropriate instead of relying on APACHE_LOG_DIR.
export APACHE_CONFDIR="${APACHE_CONFDIR:-/etc/apache2}"
[ -f /etc/apache2/envvars ] && . /etc/apache2/envvars
mkdir -p "${APACHE_RUN_DIR}"

# ── Docker Secrets / _FILE fallback ──────────────────────────────────────────
# For each sensitive variable, if VAR is unset but VAR_FILE points to a file,
# read the value from that file. This supports Docker Swarm secrets and any
# secret management system that mounts secrets as files (e.g. /run/secrets/).
#
# Usage in docker-compose.yml:
#   secrets:
#     - oidc_client_secret
#   environment:
#     - OIDC_CLIENT_SECRET_FILE=/run/secrets/oidc_client_secret
#
_read_secret() {
    local var="$1" file_var="${1}_FILE"
    if [[ -z "${!var:-}" && -n "${!file_var:-}" ]]; then
        [[ -f "${!file_var}" ]] || die "${file_var} is set but '${!file_var}' does not exist"
        export "$var"="$(cat "${!file_var}")"
        log "Loaded ${var} from ${!file_var}"
    fi
}
_read_secret OIDC_CLIENT_SECRET
_read_secret REDIS_PASSWORD
_read_secret OIDC_CRYPTO_PASSPHRASE
_read_secret ACME_EMAIL

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
export APACHE_SERVER_NAME="${APACHE_SERVER_NAME:-localhost}"

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

# ── GeoIP2 database update ───────────────────────────────────────────────────
# If GEOIP_ACCOUNT_ID and GEOIP_LICENSE_KEY are set, download the current
# GeoLite2-Country database from MaxMind on startup (and via weekly cron).
# Without credentials, the bundled legacy GeoLite database is used as-is.
#
# Free account + license key: https://www.maxmind.com/en/geolite2/signup
_read_secret GEOIP_LICENSE_KEY
GEOIP_DB_DIR="/usr/share/GeoIP"
GEOIP_DB="${GEOIP_DB_DIR}/GeoLite2-Country.mmdb"
_geoip_download() {
    local url="https://download.maxmind.com/app/geoip_download"
    url+="?edition_id=GeoLite2-Country&license_key=${GEOIP_LICENSE_KEY}&suffix=tar.gz"
    local tmp; tmp="$(mktemp -d)"
    if curl -fsSL --retry 3 "$url" | tar -xz -C "$tmp" --wildcards '*.mmdb' 2>/dev/null; then
        find "$tmp" -name '*.mmdb' -exec mv {} "${GEOIP_DB}" \;
        log "GeoIP2 database updated: ${GEOIP_DB}"
    else
        log "WARNING: GeoIP2 download failed — using existing database"
    fi
    rm -rf "$tmp"
}
if [[ -n "${GEOIP_ACCOUNT_ID:-}" && -n "${GEOIP_LICENSE_KEY:-}" ]]; then
    log "GeoIP2: downloading GeoLite2-Country (account ${GEOIP_ACCOUNT_ID})"
    mkdir -p "$GEOIP_DB_DIR"
    # Write env for weekly cron (cron.d/geoip-update sources this file)
    printf 'GEOIP_LICENSE_KEY=%s\n' "${GEOIP_LICENSE_KEY}" > /etc/apache2/conf-runtime/geoip-creds.env
    _geoip_download
else
    log "GeoIP: GEOIP_ACCOUNT_ID/GEOIP_LICENSE_KEY not set — using bundled legacy database (may be stale)"
fi

# ── Generate Apache ServerName include ───────────────────────────────────────
SERVERNAME_FILE="/etc/apache2/conf-runtime/servername.conf"
log "Configuring Apache ServerName: ${APACHE_SERVER_NAME}"
printf 'ServerName %s\n' "${APACHE_SERVER_NAME}" > "$SERVERNAME_FILE"

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

# ── ACME (Let's Encrypt) setup ────────────────────────────────────────────────
# Optional: set ACME_EMAIL to enable automatic certificate management.
# ACME_DOMAINS: comma-separated root domains (default: auto-detected from conf files).
#
# On first start, if no cert exists yet for a domain, a temporary self-signed
# cert is created so Apache can start.  The real LE cert is obtained in the
# background ~10 s after Apache starts via acme-init.sh, then Apache is
# gracefully reloaded.  Weekly cron (Sun 04:30) handles renewals.
if [[ -n "${ACME_EMAIL:-}" ]]; then
    log "ACME enabled (${ACME_EMAIL})"

    # Save to runtime env so the weekly cron can source it
    printf 'ACME_EMAIL=%s\n'    "${ACME_EMAIL}"                            > /etc/apache2/conf-runtime/acme.env
    [[ -n "${ACME_DOMAINS:-}"  ]] && printf 'ACME_DOMAINS=%s\n'  "${ACME_DOMAINS}"  >> /etc/apache2/conf-runtime/acme.env
    [[ -n "${ACME_SERVER:-}"   ]] && printf 'ACME_SERVER=%s\n'   "${ACME_SERVER}"   >> /etc/apache2/conf-runtime/acme.env
    [[ -n "${ACME_INSECURE:-}" ]] && printf 'ACME_INSECURE=%s\n' "${ACME_INSECURE}" >> /etc/apache2/conf-runtime/acme.env

    # Detect root domains for the self-signed fallback
    if [[ -n "${ACME_DOMAINS:-}" ]]; then
        IFS=',' read -ra _ACME_ROOTS <<< "$ACME_DOMAINS"
    else
        mapfile -t _ACME_ROOTS < <(
            grep -rih "^[[:space:]]*use[[:space:]]\+domain_init" \
                /etc/apache2/sites-admin/ /etc/apache2/sites-enabled/ 2>/dev/null \
            | awk '{print $3}' | tr -d "'" | sort -u
        )
    fi

    for _acme_dom in "${_ACME_ROOTS[@]:-}"; do
        _acme_dom="${_acme_dom// /}"
        [[ -z "$_acme_dom" ]] && continue
        # Skip if LE cert already present (mounted volume)
        [[ -f "/etc/letsencrypt/live/${_acme_dom}/cert.pem" ]] && continue
        # Skip if manually mounted cert already present (ssl/ volume)
        [[ -f "${APACHE_CONFDIR}/ssl/${_acme_dom}/cert.pem" ]] && continue
        log "ACME: no cert for ${_acme_dom} — creating self-signed placeholder"
        _ssl="${APACHE_CONFDIR}/ssl/${_acme_dom}"
        mkdir -p "$_ssl"
        openssl req -x509 -nodes -days 1 -newkey rsa:2048 \
            -keyout "${_ssl}/key.pem" \
            -out    "${_ssl}/cert.pem" \
            -subj   "/CN=${_acme_dom}" 2>/dev/null
        cp "${_ssl}/cert.pem" "${_ssl}/fullchain.pem"
        log "ACME: self-signed placeholder for ${_acme_dom} (replaced by LE cert in ~10 s)"
    done
fi

# ── Create per-domain Apache log directories ──────────────────────────────────
# The LOGGING macro writes to /var/log/apache2/<domain>/  Apache configtest
# fails (AH02291) when those directories are missing.
# Domain_Init/Final: domain is $3.  VHost_*: domain is $4 (after sitename).
# Split both fields, filter for valid domain patterns, mkdir all found ones.
# Case-insensitive grep (-i) handles both "Use" and "USE" variants.
# || true prevents pipefail from aborting when no conf files are found.
grep -rih '^[[:space:]]*use[[:space:]]' /etc/apache2/sites-enabled/ /etc/apache2/sites-admin/ 2>/dev/null \
    | awk '{print $3; print $4}' \
    | grep -E '^[A-Za-z0-9]([A-Za-z0-9-]*\.)+[A-Za-z]{2,}$' \
    | sort -u \
    | while IFS= read -r domain; do
        mkdir -p "/var/log/apache2/${domain}"
    done || true

# ── Start cron for daily key rotation ────────────────────────────────────────
/usr/sbin/cron -f &
log "cron daemon started (rotate-oidc-key.sh runs at 03:00 daily)"

# ── Validate Apache config ────────────────────────────────────────────────────
log "Testing Apache configuration..."
apache2ctl configtest || die "Apache config test failed — check your site configs and env vars"

# ── ACME: obtain real cert after Apache starts ────────────────────────────────
# The self-signed placeholder above lets Apache start; now request the real
# cert in the background.  The 10 s delay gives Apache time to become ready.
if [[ -n "${ACME_EMAIL:-}" ]]; then
    (sleep 10 && /usr/local/bin/acme-init.sh) &
fi

log "Starting Apache..."
exec "$@"
