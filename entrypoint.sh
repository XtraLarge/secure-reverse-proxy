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

# ── Keycloak Admin API (optional) ─────────────────────────────────────────────
# Enables the admin-kc.lua user management interface.
# The logged-in admin's OIDC access_token is used for all API calls — no
# separate service account needed.  The admin user in Keycloak needs the
# realm-management client roles: view-users, manage-users, query-roles.
#
# KEYCLOAK_REALM       Keycloak realm name.                  Default: master
# KEYCLOAK_ADMIN_URL   Full Admin REST API URL (incl. realm). Auto-derived when unset.
#                      Example: https://iam.example.com/admin/realms/master
# KEYCLOAK_ROLE_PREFIX Only show roles whose name starts with this prefix.
#                      Example: "proxy-"  →  shows only proxy-* roles.
#                      Empty (default)   →  shows all realm roles.
export KEYCLOAK_REALM="${KEYCLOAK_REALM:-master}"
export KEYCLOAK_ROLE_PREFIX="${KEYCLOAK_ROLE_PREFIX:-}"
if [[ -z "${KEYCLOAK_ADMIN_URL:-}" ]]; then
    # Auto-derive from OIDC_PROVIDER_METADATA_URL when it follows the standard
    # Keycloak pattern:  https://host/realms/REALM/.well-known/openid-configuration
    #                 →  https://host/admin/realms/REALM
    _kc_base="${OIDC_PROVIDER_METADATA_URL%%/realms/*}"
    if [[ "$_kc_base" != "$OIDC_PROVIDER_METADATA_URL" ]]; then
        export KEYCLOAK_ADMIN_URL="${_kc_base}/admin/realms/${KEYCLOAK_REALM}"
        log "Keycloak Admin URL (auto-derived): ${KEYCLOAK_ADMIN_URL}"
    else
        export KEYCLOAK_ADMIN_URL=""
        log "Keycloak Admin URL: not set (OIDC_PROVIDER_METADATA_URL is not a standard Keycloak URL — set KEYCLOAK_ADMIN_URL manually to enable admin-kc.lua)"
    fi
else
    log "Keycloak Admin URL: ${KEYCLOAK_ADMIN_URL}"
fi

# ── Sudoers rule: allow www-data to graceful-reload Apache ────────────────────
echo "www-data ALL=(root) NOPASSWD: /bin/kill -USR1 1" > /etc/sudoers.d/apache-reload
chmod 440 /etc/sudoers.d/apache-reload

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

# ── Generate OIDC config include for iam/admin-console protection ────────────
# Used by AddOn/DOMAIN/iam.preconfig via:
#   Include /etc/apache2/conf-runtime/iam-admin-oidc.conf
# Mirrors the OIDCBASE macro but writes to a file so secrets stay out of the
# volume-mounted AddOn directory.  The <Location /admin> AuthType + Require
# directives still go in the preconfig — only the VHost-level OIDC settings
# (provider URL, client creds, cookie config) live here.
IAM_ADMIN_OIDC_FILE="/etc/apache2/conf-runtime/iam-admin-oidc.conf"
{
printf 'OIDCProviderMetadataURL          %s\n'  "${OIDC_PROVIDER_METADATA_URL}"
printf 'OIDCSSLValidateServer            Off\n'
printf 'OIDCProviderTokenEndpointAuth    %s\n'  "${OIDC_PROVIDER_TOKEN_ENDPOINT_AUTH}"
printf 'OIDCClientID                     %s\n'  "${OIDC_CLIENT_ID}"
printf 'OIDCClientSecret                 %s\n'  "${OIDC_CLIENT_SECRET}"
printf 'OIDCRemoteUserClaim              %s\n'  "${OIDC_REMOTE_USER_CLAIM}"
printf 'OIDCScope                        "%s"\n' "${OIDC_SCOPE}"
printf 'OIDCRedirectURI                  https://iam.%s%s\n' "${OIDC_COOKIE_DOMAIN}" "${OIDC_REDIRECT_PATH}"
printf 'Include /etc/apache2/conf-runtime/oidc-passphrase.conf\n'
printf 'OIDCDefaultLoggedOutURL          %s\n'  "${OIDC_DEFAULT_LOGOUT_URL}"
printf 'OIDCCookieDomain                 %s\n'  "${OIDC_COOKIE_DOMAIN}"
printf 'OIDCCookie                       %s-IAM-Admin-Session\n'  "${OIDC_COOKIE_DOMAIN}"
printf 'OIDCStateCookiePrefix            %s-IAM-Admin-State-\n'   "${OIDC_COOKIE_DOMAIN}"
printf 'OIDCCookieSameSite               On\n'
printf 'OIDCCookieHTTPOnly               On\n'
printf 'OIDCSessionCacheFallbackToCookie On\n'
printf 'OIDCCacheType                    redis\n'
printf 'OIDCRedisCacheServer             %s:%s\n' "${REDIS_HOST}" "${REDIS_PORT}"
printf 'OIDCRedisCacheDatabase           %s\n'  "${REDIS_DB}"
printf 'Include /etc/apache2/conf-runtime/redis-auth.conf\n'
printf 'OIDCProviderBackChannelLogoutSupported On\n'
} > "$IAM_ADMIN_OIDC_FILE"
chmod 644 "$IAM_ADMIN_OIDC_FILE"
log "Generated iam-admin-oidc.conf (redirect URI: https://iam.${OIDC_COOKIE_DOMAIN}${OIDC_REDIRECT_PATH})"

# ── Generate per-domain OIDC client credential files ─────────────────────────
# Allows each domain to use a separate Keycloak client with its own secret.
#
# For each domain, set env vars using the domain name in UPPER_SNAKE_CASE
# (dots and hyphens replaced by underscores), e.g.:
#
#   OIDC_CLIENT_ID_EXAMPLE_COM=Proxy-example.com
#   OIDC_CLIENT_SECRET_EXAMPLE_COM=<secret>
#   OIDC_CLIENT_ID_HANDAMHUF_DE=Proxy-handamhuf.de
#   OIDC_CLIENT_SECRET_HANDAMHUF_DE=<secret>
#
# If no domain-specific vars are set, the global OIDC_CLIENT_ID /
# OIDC_CLIENT_SECRET remain active (IncludeOptional skips missing files).
#
# The OIDCBASE macro includes these files AFTER the global credentials,
# so they override on a per-domain basis.
_gen_oidc_client_conf() {
    local domain="$1"
    local domain_key
    domain_key=$(echo "$domain" | tr '.-' '_' | tr '[:lower:]' '[:upper:]')
    local id_var="OIDC_CLIENT_ID_${domain_key}"
    local secret_var="OIDC_CLIENT_SECRET_${domain_key}"
    # Use indirect expansion to read variable by name
    local client_id="${!id_var:-}"
    local client_secret="${!secret_var:-}"
    if [[ -n "$client_id" && -n "$client_secret" ]]; then
        local conf="/etc/apache2/conf-runtime/oidc-client-${domain}.conf"
        printf 'OIDCClientID     %s\n' "$client_id"     > "$conf"
        printf 'OIDCClientSecret %s\n' "$client_secret" >> "$conf"
        chmod 644 "$conf"
        log "Generated oidc-client-${domain}.conf (client_id: ${client_id})"
    fi
}

# Scan sites-enabled and sites-admin for domain names and generate conf files
while IFS= read -r conf_file; do
    domain=$(basename "$conf_file" .conf)
    _gen_oidc_client_conf "$domain"
done < <(find /etc/apache2/sites-enabled /etc/apache2/sites-admin \
    -maxdepth 1 -name '*.conf' 2>/dev/null)

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
if [[ -n "${ACME_EMAIL:-}" ]]; then
    log "ACME enabled (${ACME_EMAIL})"
    # Save to runtime env so the weekly cron can source it
    printf 'ACME_EMAIL=%s\n'    "${ACME_EMAIL}"                            > /etc/apache2/conf-runtime/acme.env
    [[ -n "${ACME_DOMAINS:-}"  ]] && printf 'ACME_DOMAINS=%s\n'  "${ACME_DOMAINS}"  >> /etc/apache2/conf-runtime/acme.env
    [[ -n "${ACME_SERVER:-}"   ]] && printf 'ACME_SERVER=%s\n'   "${ACME_SERVER}"   >> /etc/apache2/conf-runtime/acme.env
    [[ -n "${ACME_INSECURE:-}" ]] && printf 'ACME_INSECURE=%s\n' "${ACME_INSECURE}" >> /etc/apache2/conf-runtime/acme.env
fi

# ── Resolve TLS certificates → /run/apache2/active-ssl/ ──────────────────────
# The SSL macro always reads from /run/apache2/active-ssl/<domain>/.
# This function populates that directory with symlinks (or files for self-signed)
# pointing to the best available cert source, checked in order:
#   1. /etc/letsencrypt/live/<domain>/  — LE cert (ACME_EMAIL set, already obtained)
#   2. /etc/apache2/ssl/<domain>/       — manually mounted via the ssl/ volume
#   3. self-signed placeholder          — ACME first-start; replaced ~10 s after boot
#
# Keeping this separate from the ssl/ volume means ssl/ can be mounted :ro.
# acme-init.sh updates the symlinks after obtaining a real cert, then reloads.
ACTIVE_SSL_DIR="/run/apache2/active-ssl"
mkdir -p "$ACTIVE_SSL_DIR"

mapfile -t _ALL_DOMAINS < <(
    grep -rih '^[[:space:]]*use[[:space:]]' /etc/apache2/sites-enabled/ /etc/apache2/sites-admin/ 2>/dev/null \
    | awk '{print $3; print $4}' \
    | grep -E '^[A-Za-z0-9]([A-Za-z0-9-]*\.)+[A-Za-z]{2,}$' \
    | sort -u
)

for _dom in "${_ALL_DOMAINS[@]+"${_ALL_DOMAINS[@]}"}"; do
    _active="${ACTIVE_SSL_DIR}/${_dom}"
    mkdir -p "$_active"

    if [[ -f "/etc/letsencrypt/live/${_dom}/cert.pem" ]]; then
        ln -sfn "/etc/letsencrypt/live/${_dom}/cert.pem"      "${_active}/cert.pem"
        ln -sfn "/etc/letsencrypt/live/${_dom}/privkey.pem"   "${_active}/key.pem"
        ln -sfn "/etc/letsencrypt/live/${_dom}/fullchain.pem" "${_active}/fullchain.pem"
        log "SSL: ${_dom} → letsencrypt"
    elif [[ -f "${APACHE_CONFDIR}/ssl/${_dom}/cert.pem" ]]; then
        ln -sfn "${APACHE_CONFDIR}/ssl/${_dom}/cert.pem"      "${_active}/cert.pem"
        ln -sfn "${APACHE_CONFDIR}/ssl/${_dom}/key.pem"       "${_active}/key.pem"
        ln -sfn "${APACHE_CONFDIR}/ssl/${_dom}/fullchain.pem" "${_active}/fullchain.pem"
        log "SSL: ${_dom} → ssl/ volume"
    elif [[ -n "${ACME_EMAIL:-}" ]]; then
        log "SSL: ${_dom} → self-signed placeholder (ACME cert arrives in ~10 s)"
        openssl req -x509 -nodes -days 1 -newkey rsa:2048 \
            -keyout "${_active}/key.pem" \
            -out    "${_active}/cert.pem" \
            -subj   "/CN=${_dom}" 2>/dev/null
        cp "${_active}/cert.pem" "${_active}/fullchain.pem"
    else
        log "WARNING: no cert for ${_dom} — Apache may fail to start (mount ssl/ volume or set ACME_EMAIL)"
    fi
done

# ── Start cron for daily key rotation + logrotate ────────────────────────────
/usr/sbin/cron -f &
log "cron daemon started (rotate-oidc-key.sh runs at 03:00 daily)"

# ── Configure and start rsyslog ───────────────────────────────────────────────
# LOG_FILE     — path to consolidated log file (default: /var/log/apache2/apache.log)
#                set to "off" to disable local file logging
# SYSLOG_REMOTE — remote syslog target, e.g. "udp://10.x.x.x:514" or "tcp://host:514"
#                 empty = no remote forwarding
LOG_FILE="${LOG_FILE:-/var/log/apache2/apache.log}"
SYSLOG_REMOTE="${SYSLOG_REMOTE:-}"

RSYSLOG_ROUTING="/etc/rsyslog.d/50-apache-routing.conf"
LOGROTATE_ACTIVE="/etc/logrotate.d/apache-active"

# Build rsyslog routing rule
{
  echo "# Generated by entrypoint.sh — do not edit"
  echo "if \$syslogfacility-text == 'local7' then {"
  if [[ "${LOG_FILE}" != "off" && -n "${LOG_FILE}" ]]; then
    echo "    action(type=\"omfile\" file=\"${LOG_FILE}\" template=\"ApacheFmt\" FileCreateMode=\"0640\")"
  fi
  if [[ -n "${SYSLOG_REMOTE}" ]]; then
    _proto="${SYSLOG_REMOTE%%://*}"          # udp | tcp
    _hostport="${SYSLOG_REMOTE#*://}"        # host:port
    _rhost="${_hostport%%:*}"
    _rport="${_hostport##*:}"
    echo "    action(type=\"omfwd\" target=\"${_rhost}\" port=\"${_rport}\" protocol=\"${_proto}\")"
    log "rsyslog: remote forwarding → ${_proto}://${_rhost}:${_rport}"
  fi
  echo "    stop"
  echo "}"
} > "$RSYSLOG_ROUTING"

# Build logrotate config (only when file logging is enabled)
if [[ "${LOG_FILE}" != "off" && -n "${LOG_FILE}" ]]; then
  touch "${LOG_FILE}"
  chmod 0640 "${LOG_FILE}"
  cat > "$LOGROTATE_ACTIVE" <<LOGROTATE_EOF
${LOG_FILE} {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    sharedscripts
    postrotate
        pkill -HUP rsyslogd 2>/dev/null || true
    endscript
}
LOGROTATE_EOF
  log "rsyslog: logging to ${LOG_FILE} (logrotate: daily, keep 14)"
else
  # Remove logrotate config if file logging is disabled
  rm -f "$LOGROTATE_ACTIVE"
  log "rsyslog: file logging disabled (LOG_FILE=off)"
fi

# Start rsyslog — creates /dev/log (Unix socket) that Apache writes to
/usr/sbin/rsyslogd
sleep 0.3   # give rsyslog time to create /dev/log before Apache starts
log "rsyslog started"

# ── Fix volume-mount permissions for www-data ─────────────────────────────────
# Volume mounts arrive as root:root. Apache (www-data) needs write access to
# specific paths. We fix ownership here at startup so admin.lua can write
# without manual intervention on the host.
_fix_owner() {
    local path="$1" desc="$2"
    [[ -e "$path" ]] || return 0
    if chown -R www-data:www-data "$path" 2>/dev/null; then
        log "Permissions OK: ${desc} → www-data"
    else
        log "WARNING: could not set ownership for ${desc} (${path}) — admin writes may fail"
    fi
}
_check_writable() {
    local path="$1" desc="$2"
    [[ -e "$path" ]] || return 0
    if ! su -s /bin/sh www-data -c "test -w '$path'" 2>/dev/null; then
        log "WARNING: ${desc} (${path}) is not writable by www-data — admin writes will fail"
    fi
}

# basic.htpasswd — htpasswd command runs as www-data, needs write access
_fix_owner  "/etc/apache2/basic.htpasswd" "basic.htpasswd"
# AddOn/ — admin.lua creates/updates preconfig|postconfig snippets
_fix_owner  "/etc/apache2/AddOn"          "AddOn/"
# sites-admin/ — admin.lua reads and writes VHost conf files
_fix_owner  "/etc/apache2/sites-admin"    "sites-admin/"
# Verify after fix
_check_writable "/etc/apache2/basic.htpasswd" "basic.htpasswd"
_check_writable "/etc/apache2/AddOn"          "AddOn/"
_check_writable "/etc/apache2/sites-admin"    "sites-admin/"

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
