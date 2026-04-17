#!/bin/bash
# acme-init.sh — Obtain / renew Let's Encrypt certificates via HTTP-01 webroot
#
# Called from entrypoint.sh ~10 s after Apache starts, and by weekly cron.
# Controlled by environment variables:
#
#   ACME_EMAIL    (required)  Contact e-mail for Let's Encrypt registration.
#   ACME_DOMAINS  (optional)  Comma-separated root domains to obtain certs for.
#                             If unset, root domains are auto-detected from
#                             "Use Domain_Init*" lines in sites-admin/ and
#                             sites-enabled/.
#   ACME_SERVER   (optional)  ACME directory URL.  Default: Let's Encrypt
#                             production.  Set to https://pebble:14000/dir
#                             (or similar) for local testing with Pebble.
#   ACME_INSECURE (optional)  Set to 1 to skip TLS verification of the ACME
#                             server endpoint — required for Pebble (self-signed).
#
# For each root domain a single multi-SAN certificate is requested covering:
#   - the root domain itself
#   - toc.<domain>, logout.<domain>, admin.<domain>  (always present via Domain_Init)
#   - every subdomain discovered from VHost_* macro calls in the conf files
#
# Certificates are stored by certbot in /etc/letsencrypt/ and copied to
# /etc/apache2/ssl/<domain>/{cert,key,fullchain}.pem (the path the SSL macro
# and the ssl/ Docker volume use).
#
# A graceful Apache reload is issued whenever at least one cert was updated.

set -euo pipefail
log() { echo "[acme] $*"; }

WEBROOT="/var/www/acme-webroot"
SSL_DIR="/etc/apache2/ssl"
LE_LIVE="/etc/letsencrypt/live"

# ── Prerequisites ─────────────────────────────────────────────────────────────

[[ -n "${ACME_EMAIL:-}" ]] || { log "ACME_EMAIL not set — skipping"; exit 0; }
command -v certbot &>/dev/null || { log "certbot not installed — skipping"; exit 1; }

# Optional overrides for the ACME server (e.g. Pebble for local testing)
ACME_SERVER="${ACME_SERVER:-}"
ACME_INSECURE="${ACME_INSECURE:-}"

server_args=()
[[ -n "$ACME_SERVER"   ]] && server_args+=(--server "$ACME_SERVER")
[[ -n "$ACME_INSECURE" ]] && server_args+=(--no-verify-ssl)

if [[ -n "$ACME_SERVER" ]]; then
    log "Using custom ACME server: ${ACME_SERVER}"
fi

# ── Root domain list ──────────────────────────────────────────────────────────

if [[ -n "${ACME_DOMAINS:-}" ]]; then
    IFS=',' read -ra ROOT_DOMAINS <<< "$ACME_DOMAINS"
else
    mapfile -t ROOT_DOMAINS < <(
        grep -rih "^[[:space:]]*use[[:space:]]\+domain_init" \
            /etc/apache2/sites-admin/ /etc/apache2/sites-enabled/ 2>/dev/null \
        | awk '{print $3}' | tr -d "'" | sort -u
    )
fi

[[ ${#ROOT_DOMAINS[@]} -eq 0 ]] && { log "No domains found — skipping"; exit 0; }

# ── SAN list for one root domain ──────────────────────────────────────────────
# Includes the root, Domain_Init subdomains (toc/logout/admin), and every
# VHost_* site name that belongs to this domain.

get_san_list() {
    local root="$1"
    local -a subs=("$root" "toc.${root}" "logout.${root}" "admin.${root}")

    while IFS= read -r name; do
        [[ -n "$name" ]] && subs+=("${name}.${root}")
    done < <(
        grep -rih "^[[:space:]]*use[[:space:]]\+vhost_" \
            /etc/apache2/sites-admin/ /etc/apache2/sites-enabled/ 2>/dev/null \
        | awk -v dom="${root}" 'tolower($4) == tolower(dom) {print $3}' \
        | sort -u
    )

    # Deduplicate, preserve order
    printf '%s\n' "${subs[@]}" | awk '!seen[$0]++'
}

# ── Deploy cert from letsencrypt live/ to Apache ssl/ volume ──────────────────

deploy_cert() {
    local root="$1"
    local src="${LE_LIVE}/${root}"
    local dst="${SSL_DIR}/${root}"
    mkdir -p "$dst"
    cp -fL "${src}/cert.pem"      "${dst}/cert.pem"
    cp -fL "${src}/privkey.pem"   "${dst}/key.pem"
    cp -fL "${src}/fullchain.pem" "${dst}/fullchain.pem"
    log "Deployed cert for ${root} → ${dst}"
}

# ── Main loop ─────────────────────────────────────────────────────────────────

changed=0

for root in "${ROOT_DOMAINS[@]}"; do
    root="${root// /}"
    [[ -z "$root" ]] && continue

    mapfile -t sans < <(get_san_list "$root")
    d_args=(); for san in "${sans[@]}"; do d_args+=(-d "$san"); done

    log "Requesting cert for ${root} (${#sans[@]} SANs: ${sans[*]})"
    if certbot certonly \
            --non-interactive \
            --agree-tos \
            --email "${ACME_EMAIL}" \
            --webroot -w "${WEBROOT}" \
            "${d_args[@]}" \
            "${server_args[@]}" \
            --cert-name "${root}" \
            --keep-until-expiring \
            --expand \
            --quiet 2>&1; then
        deploy_cert "$root"
        changed=1
    else
        log "WARNING: certbot failed for ${root} — existing cert unchanged"
    fi
done

[[ $changed -eq 1 ]] && { log "Reloading Apache..."; /usr/sbin/apache2ctl graceful 2>/dev/null || true; }
log "Done"
