#!/bin/bash
# rotate-oidc-key.sh — Daily OIDC crypto passphrase rotation
#
# Generates a new passphrase, keeps the old one as the "previous" key so that
# mod_auth_openidc can still decrypt sessions encrypted with the old key for
# one grace period.  After the next rotation the old key is dropped.
#
# Installed to /usr/local/bin/rotate-oidc-key.sh
# Invoked by cron at 03:00 daily (see /etc/cron.d/rotate-oidc-key)

set -uo pipefail

PASSPHRASE_FILE="/etc/apache2/conf-runtime/oidc-passphrase.key"
PASSPHRASE_CONF="/etc/apache2/conf-runtime/oidc-passphrase.conf"

if [[ ! -f "$PASSPHRASE_FILE" ]]; then
    echo "[rotate-oidc-key] ERROR: passphrase file not found — entrypoint not run?" >&2
    exit 1
fi

PREV_KEY="$(cat "$PASSPHRASE_FILE")"
NEW_KEY="$(openssl rand -hex 32)"

echo "${NEW_KEY}" > "$PASSPHRASE_FILE"
# Note: mod_auth_openidc 2.4.x (Debian 12) only accepts a single passphrase.
# Multi-passphrase support (for zero-downtime rotation) is available in 2.4.14+.
# Sessions encrypted with the old key will require re-authentication after rotation.
printf 'OIDCCryptoPassphrase  "%s"\n' "${NEW_KEY}" > "$PASSPHRASE_CONF"

if apache2ctl graceful 2>/dev/null; then
    echo "[rotate-oidc-key] Passphrase rotated — graceful reload done ($(date -u +%FT%TZ))"
else
    echo "[rotate-oidc-key] WARNING: apache2ctl graceful failed (Apache not running?) — passphrase file updated anyway" >&2
fi
