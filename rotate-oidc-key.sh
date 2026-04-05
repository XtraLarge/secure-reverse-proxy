#!/bin/bash
# rotate-oidc-key.sh — Daily OIDC crypto passphrase rotation
#
# Generates a new passphrase, keeps the old one as the "previous" key so that
# mod_auth_openidc can still decrypt sessions encrypted with the old key for
# one grace period.  After the next rotation the old key is dropped.
#
# Installed to /usr/local/bin/rotate-oidc-key.sh
# Invoked by cron at 03:00 daily (see /etc/cron.d/rotate-oidc-key)

set -euo pipefail

PASSPHRASE_FILE="/etc/apache2/conf-runtime/oidc-passphrase.key"
PASSPHRASE_CONF="/etc/apache2/conf-runtime/oidc-passphrase.conf"

if [[ ! -f "$PASSPHRASE_FILE" ]]; then
    echo "[rotate-oidc-key] ERROR: passphrase file not found — entrypoint not run?" >&2
    exit 1
fi

PREV_KEY="$(cat "$PASSPHRASE_FILE")"
NEW_KEY="$(openssl rand -hex 32)"

echo "${NEW_KEY}" > "$PASSPHRASE_FILE"
# mod_auth_openidc accepts two space-separated passphrases:
# the first encrypts new sessions, the second still decrypts old ones.
printf 'OIDCCryptoPassphrase  "%s" "%s"\n' "${NEW_KEY}" "${PREV_KEY}" > "$PASSPHRASE_CONF"

apache2ctl graceful
echo "[rotate-oidc-key] Passphrase rotated — graceful reload done ($(date -u +%FT%TZ))"
