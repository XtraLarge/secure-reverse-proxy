#!/usr/bin/env bash
# check-env.sh — validate proxy env file format before deployment
#
# Usage:
#   scripts/check-env.sh <env-file>
#
# Exit codes:
#   0 — all checks passed (warnings possible)
#   1 — at least one error found

set -uo pipefail

BOLD='\033[1m'; RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
DIM='\033[2m'; RESET='\033[0m'

NERRORS=0
NWARNINGS=0

_err()  { printf "  ${RED}✖${RESET}  %s\n" "$*"; NERRORS=$((NERRORS + 1)); }
_ok()   { printf "  ${GREEN}✔${RESET}  %s\n" "$*"; }
_warn() { printf "  ${YELLOW}⚠${RESET}  %s\n" "$*"; NWARNINGS=$((NWARNINGS + 1)); }

FILE="${1:-}"
if [[ -z "$FILE" || ! -f "$FILE" ]]; then
    echo "Usage: $0 <env-file>" >&2
    exit 1
fi

printf "${BOLD}Config-Check: %s${RESET}\n" "$FILE"

# ── Parse env file (key=value, skip comments and blank lines) ─────────────────
declare -A ENV=()
while IFS= read -r line; do
    [[ "$line" =~ ^[[:space:]]*(#|$) ]] && continue
    key="${line%%=*}"
    val="${line#*=}"
    [[ -n "$key" ]] && ENV["$key"]="$val"
done < "$FILE"

_get() { printf '%s' "${ENV[${1}]:-}"; }
_has() { [[ -n "${ENV[${1}]:-}" ]]; }

# ── Validators ────────────────────────────────────────────────────────────────

_check_required() {
    local key="$1" secret="${2:-0}"
    local val; val="$(_get "$key")"
    if [[ -z "$val" ]]; then
        _err "${key} — Pflichtfeld fehlt"
    elif [[ "$secret" == "1" ]]; then
        _ok "${key}=*** (gesetzt)"
    else
        _ok "${key}=${val}"
    fi
}

_check_url() {
    local key="$1"
    local val; val="$(_get "$key")"
    _has "$key" || return 0
    if [[ "$val" =~ ^https?:// ]]; then
        _ok "${key}=${val}"
    else
        _err "${key}=${val} — kein gültiger URL (erwartet: https://...)"
    fi
}

_check_port() {
    local key="$1"
    local val; val="$(_get "$key")"
    _has "$key" || return 0
    if [[ "$val" =~ ^[0-9]+$ ]] && [[ "$val" -ge 1 && "$val" -le 65535 ]]; then
        _ok "${key}=${val}"
    else
        _err "${key}=${val} — kein gültiger Port (1–65535)"
    fi
}

_check_ip() {
    local key="$1"
    local val; val="$(_get "$key")"
    _has "$key" || return 0
    if [[ "$val" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        _ok "${key}=${val}"
    else
        _err "${key}=${val} — keine gültige IPv4-Adresse"
    fi
}

# Pipe-separated 2-letter country codes, e.g. DE|AT|CH
_check_countries() {
    local key="$1"
    local val; val="$(_get "$key")"
    _has "$key" || return 0
    if [[ "$val" == *","* ]]; then
        _err "${key}=${val} — Komma statt Pipe als Trennzeichen. Korrektur: ${val//,/|}"
    elif [[ "$val" =~ ^[A-Z]{2}(\|[A-Z]{2})*$ ]]; then
        _ok "${key}=${val}"
    else
        _warn "${key}=${val} — unerwartetes Format (erwartet: ISO-Codes Pipe-getrennt, z.B. DE|AT)"
    fi
}

# Comma-separated CIDRs, e.g. 10.0.0.0/8,172.16.0.0/12
_check_cidrs() {
    local key="$1"
    local val; val="$(_get "$key")"
    _has "$key" || return 0
    local ok=1
    IFS=',' read -ra nets <<< "$val"
    for net in "${nets[@]}"; do
        net="${net// /}"
        if [[ ! "$net" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$ ]]; then
            _err "${key}: '${net}' ist kein gültiger CIDR"
            ok=0
        fi
    done
    [[ "$ok" == "1" ]] && _ok "${key}=${val}"
}

# ── Run checks ────────────────────────────────────────────────────────────────

printf "\n${DIM}OIDC${RESET}\n"
_check_required  OIDC_PROVIDER_METADATA_URL
_check_url       OIDC_PROVIDER_METADATA_URL
_check_required  OIDC_CLIENT_ID
_check_required  OIDC_CLIENT_SECRET 1
_check_required  OIDC_COOKIE_DOMAIN

printf "\n${DIM}Redis${RESET}\n"
_check_required  REDIS_HOST
_check_port      REDIS_PORT

printf "\n${DIM}GeoIP / Netzwerke${RESET}\n"
_check_countries GEOIP_ALLOW_COUNTRIES
_check_countries GEOLOCK_COUNTRIES
_check_cidrs     INTERNAL_NETWORKS

printf "\n${DIM}Netzwerk${RESET}\n"
_check_ip        IP
_check_port      HTTPS_PORT

# ── Summary ───────────────────────────────────────────────────────────────────
echo
if [[ $NERRORS -gt 0 ]]; then
    printf "${RED}${BOLD}%d Fehler — Deploy abgebrochen.${RESET}\n" "$NERRORS"
    exit 1
elif [[ $NWARNINGS -gt 0 ]]; then
    printf "${YELLOW}${BOLD}%d Warnung(en) — bitte prüfen.${RESET}\n" "$NWARNINGS"
else
    printf "${GREEN}${BOLD}Konfiguration OK.${RESET}\n"
fi
