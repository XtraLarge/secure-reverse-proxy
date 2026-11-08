#!/bin/bash
# proxy-config-guard.sh — check the user-editable configuration before Apache parses it.
#
# sites/, AddOn/ and config/ are writable by www-data (admin UI). Apache's master runs as
# root and parses these files at start and on every reload, so a directive there could
# make root load code, run programs, write or include arbitrary files. The guard therefore
# allows per directory only what is needed:
#
#   sites/*.conf   only "Use <macro> …" lines (and LogLevel); the site/domain parameters
#                  must be plain names — they end up in file paths inside the macros
#   config/        oidc-clients/<domain>.conf: only OIDC* directives;
#                  extra-countries.conf and geolock/<domain>/<site>.conf: only SetEnvIf
#                  (all other files there are never included by Apache)
#   AddOn/**       vhost directives, but no LoadModule/LoadFile, no logs outside
#                  /var/log/apache2/ (and no piped logs), no RewriteMap programs,
#                  no SSL program hooks, no server-level directives, Include only of
#                  AddOn files and the public runtime includes, same Use checks as sites/
#   everywhere     no ${...}, no Define/UnDefine, no own <Macro>, no symlinks or
#                  special files, no control characters (except tab) or NUL bytes;
#                  line continuations are joined (not allowed on the last line),
#                  CR and BOM removed
#
# Usage: proxy-config-guard.sh                      (the real directories)
#        GUARD_SITES=… GUARD_ADDON=… GUARD_CONFIG=… [GUARD_INCLUDE_ROOT=…] proxy-config-guard.sh
# Prints "file:line: reason" per finding; exit 0 = clean, 1 = findings.
set -u
shopt -s nocasematch

SITES="${GUARD_SITES:-/etc/apache2/sites}"
ADDON="${GUARD_ADDON:-/etc/apache2/AddOn}"
CONFIG="${GUARD_CONFIG:-/etc/apache2/config}"
# AddOn files may include other AddOn files below this root (live: /etc/apache2,
# snapshot: /run/apache2/cfg — the entrypoint rewrites those Include paths in the copy)
INCLUDE_ROOT="${GUARD_INCLUDE_ROOT:-/etc/apache2}"
found=0
report() { printf '%s\n' "$1"; found=1; }

NAME_RE='^[A-Za-z0-9][A-Za-z0-9.-]*$'        # site / domain / default subdomain
# macros whose first parameters are a URL or an auth setting, not a site/domain name
NOT_NAME_MACROS='^(rewrite2url|proxy|clientbasic|defaults|security_headers|oidc_no_access_handler)$'

# Use <macro> <p1> <p2> …: the first two parameters are always site/domain names
# (Domain_*: domain + default subdomain) and are used in Include and log paths.
check_use() {   # $1 file:line, $2 line
    local where="$1" l="$2" macro p1 p2
    IFS=$' \t' read -r _ macro p1 p2 _rest <<< "$l"
    if [[ -z "${macro:-}" ]]; then report "$where: Use without macro"; return; fi
    if ! [[ "$macro" =~ ^[A-Za-z0-9_]+$ ]]; then report "$where: Use: macro name '$macro' is not allowed here"; return; fi
    [[ "$macro" =~ $NOT_NAME_MACROS ]] && return
    for p in "${p1:-}" "${p2:-}"; do
        [[ -z "$p" ]] && continue
        if [[ "$p" == *..* ]] || ! [[ "$p" =~ $NAME_RE ]]; then
            report "$where: Use $macro: parameter '$p' must be a plain site/domain name"
        fi
    done
}

common_checks() {   # returns 0 if a finding was reported
    local where="$1" l="$2"
    if [[ "$l" == *'${'* ]]; then report "$where: \${...} variables are not allowed here"; return 0; fi
    if [[ "$l" =~ ^(\<Macro|Define|UnDefine)([[:space:]]|$) ]]; then
        report "$where: ${BASH_REMATCH[1]} is not allowed here"; return 0
    fi
    return 1
}

check_sites_line() {
    local where="$1" l="$2"
    common_checks "$where" "$l" && return
    if [[ "$l" =~ ^Use[[:space:]] ]]; then check_use "$where" "$l"
    elif [[ "$l" =~ ^LogLevel[[:space:]]+[A-Za-z0-9:_[:space:]-]+$ ]]; then :
    else report "$where: only 'Use <macro> …' lines are allowed in sites/"
    fi
}

check_addon_line() {
    local where="$1" l="$2" p
    common_checks "$where" "$l" && return
    if [[ "$l" =~ ^Use[[:space:]] ]]; then check_use "$where" "$l"
    elif [[ "$l" =~ ^(LoadModule|LoadFile)([[:space:]]|$) ]]; then
        report "$where: ${BASH_REMATCH[1]} is not allowed here"
    elif [[ "$l" =~ ^(ErrorLog|CustomLog|TransferLog|GlobalLog|ScriptLog)([[:space:]]+\"?([^\"[:space:]]*))? ]]; then
        local d="${BASH_REMATCH[1]}"; p="${BASH_REMATCH[3]:-}"
        if [[ "$p" == *..* ]] || ! [[ "$p" =~ ^(/var/log/apache2/[^|]+|syslog(:[a-z0-9]+)?)$ ]]; then
            report "$where: $d only to /var/log/apache2/ or syslog"
        fi
    elif [[ "$l" =~ ^(User|Group|ServerRoot|PidFile|Mutex|ScriptSock|CoreDumpDirectory|DefaultRuntimeDir|ScoreBoardFile|SSLPassPhraseDialog|SSLCryptoDevice|SSLOpenSSLConfCmd|SSLSessionCache|SSLStaplingCache|LuaPackagePath|LuaPackageCPath|DavLockDB|BalancerPersist)([[:space:]]|$) ]]; then
        report "$where: ${BASH_REMATCH[1]} is not allowed here"
    elif [[ "$l" =~ ^(SetHandler|AddHandler)[[:space:]].*(server-info|server-status|balancer-manager|ldap-status) ]]; then
        report "$where: ${BASH_REMATCH[2]} is not allowed here"
    elif [[ "$l" =~ ^SSLRandomSeed[[:space:]].*exec: ]]; then
        report "$where: SSLRandomSeed exec: is not allowed here"
    elif [[ "$l" =~ ^RewriteMap[[:space:]].*(prg|dbd|fastdbd): ]]; then
        report "$where: RewriteMap ${BASH_REMATCH[1]}: is not allowed here"
    elif [[ "$l" =~ ^Include(Optional)?([[:space:]]+\"?([^\"[:space:]]*))? ]]; then
        p="${BASH_REMATCH[3]:-}"
        if [[ "$p" == *..* || "$p" == *[\*\?\[]* ]] \
           || ! [[ "$p" == "$INCLUDE_ROOT"/AddOn/* && "${p#"$INCLUDE_ROOT"/AddOn/}" =~ ^[^/]+(/[^/]+)*$ \
                || "$p" =~ ^/etc/apache2/conf-runtime/(internal-networks|internal-env|iam-admin-oidc)\.conf$ ]]; then
            report "$where: Include of ${p:-<empty>} is not allowed here"
        fi
    fi
}

check_config_line() {   # $3 = kind (oidc|setenvif)
    local where="$1" l="$2" kind="$3"
    common_checks "$where" "$l" && return
    case "$kind" in
        oidc)     [[ "$l" =~ ^OIDC[A-Za-z]+[[:space:]] ]] || report "$where: only OIDC* directives are allowed here" ;;
        setenvif) [[ "$l" =~ ^SetEnvIf[[:space:]] ]]       || report "$where: only SetEnvIf is allowed here" ;;
    esac
}

scan_file() {   # $1 file, $2 checker, $3 extra arg
    local f="$1" checker="$2" extra="${3:-}" n=0 start=0 buf="" line l bad=0 cont=0
    # bash drops NUL bytes while Apache ends the line there — both must see the same text
    if [ "$(tr -d '\000' < "$f" | wc -c)" != "$(wc -c < "$f")" ]; then
        report "$f: NUL bytes are not allowed here"; return
    fi
    while IFS= read -r line || [ -n "$line" ]; do
        n=$((n + 1)); [ "$cont" = 0 ] && { start=$n; bad=0; }
        line="${line%$'\r'}"; [ "$n" = 1 ] && line="${line#$'\xef\xbb\xbf'}"
        # Apache splits words at every whitespace incl. VT/FF; the checks here don't —
        # control characters (except tab) are rejected per physical line, before joining
        if [[ "$line" == *[$'\x01'-$'\x08'$'\x0a'-$'\x1f'$'\x7f']* ]]; then bad=1; fi
        if [[ "$line" == *'\' ]]; then buf+="${line%\\}"; cont=1; continue; fi   # Apache line continuation
        buf+="$line"; cont=0
        l="${buf#"${buf%%[![:space:]]*}"}"; buf=""
        if [ "$bad" = 1 ]; then report "$f:$start: control characters are not allowed here"; continue; fi
        case "$l" in ''|'#'*) continue ;; esac
        "$checker" "$f:$start" "$l" "$extra"
    done < "$f"
    # a continuation on the last line has no end — never pass it on unchecked
    if [ "$cont" = 1 ]; then
        report "$f:$start: line continuation at end of file is not allowed here"
    fi
}

for d in "$SITES" "$ADDON" "$CONFIG"; do
    [ -d "$d" ] || continue
    while IFS= read -r -d '' f; do
        report "$f: symbolic links and special files are not allowed here"
    done < <(find "$d" -mindepth 1 \( -type l -o -type p -o -type c -o -type b -o -type s \) -print0 2>/dev/null)
done

# sites/: Apache includes sites/*.conf (top level only)
if [ -d "$SITES" ]; then
    while IFS= read -r -d '' f; do scan_file "$f" check_sites_line
    done < <(find "$SITES" -maxdepth 1 -type f -name '*.conf' -print0 2>/dev/null)
fi
# AddOn/: everything can be included from a vhost
if [ -d "$ADDON" ]; then
    while IFS= read -r -d '' f; do scan_file "$f" check_addon_line
    done < <(find "$ADDON" -type f -print0 2>/dev/null)
fi
# config/: only the files the macros include
if [ -d "$CONFIG" ]; then
    while IFS= read -r -d '' f; do
        rel="${f#"$CONFIG"/}"
        if [[ "$rel" =~ ^oidc-clients/[^/]+\.conf$ ]]; then scan_file "$f" check_config_line oidc
        elif [[ "$rel" == extra-countries.conf || "$rel" =~ ^geolock/[^/]+/[^/]+\.conf$ ]]; then
            scan_file "$f" check_config_line setenvif
        fi
    done < <(find "$CONFIG" -type f -print0 2>/dev/null)
fi
exit "$found"
