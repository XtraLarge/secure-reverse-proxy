#!/bin/bash
# proxy-config-guard.sh — check the user-editable configuration before Apache parses it.
#
# sites/, AddOn/ and config/ are writable by www-data (admin UI). Apache's master runs
# as root and parses these files at start and on every reload, so some directives there
# would let whoever writes them run code or read files as root. Those are rejected:
#   - LoadModule / LoadFile, piped logs, RewriteMap programs, SSL program hooks
#   - server-level settings (User, Group, ServerRoot, PidFile, Mutex, …)
#   - ${...} variables, Define/UnDefine and own <Macro> blocks (could assemble the above)
#   - Include / IncludeOptional outside sites/, AddOn/, config/ and the few public
#     runtime includes; paths with ".." or wildcards
#   - symlinks and special files (Apache would follow them, this check could not)
#
# Usage: proxy-config-guard.sh [dir ...]   (default: the three user directories)
# Prints "file:line: reason" per finding; exit 0 = clean, 1 = findings.
set -u
shopt -s nocasematch

if [ "$#" -gt 0 ]; then DIRS=("$@"); else
    DIRS=(/etc/apache2/sites /etc/apache2/AddOn /etc/apache2/config)
fi
found=0
report() { printf '%s\n' "$1"; found=1; }

check_line() {   # $1 file, $2 line number, $3 logical line (continuations joined)
    local f="$1" n="$2" l="$3" p
    l="${l#"${l%%[![:space:]]*}"}"
    case "$l" in ''|'#'*) return ;; esac
    if [[ "$l" == *'${'* ]]; then
        report "$f:$n: \${...} variables are not allowed here"
    elif [[ "$l" =~ ^(LoadModule|LoadFile)[[:space:]] ]]; then
        report "$f:$n: ${BASH_REMATCH[1]} is not allowed here"
    elif [[ "$l" =~ ^(\<Macro|Define|UnDefine)([[:space:]]|$) ]]; then
        report "$f:$n: ${BASH_REMATCH[1]} is not allowed here"
    elif [[ "$l" =~ ^(ErrorLog|CustomLog|TransferLog|GlobalLog)[[:space:]]+\"?[[:space:]]*\| ]]; then
        report "$f:$n: piped logs are not allowed here"
    elif [[ "$l" =~ ^(User|Group|ServerRoot|PidFile|Mutex|ScriptSock|CoreDumpDirectory|DefaultRuntimeDir|SSLPassPhraseDialog|SSLCryptoDevice|SSLOpenSSLConfCmd)([[:space:]]|$) ]]; then
        report "$f:$n: ${BASH_REMATCH[1]} is not allowed here"
    elif [[ "$l" =~ ^SSLRandomSeed[[:space:]].*exec: ]]; then
        report "$f:$n: SSLRandomSeed exec: is not allowed here"
    elif [[ "$l" =~ ^RewriteMap[[:space:]].*(prg|dbd|fastdbd): ]]; then
        report "$f:$n: RewriteMap ${BASH_REMATCH[1]}: is not allowed here"
    elif [[ "$l" =~ ^Include(Optional)?[[:space:]]+\"?([^\"[:space:]]+) ]]; then
        p="${BASH_REMATCH[2]}"
        if [[ "$p" == *..* || "$p" == *[\*\?\[]* ]] || ! [[ "$p" =~ ^/etc/apache2/(sites|AddOn|config)/ \
             || "$p" =~ ^/etc/apache2/conf-runtime/(internal-networks|internal-env|iam-admin-oidc)\.conf$ ]]; then
            report "$f:$n: Include of $p is not allowed here"
        fi
    fi
}

for d in "${DIRS[@]}"; do
    [ -d "$d" ] || continue
    while IFS= read -r -d '' f; do
        report "$f: symbolic links and special files are not allowed here"
    done < <(find "$d" -mindepth 1 \( -type l -o -type p -o -type c -o -type b -o -type s \) -print0 2>/dev/null)
    while IFS= read -r -d '' f; do
        n=0; start=0; buf=""
        while IFS= read -r line || [ -n "$line" ]; do
            n=$((n + 1)); [ -z "$buf" ] && start=$n
            if [[ "$line" == *'\' ]]; then buf+="${line%\\}"; continue; fi   # Apache line continuation
            buf+="$line"
            check_line "$f" "$start" "$buf"
            buf=""
        done < "$f"
        [ -n "$buf" ] && check_line "$f" "$start" "$buf"
    done < <(find "$d" -type f -print0 2>/dev/null)
done
exit "$found"
