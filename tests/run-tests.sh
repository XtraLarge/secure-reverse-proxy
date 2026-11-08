#!/bin/bash
# Integration test runner for secure-reverse-proxy
# Usage: ./tests/run-tests.sh [image-name]
# Default image: secure-reverse-proxy:test

set -eu
# Note: pipefail is intentionally NOT set here.
# Many tests use:  run ... 2>&1 | grep -q "pattern"
# grep -q exits immediately on first match, giving docker run a SIGPIPE (exit 141).
# With pipefail the pipeline exit would be 141 even though grep found the pattern.
# Without pipefail the exit status is grep's exit code (0=found, 1=not found).

IMAGE="${1:-secure-reverse-proxy:test}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

PASS=0
FAIL=0

pass() { echo "  PASS: $*"; ((PASS++)) || true; }
fail() { echo "  FAIL: $*"; ((FAIL++)) || true; }

# Standard env + volume mounts used by most tests
BASE_ARGS=(
    -v "$SCRIPT_DIR/ssl:/etc/apache2/ssl:ro"
    -v "$SCRIPT_DIR/sites-enabled:/etc/apache2/sites:ro"
    -v "$SCRIPT_DIR/AddOn:/etc/apache2/AddOn:ro"
    -e OIDC_PROVIDER_METADATA_URL=https://iam.example.com/realms/master/.well-known/openid-configuration
    -e OIDC_CLIENT_ID=Proxy
    -e OIDC_CLIENT_SECRET=test-secret-not-real
    -e OIDC_CRYPTO_PASSPHRASE=test-passphrase-not-real
    -e OIDC_COOKIE_DOMAIN=test.example.com
    -e REDIS_HOST=127.0.0.1
    -e INTERNAL_NETWORKS=10.0.0.0/8
    -e TOC_TITLE=Test-Inhaltsverzeichnis
)

run() { docker run --rm "${BASE_ARGS[@]}" "$IMAGE" "$@"; }

echo "============================================"
echo "secure-reverse-proxy integration tests"
echo "Image: $IMAGE"
echo "============================================"


# ══════════════════════════════════════════════════════════════════════════════
# GROUP 1: Apache config syntax
# ══════════════════════════════════════════════════════════════════════════════

echo ""
echo "[1] Apache configtest with all VHost macro types"
if run apache2ctl configtest 2>&1 | grep -q "Syntax OK"; then
    pass "apache2ctl configtest: Syntax OK"
else
    fail "apache2ctl configtest failed"
    run apache2ctl configtest 2>&1 || true
fi

echo ""
echo "[1b] AddOn snippets are included by exact name only (no backups)"
# tests/AddOn/test.example.com/monitor.preconfig.bak-regression contains an
# invalid directive; it must not appear in the include list.
if run apache2ctl -t -D DUMP_INCLUDES 2>&1 | grep -q "monitor.preconfig.bak-regression"; then
    fail "AddOn backup file was included — macros must use <site>.preconfig/.postconfig, not a glob"
elif run apache2ctl -t -D DUMP_INCLUDES 2>&1 | grep -q "AddOn/test.example.com/monitor.preconfig"; then
    pass "monitor.preconfig included, monitor.preconfig.bak-regression ignored"
else
    fail "monitor.preconfig not found in DUMP_INCLUDES"
fi

echo ""
echo "[2] Apache configtest with empty sites-enabled"
EMPTY_DIR=$(mktemp -d)
if docker run --rm \
    -v "$EMPTY_DIR:/etc/apache2/sites:ro" \
    -e OIDC_PROVIDER_METADATA_URL=https://iam.example.com/.well-known/openid-configuration \
    -e OIDC_CLIENT_SECRET=x \
    -e OIDC_CRYPTO_PASSPHRASE=x \
    -e OIDC_COOKIE_DOMAIN=test.example.com \
    "$IMAGE" apache2ctl configtest 2>&1 | grep -q "Syntax OK"; then
    pass "configtest OK with empty sites-enabled"
else
    fail "configtest failed with empty sites-enabled"
fi
rm -rf "$EMPTY_DIR"


# ══════════════════════════════════════════════════════════════════════════════
# GROUP 2: Required env var validation
# ══════════════════════════════════════════════════════════════════════════════

echo ""
echo "[3] Entrypoint rejects missing OIDC_PROVIDER_METADATA_URL"
if docker run --rm \
    -e OIDC_CLIENT_SECRET=x -e OIDC_CRYPTO_PASSPHRASE=x -e OIDC_COOKIE_DOMAIN=x \
    "$IMAGE" apache2ctl configtest 2>&1 | grep -q "OIDC_PROVIDER_METADATA_URL is required"; then
    pass "Missing OIDC_PROVIDER_METADATA_URL is rejected"
else
    fail "Missing OIDC_PROVIDER_METADATA_URL was not caught"
fi

echo ""
echo "[4] Entrypoint rejects missing OIDC_CLIENT_SECRET"
if docker run --rm \
    -e OIDC_PROVIDER_METADATA_URL=https://iam.example.com/.well-known/openid-configuration \
    -e OIDC_CRYPTO_PASSPHRASE=x -e OIDC_COOKIE_DOMAIN=x \
    "$IMAGE" apache2ctl configtest 2>&1 | grep -q "OIDC_CLIENT_SECRET is required"; then
    pass "Missing OIDC_CLIENT_SECRET is rejected"
else
    fail "Missing OIDC_CLIENT_SECRET was not caught"
fi

echo ""
echo "[5] Entrypoint accepts missing OIDC_CRYPTO_PASSPHRASE (auto-generates key)"
if docker run --rm \
    -v "$SCRIPT_DIR/ssl:/etc/apache2/ssl:ro" \
    -v "$SCRIPT_DIR/sites-enabled:/etc/apache2/sites:ro" \
    -e OIDC_PROVIDER_METADATA_URL=https://iam.example.com/.well-known/openid-configuration \
    -e OIDC_CLIENT_SECRET=x -e OIDC_COOKIE_DOMAIN=test.example.com \
    "$IMAGE" sh -c "grep -q 'OIDCCryptoPassphrase' /etc/apache2/conf-runtime/oidc-passphrase.conf && echo OK" \
    2>&1 | grep -q "OK"; then
    pass "Auto-generated passphrase written to oidc-passphrase.conf"
else
    fail "Passphrase not auto-generated when OIDC_CRYPTO_PASSPHRASE is unset"
fi

echo ""
echo "[6] Entrypoint rejects missing OIDC_COOKIE_DOMAIN"
if docker run --rm \
    -e OIDC_PROVIDER_METADATA_URL=https://iam.example.com/.well-known/openid-configuration \
    -e OIDC_CLIENT_SECRET=x -e OIDC_CRYPTO_PASSPHRASE=x \
    "$IMAGE" apache2ctl configtest 2>&1 | grep -q "OIDC_COOKIE_DOMAIN is required"; then
    pass "Missing OIDC_COOKIE_DOMAIN is rejected"
else
    fail "Missing OIDC_COOKIE_DOMAIN was not caught"
fi


# ══════════════════════════════════════════════════════════════════════════════
# GROUP 3: INTERNAL_NETWORKS CIDR validation
# ══════════════════════════════════════════════════════════════════════════════

echo ""
echo "[7] Entrypoint rejects invalid CIDR in INTERNAL_NETWORKS"
if docker run --rm \
    -v "$SCRIPT_DIR/ssl:/etc/apache2/ssl:ro" \
    -v "$SCRIPT_DIR/sites-enabled:/etc/apache2/sites:ro" \
    -e OIDC_PROVIDER_METADATA_URL=https://iam.example.com/.well-known/openid-configuration \
    -e OIDC_CLIENT_SECRET=x -e OIDC_CRYPTO_PASSPHRASE=x -e OIDC_COOKIE_DOMAIN=test.example.com \
    -e INTERNAL_NETWORKS="not-a-cidr,10.0.0.0/8" \
    "$IMAGE" apache2ctl configtest 2>&1 | grep -q "Invalid CIDR"; then
    pass "Invalid CIDR 'not-a-cidr' is rejected"
else
    fail "Invalid CIDR was not caught"
fi

echo ""
echo "[8] Entrypoint accepts valid multi-CIDR list"
if docker run --rm "${BASE_ARGS[@]}" \
    -e INTERNAL_NETWORKS="10.0.0.0/8,192.168.0.0/16,172.16.0.0/12" \
    "$IMAGE" apache2ctl configtest 2>&1 | grep -q "Syntax OK"; then
    pass "Multiple valid CIDRs accepted"
else
    fail "Valid CIDR list was rejected"
fi


# ══════════════════════════════════════════════════════════════════════════════
# GROUP 4: TOC page (toc.lua)
# ══════════════════════════════════════════════════════════════════════════════

echo ""
echo "[9] toc.lua is present in image at /var/www/html/toc.lua"
if run sh -c "test -f /var/www/html/toc.lua && echo FOUND" 2>&1 | grep -q "FOUND"; then
    pass "toc.lua exists in image"
else
    fail "toc.lua missing from image"
fi

echo ""
echo "[10] toc.lua is valid Lua syntax"
if run sh -c "luac -p /var/www/html/toc.lua && echo LUA_OK" 2>&1 | grep -q "LUA_OK"; then
    pass "toc.lua passes Lua syntax check"
else
    fail "toc.lua has Lua syntax errors"
    run sh -c "luac -p /var/www/html/toc.lua" 2>&1 || true
fi

echo ""
echo "[11] mod_lua is enabled in Apache"
if run sh -c "apache2ctl -M 2>/dev/null | grep -q lua_module && echo MOD_LUA" 2>&1 | grep -q "MOD_LUA"; then
    pass "mod_lua is enabled"
else
    fail "mod_lua is not enabled"
fi

echo ""
echo "[12] TableFilter JS library is present"
if run sh -c "test -f /var/www/res/tablefilter/dist/tablefilter/tablefilter.js && echo FOUND" 2>&1 | grep -q "FOUND"; then
    pass "tablefilter.js exists in image"
else
    fail "tablefilter.js missing from image"
fi


# ══════════════════════════════════════════════════════════════════════════════
# GROUP 5: Logout animation page
# ══════════════════════════════════════════════════════════════════════════════

echo ""
echo "[13] Logout help page index.html is present"
if run sh -c "test -f /var/www/help/index.html && echo FOUND" 2>&1 | grep -q "FOUND"; then
    pass "help/index.html exists in image"
else
    fail "help/index.html missing from image"
fi

echo ""
echo "[14] help4_terminal.js is generated from template on startup"
if run sh -c "test -f /var/www/help/js/help4_terminal.js && echo FOUND" 2>&1 | grep -q "FOUND"; then
    pass "help4_terminal.js generated from template"
else
    fail "help4_terminal.js not generated (template substitution failed?)"
fi

echo ""
echo "[15] help4_terminal.js contains correct OIDC_COOKIE_DOMAIN (not raw placeholder)"
if run sh -c "grep -q 'test.example.com' /var/www/help/js/help4_terminal.js && echo DOMAIN_OK" 2>&1 | grep -q "DOMAIN_OK"; then
    pass "OIDC_COOKIE_DOMAIN substituted correctly in help4_terminal.js"
else
    fail "OIDC_COOKIE_DOMAIN not substituted in help4_terminal.js"
    run sh -c "grep 'redirect' /var/www/help/js/help4_terminal.js" 2>&1 || true
fi

echo ""
echo "[16] help4_terminal.js does not contain raw \${OIDC_COOKIE_DOMAIN} placeholder"
if run sh -c "grep -q '\${OIDC_COOKIE_DOMAIN}' /var/www/help/js/help4_terminal.js 2>/dev/null && echo RAW || echo CLEAN" 2>&1 | grep -q "CLEAN"; then
    pass "No raw template placeholders left in help4_terminal.js"
else
    fail "Raw placeholder \${OIDC_COOKIE_DOMAIN} still present in help4_terminal.js"
fi


# ══════════════════════════════════════════════════════════════════════════════
# GROUP 6: CGI env-dump script
# ══════════════════════════════════════════════════════════════════════════════

echo ""
echo "[17] CGI script echo.pl is present and executable"
if run sh -c "test -x /var/www/cgi/echo.pl && echo FOUND" 2>&1 | grep -q "FOUND"; then
    pass "cgi/echo.pl exists and is executable"
else
    fail "cgi/echo.pl missing or not executable"
fi

echo ""
echo "[18] mod_cgid is enabled in Apache"
if run sh -c "apache2ctl -M 2>/dev/null | grep -q cgid_module && echo MOD_CGID" 2>&1 | grep -q "MOD_CGID"; then
    pass "mod_cgid is enabled"
else
    fail "mod_cgid is not enabled"
fi


# ══════════════════════════════════════════════════════════════════════════════
# GROUP 7: OIDC crypto passphrase rotation
# ══════════════════════════════════════════════════════════════════════════════

echo ""
echo "[19] rotate-oidc-key.sh is present and executable"
if run sh -c "test -x /usr/local/bin/rotate-oidc-key.sh && echo FOUND" 2>&1 | grep -q "FOUND"; then
    pass "rotate-oidc-key.sh exists and is executable"
else
    fail "rotate-oidc-key.sh missing or not executable"
fi

echo ""
echo "[20] oidc-passphrase.conf is generated by entrypoint"
if run sh -c "test -f /etc/apache2/conf-runtime/oidc-passphrase.conf && echo FOUND" 2>&1 | grep -q "FOUND"; then
    pass "oidc-passphrase.conf generated at startup"
else
    fail "oidc-passphrase.conf not generated (entrypoint bug?)"
fi

echo ""
echo "[21] oidc-passphrase.conf contains OIDCCryptoPassphrase directive"
if run sh -c "grep -q 'OIDCCryptoPassphrase' /etc/apache2/conf-runtime/oidc-passphrase.conf && echo OK" 2>&1 | grep -q "OK"; then
    pass "oidc-passphrase.conf has OIDCCryptoPassphrase directive"
else
    fail "oidc-passphrase.conf missing OIDCCryptoPassphrase directive"
    run sh -c "cat /etc/apache2/conf-runtime/oidc-passphrase.conf" 2>&1 || true
fi

echo ""
echo "[22] oidc-passphrase.conf uses provided OIDC_CRYPTO_PASSPHRASE when set"
if run sh -c "grep -q 'test-passphrase-not-real' /etc/apache2/conf-runtime/oidc-passphrase.conf && echo OK" 2>&1 | grep -q "OK"; then
    pass "Provided OIDC_CRYPTO_PASSPHRASE written to oidc-passphrase.conf"
else
    fail "Provided OIDC_CRYPTO_PASSPHRASE not found in oidc-passphrase.conf"
fi

echo ""
echo "[23] rotate-oidc-key.sh updates oidc-passphrase.conf with new key"
# rotate-oidc-key.sh ends with kill -TERM 1 (container restart).
# --init makes tini PID 1 so the test sh is not PID 1.
# trap 'true' TERM lets the test sh survive the SIGTERM propagated by tini.
# mod_auth_openidc < 2.4.14 (Debian 12 ships 2.4.12.x) accepts only one passphrase;
# rotation writes the new single key (re-auth required for sessions with old key).
if docker run --rm --init "${BASE_ARGS[@]}" "$IMAGE" sh -c "
    trap 'true' TERM
    /usr/local/bin/rotate-oidc-key.sh >/dev/null 2>&1 || true
    grep -q 'OIDCCryptoPassphrase' /etc/apache2/conf-runtime/oidc-passphrase.conf && echo UPDATED
" 2>&1 | grep -q "UPDATED"; then
    pass "rotate-oidc-key.sh writes new OIDCCryptoPassphrase after rotation"
else
    fail "rotate-oidc-key.sh did not update oidc-passphrase.conf"
    docker run --rm "${BASE_ARGS[@]}" "$IMAGE" sh -c "cat /etc/apache2/conf-runtime/oidc-passphrase.conf" 2>&1 || true
fi

echo ""
echo "[24] cron.d entry for rotate-oidc-key is installed"
if run sh -c "test -f /etc/cron.d/rotate-oidc-key && echo FOUND" 2>&1 | grep -q "FOUND"; then
    pass "/etc/cron.d/rotate-oidc-key installed"
else
    fail "/etc/cron.d/rotate-oidc-key missing"
fi


# ══════════════════════════════════════════════════════════════════════════════
# GROUP 8: Real startup behaviour
# ══════════════════════════════════════════════════════════════════════════════

echo ""
echo "[25] Container stays running with default APACHE_SERVER_NAME"
START_CID="$(docker run -d --rm \
    -v "$SCRIPT_DIR/ssl:/etc/apache2/ssl:ro" \
    -v "$SCRIPT_DIR/sites-enabled:/etc/apache2/sites:ro" \
    -v "$SCRIPT_DIR/AddOn:/etc/apache2/AddOn:ro" \
    -e OIDC_PROVIDER_METADATA_URL=https://iam.example.com/.well-known/openid-configuration \
    -e OIDC_CLIENT_SECRET=x \
    -e OIDC_CRYPTO_PASSPHRASE=x \
    -e OIDC_COOKIE_DOMAIN=test.example.com \
    -e REDIS_HOST=127.0.0.1 \
    "$IMAGE")"
sleep 2
if [ "$(docker inspect -f '{{.State.Running}}' "$START_CID" 2>/dev/null || echo false)" = "true" ]; then
    pass "Container starts and stays running"
else
    fail "Container did not stay running"
    docker logs "$START_CID" 2>&1 || true
fi

echo ""
echo "[26] Startup logs do not contain AH00558 when APACHE_SERVER_NAME is unset"
if docker logs "$START_CID" 2>&1 | grep -q "AH00558"; then
    fail "AH00558 still present in startup logs"
    docker logs "$START_CID" 2>&1 || true
else
    pass "No AH00558 warning in startup logs"
fi

docker rm -f "$START_CID" >/dev/null 2>&1 || true

echo ""
echo "[27] Compose-like capabilities allow clean cgid startup"
CAP_CID="$(docker run -d --rm \
    --cap-drop ALL \
    --cap-add CHOWN \
    --cap-add KILL \
    --cap-add NET_BIND_SERVICE \
    --cap-add SETGID \
    --cap-add SETUID \
    -v "$SCRIPT_DIR/ssl:/etc/apache2/ssl:ro" \
    -v "$SCRIPT_DIR/sites-enabled:/etc/apache2/sites:ro" \
    -v "$SCRIPT_DIR/AddOn:/etc/apache2/AddOn:ro" \
    -e OIDC_PROVIDER_METADATA_URL=https://iam.example.com/.well-known/openid-configuration \
    -e OIDC_CLIENT_SECRET=x \
    -e OIDC_CRYPTO_PASSPHRASE=x \
    -e OIDC_COOKIE_DOMAIN=test.example.com \
    -e REDIS_HOST=127.0.0.1 \
    "$IMAGE")"
sleep 2
if docker logs "$CAP_CID" 2>&1 | grep -Eq 'AH01238|AH01243|AH02156'; then
    fail "Compose-like startup still logs cgid/setgid errors"
    docker logs "$CAP_CID" 2>&1 || true
else
    pass "Compose-like startup is free of cgid/setgid errors"
fi

echo ""
echo "[27b] Graceful reload with compose-like capabilities keeps serving"
# Without CAP_KILL the root master cannot signal the www-data mod_cgid daemon,
# blocks in waitpid() and stops serving entirely (regression 2026-10-30).
sleep 8
docker exec "$CAP_CID" apache2ctl -k graceful >/dev/null 2>&1 || true
GRACE_OK=0
for _ in 1 2 3 4 5 6 7 8 9 10; do
    sleep 1
    if docker exec "$CAP_CID" curl -so /dev/null --max-time 2 http://localhost/ 2>/dev/null; then GRACE_OK=1; fi
done
if [ "$GRACE_OK" = 1 ] && docker exec "$CAP_CID" curl -so /dev/null --max-time 2 http://localhost/; then
    pass "Apache answers after graceful reload"
else
    fail "Apache stopped answering after graceful reload (missing CAP_KILL?)"
fi

echo ""
echo "[27d] Admin-GUI configtest as www-data works via the root listener"
# The secret includes are root-only (0600); the admin UI runs as www-data and must
# get its configtest from the entrypoint's root listener (regression 2026-11-07).
docker exec -u www-data "$CAP_CID" touch /run/apache-proxy/configtest-req-ci4711 2>/dev/null || true
CT_RES=""
for _ in $(seq 1 20); do
    sleep 1
    CT_RES="$(docker exec -u www-data "$CAP_CID" cat /run/apache-proxy/configtest-res-ci4711 2>/dev/null || true)"
    [ -n "$CT_RES" ] && break
done
if [ "$(echo "$CT_RES" | head -1)" = "rc=0" ] && echo "$CT_RES" | grep -q "Syntax OK" \
   && ! echo "$CT_RES" | grep -q "oidc-passphrase"; then
    pass "configtest via root listener: rc=0, Syntax OK, no protected paths in the output"
else
    fail "configtest via root listener failed or timed out"
    echo "$CT_RES" | tail -5
fi
if docker exec -u www-data "$CAP_CID" cat /etc/apache2/conf-runtime/oidc-passphrase.conf >/dev/null 2>&1; then
    fail "www-data can read the passphrase include"
else
    pass "passphrase include stays unreadable for www-data"
fi

echo ""
echo "[27e] configtest answer does not echo root-only files included from a site file"
# A site file is writable by www-data. If it includes a root-only file, Apache quotes
# that file's first line in the error; the answer to www-data must not contain it.
LEAK_SITES=$(mktemp -d)
cp "$SCRIPT_DIR/sites-enabled/"*.conf "$LEAK_SITES/"
chmod -R a+rwX "$LEAK_SITES"
LEAK_CID="$(docker run -d --rm \
    --cap-drop ALL --cap-add CHOWN --cap-add KILL --cap-add NET_BIND_SERVICE \
    --cap-add SETGID --cap-add SETUID \
    -v "$SCRIPT_DIR/ssl:/etc/apache2/ssl:ro" \
    -v "$LEAK_SITES:/etc/apache2/sites" \
    -v "$SCRIPT_DIR/AddOn:/etc/apache2/AddOn:ro" \
    -e OIDC_PROVIDER_METADATA_URL=https://iam.example.com/.well-known/openid-configuration \
    -e OIDC_CLIENT_SECRET=x -e OIDC_CRYPTO_PASSPHRASE=x \
    -e OIDC_COOKIE_DOMAIN=test.example.com -e REDIS_HOST=127.0.0.1 \
    "$IMAGE")"
sleep 8
docker exec -u www-data "$LEAK_CID" sh -c 'echo "Include /etc/shadow" > /etc/apache2/sites/zz-leak.conf' 2>/dev/null || true
docker exec -u www-data "$LEAK_CID" touch /run/apache-proxy/configtest-req-ci4712 2>/dev/null || true
LEAK_RES=""
for _ in $(seq 1 20); do
    sleep 1
    LEAK_RES="$(docker exec -u www-data "$LEAK_CID" cat /run/apache-proxy/configtest-res-ci4712 2>/dev/null || true)"
    [ -n "$LEAK_RES" ] && break
done
if [ -n "$LEAK_RES" ] && [ "$(echo "$LEAK_RES" | head -1)" != "rc=0" ] \
   && ! echo "$LEAK_RES" | grep -q "root:" && echo "$LEAK_RES" | grep -q "hidden"; then
    pass "configtest failed as expected and the included root-only content is hidden"
else
    fail "configtest answer leaks content of a root-only file (or no answer)"
    echo "$LEAK_RES" | sed 's/root:[^ ]*/root:<cut>/' | tail -5
fi
docker rm -f "$LEAK_CID" >/dev/null 2>&1 || true
# the container chowned the dir to www-data (uid 33) — remove its content from inside a container
docker run --rm --entrypoint sh -v "$LEAK_SITES:/x" "$IMAGE" -c 'rm -rf /x/* /x/.[!.]*' >/dev/null 2>&1 || true
rm -rf "$LEAK_SITES" 2>/dev/null || true

echo ""
echo "[27f] planted symlinks / directories in the run dir do not redirect root's writes"
KEY=/etc/apache2/conf-runtime/oidc-passphrase.key
SUM_BEFORE="$(docker exec "$CAP_CID" sh -c "stat -c '%a %U %G' $KEY; md5sum < $KEY")"
docker exec -u www-data "$CAP_CID" sh -c "ln -s $KEY /run/apache-proxy/configtest-res-ci4713; \
  mkdir /run/apache-proxy/configtest-req-cidir; ln -s $KEY /run/apache-proxy/configtest-req-cilink; \
  touch /run/apache-proxy/configtest-req-ci4713" 2>/dev/null || true
sleep 6
SUM_AFTER="$(docker exec "$CAP_CID" sh -c "stat -c '%a %U %G' $KEY; md5sum < $KEY")"
LEFT="$(docker exec "$CAP_CID" sh -c 'ls -d /run/apache-proxy/configtest-req-* 2>/dev/null' || true)"
RES_IS_FILE="$(docker exec "$CAP_CID" sh -c '[ -f /run/apache-proxy/configtest-res-ci4713 ] && [ ! -L /run/apache-proxy/configtest-res-ci4713 ] && echo yes' || true)"
if [ -n "$SUM_BEFORE" ] && [ "$SUM_BEFORE" = "$SUM_AFTER" ] && [ -z "$LEFT" ] && [ "$RES_IS_FILE" = yes ]; then
    pass "protected file unchanged, symlink replaced by the answer, bogus requests removed"
else
    fail "planted symlink/dir changed something (key unchanged: $([ "$SUM_BEFORE" = "$SUM_AFTER" ] && echo yes || echo NO), left: $LEFT, answer is file: $RES_IS_FILE)"
fi

echo ""
echo "[27c] Admin-GUI reload trigger reloads gracefully (no container restart)"
MPID_BEFORE="$(docker exec "$CAP_CID" pgrep -o -x apache2 2>/dev/null || true)"
docker exec "$CAP_CID" touch /run/apache-proxy/reload-requested 2>/dev/null || true
sleep 12
MPID_AFTER="$(docker exec "$CAP_CID" pgrep -o -x apache2 2>/dev/null || true)"
if [ -n "$MPID_BEFORE" ] && [ "$MPID_BEFORE" = "$MPID_AFTER" ] \
   && docker exec "$CAP_CID" curl -so /dev/null --max-time 2 http://localhost/ \
   && docker logs "$CAP_CID" 2>&1 | grep -q "Graceful reload OK"; then
    pass "Reload trigger handled gracefully (master PID ${MPID_AFTER} unchanged)"
else
    fail "Reload trigger did not reload gracefully (before=${MPID_BEFORE} after=${MPID_AFTER})"
    docker logs "$CAP_CID" 2>&1 | tail -20 || true
fi

docker rm -f "$CAP_CID" >/dev/null 2>&1 || true


# ══════════════════════════════════════════════════════════════════════════════
# GROUP 9: active-ssl certificate resolution
# ══════════════════════════════════════════════════════════════════════════════

echo ""
echo "[28] active-ssl symlink points to ssl/ volume when no letsencrypt cert exists"
if run sh -c "readlink /run/apache2/active-ssl/test.example.com/cert.pem" 2>&1 \
        | grep -q "/etc/apache2/ssl/test.example.com/cert.pem"; then
    pass "active-ssl/test.example.com/cert.pem → ssl/ volume"
else
    fail "active-ssl/test.example.com/cert.pem does not point to ssl/ volume"
fi

echo ""
echo "[29] active-ssl symlink prefers letsencrypt over ssl/ volume"
if docker run --rm \
        -v "$SCRIPT_DIR/ssl:/etc/apache2/ssl:ro" \
        -v "$SCRIPT_DIR/sites-enabled:/etc/apache2/sites:ro" \
        -v "$SCRIPT_DIR/AddOn:/etc/apache2/AddOn:ro" \
        -v "$SCRIPT_DIR/letsencrypt:/etc/letsencrypt:ro" \
        -e OIDC_PROVIDER_METADATA_URL=https://iam.example.com/realms/master/.well-known/openid-configuration \
        -e OIDC_CLIENT_SECRET=test-secret-not-real \
        -e OIDC_CRYPTO_PASSPHRASE=test-passphrase-not-real \
        -e OIDC_COOKIE_DOMAIN=test.example.com \
        -e REDIS_HOST=127.0.0.1 \
        -e INTERNAL_NETWORKS=10.0.0.0/8 \
        "$IMAGE" sh -c "readlink /run/apache2/active-ssl/test.example.com/cert.pem" 2>&1 \
        | grep -q "/etc/letsencrypt/live/"; then
    pass "active-ssl/test.example.com/cert.pem → letsencrypt when LE cert present"
else
    fail "active-ssl/test.example.com/cert.pem does not prefer letsencrypt over ssl/"
fi

echo ""
echo "[30] self-signed placeholder created when ACME_EMAIL set and no cert in ssl/"
EMPTY_SSL_DIR="$(mktemp -d)"
if docker run --rm \
        -v "$EMPTY_SSL_DIR:/etc/apache2/ssl:ro" \
        -v "$SCRIPT_DIR/sites-enabled:/etc/apache2/sites:ro" \
        -v "$SCRIPT_DIR/AddOn:/etc/apache2/AddOn:ro" \
        -e OIDC_PROVIDER_METADATA_URL=https://iam.example.com/realms/master/.well-known/openid-configuration \
        -e OIDC_CLIENT_SECRET=test-secret-not-real \
        -e OIDC_CRYPTO_PASSPHRASE=test-passphrase-not-real \
        -e OIDC_COOKIE_DOMAIN=test.example.com \
        -e REDIS_HOST=127.0.0.1 \
        -e INTERNAL_NETWORKS=10.0.0.0/8 \
        -e ACME_EMAIL=test@example.com \
        "$IMAGE" sh -c "test -f /run/apache2/active-ssl/test.example.com/cert.pem && echo SELFSIGNED" 2>&1 \
        | grep -q "SELFSIGNED"; then
    pass "Self-signed placeholder created for test.example.com"
else
    fail "Self-signed placeholder not created when ACME_EMAIL set and no ssl/ cert"
fi
rm -rf "$EMPTY_SSL_DIR"


# ══════════════════════════════════════════════════════════════════════════════
# GROUP 10: acme-init.sh behavior
# ══════════════════════════════════════════════════════════════════════════════

echo ""
echo "[31] acme-init.sh exits 0 when ACME_EMAIL not set"
if docker run --rm \
        --entrypoint /usr/local/bin/acme-init.sh \
        "$IMAGE" 2>&1 | grep -q "ACME_EMAIL not set"; then
    pass "acme-init.sh skips cleanly when ACME_EMAIL not set"
else
    fail "acme-init.sh did not skip when ACME_EMAIL not set"
fi

echo ""
echo "[32] acme-init.sh exits 0 when no domains found in conf files"
EMPTY_SITES_DIR="$(mktemp -d)"
if docker run --rm \
        --entrypoint /usr/local/bin/acme-init.sh \
        -v "$EMPTY_SITES_DIR:/etc/apache2/sites:ro" \
        -v "$EMPTY_SITES_DIR:/etc/apache2/sites-admin:ro" \
        -e ACME_EMAIL=test@example.com \
        "$IMAGE" 2>&1 | grep -q "No domains found"; then
    pass "acme-init.sh skips cleanly when no domains found"
else
    fail "acme-init.sh did not skip when no domains found"
fi
rm -rf "$EMPTY_SITES_DIR"


# ══════════════════════════════════════════════════════════════════════════════
# GROUP 10: Lua module integration — syntax, lfs availability, deadlock check
# ══════════════════════════════════════════════════════════════════════════════

echo ""
echo "[33] admin.lua is valid Lua syntax"
if run sh -c "luac -p /var/www/html/admin.lua && echo LUA_OK" 2>&1 | grep -q "LUA_OK"; then
    pass "admin.lua passes Lua syntax check"
else
    fail "admin.lua has Lua syntax errors"
    run sh -c "luac -p /var/www/html/admin.lua" 2>&1 || true
fi

echo ""
echo "[34] admin-kc.lua is valid Lua syntax"
if run sh -c "luac -p /var/www/html/admin-kc.lua && echo LUA_OK" 2>&1 | grep -q "LUA_OK"; then
    pass "admin-kc.lua passes Lua syntax check"
else
    fail "admin-kc.lua has Lua syntax errors"
    run sh -c "luac -p /var/www/html/admin-kc.lua" 2>&1 || true
fi

echo ""
echo "[35] lua-filesystem available and lfs.dir() replaces popen('ls') for conf scanning"
if run sh -c "lua5.4 -e \"
  local ok, lfs = pcall(require, 'lfs')
  if not ok then io.write('LFS_MISSING'); os.exit(1) end
  local n = 0
  pcall(function()
    for f in lfs.dir('/etc/apache2/sites') do
      if f:match('%.conf$') then n = n + 1 end
    end
  end)
  io.write('LFS_SCAN_OK_' .. n)
\" && echo" 2>&1 | grep -q "LFS_SCAN_OK"; then
    pass "lfs.dir() available and scans sites/ (no popen fork needed)"
else
    fail "lua-filesystem missing or lfs.dir() failed — popen fallback would be used"
fi

echo ""
echo "[36] No zombie Apache workers after first Lua request (LuaScope server deadlock check)"
LUA_CID="$(docker run -d -p 0:80 "${BASE_ARGS[@]}" "$IMAGE")"
LUA_PORT="$(docker inspect -f '{{(index (index .NetworkSettings.Ports "80/tcp") 0).HostPort}}' \
    "$LUA_CID" 2>/dev/null || echo "")"
# Wait for Apache to be up (health check: curl http://localhost/ returns non-5xx)
_lua_up=0
for _i in 1 2 3 4 5 6 7 8 9 10; do
    sleep 1
    if docker exec "$LUA_CID" curl -sf --max-time 1 http://localhost/ -o /dev/null 2>/dev/null; then
        _lua_up=1; break
    fi
done
if [ -n "$LUA_PORT" ] && [ "$_lua_up" -eq 1 ]; then
    # Hit the unprotected Lua vhost — forces mod_lua to initialise LuaScope server state
    # including _scan_conf_dirs() (lfs.dir). A popen-based deadlock would leave workers as zombies.
    ZOMBIES_BEFORE="$(docker exec "$LUA_CID" ps aux 2>/dev/null | { grep -c '<defunct>' || true; })"
    curl -sf --max-time 5 "http://localhost:${LUA_PORT}/" \
        -H "Host: lua-test.test.example.com" -o /dev/null 2>/dev/null || true
    sleep 3
    ZOMBIES_AFTER="$(docker exec "$LUA_CID" ps aux 2>/dev/null | { grep -c '<defunct>' || true; })"
    if [ "$ZOMBIES_AFTER" -le "$ZOMBIES_BEFORE" ]; then
        pass "No new zombie workers after Lua request — lfs.dir init is deadlock-free"
    else
        fail "Found $((ZOMBIES_AFTER - ZOMBIES_BEFORE)) new zombie worker(s) after Lua init — possible lfs.dir deadlock"
        docker exec "$LUA_CID" ps aux 2>/dev/null || true
    fi
else
    fail "Container or Apache did not start within 10s for Lua zombie test"
    docker logs "$LUA_CID" 2>&1 | tail -10 || true
fi
docker rm -f "$LUA_CID" >/dev/null 2>&1 || true


# ══════════════════════════════════════════════════════════════════════════════
# GROUP: shipped example configurations
# ══════════════════════════════════════════════════════════════════════════════
# The documented examples must start as they are. No certificates are mounted:
# the entrypoint has to create a temporary self-signed certificate per domain.

REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
EX_DIR=$(mktemp -d)
mkdir -p "$EX_DIR/example" "$EX_DIR/keycloak" "$EX_DIR/setup"
cp "$REPO_DIR/conf/sites-available/example.conf" "$EX_DIR/example/example.com.conf"
sed -n "/<<'SITEEOF'/,/^SITEEOF/p" "$REPO_DIR/examples/keycloak/prepare.sh" | sed '1d;$d' \
    > "$EX_DIR/keycloak/127.0.0.1.nip.io.conf"
sed -n '/<<SITEEOF/,/^SITEEOF/p' "$REPO_DIR/scripts/setup.sh" | sed '1d;$d' \
    | sed 's/\${DOMAIN}/example.org/g; s/\${ADMIN_USER}/alice/g' > "$EX_DIR/setup/example.org.conf"
chmod -R a+rX "$EX_DIR"

for ex in example:example.com keycloak:127.0.0.1.nip.io setup:example.org; do
    name="${ex%%:*}"; dom="${ex#*:}"
    echo ""
    echo "[38-$name] shipped example ($name) passes configtest and creates the frame vhosts"
    if [ ! -s "$EX_DIR/$name/$dom.conf" ]; then
        fail "example $name could not be extracted"
        continue
    fi
    EX_OUT="$(docker run --rm \
        -v "$EX_DIR/$name:/etc/apache2/sites:ro" \
        -e OIDC_PROVIDER_METADATA_URL="https://idp.$dom/realms/master/.well-known/openid-configuration" \
        -e OIDC_CLIENT_ID=Proxy -e OIDC_CLIENT_SECRET=test-secret-not-real \
        -e OIDC_CRYPTO_PASSPHRASE=test-passphrase-not-real -e OIDC_COOKIE_DOMAIN="$dom" \
        -e REDIS_HOST=127.0.0.1 \
        "$IMAGE" sh -c 'apache2ctl -t 2>&1; apache2ctl -S 2>/dev/null' 2>&1 || true)"
    missing=""
    for v in toc logout admin geolock; do
        echo "$EX_OUT" | grep -q "namevhost $v.$dom " || missing="$missing $v"
    done
    if echo "$EX_OUT" | grep -q "Syntax OK" && [ -z "$missing" ]; then
        pass "example $name: Syntax OK, toc/logout/admin/geolock present"
    else
        fail "example $name: configtest failed or frame vhosts missing:$missing"
        echo "$EX_OUT" | grep -vE "AH00558" | tail -5
    fi
done
rm -rf "$EX_DIR" 2>/dev/null || true

echo ""
echo "[39] domain without certificate gets a self-signed placeholder (no failed start)"
NOCERT_DIR=$(mktemp -d)
printf "USE Domain_Init nocert.example.net www 'alice'\nUSE Domain_Final nocert.example.net www\n" \
    > "$NOCERT_DIR/nocert.example.net.conf"
chmod -R a+rX "$NOCERT_DIR"
NC_OUT="$(docker run --rm -v "$NOCERT_DIR:/etc/apache2/sites:ro" \
    -e OIDC_PROVIDER_METADATA_URL=https://idp.example.net/realms/master/.well-known/openid-configuration \
    -e OIDC_CLIENT_ID=Proxy -e OIDC_CLIENT_SECRET=x -e OIDC_CRYPTO_PASSPHRASE=x \
    -e OIDC_COOKIE_DOMAIN=nocert.example.net -e REDIS_HOST=127.0.0.1 \
    "$IMAGE" sh -c 'apache2ctl -t 2>&1; stat -c "%a" /run/apache2/active-ssl/nocert.example.net/key.pem' 2>&1 || true)"
if echo "$NC_OUT" | grep -q "Syntax OK" && echo "$NC_OUT" | grep -q "self-signed placeholder" \
   && echo "$NC_OUT" | grep -qx "600"; then
    pass "placeholder certificate created (key 0600), configtest OK"
else
    fail "no placeholder certificate or configtest failed"
    echo "$NC_OUT" | tail -5
fi
rm -rf "$NOCERT_DIR" 2>/dev/null || true


# ══════════════════════════════════════════════════════════════════════════════
# Summary
# ══════════════════════════════════════════════════════════════════════════════

echo ""
echo "============================================"
echo "Results: $PASS passed, $FAIL failed"
echo "============================================"

[ "$FAIL" -eq 0 ]
