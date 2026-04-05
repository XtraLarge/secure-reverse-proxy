#!/bin/bash
# Integration test runner for apache-oidc-proxy
# Usage: ./tests/run-tests.sh [image-name]
# Default image: apache-oidc-proxy:test

set -euo pipefail

IMAGE="${1:-apache-oidc-proxy:test}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

PASS=0
FAIL=0

pass() { echo "  PASS: $*"; ((PASS++)) || true; }
fail() { echo "  FAIL: $*"; ((FAIL++)) || true; }

# Standard env + volume mounts used by most tests
BASE_ARGS=(
    -v "$SCRIPT_DIR/ssl:/etc/apache2/ssl:ro"
    -v "$SCRIPT_DIR/sites-enabled:/etc/apache2/sites-enabled:ro"
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
echo "apache-oidc-proxy integration tests"
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
echo "[2] Apache configtest with empty sites-enabled"
EMPTY_DIR=$(mktemp -d)
if docker run --rm \
    -v "$EMPTY_DIR:/etc/apache2/sites-enabled:ro" \
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
    -v "$SCRIPT_DIR/sites-enabled:/etc/apache2/sites-enabled:ro" \
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
    -v "$SCRIPT_DIR/sites-enabled:/etc/apache2/sites-enabled:ro" \
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
echo "[23] rotate-oidc-key.sh produces two-passphrase conf after rotation"
if run sh -c "
    /usr/local/bin/rotate-oidc-key.sh >/dev/null 2>&1 || true
    COUNT=\$(grep -o '\"[^\"]*\"' /etc/apache2/conf-runtime/oidc-passphrase.conf | wc -l)
    [ \"\$COUNT\" -ge 2 ] && echo TWO_KEYS
" 2>&1 | grep -q "TWO_KEYS"; then
    pass "rotate-oidc-key.sh writes two passphrases (new + previous)"
else
    fail "rotate-oidc-key.sh did not produce two passphrases"
    run sh -c "cat /etc/apache2/conf-runtime/oidc-passphrase.conf" 2>&1 || true
fi

echo ""
echo "[24] cron.d entry for rotate-oidc-key is installed"
if run sh -c "test -f /etc/cron.d/rotate-oidc-key && echo FOUND" 2>&1 | grep -q "FOUND"; then
    pass "/etc/cron.d/rotate-oidc-key installed"
else
    fail "/etc/cron.d/rotate-oidc-key missing"
fi


# ══════════════════════════════════════════════════════════════════════════════
# Summary
# ══════════════════════════════════════════════════════════════════════════════

echo ""
echo "============================================"
echo "Results: $PASS passed, $FAIL failed"
echo "============================================"

[ "$FAIL" -eq 0 ]
