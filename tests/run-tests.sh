#!/bin/bash
# Integration test runner for apache-oidc-proxy
# Usage: ./tests/run-tests.sh [image-name]
# Default image: apache-oidc-proxy:test

set -euo pipefail

IMAGE="${1:-apache-oidc-proxy:test}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"

PASS=0
FAIL=0

pass() { echo "  PASS: $*"; ((PASS++)) || true; }
fail() { echo "  FAIL: $*"; ((FAIL++)) || true; }

run_container() {
    # $1 = test name, remaining = extra docker run args
    local name="$1"; shift
    docker run --rm \
        -v "$SCRIPT_DIR/ssl:/etc/apache2/ssl:ro" \
        -v "$SCRIPT_DIR/sites-enabled:/etc/apache2/sites-enabled:ro" \
        -v "$SCRIPT_DIR/AddOn:/etc/apache2/AddOn:ro" \
        -e OIDC_PROVIDER_METADATA_URL=https://iam.example.com/realms/master/.well-known/openid-configuration \
        -e OIDC_CLIENT_ID=Proxy \
        -e OIDC_CLIENT_SECRET=test-secret-not-real \
        -e OIDC_CRYPTO_PASSPHRASE=test-passphrase-not-real \
        -e OIDC_COOKIE_DOMAIN=test.example.com \
        -e REDIS_HOST=127.0.0.1 \
        -e INTERNAL_NETWORKS=10.0.0.0/8 \
        "$@" \
        "$IMAGE" \
        apache2ctl configtest 2>&1
}

echo "============================================"
echo "apache-oidc-proxy integration tests"
echo "Image: $IMAGE"
echo "============================================"

# ── Test 1: configtest passes with test site config ───────────────────────────
echo ""
echo "[1] Apache configtest with all VHost macro types"
if run_container "configtest" 2>&1 | grep -q "Syntax OK"; then
    pass "apache2ctl configtest: Syntax OK"
else
    fail "apache2ctl configtest failed"
    run_container "configtest" 2>&1 || true
fi

# ── Test 2: Required env vars enforced ───────────────────────────────────────
echo ""
echo "[2] Entrypoint rejects missing OIDC_PROVIDER_METADATA_URL"
if docker run --rm \
    -e OIDC_CLIENT_SECRET=x \
    -e OIDC_CRYPTO_PASSPHRASE=x \
    -e OIDC_COOKIE_DOMAIN=x \
    "$IMAGE" apache2ctl configtest 2>&1 | grep -q "OIDC_PROVIDER_METADATA_URL is required"; then
    pass "Missing OIDC_PROVIDER_METADATA_URL is rejected"
else
    fail "Missing OIDC_PROVIDER_METADATA_URL was not caught"
fi

echo ""
echo "[3] Entrypoint rejects missing OIDC_CLIENT_SECRET"
if docker run --rm \
    -e OIDC_PROVIDER_METADATA_URL=https://iam.example.com/.well-known/openid-configuration \
    -e OIDC_CRYPTO_PASSPHRASE=x \
    -e OIDC_COOKIE_DOMAIN=x \
    "$IMAGE" apache2ctl configtest 2>&1 | grep -q "OIDC_CLIENT_SECRET is required"; then
    pass "Missing OIDC_CLIENT_SECRET is rejected"
else
    fail "Missing OIDC_CLIENT_SECRET was not caught"
fi

echo ""
echo "[4] Entrypoint rejects missing OIDC_CRYPTO_PASSPHRASE"
if docker run --rm \
    -e OIDC_PROVIDER_METADATA_URL=https://iam.example.com/.well-known/openid-configuration \
    -e OIDC_CLIENT_SECRET=x \
    -e OIDC_COOKIE_DOMAIN=x \
    "$IMAGE" apache2ctl configtest 2>&1 | grep -q "OIDC_CRYPTO_PASSPHRASE is required"; then
    pass "Missing OIDC_CRYPTO_PASSPHRASE is rejected"
else
    fail "Missing OIDC_CRYPTO_PASSPHRASE was not caught"
fi

echo ""
echo "[5] Entrypoint rejects missing OIDC_COOKIE_DOMAIN"
if docker run --rm \
    -e OIDC_PROVIDER_METADATA_URL=https://iam.example.com/.well-known/openid-configuration \
    -e OIDC_CLIENT_SECRET=x \
    -e OIDC_CRYPTO_PASSPHRASE=x \
    "$IMAGE" apache2ctl configtest 2>&1 | grep -q "OIDC_COOKIE_DOMAIN is required"; then
    pass "Missing OIDC_COOKIE_DOMAIN is rejected"
else
    fail "Missing OIDC_COOKIE_DOMAIN was not caught"
fi

# ── Test 3: Invalid CIDR rejected ────────────────────────────────────────────
echo ""
echo "[6] Entrypoint rejects invalid CIDR in INTERNAL_NETWORKS"
if docker run --rm \
    -v "$SCRIPT_DIR/ssl:/etc/apache2/ssl:ro" \
    -v "$SCRIPT_DIR/sites-enabled:/etc/apache2/sites-enabled:ro" \
    -e OIDC_PROVIDER_METADATA_URL=https://iam.example.com/.well-known/openid-configuration \
    -e OIDC_CLIENT_SECRET=x \
    -e OIDC_CRYPTO_PASSPHRASE=x \
    -e OIDC_COOKIE_DOMAIN=test.example.com \
    -e INTERNAL_NETWORKS="not-a-cidr,10.0.0.0/8" \
    "$IMAGE" apache2ctl configtest 2>&1 | grep -q "Invalid CIDR"; then
    pass "Invalid CIDR 'not-a-cidr' is rejected"
else
    fail "Invalid CIDR was not caught"
fi

echo ""
echo "[7] Entrypoint accepts valid CIDR list"
if docker run --rm \
    -v "$SCRIPT_DIR/ssl:/etc/apache2/ssl:ro" \
    -v "$SCRIPT_DIR/sites-enabled:/etc/apache2/sites-enabled:ro" \
    -v "$SCRIPT_DIR/AddOn:/etc/apache2/AddOn:ro" \
    -e OIDC_PROVIDER_METADATA_URL=https://iam.example.com/.well-known/openid-configuration \
    -e OIDC_CLIENT_SECRET=x \
    -e OIDC_CRYPTO_PASSPHRASE=x \
    -e OIDC_COOKIE_DOMAIN=test.example.com \
    -e INTERNAL_NETWORKS="10.0.0.0/8,192.168.0.0/16,172.16.0.0/12" \
    "$IMAGE" apache2ctl configtest 2>&1 | grep -q "Syntax OK"; then
    pass "Multiple valid CIDRs accepted"
else
    fail "Valid CIDR list was rejected"
fi

# ── Test 4: configtest passes without any sites (empty sites-enabled) ─────────
echo ""
echo "[8] Apache configtest with empty sites-enabled"
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

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "============================================"
echo "Results: $PASS passed, $FAIL failed"
echo "============================================"

[ "$FAIL" -eq 0 ]
