#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${SCRIPT_DIR}/.env"
ENV_EXAMPLE="${SCRIPT_DIR}/.env.example"
CERT_ROOT="${SCRIPT_DIR}/ssl/127.0.0.1.nip.io"

if [ ! -f "${ENV_FILE}" ]; then
    cp "${ENV_EXAMPLE}" "${ENV_FILE}"
    echo "Created ${ENV_FILE}"
fi

mkdir -p "${CERT_ROOT}"

if [ ! -f "${CERT_ROOT}/fullchain.pem" ] || [ ! -f "${CERT_ROOT}/key.pem" ] || [ ! -f "${CERT_ROOT}/cert.pem" ]; then
    openssl req -x509 -nodes -newkey rsa:2048 -sha256 -days 365 \
        -subj "/CN=127.0.0.1.nip.io" \
        -addext "subjectAltName=DNS:127.0.0.1.nip.io,DNS:*.127.0.0.1.nip.io" \
        -keyout "${CERT_ROOT}/key.pem" \
        -out "${CERT_ROOT}/cert.pem"
    cp "${CERT_ROOT}/cert.pem" "${CERT_ROOT}/fullchain.pem"
    echo "Generated self-signed certificate in ${CERT_ROOT}"
else
    echo "Using existing certificate in ${CERT_ROOT}"
fi

SITES_DIR="${SCRIPT_DIR}/sites"
SITE_FILE="${SITES_DIR}/127.0.0.1.nip.io.conf"
mkdir -p "${SITES_DIR}"
if [ ! -f "${SITE_FILE}" ]; then
    cat > "${SITE_FILE}" <<'SITEEOF'
# Demo site — created by prepare.sh. 'demo' may use admin. and geolock.
USE Domain_Init 127.0.0.1.nip.io www 'demo'

# Keycloak via the proxy (no proxy login, the browser needs it for the OIDC flow)
Use VHost_Proxy_Open      keycloak  127.0.0.1.nip.io  http://keycloak:8080/

# OIDC-protected test backend
Use VHost_Proxy_OIDC_Any  whoami    127.0.0.1.nip.io  http://whoami:80/

USE Domain_Final 127.0.0.1.nip.io www
SITEEOF
    echo "Created ${SITE_FILE}"
else
    echo "Using existing ${SITE_FILE}"
fi

echo "Ready:"
echo "  env:   ${ENV_FILE}"
echo "  certs: ${CERT_ROOT}"
echo "  site:  ${SITE_FILE}"
