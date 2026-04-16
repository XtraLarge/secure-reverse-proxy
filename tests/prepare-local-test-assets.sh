#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
TARGET_ROOT="${1:-${OIDCPROXY_TEST_ROOT:-${TMPDIR:-/tmp}/oidcproxy-test}}"
SAMPLE_ENV="${SCRIPT_DIR}/deploy-sample/.env"
COOKIE_DOMAIN="$(awk -F= '/^OIDC_COOKIE_DOMAIN=/{print $2; exit}' "${SAMPLE_ENV}")"

[ -n "${COOKIE_DOMAIN}" ] || {
    echo "OIDC_COOKIE_DOMAIN missing in ${SAMPLE_ENV}" >&2
    exit 1
}

echo "Preparing test assets in ${TARGET_ROOT}"

rm -rf "${TARGET_ROOT}/sites-enabled" "${TARGET_ROOT}/AddOn" "${TARGET_ROOT}/ssl"
mkdir -p "${TARGET_ROOT}/sites-enabled" "${TARGET_ROOT}/AddOn" "${TARGET_ROOT}/ssl"

cp "${SAMPLE_ENV}" "${TARGET_ROOT}/.env"

while IFS= read -r site_file; do
    cp "${site_file}" "${TARGET_ROOT}/sites-enabled/"
done < <(grep -Ril "USE Domain_Init ${COOKIE_DOMAIN}[[:space:]]" "${REPO_DIR}/conf/sites-available")

if [ -d "${SCRIPT_DIR}/AddOn/${COOKIE_DOMAIN}" ]; then
    mkdir -p "${TARGET_ROOT}/AddOn/${COOKIE_DOMAIN}"
    cp -a "${SCRIPT_DIR}/AddOn/${COOKIE_DOMAIN}/." "${TARGET_ROOT}/AddOn/${COOKIE_DOMAIN}/"
fi

mkdir -p "${TARGET_ROOT}/ssl/${COOKIE_DOMAIN}"
cp "${SCRIPT_DIR}/ssl/test.example.com/cert.pem" "${TARGET_ROOT}/ssl/${COOKIE_DOMAIN}/cert.pem"
cp "${SCRIPT_DIR}/ssl/test.example.com/key.pem" "${TARGET_ROOT}/ssl/${COOKIE_DOMAIN}/key.pem"
cp "${SCRIPT_DIR}/ssl/test.example.com/fullchain.pem" "${TARGET_ROOT}/ssl/${COOKIE_DOMAIN}/fullchain.pem"

echo "Prepared:"
echo "  env:          ${TARGET_ROOT}/.env"
echo "  sites:        ${TARGET_ROOT}/sites-enabled"
echo "  add-ons:      ${TARGET_ROOT}/AddOn"
echo "  certificates: ${TARGET_ROOT}/ssl"
echo "  cookie domain: ${COOKIE_DOMAIN}"
