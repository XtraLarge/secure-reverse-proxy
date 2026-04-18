#!/bin/bash
# build.sh — Sync repo to docker-sys build context, build image, optionally deploy
#
# Usage (from repo root or scripts/):
#   ./scripts/build.sh              # sync + build
#   ./scripts/build.sh --deploy     # sync + build + restart proxy container
#
# Requires SSH access to DOCKER_HOST.

set -euo pipefail

DOCKER_HOST="${DOCKER_HOST:-10.0.0.1}"
BUILD_CTX="/data/_DockerCreate/apache-oidc-proxy"
IMAGE="apache-oidc-proxy:test"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

DEPLOY=false
[[ "${1:-}" == "--deploy" ]] && DEPLOY=true

echo "==> Syncing ${REPO_DIR}/ → ${DOCKER_HOST}:${BUILD_CTX}/"
rsync -av --delete \
    --exclude='.git' \
    "${REPO_DIR}/" \
    "root@${DOCKER_HOST}:${BUILD_CTX}/"

echo "==> Building ${IMAGE} on ${DOCKER_HOST}"
ssh "root@${DOCKER_HOST}" "docker build -t ${IMAGE} ${BUILD_CTX}"

if $DEPLOY; then
    echo "==> Deploying proxy container"
    ssh "root@${DOCKER_HOST}" \
        "docker compose \
            -f /data/_DockerCreate/compose/proxy.yaml \
            --env-file /data/_DockerCreate/compose/.env \
            --env-file /data/_DockerCreate/compose/proxy.env \
            -p proxy \
            up -d proxy"
fi

echo "==> Done."
