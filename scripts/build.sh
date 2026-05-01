#!/bin/bash
# build.sh — Build and deploy secure-reverse-proxy
#
# Usage (from repo root or scripts/):
#   ./scripts/build.sh              # sync + build only (local test image)
#   ./scripts/build.sh --test       # sync + build + deploy to test (10.10.25.50)
#   ./scripts/build.sh --prod       # docker pull from DockerHub + deploy to prod
#   ./scripts/build.sh --test --skip-git-check
#
# Requires SSH access to DOCKER_HOST (default: 10.0.0.1).

set -euo pipefail

DOCKER_HOST="${DOCKER_HOST:-10.0.0.1}"
BUILD_CTX="/data/_DockerBuild/secure-reverse-proxy"
IMAGE_LOCAL="secure-reverse-proxy:test"
IMAGE_PROD="ghcr.io/xtralarge71/secure-reverse-proxy:latest"
CONTAINER_PROD="proxy-proxy"
CONTAINER_TEST="proxy-test-proxy"
VLAN_IP_PROD="${VLAN_IP:-10.0.0.2}"
VLAN_IP_TEST="${VLAN_IP_TEST:-10.10.25.50}"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

MODE=""
SKIP_GIT=false
for arg in "$@"; do
  case "$arg" in
    --test)            MODE="test" ;;
    --prod)            MODE="prod" ;;
    --skip-git-check)  SKIP_GIT=true ;;
  esac
done

# ── Smoke test ────────────────────────────────────────────────────────────────
_smoke_test() {
  local container="$1"
  local vlan_ip="$2"
  echo "==> Smoke test..."

  ACTUAL_NAME=$(ssh "root@${DOCKER_HOST}" \
    "docker ps --filter name=^${container}$ --format '{{.Names}}'" 2>/dev/null || true)
  if [[ "$ACTUAL_NAME" != "$container" ]]; then
    echo "ERR: Container-Name falsch! Gefunden: '${ACTUAL_NAME}', erwartet: '${container}'"
    exit 1
  fi
  echo "    Container-Name: OK (${container})"

  local HEALTH=""
  for i in $(seq 1 12); do
    HEALTH=$(ssh "root@${DOCKER_HOST}" \
      "docker inspect --format='{{.State.Health.Status}}' ${container} 2>/dev/null" || true)
    [[ "$HEALTH" == "healthy" ]] && break
    echo "    Warte auf healthy... ($i/12, aktuell: ${HEALTH:-unbekannt})"
    sleep 5
  done

  if [[ "$HEALTH" != "healthy" ]]; then
    echo "ERR: Container nicht healthy nach 60 s (Status: ${HEALTH})"
    ssh "root@${DOCKER_HOST}" "docker logs ${container} --tail 20" || true
    exit 1
  fi
  echo "    Health: OK"

  local HTTP_CODE
  HTTP_CODE=$(ssh "root@${DOCKER_HOST}" \
    "curl -s -o /dev/null -w '%{http_code}' --max-time 10 -k https://${vlan_ip}/" 2>/dev/null || echo "000")
  if [[ "$HTTP_CODE" =~ ^(200|301|302|303|307|308|401|403)$ ]]; then
    echo "    HTTPS:  OK (HTTP ${HTTP_CODE})"
  else
    echo "ERR: HTTPS Smoke-Test fehlgeschlagen — HTTP ${HTTP_CODE} von ${vlan_ip}"
    exit 1
  fi
  echo "==> Done."
}

# ── Git check ─────────────────────────────────────────────────────────────────
if [[ -n "$MODE" ]] && ! $SKIP_GIT; then
  if ! git -C "$REPO_DIR" diff --quiet HEAD 2>/dev/null; then
    echo "ERR: Uncommitted changes — bitte erst committen:"
    git -C "$REPO_DIR" status --short
    echo ""
    echo "  Hint: git add -p && git commit -m '...' && ./scripts/build.sh --${MODE:-test}"
    echo "  Oder: ./scripts/build.sh --${MODE:-test} --skip-git-check  (nur für Quick-Iteration)"
    exit 1
  fi
fi

# ── Prod: pull from DockerHub + deploy ────────────────────────────────────────
if [[ "$MODE" == "prod" ]]; then
  echo "==> Pulling ${IMAGE_PROD} on ${DOCKER_HOST}"
  ssh "root@${DOCKER_HOST}" "docker pull ${IMAGE_PROD}"

  echo "==> Deploying ${CONTAINER_PROD} (prod)"
  ssh "root@${DOCKER_HOST}" \
      "docker compose \
          -f /data/_DockerCreate/compose/proxy.yaml \
          --env-file /data/_DockerCreate/compose/.env \
          --env-file /data/_DockerCreate/compose/proxy.env \
          -p proxy \
          up -d --force-recreate proxy"

  _smoke_test "$CONTAINER_PROD" "$VLAN_IP_PROD"
  exit 0
fi

# ── Sync + build (local test image) ───────────────────────────────────────────
echo "==> Syncing ${REPO_DIR}/ → ${DOCKER_HOST}:${BUILD_CTX}/"
rsync -av --delete \
    --exclude='.git' \
    "${REPO_DIR}/" \
    "root@${DOCKER_HOST}:${BUILD_CTX}/"

echo "==> Building ${IMAGE_LOCAL} on ${DOCKER_HOST}"
ssh "root@${DOCKER_HOST}" "docker build -t ${IMAGE_LOCAL} ${BUILD_CTX}"

if [[ "$MODE" != "test" ]]; then
  echo "==> Done (build only — kein Deploy)."
  exit 0
fi

# ── Test: deploy to test environment ──────────────────────────────────────────
echo "==> Deploying ${CONTAINER_TEST} (test)"
ssh "root@${DOCKER_HOST}" \
    "docker compose \
        -f /data/_DockerCreate/compose/proxy-test.yaml \
        --env-file /data/_DockerCreate/compose/.env \
        --env-file /data/_DockerCreate/compose/proxy-test.env \
        -p proxy-test \
        up -d --force-recreate proxy"

_smoke_test "$CONTAINER_TEST" "$VLAN_IP_TEST"
