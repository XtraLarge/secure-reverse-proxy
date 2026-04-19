#!/bin/bash
# build.sh — Sync repo to docker-sys build context, build image, optionally deploy
#
# Usage (from repo root or scripts/):
#   ./scripts/build.sh              # sync + build only
#   ./scripts/build.sh --deploy     # sync + build + deploy + smoke test
#   ./scripts/build.sh --deploy --skip-git-check   # deploy without clean-git requirement
#
# Requires SSH access to DOCKER_HOST (default: 10.0.0.1).

set -euo pipefail

DOCKER_HOST="${DOCKER_HOST:-10.0.0.1}"
BUILD_CTX="/data/_DockerCreate/apache-oidc-proxy"
IMAGE="apache-oidc-proxy:test"
CONTAINER="proxy-proxy"
VLAN_IP="10.0.0.2"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

DEPLOY=false
SKIP_GIT=false
for arg in "$@"; do
  case "$arg" in
    --deploy)          DEPLOY=true ;;
    --skip-git-check)  SKIP_GIT=true ;;
  esac
done

# ── Git check ─────────────────────────────────────────────────────────────────
# Every deployment must start from a committed state so that deployed code is
# always traceable via git log. Use --skip-git-check only for quick iteration.
if $DEPLOY && ! $SKIP_GIT; then
  if ! git -C "$REPO_DIR" diff --quiet HEAD 2>/dev/null; then
    echo "ERR: Uncommitted changes — bitte erst committen:"
    git -C "$REPO_DIR" status --short
    echo ""
    echo "  Hint: git add -p && git commit -m '...' && ./scripts/build.sh --deploy"
    echo "  Oder: ./scripts/build.sh --deploy --skip-git-check  (nur für Quick-Iteration)"
    exit 1
  fi
fi

# ── Sync + build ──────────────────────────────────────────────────────────────
echo "==> Syncing ${REPO_DIR}/ → ${DOCKER_HOST}:${BUILD_CTX}/"
rsync -av --delete \
    --exclude='.git' \
    "${REPO_DIR}/" \
    "root@${DOCKER_HOST}:${BUILD_CTX}/"

echo "==> Building ${IMAGE} on ${DOCKER_HOST}"
ssh "root@${DOCKER_HOST}" "docker build -t ${IMAGE} ${BUILD_CTX}"

# ── Deploy ────────────────────────────────────────────────────────────────────
if ! $DEPLOY; then
  echo "==> Done (build only — kein Deploy)."
  exit 0
fi

echo "==> Deploying ${CONTAINER}"
ssh "root@${DOCKER_HOST}" \
    "docker compose \
        -f /data/_DockerCreate/compose/proxy.yaml \
        --env-file /data/_DockerCreate/compose/.env \
        --env-file /data/_DockerCreate/compose/proxy.env \
        -p proxy \
        up -d --force-recreate proxy"

# ── Smoke test ────────────────────────────────────────────────────────────────
echo "==> Smoke test..."

# 1) Richtiger Container-Name?
ACTUAL_NAME=$(ssh "root@${DOCKER_HOST}" \
  "docker ps --filter name=^${CONTAINER}$ --format '{{.Names}}'" 2>/dev/null || true)
if [[ "$ACTUAL_NAME" != "$CONTAINER" ]]; then
  echo "ERR: Container-Name falsch! Gefunden: '${ACTUAL_NAME}', erwartet: '${CONTAINER}'"
  echo "     Bitte prüfen ob COMPOSE_PROJECT_NAME und NAME in proxy.env korrekt sind."
  exit 1
fi
echo "    Container-Name: OK (${CONTAINER})"

# 2) Warten bis healthy (max. 60 s)
HEALTH=""
for i in $(seq 1 12); do
  HEALTH=$(ssh "root@${DOCKER_HOST}" \
    "docker inspect --format='{{.State.Health.Status}}' ${CONTAINER} 2>/dev/null" || true)
  [[ "$HEALTH" == "healthy" ]] && break
  echo "    Warte auf healthy... ($i/12, aktuell: ${HEALTH:-unbekannt})"
  sleep 5
done

if [[ "$HEALTH" != "healthy" ]]; then
  echo "ERR: Container nicht healthy nach 60 s (Status: ${HEALTH})"
  echo "     docker logs ${CONTAINER} | tail -20:"
  ssh "root@${DOCKER_HOST}" "docker logs ${CONTAINER} --tail 20" || true
  exit 1
fi
echo "    Health: OK"

# 3) HTTPS antwortet?
HTTP_CODE=$(ssh "root@${DOCKER_HOST}" \
  "curl -s -o /dev/null -w '%{http_code}' --max-time 10 -k https://${VLAN_IP}/" 2>/dev/null || echo "000")
if [[ "$HTTP_CODE" =~ ^(200|301|302|401|403)$ ]]; then
  echo "    HTTPS:  OK (HTTP ${HTTP_CODE})"
else
  echo "ERR: HTTPS Smoke-Test fehlgeschlagen — HTTP ${HTTP_CODE} von ${VLAN_IP}"
  exit 1
fi

echo "==> Done."
