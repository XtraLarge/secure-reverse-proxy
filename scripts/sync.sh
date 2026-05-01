#!/bin/bash
# sync.sh — Full publish pipeline:
#   1. git push → GitHub (anonymized public repo)
#   2. Wait for docker-build-push CI to succeed
#   3. Create Bookstack session page with recent commits
#   4. Pull image from DockerHub + deploy to production
#
# Private config is sourced from .sync.env (gitignored).
# Required env vars (or set in .sync.env):
#   DOCKER_HOST         SSH target for docker host (default: 10.0.0.1)
#   VLAN_IP             Prod container VLAN IP for smoke test (default: 10.0.0.2)
#   BOOKSTACK_URL       Bookstack base URL (optional — skips docs if unset)
#   BOOKSTACK_TOKEN     Bookstack API token as "id:secret" (optional)
#   BOOKSTACK_CHAPTER   Bookstack chapter ID for session logs (optional)

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ -f "${REPO_DIR}/.sync.env" ]] && source "${REPO_DIR}/.sync.env"

DOCKER_HOST="${DOCKER_HOST:-10.0.0.1}"
VLAN_IP="${VLAN_IP:-10.0.0.2}"
BOOKSTACK_URL="${BOOKSTACK_URL:-}"
BOOKSTACK_TOKEN="${BOOKSTACK_TOKEN:-}"
BOOKSTACK_CHAPTER="${BOOKSTACK_CHAPTER:-}"

log() { echo "[sync] $*"; }

# ── 1. git push ───────────────────────────────────────────────────────────────

log "git push → GitHub..."
git -C "$REPO_DIR" push

# ── 2. Wait for CI ────────────────────────────────────────────────────────────

log "Warte auf docker-build-push CI..."
sleep 10  # GitHub braucht einen Moment um den Trigger zu registrieren

BRANCH=$(git -C "$REPO_DIR" branch --show-current)
RUN_ID=$(gh run list \
    --workflow=docker-build-push.yml \
    --branch="$BRANCH" \
    --limit 1 \
    --json databaseId \
    --jq '.[0].databaseId' 2>/dev/null || true)

if [[ -n "$RUN_ID" && "$RUN_ID" != "null" ]]; then
    log "CI-Run ${RUN_ID} beobachten..."
    gh run watch "$RUN_ID" --exit-status
    log "CI erfolgreich — Image auf DockerHub veröffentlicht"
else
    log "WARN: Kein CI-Run gefunden — überspringe Warten auf CI"
fi

# ── 3. Bookstack-Dokumentation ────────────────────────────────────────────────

if [[ -n "$BOOKSTACK_URL" && -n "$BOOKSTACK_TOKEN" && -n "$BOOKSTACK_CHAPTER" ]]; then
    log "Bookstack-Seite anlegen..."

    DATE=$(date +%Y-%m-%d)
    LAST_SUBJECT=$(git -C "$REPO_DIR" log --format="%s" -1)
    PAGE_TITLE="${DATE} ${LAST_SUBJECT}"

    COMMITS_FILE=$(mktemp)
    TITLE_FILE=$(mktemp)
    git -C "$REPO_DIR" log --oneline -15 > "$COMMITS_FILE"
    printf '%s' "$PAGE_TITLE" > "$TITLE_FILE"

    PAGE_JSON=$(
        DATE="$DATE" \
        TITLE_FILE="$TITLE_FILE" \
        COMMITS_FILE="$COMMITS_FILE" \
        CHAPTER_ID="$BOOKSTACK_CHAPTER" \
        python3 -c '
import json, html, os
date       = os.environ["DATE"]
chapter_id = int(os.environ["CHAPTER_ID"])
title      = open(os.environ["TITLE_FILE"]).read().strip()
commits    = [c for c in open(os.environ["COMMITS_FILE"]).read().strip().splitlines() if c]
li = "".join(f"<li><code>{html.escape(c)}</code></li>" for c in commits)
h = (f"<h2>{html.escape(title)}</h2>"
     f"<p><strong>Datum:</strong> {html.escape(date)} | <strong>Status:</strong> ✅ produktiv</p>"
     f"<h3>Commits (letzte 15)</h3><ul>{li}</ul>")
print(json.dumps({"chapter_id": chapter_id, "name": title, "html": h}))
'
    )
    rm -f "$COMMITS_FILE" "$TITLE_FILE"

    RESPONSE_FILE=$(mktemp)
    HTTP_CODE=$(curl -s -o "$RESPONSE_FILE" -w "%{http_code}" \
        -X POST \
        -H "Authorization: Token ${BOOKSTACK_TOKEN}" \
        -H "Content-Type: application/json" \
        "${BOOKSTACK_URL}/api/pages" \
        -d "$PAGE_JSON")

    if [[ "$HTTP_CODE" =~ ^(200|201)$ ]]; then
        PAGE_ID=$(python3 -c "import json; print(json.load(open('${RESPONSE_FILE}'))['id'])" 2>/dev/null || echo "?")
        PAGE_SLUG=$(python3 -c "import json; print(json.load(open('${RESPONSE_FILE}'))['slug'])" 2>/dev/null || echo "")
        log "Bookstack-Seite angelegt: ID ${PAGE_ID}"
        [[ -n "$PAGE_SLUG" ]] && log "URL: ${BOOKSTACK_URL}/books/apache-oidc-proxy/page/${PAGE_SLUG}"
    else
        log "WARN: Bookstack fehlgeschlagen (HTTP ${HTTP_CODE})"
        cat "$RESPONSE_FILE" >&2 || true
    fi
    rm -f "$RESPONSE_FILE"
else
    log "Bookstack nicht konfiguriert — Dokumentation übersprungen"
fi

# ── 4. Prod-Deploy ────────────────────────────────────────────────────────────

log "Prod-Deploy starten..."
DOCKER_HOST="$DOCKER_HOST" VLAN_IP="$VLAN_IP" "$REPO_DIR/scripts/build.sh" --prod

log "Sync abgeschlossen."
