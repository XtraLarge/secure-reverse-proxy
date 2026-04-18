#!/bin/bash
# watchdog.sh — restart proxy container when Docker marks it unhealthy
#
# Install on the Docker host:
#   sudo cp scripts/watchdog.sh /usr/local/bin/proxy-watchdog.sh
#   sudo chmod +x /usr/local/bin/proxy-watchdog.sh
#
# Add to root crontab (crontab -e):
#   */2 * * * * /usr/local/bin/proxy-watchdog.sh >> /var/log/proxy-watchdog.log 2>&1

CONTAINER="${WATCHDOG_CONTAINER:-proxy-proxy}"
LOGPREFIX="$(date '+%Y-%m-%d %H:%M:%S') [$CONTAINER]"

# Require Docker to be available
if ! command -v docker &>/dev/null; then
    echo "$LOGPREFIX ERROR: docker not found" >&2
    exit 1
fi

STATUS=$(docker inspect --format='{{.State.Health.Status}}' "$CONTAINER" 2>/dev/null)

if [ -z "$STATUS" ]; then
    echo "$LOGPREFIX SKIP: container not found or has no healthcheck"
    exit 0
fi

if [ "$STATUS" = "unhealthy" ]; then
    echo "$LOGPREFIX UNHEALTHY — restarting container"
    docker restart "$CONTAINER"
    EXIT=$?
    if [ $EXIT -eq 0 ]; then
        echo "$LOGPREFIX restart OK"
    else
        echo "$LOGPREFIX ERROR: docker restart exited $EXIT" >&2
    fi
    exit $EXIT
fi

# healthy / starting / none — nothing to do (no output to keep cron log quiet)
exit 0
