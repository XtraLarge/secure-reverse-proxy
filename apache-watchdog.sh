#!/bin/bash
# In-container Apache health watchdog — runs every 2 minutes as root via cron.
#
# If Apache is unresponsive but the master process still exists (stuck after a
# reload), SIGKILL the master.  When the master dies tini's main child is gone
# and tini exits, which triggers Docker's restart policy for a clean recovery.
#
# Guards:
#   - no apache2 process found  → exit silently (container still starting)
#   - curl succeeds              → exit silently (healthy)
#   - curl fails + process found → SIGKILL master → container restarts via tini

APID=$(pgrep -o -x apache2 2>/dev/null) || exit 0

if ! curl -fso /dev/null --max-time 5 http://localhost/; then
    echo "[apache-watchdog] $(date '+%Y-%m-%d %H:%M:%S') Apache not responding (PID $APID) — force restart" >> /proc/1/fd/1
    kill -KILL "$APID" 2>/dev/null || true
fi
