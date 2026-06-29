#!/usr/bin/env bash
# naming-guard.sh — verhindert, dass interne Netz-/Hostnamen in dieses
# OEFFENTLICHE Repo gelangen. Prueft alle git-getrackten Textdateien.
# Exit 1 + Trefferliste bei Fund, sonst 0.
#
# Ausnahmen (bewusst, dokumentiert):
#   - Inline:  am Zeilenende den Marker  naming-guard:allow  setzen.
#   - Regex:   eine erweiterte Regex je Zeile in .naming-guard-allow ablegen
#              (matcht gegen 'datei:zeile:inhalt'); '#'-Kommentare/Leerzeilen erlaubt.
set -euo pipefail

cd -- "$(git rev-parse --show-toplevel)"

PATTERN='10\.10\.|\.fritz\.box|derwerres\.de'
ALLOW_FILE='.naming-guard-allow'

allow_filter() {
  if [[ -s "$ALLOW_FILE" ]]; then
    grep -vEf <(grep -vE '^[[:space:]]*(#|$)' "$ALLOW_FILE")
  else
    cat
  fi
}

hits="$(
  git ls-files -z \
    | xargs -0 grep -HnIE "$PATTERN" -- 2>/dev/null \
    | grep -v 'naming-guard:allow' \
    | grep -v "^${ALLOW_FILE}:" \
    | allow_filter \
    || true
)"

if [[ -n "$hits" ]]; then
  {
    echo "naming-guard: interne Netz-/Hostnamen in getrackten Dateien gefunden"
    echo "             (dies ist ein OEFFENTLICHES Repo — solche Werte gehoeren nicht hierher):"
    echo
    echo "$hits"
    echo
    echo "Behebung: Wert durch Platzhalter ersetzen (z.B. example.net / <host>)."
    echo "Bewusste Ausnahme: Zeilen-Marker  naming-guard:allow  oder Regex in ${ALLOW_FILE}."
  } >&2
  exit 1
fi

echo "naming-guard: ok — keine internen Netz-/Hostnamen in getrackten Dateien."
