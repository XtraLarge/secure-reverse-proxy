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

# Abdeckung: interne 10.<VLAN>.x.x Host-IPs aller internen VLANs (2. Oktett = VLAN-ID,
# nonzero) sowie das Exposed-Net (2. Oktett 0, 3. Oktett nonzero); zusaetzlich die
# interne Router-Domain und die Eigen-Domain (bare und als FQDN-Suffix).
# Bewusst NICHT erfasst (generische Beispiele): RFC1918-CIDR-Ranges (/8, /12, /16)
# und Doku-Beispiel-Backends 10.0.0.x.
PATTERN='10\.[1-9][0-9]?\.[0-9]{1,3}\.[0-9]{1,3}|10\.0\.[1-9][0-9]{0,2}\.[0-9]{1,3}|fritz\.box|derwerres\.de'
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
