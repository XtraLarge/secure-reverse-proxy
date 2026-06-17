#!/bin/bash
# status-probe.sh — Hintergrund-Statusprüfer für den Reverse Proxy.
#
# Läuft minütlich via cron (root) im Container, entkoppelt vom Seitenaufruf.
# Prüft je echtem Reverse-Proxy-Eintrag (Use VHost_Proxy*; KEINE Aliase/Redirects,
# KEIN GeoLock) zwei unabhängige Dimensionen und schreibt das Ergebnis nach
# /run/apache-proxy/status.tab (tab-separiert, von toc.lua nur gelesen).
#
#   INTERN  = Backend gesund?  Probe über die eigene interne IP des Containers
#             -> greift der vorhandene interne Bypass (wie ein interner User)
#             -> erreicht das Backend.  KEIN neuer Allow/Bypass, keine Credentials.
#   EXTERN  = Funktioniert die Proxy-Konfiguration über den öffentlichen Pfad?
#             Probe wird über die *öffentliche* IP der Domain erzwungen
#             (immun gegen interne DNS-/etc-hosts-Pins), MIT Zertifikatsprüfung.
#             OIDC: korrekter 302->IdP = ok.  5xx/000/TLS-Fehler = kaputt.
#
# Sicherheit:
#   - Hostnamen werden strikt validiert (kein Shell-Injection über Conf-Zeilen).
#   - Es werden NUR Status-Codes ausgewertet, keine Response-Bodies gespeichert.
#   - Ausgabe liegt unter /run (nicht im DocumentRoot), Datei-Modus 640.
#   - flock verhindert überlappende Läufe; jede Probe hat ein hartes Timeout.

set -uo pipefail

OUTDIR=/run/apache-proxy
OUT="$OUTDIR/status.tab"
TMP="$OUTDIR/.status.tab.$$"
LOCK="$OUTDIR/.status.lock"
SITES_DIR=/etc/apache2/sites
PORT=443
MAXTIME=5
PARALLEL=10

mkdir -p "$OUTDIR" 2>/dev/null || true

# Nur ein Lauf gleichzeitig
exec 9>"$LOCK" || exit 0
flock -n 9 || exit 0

# Eigene interne IP (macvlan, in 10.10/20/21.0.0/16) für den Intern-Bypass
SELF_IP="$(hostname -i 2>/dev/null | tr ' ' '\n' | grep -E '^10\.(10|20|21)\.' | head -1)"
[ -z "$SELF_IP" ] && SELF_IP="$(hostname -i 2>/dev/null | awk '{print $1}')"

# Eine Probe; gibt "http_code redirect_url" aus ("000 " bei Fehler/Timeout).
# $1 host, $2 resolve_ip ("" = Standard-DNS).  Ein Retry bei transientem 000.
do_curl() {
  local host="$1" ip="$2" extra=() out
  [ -n "$ip" ] && extra=(--resolve "${host}:${PORT}:${ip}")
  out="$(curl -s -o /dev/null -w '%{http_code} %{redirect_url}' "${extra[@]}" --max-time "$MAXTIME" "https://${host}/" 2>/dev/null)"
  if [ -z "$out" ] || [ "${out%% *}" = "000" ]; then
    out="$(curl -s -o /dev/null -w '%{http_code} %{redirect_url}' "${extra[@]}" --max-time "$((MAXTIME+3))" "https://${host}/" 2>/dev/null)"
  fi
  [ -z "$out" ] && out="000 "
  echo "$out"
}

# Bewertet einen Eintrag; Ausgabe: host \t intern \t extern \t code_int \t code_ext
# spec = "host;macro;pubip"
probe_one() {
  local spec="$1" selfip="$2"
  local host="${spec%%;*}" rest="${spec#*;}"
  local macro="${rest%%;*}" pubip="${rest#*;}"

  case "$host" in
    *[!A-Za-z0-9.-]*|'' ) return 0 ;;
  esac

  local is_oidc=0
  case "$(printf '%s' "$macro" | tr 'A-Z' 'a-z')" in
    vhost_proxy_oidc*) is_oidc=1 ;;
  esac

  # INTERN: über eigene interne IP -> Bypass -> Backend
  local r_int code_int
  r_int="$(do_curl "$host" "$selfip")"
  code_int="${r_int%% *}"
  local intern="warn"
  case "$code_int" in
    2??|3??|401|403) intern="up" ;;
    000|''|5??)      intern="down" ;;
    *)               intern="warn" ;;
  esac

  # EXTERN: über öffentliche IP der Domain (immun gegen interne Pins), MIT Zertprüfung
  local r_ext code_ext redir_ext
  r_ext="$(do_curl "$host" "$pubip")"
  code_ext="${r_ext%% *}"
  redir_ext="${r_ext#* }"
  local extern="warn"
  case "$code_ext" in
    000|'') extern="down" ;;             # nicht erreichbar / TLS kaputt
    5??)    extern="down" ;;             # Gateway-/Proxy-Fehler
    *)
      if [ "$is_oidc" = 1 ]; then
        case "$code_ext" in
          30[1237])
            if printf '%s' "$redir_ext" | grep -qiE 'openid-connect/auth|/realms/'; then
              extern="up"                # OIDC korrekt zum IdP verdrahtet
            else
              extern="warn"              # Redirect, aber unerwartetes Ziel
            fi ;;
          2??)     extern="up" ;;
          401|403) extern="warn" ;;      # Gate ohne Redirect -> verdächtig
          *)       extern="warn" ;;
        esac
      else
        case "$code_ext" in
          2??|3??|401|403|404) extern="up" ;;   # Backend liefert, kein Gateway-Fehler
          *)                   extern="warn" ;;
        esac
      fi ;;
  esac

  printf '%s\t%s\t%s\t%s\t%s\n' "$host" "$intern" "$extern" "$code_int" "$code_ext"
}
export -f probe_one do_curl
export PORT MAXTIME

# Echte Proxy-Einträge sammeln: "host;macro"
mapfile -t SPECS < <(
  grep -rhiE '^[[:space:]]*Use[[:space:]]+VHost_Proxy' "$SITES_DIR"/*.conf 2>/dev/null \
  | grep -vE '\.bak' \
  | awk '{ macro=$2; name=$3; dom=$4;
           if (name!="" && dom!="") printf "%s.%s;%s;%s\n", name, dom, macro, dom }' \
  | sort -u
)

# Öffentliche IP je Domain ermitteln (häufigste *öffentliche* IP; private/gepinnte ignorieren)
declare -A DOMPUB
for spec in "${SPECS[@]}"; do
  dom="${spec##*;}"
  [ -n "${DOMPUB[$dom]:-}" ] && continue
  host="${spec%%;*}"
  ip="$(getent ahostsv4 "$host" 2>/dev/null | awk '{print $1; exit}')"
  case "$ip" in
    10.*|192.168.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*|127.*|'') continue ;;
    *) DOMPUB[$dom]="$ip" ;;
  esac
done

# Probe-Specs mit Public-IP anreichern: "host;macro;pubip"
PROBESPECS=()
for spec in "${SPECS[@]}"; do
  host="${spec%%;*}"; rest="${spec#*;}"; macro="${rest%%;*}"; dom="${spec##*;}"
  PROBESPECS+=("${host};${macro};${DOMPUB[$dom]:-}")
done

{
  printf '# generated %s  self=%s  entries=%s\n' "$(date -Is)" "$SELF_IP" "${#PROBESPECS[@]}"
  if [ "${#PROBESPECS[@]}" -gt 0 ]; then
    printf '%s\n' "${PROBESPECS[@]}" \
      | xargs -P "$PARALLEL" -I{} bash -c 'probe_one "$1" "$2"' _ {} "$SELF_IP" \
      | sort
  fi
} > "$TMP" 2>/dev/null

chmod 640 "$TMP" 2>/dev/null || true
mv -f "$TMP" "$OUT" 2>/dev/null || rm -f "$TMP"
