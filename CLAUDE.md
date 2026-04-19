# CLAUDE.md — Arbeitsregeln für dieses Projekt

Dieses Dokument beschreibt verbindliche Regeln für die Entwicklung mit Claude Code.
**Alle Regeln gelten immer — auch wenn sie im Eifer des Gefechts unbequem sind.**

---

## Workflow: Änderung → Deploy

```
1. Dateien lesen und verstehen (nie blind ändern)
2. Änderung implementieren
3. git commit
4. ./scripts/build.sh --deploy
5. Smoke-Test beobachten
```

**Nie** Schritt 3 überspringen. Jeder Deploy muss aus einem committed State starten,
damit Regressionsfehler über `git log` / `git revert` rückverfolgbar sind.

---

## Prod-Umgebung

| Was | Wert |
|-----|------|
| Docker-Host | `10.0.0.1` (docker-sys) |
| Container-Name | `proxy-proxy` |
| VLan-IP | `10.0.0.2` |
| Compose-Datei | `/data/_DockerCreate/compose/proxy.yaml` |
| Env-Dateien | `/data/_DockerCreate/compose/.env` + `proxy.env` |
| Volumes unter | `/data/proxy/` (sites-enabled, AddOn, ssl, ...) |
| dc-Alias auf docker-sys | `dc proxy up -d --force-recreate proxy` |

**OIDC / Keycloak:**
- Keycloak: `https://10.10.22.12` (HTTPS 443, selbstsigniertes Cert)
- Realm: `master`, Client: `proxy-example.com`
- extra_hosts in proxy.yaml: `iam.example.com:10.10.22.12` (verhindert Hairpin-NAT)

---

## Was NICHT tun (gelernte Fehler)

### ❌ Nie `docker compose` direkt auf Prod ausführen
Immer über `./scripts/build.sh --deploy`. Direkter Aufruf ohne beide `--env-file`-Argumente
erzeugt einen falsch benannten Container (`compose-proxy` statt `proxy-proxy`) mit falschen
Volume-Pfaden (`/data/compose/` statt `/data/proxy/`).

### ❌ Nie `apachectl graceful` oder `apachectl restart` im Container
Bricht den Container (unhealthy). Stattdessen: `kill -TERM 1` → Docker-Restart-Policy übernimmt.
Das `rotate-oidc-key.sh` macht das bereits so.

### ❌ Nie auf Prod debuggen ohne vorher Logs zu lesen
```bash
ssh 10.0.0.1 'docker logs proxy-proxy --tail 50'
ssh 10.0.0.1 'docker exec proxy-proxy tail -30 /var/log/apache2/apache.log'
```

### ❌ Nie --force-recreate ohne Verifikation
Vor jedem force-recreate prüfen:
```bash
ssh 10.0.0.1 'docker ps --format "{{.Names}}\t{{.Status}}"'
```

---

## Debugging-Checkliste

**Container läuft nicht / unhealthy:**
```bash
ssh 10.0.0.1 'docker logs proxy-proxy --tail 30'
ssh 10.0.0.1 'docker exec proxy-proxy apache2ctl -S 2>&1 | head -20'
```

**HTTPS antwortet nicht:**
```bash
ssh 10.0.0.1 'docker exec proxy-proxy apache2ctl -S 2>&1 | grep -i "port\|vhost"'
ssh 10.0.0.1 'docker inspect proxy-proxy | python3 -c "import sys,json; c=json.load(sys.stdin)[0]; [print(m[\"Source\"],\"→\",m[\"Destination\"]) for m in c[\"Mounts\"]]"'
```

**OIDC / Keycloak-Fehler:**
- `redirect_uri invalid` → Fehlt in Keycloak Client `proxy-example.com` → Admin API: `https://10.10.22.12/admin/realms/master/clients/...`
- `OIDC_access_token` leer → `OIDCPassAccessToken` nicht gesetzt oder kein Code-Flow
- Keycloak Admin API gibt 403 → User hat keine `manage-users`/`view-users` Realm-Rolle

**Reverse-Proxy-Fehler (AH01102):**
- NETIO-230B (xtrastrom) spricht nur HTTP/1.0
- Fix: `SetEnv force-proxy-request-1.0 1` in `xtrastrom.preconfig`

---

## Prod-Konfiguration (nicht im Repo)

Folgende Dateien auf docker-sys müssen manuell gepflegt werden:

**`/data/_DockerCreate/compose/proxy.yaml`** (Ergänzungen):
- `extra_hosts: iam.example.com:10.10.22.12` im proxy-Service
- `env_file: /data/proxy/.env` im redis-Service (für REDIS_PASSWORD)
- Volume-Mount: `${DPATH}/${COMPOSE_PROJECT_NAME}/basic.htpasswd:/etc/apache2/basic.htpasswd:rw`

**`/data/proxy/basic.htpasswd`**: Permissions `644` (nicht `640`), sonst 500 bei Basic-Auth

**`/data/proxy/sites-enabled/derwerres.conf`**:
- iam-Backend: `Use VHost_Proxy iam example.com https://10.10.22.12/` (HTTPS, nicht HTTP:8080)

**`/data/proxy/AddOn/example.com/xtrastrom.preconfig`**:
- HTTP/1.0-Fix für NETIO-230B (siehe Debugging oben)

**`/data/_DockerCreate/compose/proxy.env`**:
- `KEYCLOAK_ADMIN_URL=https://iam.example.com/realms/master`
- `TOC_TITLE=Inhaltsverzeichnis der Server`

---

## Offene TODOs (vor Public Release)

- [ ] TOC-Topbar: Admin/Logout-Buttons rechtsbündig
- [ ] Duplicate vhosts: `sites-admin/` und `sites-enabled/` → Apache-Warnungen
- [ ] Logout SSL revoke: `OIDCSSLValidateServer Off` greift nicht für Revoke-Endpoint
- [ ] tini/dumb-init als PID 1
- [ ] `scripts/setup.sh` Installationsscript
