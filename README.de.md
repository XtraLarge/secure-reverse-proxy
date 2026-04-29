# secure-reverse-proxy

[🇬🇧 English version](README.md)

> Apache Reverse Proxy mit integriertem OIDC Single Sign-On, einer webbasierten Admin-Oberfläche und einer Live-Übersichtsseite für alle deine Dienste.

[![Docker Image](https://img.shields.io/badge/Docker-xtralarge71%2Fsecure--reverse--proxy-blue?logo=docker)](https://hub.docker.com/r/xtralarge71/secure-reverse-proxy)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## Was macht das?

Ein einziger Container sitzt vor allen internen Diensten.
Benutzer melden sich einmal über ihren OIDC-Provider (Keycloak, Authentik, Dex, …) an
und greifen danach auf jeden Dienst zu, ohne sich erneut anmelden zu müssen.

Nach der Anmeldung landen sie auf dem **Inhaltsverzeichnis** — einer Live-Übersicht
aller Dienste mit Erreichbarkeitsstatus und Suchfilter.

![TOC-Seite](docs/screenshots/toc.png)
<!-- TODO: Screenshot von toc.<domain> nach OIDC-Login -->

---

## Features

| | |
|---|---|
| **Single Sign-On** | `mod_auth_openidc` — kompatibel mit jedem OIDC/OAuth2-Provider |
| **Zugriffskontrolle pro Dienst** | Jeder VHost beschränkt den Zugriff per Benutzername (`preferred_username`-Claim) oder Gruppenzugehörigkeit (`groups`-Claim) |
| **GeoIP-Länderfilter** | Externer Zugriff nur aus konfigurierten Ländern |
| **Inhaltsverzeichnis** | OIDC-geschützte Übersichtsseite (`toc.<domain>`) mit Live-Erreichbarkeitsprüfung |
| **Admin-Oberfläche** | Browserbasierter VHost-Editor unter `admin.<domain>` — VHosts hinzufügen, bearbeiten und neu laden ohne SSH |
| **Keycloak-Benutzerverwaltung** | Keycloak-Benutzer direkt aus der Admin-Oberfläche anlegen, bearbeiten und verwalten (`admin.<domain>/admin-kc.lua`) |
| **Backchannel Logout** | Abmeldung wird an den OIDC-Provider weitergeleitet und löscht die Redis-Session |
| **Redis Session Cache** | Eine gemeinsame Session über alle Subdomains einer Domain |
| **Let's Encrypt / ACME** | Automatische Zertifikatsbeschaffung und -erneuerung via certbot |
| **WebSocket-Unterstützung** | Durchleitung von WebSocket-Verbindungen zu Backends |
| **mod_macro-Templates** | Wiederverwendbare VHost-Muster — eine Zeile pro Dienst |
| **Passphrasen-Rotation** | OIDC-Sitzungsverschlüsselungsschlüssel wird automatisch generiert und täglich rotiert |

---

## Schnellstart

### 1. Klonen und konfigurieren

```bash
git clone https://github.com/XtraLarge/secure-reverse-proxy.git
cd secure-reverse-proxy
```

**Option A — interaktives Setup (empfohlen):**

```bash
bash scripts/setup.sh
```

Das Script fragt alle erforderlichen Werte ab, generiert automatisch Secrets für
Redis und die OIDC-Session-Passphrase und legt die Verzeichnisstruktur an.

**Option B — manuell:**

```bash
cp .env.example .env
```

`.env` bearbeiten — mindestens diese Werte sind erforderlich:

```dotenv
OIDC_PROVIDER_METADATA_URL=https://sso.example.com/realms/myrealm/.well-known/openid-configuration
OIDC_CLIENT_SECRET=dein-client-secret
OIDC_COOKIE_DOMAIN=example.com
```

### 2. TLS-Zertifikate ablegen

```bash
mkdir -p ssl/example.com
cp /pfad/zu/cert.pem      ssl/example.com/cert.pem
cp /pfad/zu/key.pem       ssl/example.com/key.pem
cp /pfad/zu/fullchain.pem ssl/example.com/fullchain.pem
```

### 3. Site-Konfiguration erstellen

```bash
mkdir -p sites
cp conf/sites-available/example.conf sites/example.com.conf
# sites/example.com.conf bearbeiten — example.com durch eigene Domain ersetzen
```

### 4. Starten

```bash
docker compose up -d
```

`https://toc.example.com` aufrufen — der Browser leitet zum OIDC-Provider weiter
und landet nach der Anmeldung auf dem Inhaltsverzeichnis.

---

> **Lokaler Test ohne eigene Domain oder OIDC-Provider?**
> Unter [`examples/keycloak/`](examples/keycloak/README.md) gibt es einen
> vollständigen Stack mit Keycloak, Testbenutzer und einem Beispiel-Backend.

---

## Verzeichnisstruktur

```
secure-reverse-proxy/
├── docker-compose.yml
├── .env                        ← Secrets (gitignored)
├── ssl/                        ← TLS-Zertifikate (gitignored)
│   └── <domain>/
│       ├── cert.pem
│       ├── key.pem
│       └── fullchain.pem
├── sites/                      ← Eigene VHost-Konfigurationen (gitignored)
│   └── <domain>.conf
└── AddOn/                      ← Optionale Apache-Snippets pro VHost (gitignored)
    ├── <domain>/
    │   ├── <site>.preconfig    ← Vor ProxyPass eingefügt
    │   └── <site>.postconfig   ← Nach ProxyPass eingefügt
    └── .oidc/                  ← Domain-spezifische OIDC-Credentials (von Admin-UI geschrieben)
        └── <domain>.conf       ← OIDCClientID / OIDCClientSecret-Überschreibungen
```

`ssl/`, `sites/`, `AddOn/` und `config/` werden als Bind-Mounts in den Container
eingehängt und nie ins Git eingecheckt.

---

## Umgebungsvariablen

`.env.example` nach `.env` kopieren und anpassen.

### OIDC

| Variable | Pflicht | Standard | Beschreibung |
|---|---|---|---|
| `OIDC_PROVIDER_METADATA_URL` | ✓ | — | OIDC Discovery Endpoint |
| `OIDC_CLIENT_ID` | — | `Proxy` | Client-ID beim IdP |
| `OIDC_CLIENT_SECRET` | ✓ | — | Client Secret |
| `OIDC_COOKIE_DOMAIN` | ✓ | — | Basis-Domain für Session-Cookies, z.B. `example.com` |
| `OIDC_SCOPE` | — | `openid email` | OAuth2-Scopes (muss `openid` enthalten) |
| `OIDC_REMOTE_USER_CLAIM` | — | `email` | Claim für `REMOTE_USER` |
| `OIDC_REDIRECT_PATH` | — | `/protected` | OIDC-Callback-Pfad |
| `OIDC_DEFAULT_LOGOUT_URL` | — | automatisch | Weiterleitungs-URL nach dem Logout |
| `OIDC_CRYPTO_PASSPHRASE` | — | automatisch | Session-Verschlüsselungsschlüssel; wird automatisch generiert und täglich rotiert wenn nicht gesetzt |
| `OIDC_PROVIDER_TOKEN_ENDPOINT_AUTH` | — | `client_secret_basic` | Authentifizierungsmethode am Token-Endpoint |

### Redis

| Variable | Pflicht | Standard | Beschreibung |
|---|---|---|---|
| `REDIS_HOST` | — | `redis` | Redis-Hostname |
| `REDIS_PORT` | — | `6379` | Redis-Port |
| `REDIS_DB` | — | `1` | Redis-Datenbankindex |
| `REDIS_PASSWORD` | — | — | Redis-Passwort; leer lassen um Auth zu deaktivieren |

### Zugriffskontrolle

| Variable | Pflicht | Standard | Beschreibung |
|---|---|---|---|
| `INTERNAL_NETWORKS` | — | — | Kommagetrennte CIDRs, die GeoIP und OIDC-Auth umgehen (z.B. `10.0.0.0/8,192.168.0.0/16`) |
| `GEOIP_ALLOW_COUNTRIES` | — | `DE` | Durch `\|` getrennte ISO-3166-1-Ländercodes für externen Zugriff (z.B. `DE\|AT\|CH`) |

### TLS / ACME

| Variable | Pflicht | Standard | Beschreibung |
|---|---|---|---|
| `ACME_EMAIL` | — | — | Wenn gesetzt, beantragt certbot automatisch Let's-Encrypt-Zertifikate |

### Keycloak-Benutzerverwaltung

| Variable | Pflicht | Standard | Beschreibung |
|---|---|---|---|
| `KEYCLOAK_ADMIN_URL` | — | automatisch | Keycloak Admin REST API Basis-URL, z.B. `https://sso.example.com/admin/realms/myrealm`. Wird automatisch aus `OIDC_PROVIDER_METADATA_URL` abgeleitet. |
| `KEYCLOAK_ROLE_PREFIX` | — | — | Nur Rollen mit diesem Namenspräfix anzeigen/verwalten (z.B. `proxy-`). Leer = alle Rollen. |

### Sonstiges

| Variable | Pflicht | Standard | Beschreibung |
|---|---|---|---|
| `APACHE_SERVER_NAME` | — | `localhost` | Globaler Apache `ServerName` (unterdrückt `AH00558`) |
| `TOC_TITLE` | — | Domainname | Titel der TOC-Seite |

---

## TLS-Zertifikate

### Manuelle Zertifikate

Zertifikatsdateien unter `ssl/<domain>/` ablegen:

```
ssl/example.com/
├── cert.pem        # Serverzertifikat
├── key.pem         # Privater Schlüssel
└── fullchain.pem   # Zertifikatskette (Zertifikat + Zwischenzertifikate)
```

Der Entrypoint erkennt Zertifikate beim Start automatisch und konfiguriert SSL
für jede Domain, die ein passendes Zertifikatsverzeichnis hat.

### Let's Encrypt (automatisch)

`ACME_EMAIL` in `.env` setzen. Der Entrypoint führt certbot beim Start aus und
richtet einen wöchentlichen Cron-Job für die Erneuerung ein. Zertifikate werden
im `letsencrypt`-Volume gespeichert.

```dotenv
ACME_EMAIL=admin@example.com
```

Port 80 muss erreichbar sein, damit certbot die HTTP-01-Challenge abschließen kann.

---

## Site-Konfiguration

Pro Domain eine `.conf`-Datei in `sites/` erstellen. Als Vorlage dient
[`conf/sites-available/example.conf`](conf/sites-available/example.conf).

### Domain-Rahmen

Jede Konfigurationsdatei braucht `Domain_Init` am Anfang und `Domain_Final`
am Ende. `Domain_Init` erstellt automatisch:

- `https://example.com` → Weiterleitung zu `https://www.example.com`
- `https://toc.example.com` → OIDC-geschütztes Inhaltsverzeichnis
- `https://logout.example.com` → OIDC-Logout und Bestätigungsseite

```apache
USE Domain_Init example.com www

# ... eigene VHosts ...

USE Domain_Final example.com www
```

### VHost-Makros

```apache
# Weiterleitungs-Alias (ohne Auth)
Use VHost_Alias  <site>  <domain>  <ziel-url>

# Reverse Proxy — nur bestimmte OIDC-Benutzer (durch | getrennt, Groß-/Kleinschreibung egal)
Use VHost_Proxy_OIDC_User  <site>  <domain>  <backend-url>/  'alice|bob'

# Reverse Proxy — nur Mitglieder bestimmter Gruppen (durch | getrennt)
Use VHost_Proxy_OIDC_Group  <site>  <domain>  <backend-url>/  'editors|admins'

# Reverse Proxy — alle authentifizierten OIDC-Benutzer
Use VHost_Proxy_OIDC_Any  <site>  <domain>  <backend-url>/

# Reverse Proxy — HTTP Basic Auth
Use VHost_Proxy_Basic  <site>  <domain>  <backend-url>/  user  'benutzername'

# Reverse Proxy — HTTP Basic Auth + WebSocket (z.B. Frigate, Home Assistant)
Use VHost_Proxy_WS_Basic  <site>  <domain>  <backend-url>/  user  'benutzername'

# Reverse Proxy — ohne Auth (Backend kümmert sich selbst darum)
Use VHost_Proxy  <site>  <domain>  <backend-url>/

# Admin-Oberfläche (optional)
Use Admin_VHost  <domain>  'alice'
```

### Beispiel

```apache
USE Domain_Init example.com www

Use VHost_Alias          www       example.com  https://www-backend.internal/
Use VHost_Proxy_OIDC_User  app       example.com  http://10.0.0.5:8080/   'alice|bob'
Use VHost_Proxy_OIDC_Group wiki      example.com  http://10.0.0.8:3000/   'editors'
Use VHost_Proxy_OIDC_Any   monitor   example.com  http://10.0.0.6:3000/
Use VHost_Proxy          idp       example.com  https://10.0.0.7:8443/
Use Admin_VHost          example.com  'alice'

USE Domain_Final example.com www
```

Daraus entstehen folgende VHosts:

| URL | Auth | Backend |
|---|---|---|
| `https://www.example.com` | — | `https://www-backend.internal/` |
| `https://app.example.com` | OIDC (nur alice und bob) | `http://10.0.0.5:8080/` |
| `https://wiki.example.com` | OIDC (Gruppe: editors) | `http://10.0.0.8:3000/` |
| `https://monitor.example.com` | OIDC (alle Benutzer) | `http://10.0.0.6:3000/` |
| `https://idp.example.com` | keine | `https://10.0.0.7:8443/` |
| `https://toc.example.com` | OIDC (alle Benutzer) | eingebaute TOC-Seite |
| `https://admin.example.com` | OIDC (nur alice) | eingebaute Admin-Oberfläche |
| `https://logout.example.com` | — | eingebaute Logout-Seite |

### AddOn-Snippets pro VHost

Für VHost-spezifische Apache-Direktiven (SSL-Einstellungen, eigene Header,
WebSocket-Rewrite-Regeln) Dateien in `AddOn/<domain>/` anlegen:

```
AddOn/example.com/
├── app.preconfig     ← vor ProxyPass für app.example.com eingefügt
└── app.postconfig    ← nach ProxyPass für app.example.com eingefügt
```

**HTTPS-Backend mit selbstsigniertem Zertifikat:**

```apache
# AddOn/example.com/app.preconfig
SSLProxyVerify none
SSLProxyCheckPeerCN off
SSLProxyCheckPeerName off
SSLProxyCheckPeerExpire off
```

**WebSocket-Backend:**

`VHost_Proxy_WS_Basic` (oder `VHost_Proxy_OIDC_*` mit `.preconfig`-Snippet) —
`upgrade=ANY` ist bereits im Macro gesetzt, kein extra RewriteRule nötig:

```apache
# Basic Auth + WebSocket (Frigate, Node-RED, …)
Use VHost_Proxy_WS_Basic  camera  example.com  http://10.0.0.9:5000/  user  'alice'

# OIDC + WebSocket (Home Assistant, …)
# In AddOn/example.com/ha.preconfig ergänzen:
#   ProxyPassMatch ^/api/websocket ws://10.0.0.7:8123/api/websocket
```

Weitere Beispiele: [`examples/addons/`](examples/addons/README.md)

---

## Eingebaute Seiten

### Inhaltsverzeichnis (`toc.<domain>`)

Nach der Anmeldung landen Benutzer hier. Alle konfigurierten VHosts der Domain
werden mit aktuellem Erreichbarkeitsstatus aufgelistet. Die Liste ist filterbar.

![TOC-Seite](docs/screenshots/toc.png)
<!-- TODO: Screenshot -->

### Admin-Oberfläche (`admin.<domain>`)

Verfügbar wenn `Use Admin_VHost` in der Site-Konfiguration eingetragen ist.
Nur die genannten Benutzer können sich anmelden.

Die Admin-Oberfläche ermöglicht:

- **Anzeigen** der expandierten Apache-Konfiguration pro VHost
- **Hinzufügen und Bearbeiten** von VHost-Konfigurationen direkt im Browser
- **Neu laden** der Apache-Konfiguration ohne Container-Neustart
- **Keycloak-Clients anlegen und rotieren** — der `proxy-<domain>`-Client,
  `admin`/`user`-Rollen und `<domain>-admins`/`<domain>-users`-Gruppen werden
  automatisch erstellt; die Credentials werden in `config/oidc-clients/<domain>.conf` gespeichert

![Admin-Oberfläche](docs/screenshots/admin.png)
<!-- TODO: Screenshot -->

### Keycloak-Benutzerverwaltung (`admin.<domain>/admin-kc.lua`)

Benötigt `KEYCLOAK_ADMIN_URL` (oder `OIDC_PROVIDER_METADATA_URL` im
Standard-Keycloak-Format). Das OIDC-Access-Token des angemeldeten Admins wird
verwendet — kein separates Service-Account nötig.

Funktionen:

- **Benutzer auflisten und suchen**
- **Benutzer anlegen** mit temporärem Passwort
- **Bearbeiten** von Name, E-Mail und Gruppenzuweisungen
- **Passwörter zurücksetzen**
- **Benutzer aktivieren / deaktivieren** oder **löschen**
- **Gruppen verwalten** — `<domain>-admins` / `<domain>-users`-Gruppen anlegen und löschen

![Keycloak-Benutzerverwaltung](docs/screenshots/admin-kc.png)
<!-- TODO: Screenshot -->

**Erforderliche Keycloak-Rollen** für den Admin-Benutzer (Client Roles → `realm-management`):

| Rolle | Zweck |
|---|---|
| `view-users` | Benutzer auflisten und anzeigen |
| `manage-users` | Benutzer anlegen, bearbeiten, löschen und Passwörter setzen |
| `query-roles` | Realm-Rollen auflisten |

### Logout-Seite (`logout.<domain>`)

Löst den OIDC-Backchannel-Logout aus, löscht die Redis-Session und zeigt eine
animierte Terminal-Bestätigung bevor zur Domain weitergeleitet wird.

---

## OIDC-Provider einrichten

### Keycloak

1. **Clients** → **Client erstellen** öffnen
2. **Client-ID** auf den Wert von `OIDC_CLIENT_ID` setzen (Standard: `Proxy`)
3. **Client authentication** aktivieren (confidential)
4. Unter **Gültige Redirect-URIs** eintragen: `https://*.example.com/protected`
5. **Client Secret** kopieren und als `OIDC_CLIENT_SECRET` in `.env` eintragen
6. `OIDC_PROVIDER_METADATA_URL` setzen auf:
   `https://<keycloak-host>/realms/<realm>/.well-known/openid-configuration`

Einen vollständig vorbereiteten lokalen Teststack mit Realm-Import und Beispielbenutzern
gibt es unter [`examples/keycloak/`](examples/keycloak/README.md).

### Andere Provider

Jeder OIDC-kompatible Provider funktioniert (Authentik, Dex, Azure AD, Google, …).
`OIDC_PROVIDER_METADATA_URL` auf den Discovery-Endpoint des Providers setzen und
die Redirect-URI als `https://*.example.com/<OIDC_REDIRECT_PATH>` konfigurieren.

---

## Betrieb

```bash
# Starten
docker compose up -d

# Logs verfolgen
docker compose logs -f proxy

# Apache-Konfiguration testen ohne Neustart
docker compose exec proxy apache2ctl configtest

# Apache nach Änderungen an sites/ oder AddOn/ neu laden (Container-Neustart)
docker compose exec proxy kill -TERM 1

# Stoppen
docker compose down
```

---

## Docker Hub

```bash
docker pull xtralarge71/secure-reverse-proxy:latest
```

Um das fertige Image statt eines lokalen Builds zu verwenden, `image:` in
`docker-compose.yml` setzen:

```yaml
services:
  proxy:
    image: xtralarge71/secure-reverse-proxy:latest
    cap_add:
      - CHOWN
      - NET_BIND_SERVICE
      - SETGID
      - SETUID
```

> `CHOWN`, `SETGID` und `SETUID` sind erforderlich, damit Apache nach dem Binden
> an die Ports 80/443 von `root` zu `www-data` wechseln kann. Ohne diese
> Capabilities startet der Proxy zwar, aber CGI-Endpunkte (z.B.
> `toc.<domain>/cgi/echo.pl`) schlagen zur Laufzeit fehl.

---

## Entwicklung / lokaler Build

```bash
docker build -t secure-reverse-proxy:local .
tests/run-tests.sh secure-reverse-proxy:local
```
