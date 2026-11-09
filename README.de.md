# secure-reverse-proxy

[🇬🇧 English version](README.md)

> Apache-Reverse-Proxy mit eingebautem OIDC-Single-Sign-on, webbasierter Admin-Oberfläche und einer Live-Übersichtsseite für alle Dienste.

[![Container Image](https://img.shields.io/badge/ghcr.io-xtralarge%2Fsecure--reverse--proxy-blue?logo=github)](https://github.com/XtraLarge/secure-reverse-proxy/pkgs/container/secure-reverse-proxy)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## Was macht das?

Ein Container steht vor allen internen Diensten.
Benutzer melden sich einmal bei ihrem OIDC-Provider an (Keycloak, Authentik, Dex, …)
und erreichen danach jeden Dienst hinter dem Proxy ohne erneute Anmeldung.

Nach dem Login landen sie im **Inhaltsverzeichnis (TOC)** — einer Live-Übersicht
aller Dienste mit Erreichbarkeitsstatus je Zeile, der wirksamen Ländersperre und
Spaltenfiltern.

---

## Features

| | |
|---|---|
| **Single Sign-on** | `mod_auth_openidc` — funktioniert mit jedem OIDC/OAuth2-Provider |
| **Zugriffskontrolle pro Dienst** | Jeder VHost beschränkt den Zugriff auf Benutzernamen (`preferred_username`-Claim), Gruppen (`groups`-Claim) oder beides |
| **GeoIP-Ländersperre** | Externer Zugriff nur aus einer konfigurierbaren Länderliste; die Sperre lässt sich in der Admin-Oberfläche pro Site umschalten |
| **GeoLock-Seite** | `geolock.<domain>` — vorübergehend zusätzliche Länder freischalten (z. B. auf Reisen), geschützt durch OIDC-Login + PIN und weltweit erreichbar |
| **Inhaltsverzeichnis** | Übersichtsseite (`toc.<domain>`) mit Live-Prüfung der Erreichbarkeit von innen und außen und der wirksamen GeoIP-Sperre je Eintrag |
| **Admin-Oberfläche** | Browser-Editor für VHosts unter `admin.<domain>` — VHosts anlegen, bearbeiten und neu laden ohne SSH; Login immer Pflicht |
| **Keycloak-Benutzerverwaltung** | Keycloak-Benutzer direkt aus der Admin-Oberfläche anlegen und verwalten (`admin.<domain>/admin-kc.lua`) |
| **Backchannel-Logout** | Logout wird an den OIDC-Provider weitergegeben und löscht die Redis-Session |
| **Redis-Session-Cache** | Eine Session gilt für alle Subdomains einer Domain |
| **Secrets als Dateien** | Jedes Secret kann als `<VAR>_FILE` übergeben werden; Secrets werden vor dem Start von Apache aus der Umgebung entfernt |
| **Let's Encrypt / ACME** | Automatische Zertifikatsausstellung und -verlängerung per certbot |
| **WebSocket-Unterstützung** | WebSocket-Verbindungen werden zum Backend durchgereicht |
| **mod_macro-Vorlagen** | Wiederverwendbare VHost-Muster — eine Zeile pro Dienst |
| **Passphrase-Rotation** | Der OIDC-Session-Schlüssel wird automatisch erzeugt und täglich rotiert |

---

## Schnellstart

### 1. Klonen und konfigurieren

```bash
git clone https://github.com/XtraLarge/secure-reverse-proxy.git
cd secure-reverse-proxy
```

**Variante A — interaktives Setup (empfohlen):**

```bash
bash scripts/setup.sh
```

Das Skript fragt alle nötigen Werte ab, erzeugt Secrets für Redis und die
OIDC-Session-Passphrase und legt die Verzeichnisstruktur an.

**Variante B — manuell:**

```bash
cp .env.example .env
```

`.env` bearbeiten — mindestens nötig sind:

```dotenv
OIDC_PROVIDER_METADATA_URL=https://sso.example.com/realms/myrealm/.well-known/openid-configuration
OIDC_CLIENT_SECRET=your-client-secret
OIDC_COOKIE_DOMAIN=example.com
```

### 2. TLS-Zertifikate ablegen

```bash
mkdir -p ssl/example.com
cp /path/to/cert.pem      ssl/example.com/cert.pem
cp /path/to/key.pem       ssl/example.com/key.pem
cp /path/to/fullchain.pem ssl/example.com/fullchain.pem
```

### 3. Site-Konfiguration erstellen

```bash
mkdir -p sites
cp conf/sites-available/example.conf sites/example.com.conf
# sites/example.com.conf bearbeiten — example.com durch die eigene Domain ersetzen
# und 'alice' durch die Benutzer, die die Admin-Oberfläche nutzen dürfen
```

### 4. Starten

```bash
docker compose up -d
```

`https://toc.example.com` öffnen — es folgt die Weiterleitung zum OIDC-Provider,
nach dem Login erscheint das Inhaltsverzeichnis.

---

> **Lokal testen ohne echte Domain oder OIDC-Provider?**
> Siehe [`examples/keycloak/`](examples/keycloak/README.md) — ein eigenständiger
> Stack mit Keycloak, Testbenutzer und Beispiel-Backend.

---

## Verzeichnisstruktur

```
secure-reverse-proxy/
├── docker-compose.yml
├── .env                        ← Einstellungen und Secrets (gitignored)
├── ssl/                        ← TLS-Zertifikate (gitignored)
│   └── <domain>/
│       ├── cert.pem
│       ├── key.pem
│       └── fullchain.pem
├── sites/                      ← eigene VHost-Konfigurationen (gitignored)
│   └── <domain>.conf
├── AddOn/                      ← optionale Apache-Snippets pro VHost (gitignored)
│   └── <domain>/
│       ├── <site>.preconfig    ← wird vor ProxyPass eingebunden
│       └── <site>.postconfig   ← wird nach ProxyPass eingebunden
└── config/                     ← Laufzeit-Konfiguration (gitignored)
    ├── basic.htpasswd          ← Benutzerdatenbank für Basic Auth
    ├── extra-countries.conf    ← zusätzlich erlaubte Länder (schreibt die GeoLock-Seite)
    ├── geolock/                ← GeoLock-Einstellung pro Site (schreibt die Admin-Oberfläche)
    │   └── <domain>/<site>.conf
    └── oidc-clients/           ← OIDC-Zugangsdaten pro Domain (schreibt die Admin-Oberfläche)
        └── <domain>.conf       ← OIDCClientID / OIDCClientSecret
```

`ssl/`, `sites/`, `AddOn/` und `config/` werden in den Container gemountet und
nie in git eingecheckt.

---

## Umgebungsvariablen

`.env.example` nach `.env` kopieren und Werte eintragen.

### OIDC

| Variable | Pflicht | Standard | Beschreibung |
|---|---|---|---|
| `OIDC_PROVIDER_METADATA_URL` | ✓ | — | OIDC-Discovery-Endpunkt |
| `OIDC_CLIENT_ID` | — | `Proxy` | Client-ID beim Identity-Provider |
| `OIDC_CLIENT_SECRET` | ✓ | — | Client-Secret |
| `OIDC_COOKIE_DOMAIN` | ✓ | — | Basisdomain für Session-Cookies, z. B. `example.com` |
| `OIDC_SCOPE` | — | `openid email` | OAuth2-Scopes (muss `openid` enthalten) |
| `OIDC_REMOTE_USER_CLAIM` | — | `email` | Claim, der als `REMOTE_USER` gesetzt wird |
| `OIDC_REDIRECT_PATH` | — | `/protected` | OIDC-Callback-Pfad |
| `OIDC_DEFAULT_LOGOUT_URL` | — | automatisch | Weiterleitungsziel nach dem Logout |
| `OIDC_CRYPTO_PASSPHRASE` | — | automatisch | Schlüssel für die Session-Verschlüsselung; ohne Angabe automatisch erzeugt und täglich rotiert |
| `OIDC_PROVIDER_TOKEN_ENDPOINT_AUTH` | — | `client_secret_basic` | Authentifizierung am Token-Endpunkt |

### Redis

| Variable | Pflicht | Standard | Beschreibung |
|---|---|---|---|
| `REDIS_HOST` | — | `redis` | Redis-Hostname |
| `REDIS_PORT` | — | `6379` | Redis-Port |
| `REDIS_DB` | — | `1` | Redis-Datenbanknummer |
| `REDIS_PASSWORD` | — | — | Redis-Passwort; dringend empfohlen (leer nur für Tests) |

### Zugriffskontrolle

| Variable | Pflicht | Standard | Beschreibung |
|---|---|---|---|
| `INTERNAL_NETWORKS` | — | — | Komma-getrennte CIDRs, die Ländersperre und Login der normalen Sites umgehen (z. B. `10.0.0.0/8,192.168.0.0/16`). **Nicht** für Admin-Oberfläche und GeoLock-Seite: Dort ist der Login immer Pflicht. |
| `GEOIP_ALLOW_COUNTRIES` | — | `DE` | Durch `\|` getrennte Ländercodes (ISO 3166-1 alpha-2), die von außen zugreifen dürfen (z. B. `DE\|AT\|CH`) |
| `GEOIP_ACCOUNT_ID` / `GEOIP_LICENSE_KEY` | — | — | MaxMind-Zugang, um beim Start und wöchentlich eine aktuelle GeoLite2-Country-Datenbank zu laden; ohne ihn wird die mitgelieferte Datenbank genutzt |

> Interne Clients gelten nur als intern, wenn sie den Proxy direkt erreichen.
> Löst der interne DNS die Dienstnamen auf die öffentliche IP auf (NAT-Hairpin),
> sieht der Proxy die öffentliche Adresse des Routers und behandelt sie als extern.
> Mit Split-DNS (die Dienstnamen zeigen intern auf die IP des Proxys) greift
> `INTERNAL_NETWORKS`.

### GeoLock-Seite

| Variable | Pflicht | Standard | Beschreibung |
|---|---|---|---|
| `GEOLOCK_PIN` | — | — | PIN für `geolock.<domain>` (nur als Hash gespeichert). Ohne PIN zeigt die Seite „nicht konfiguriert“. Mehr als 4 Stellen verwenden. |
| `GEOLOCK_COUNTRIES` | — | — | Zusätzliche Länder (durch `\|` getrennt), die nur beim **ersten** Start nach `config/extra-countries.conf` geschrieben werden, also wenn die Datei noch fehlt. Danach verwaltet die GeoLock-Seite die Datei. |

### TLS / ACME

| Variable | Pflicht | Standard | Beschreibung |
|---|---|---|---|
| `ACME_EMAIL` | — | — | Wenn gesetzt, holt certbot automatisch Let's-Encrypt-Zertifikate für alle Domains |
| `ACME_DOMAINS` | — | automatisch | Komma-getrennte Hauptdomains; Standard: aus den Site-Konfigurationen ermittelt |
| `ACME_SERVER` | — | Let's Encrypt | ACME-Verzeichnis-URL (z. B. der Staging-Endpunkt für Tests) |

### Keycloak-Benutzerverwaltung

| Variable | Pflicht | Standard | Beschreibung |
|---|---|---|---|
| `KEYCLOAK_ADMIN_URL` | — | automatisch | Basis-URL der Keycloak-Admin-REST-API, z. B. `https://sso.example.com/admin/realms/myrealm`. Ohne Angabe aus `OIDC_PROVIDER_METADATA_URL` abgeleitet. |
| `KEYCLOAK_REALM` | — | `master` | Realm, in dem Proxy-Clients und Benutzer liegen |
| `KEYCLOAK_ROLE_PREFIX` | — | — | Nur Rollen mit diesem Namenspräfix anzeigen/verwalten (z. B. `proxy-`). Leer = alle Rollen. |
| `KEYCLOAK_API_CLIENT_ID` | — | — | Vertraulicher Client mit Service Account (Client Credentials) für die Admin-Oberfläche und den Abgleich der Redirect-URIs. Nur die nötigen `realm-management`-Rollen vergeben (im Realm `master`: Client `master-realm`): `view-users`, `query-users`, `manage-users`, `query-groups`, `view-clients`, `query-clients`, `manage-clients`, `view-realm`. |
| `KEYCLOAK_API_CLIENT_SECRET` | — | — | Secret dieses Clients (oder `KEYCLOAK_API_CLIENT_SECRET_FILE`) |
| `KEYCLOAK_ADMIN_USER` / `KEYCLOAK_ADMIN_PASS` | — | — | Altlast: Admin-Passwort über `admin-cli`. Wird nur genutzt, wenn kein Service Account eingerichtet ist — besser den Service Account verwenden. |

### Secrets als Dateien

Jedes Secret kann stattdessen als Datei übergeben werden: `<VAR>_FILE=/run/secrets/<name>` setzen und `<VAR>` leer lassen (`OIDC_CLIENT_SECRET`, `OIDC_CRYPTO_PASSPHRASE`, `REDIS_PASSWORD`, `KEYCLOAK_API_CLIENT_SECRET`, `KEYCLOAK_ADMIN_PASS`, `GEOLOCK_PIN`, `GEOIP_LICENSE_KEY`, `ACME_EMAIL`). Der Entrypoint erzeugt alle Konfigurationen und entfernt die Secrets danach aus der Umgebung, bevor Apache und die Hintergrunddienste starten — Worker, Lua und CGI sehen sie also nie. Erzeugte Dateien mit Secrets sind nur für root lesbar (0600).

### Logging

| Variable | Pflicht | Standard | Beschreibung |
|---|---|---|---|
| `LOG_FILE` | — | `/var/log/apache2/apache.log` | Zusammengefasste Logdatei; `off` schaltet das lokale Dateilogging ab |
| `SYSLOG_REMOTE` | — | — | Entferntes Syslog-Ziel, z. B. `udp://10.0.0.20:514` |
| `LOG_RETENTION_DAYS` | — | `14` | Aufbewahrung rotierter Logdateien in Tagen |

### Sonstiges

| Variable | Pflicht | Standard | Beschreibung |
|---|---|---|---|
| `APACHE_SERVER_NAME` | — | `localhost` | Globaler Apache-`ServerName` (unterdrückt `AH00558`) |
| `TOC_TITLE` | — | Domainname | Titel der TOC-Seite |
| `HTTPS_PORT` | — | `443` | Externer HTTPS-Port; nur ändern, wenn der Proxy auf einem anderen Port erreichbar ist |

---

## TLS-Zertifikate

### Manuelle Zertifikate

Zertifikatsdateien unter `ssl/<domain>/` ablegen:

```
ssl/example.com/
├── cert.pem        # Serverzertifikat
├── key.pem         # privater Schlüssel
└── fullchain.pem   # vollständige Kette (Zertifikat + Zwischenzertifikate)
```

Der Entrypoint erkennt die Zertifikate beim Start und richtet SSL für jede Domain
mit passendem Zertifikatsverzeichnis automatisch ein.

### Let's Encrypt (automatisch)

`ACME_EMAIL` in `.env` setzen. Der Entrypoint startet certbot beim Start und legt
einen wöchentlichen Cronjob zur Verlängerung an. Die Zertifikate liegen im
Volume `letsencrypt`.

```dotenv
ACME_EMAIL=admin@example.com
```

Port 80 muss erreichbar sein, damit certbot die HTTP-01-Challenge abschließen kann.

---

## Site-Konfiguration

Pro Domain eine `.conf`-Datei in `sites/` anlegen und die mitgelieferten Makros
verwenden — eine vollständig kommentierte Vorlage ist
[`conf/sites-available/example.conf`](conf/sites-available/example.conf).

### Domain-Rahmen

Jede Konfigurationsdatei braucht `Domain_Init` am Anfang und `Domain_Final` am Ende:

```apache
USE Domain_Init example.com www 'alice|bob'

# ... eigene VHosts ...

USE Domain_Final example.com www
```

`Domain_Init <domain> <standard-subdomain> '<admin-benutzer>'` erzeugt automatisch:

- `https://example.com` → Weiterleitung auf `https://www.example.com`
- `https://toc.example.com` → Inhaltsverzeichnis
- `https://logout.example.com` → OIDC-Logout mit Bestätigungsseite
- `https://admin.example.com` → Admin-Oberfläche, nur für die genannten Admin-Benutzer
- `https://geolock.example.com` → GeoLock-Seite, nur für die genannten Admin-Benutzer

Die Admin-Benutzer sind eine durch `|` getrennte Liste von `preferred_username`-Werten,
Groß-/Kleinschreibung egal. Admin- und GeoLock-VHost gehören bewusst zum Rahmen,
damit sie beim Bearbeiten der Domain nicht versehentlich verschwinden —
`Admin_VHost` oder `GeoLock_VHost` daher nicht selbst einfügen.

`Domain_Final` fängt alle nicht definierten Subdomains ab und leitet sie auf die
Standard-Subdomain um.

Für eine zweite Domain, deren Cookie-Domain von `OIDC_COOKIE_DOMAIN` abweicht,
gibt es `Domain_Init_Simple <domain> <standard-subdomain>` (ohne TOC, Logout,
Admin und OIDC-Direktiven).

### VHost-Makros

```apache
# Weiterleitungs-Alias (ohne Auth)
Use VHost_Alias  <site>  <domain>  <ziel-url>

# Reverse Proxy — nur bestimmte OIDC-Benutzer (durch | getrennt, Groß-/Kleinschreibung egal)
Use VHost_Proxy_OIDC_User  <site>  <domain>  <backend-url>/  'alice|bob'

# Reverse Proxy — OIDC-Benutzer und/oder -Gruppen (durch | getrennt, '' lässt eine Seite weg)
Use VHost_Proxy_OIDC  <site>  <domain>  <backend-url>/  'alice'  'editors|admins'

# Reverse Proxy — alle angemeldeten OIDC-Benutzer
Use VHost_Proxy_OIDC_Any  <site>  <domain>  <backend-url>/

# Reverse Proxy — HTTP Basic Auth
Use VHost_Proxy_Basic  <site>  <domain>  <backend-url>/  user  'username'

# Reverse Proxy — HTTP Basic Auth + WebSocket (z. B. Frigate, Home Assistant)
Use VHost_Proxy_WS_Basic  <site>  <domain>  <backend-url>/  user  'username'

# Reverse Proxy — ohne Proxy-Login, Ländersperre greift (Backend hat eigenen Login)
Use VHost_Proxy  <site>  <domain>  <backend-url>/

# Reverse Proxy — ohne Proxy-Login und ohne Ländersperre: weltweit erreichbar
Use VHost_Proxy_Open  <site>  <domain>  <backend-url>/
```

Alle `VHost_Proxy*`-Makros außer `VHost_Proxy_Open` sperren externe Zugriffe auf
die erlaubten Länder. Clients aus `INTERNAL_NETWORKS` umgehen Ländersperre und
Proxy-Login.

### Beispiel

```apache
USE Domain_Init example.com www 'alice'

Use VHost_Alias            www      example.com  https://www-backend.internal/
Use VHost_Proxy_OIDC_User  app      example.com  http://10.0.0.5:8080/   'alice|bob'
Use VHost_Proxy_OIDC       wiki     example.com  http://10.0.0.8:3000/   ''  'editors'
Use VHost_Proxy_OIDC_Any   monitor  example.com  http://10.0.0.6:3000/
Use VHost_Proxy            files    example.com  http://10.0.0.9:8080/
Use VHost_Proxy_Open       idp      example.com  https://10.0.0.7:8443/

USE Domain_Final example.com www
```

Daraus entstehen folgende VHosts (Zugriff von außen; interne Netze umgehen
Ländersperre und Login der normalen Sites):

| URL | Auth | Ländersperre | Backend |
|---|---|---|---|
| `https://www.example.com` | — | — | Weiterleitung auf `https://www-backend.internal/` |
| `https://app.example.com` | OIDC (nur alice oder bob) | ja | `http://10.0.0.5:8080/` |
| `https://wiki.example.com` | OIDC (Gruppe: editors) | ja | `http://10.0.0.8:3000/` |
| `https://monitor.example.com` | OIDC (jeder Benutzer) | ja | `http://10.0.0.6:3000/` |
| `https://files.example.com` | Login des Backends | ja | `http://10.0.0.9:8080/` |
| `https://idp.example.com` | Login des Backends | nein | `https://10.0.0.7:8443/` |
| `https://toc.example.com` | OIDC (jeder Benutzer) | ja | eingebautes Inhaltsverzeichnis |
| `https://admin.example.com` | OIDC (nur alice), auch aus internen Netzen | ja | eingebaute Admin-Oberfläche |
| `https://geolock.example.com` | OIDC (nur alice) + PIN | nein | eingebaute GeoLock-Seite |
| `https://logout.example.com` | — | — | eingebaute Logout-Seite |

### GeoLock pro Site

Die Ländersperre (`GEOIP_ALLOW_COUNTRIES` plus die auf `geolock.<domain>` freigeschalteten Länder) ist in jedem Site-Makro eine eigene Schicht. Jedes Makro hat eine Vorgabe (`VHost_Proxy_Open`: aus, alle anderen: an); in der Admin-Oberfläche lässt sie sich pro Site auf *an* oder *aus* stellen, ohne die Authentifizierung zu ändern. Die Einstellung liegt in `config/geolock/<domain>/<site>.conf`:

```apache
SetEnvIf Request_URI ^ GEOLOCK=on        # an: Sperre erzwingen, auch ohne Auth
SetEnvIf Request_URI ^ AllowCountry=1    # aus: Sperre aufheben, Authentifizierung bleibt
```

*An* sperrt andere Länder schon vor der Authentifizierung. Bei der Vorgabe ist die
Sperre Teil der `Require`-Regeln des VHosts; ein Preconfig mit
`Require all granted` würde sie aufheben — Sites, bei denen die Sperre unabhängig
von Preconfigs gelten muss, ausdrücklich auf *an* stellen.

Interne Netze sind nie gesperrt. Ein Preconfig kann die Sperre weiterhin für einzelne Pfade aufheben, z. B. `SetEnvIf Request_URI "^/api/" AllowCountry=1`.

### Was sites/, AddOn/ und config/ enthalten dürfen

Diese Verzeichnisse beschreibt die Admin-Oberfläche (www-data), Apaches Master läuft
aber als root. Deshalb liest Apache sie nie direkt: Vor jedem Start und Reload kopiert
der Container sie in einen nur für root lesbaren Schnappschuss (`/run/apache2/cfg`),
prüft die Kopie mit `proxy-config-guard.sh` und liest erst dann diese Kopie. Eine
abgewiesene Konfiguration verhindert den Start (fail closed) bzw. den Reload — Apache
behält dann die bisherige Konfiguration —, die Befunde stehen im Log; die
Admin-Oberfläche zeigt sie schon vor dem Speichern.

- `sites/*.conf`: nur `Use <makro> …`-Zeilen (und `LogLevel`). Die ersten beiden
  Makro-Parameter müssen einfache Site-/Domainnamen sein (keine Pfade, kein `..`).
- `AddOn/`: VHost-Direktiven, aber kein `LoadModule`/`LoadFile`, Logs nur nach
  `/var/log/apache2/` oder an syslog (keine Pipes), keine `RewriteMap`-Programme, keine
  SSL-Programmaufrufe, keine Server-Direktiven (`User`, `PidFile`, `Mutex`, …),
  `Include` nur von anderen AddOn-Dateien und den öffentlichen Runtime-Dateien
  (`internal-networks.conf`, `internal-env.conf`, `iam-admin-oidc.conf`).
- `config/`: `oidc-clients/<domain>.conf` nur `OIDC*`-Direktiven,
  `extra-countries.conf` und `geolock/…` nur `SetEnvIf`.
- überall: kein `${…}`, kein `Define`/`UnDefine`, keine eigenen `<Macro>`, keine
  Symlinks oder Sonderdateien.

### AddOn-Snippets pro VHost

Für Apache-Direktiven pro VHost (SSL-Proxy-Einstellungen, eigene Header,
WebSocket-Regeln) Dateien in `AddOn/<domain>/` anlegen:

```
AddOn/example.com/
├── app.preconfig     ← wird vor ProxyPass für app.example.com eingebunden
└── app.postconfig    ← wird nach ProxyPass für app.example.com eingebunden
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

`VHost_Proxy_WS_Basic` verwenden (oder `VHost_Proxy_OIDC_*` mit einem `.preconfig`-Snippet) —
`upgrade=ANY` ist im Makro schon gesetzt, eine zusätzliche RewriteRule ist nicht nötig:

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

Nach dem Login landen die Benutzer hier. Jeder VHost der Domain, den der Benutzer
nutzen darf, wird aufgeführt mit:

- **Status / Ext** — Erreichbarkeit, jede Minute geprüft von innen (über die
  interne Adresse des Proxys) und von außen (über die öffentliche IP der Domain);
  grün = erreichbar, gelb = unerwartete Antwort, rot = nicht erreichbar
- **GeoIP** — `ja`/`nein`: ob der Zugriff von außen auf die erlaubten Länder
  beschränkt ist; der Tooltip zeigt, woher der Wert kommt (Makro-Vorgabe,
  Einstellung in der Admin-Oberfläche oder fester Rahmen-VHost)
- **Secured** — die Art der Authentifizierung (OpenID Connect, Basic, PIN, …)

Der Hinweis über der Tabelle nennt die erlaubten Länder und vorübergehend
freigeschaltete Zusatzländer. Jede Spalte lässt sich filtern.

Aus `INTERNAL_NETWORKS` öffnet sich das Inhaltsverzeichnis ohne Login.

### Admin-Oberfläche (`admin.<domain>`)

Nur die in `Domain_Init` genannten Admin-Benutzer können sich anmelden — **immer
über OIDC, auch aus internen Netzen**. Ändernde Anfragen werden nur mit
angemeldetem Benutzer und einem `Origin`/`Referer` des Admin-Hosts selbst
angenommen (Schutz gegen Cross-Site-Anfragen, ohne Formular-Tokens).

Die Admin-Oberfläche kann:

- die erzeugte Apache-Konfiguration jedes VHosts **anzeigen**
- VHost-Konfigurationen direkt im Browser **anlegen und bearbeiten**
- den **GeoLock pro Site umschalten** (Vorgabe / an / aus, siehe oben)
- die **GeoLock-Seite entsperren**, nachdem zu oft eine falsche PIN eingegeben wurde
- die Apache-Konfiguration ohne Container-Neustart **neu laden**: Erst wird die
  Konfiguration getestet, dann werden die Keycloak-Redirect-URIs abgeglichen,
  dann lädt Apache sanft neu (graceful); eine fehlerhafte Konfiguration wird
  nicht übernommen
- **Keycloak-Clients pro Domain anlegen und rotieren** — Client `proxy-<domain>`,
  Rollen `admin`/`user` und Gruppen `<domain>-admins`/`<domain>-users` werden
  automatisch eingerichtet; die Zugangsdaten pro Domain liegen in
  `config/oidc-clients/<domain>.conf`. Dafür wird der Service Account aus
  `KEYCLOAK_API_CLIENT_ID` genutzt (oder als Altlast das Admin-Passwort).

### Keycloak-Benutzerverwaltung (`admin.<domain>/admin-kc.lua`)

Benötigt `KEYCLOAK_ADMIN_URL` (oder `OIDC_PROVIDER_METADATA_URL` im üblichen
Keycloak-Format). Verwendet wird das OIDC-Access-Token des angemeldeten Admins —
seine Keycloak-Rollen bestimmen, was möglich ist.

Funktionen:

- Keycloak-Benutzer **auflisten und suchen**
- Benutzer mit temporärem Passwort **anlegen**
- Name, E-Mail und Gruppen **bearbeiten**
- Passwörter **zurücksetzen**
- Benutzer **aktivieren / deaktivieren** oder **löschen**
- **Gruppen verwalten** — Gruppen `<domain>-admins` / `<domain>-users` anlegen und löschen

**Benötigte Keycloak-Rollen** für den Admin-Benutzer (Client-Rollen → `realm-management`):

| Rolle | Zweck |
|---|---|
| `view-users` | Benutzer auflisten und anzeigen |
| `manage-users` | Benutzer anlegen, ändern, löschen und Passwörter setzen |
| `query-roles` | Realm-Rollen auflisten |

### GeoLock-Seite (`geolock.<domain>`)

Damit können die Admin-Benutzer vorübergehend zusätzliche Länder freischalten,
z. B. auf Reisen. Nötig sind der OIDC-Login eines Admin-Benutzers **und** die
`GEOLOCK_PIN`. Anders als die Admin-Oberfläche ist die Seite aus allen Ländern
erreichbar — sonst ließe sie sich aus dem Ausland nicht nutzen. Nach 3 falschen
PINs sperrt sich die Seite, bis sie in der Admin-Oberfläche entsperrt wird. Die
Zusatzländer liegen in `config/extra-countries.conf` und gelten für alle Sites mit
Ländersperre; die Änderung wird nach einem sanften Neuladen wirksam.

### Logout-Seite (`logout.<domain>`)

Löst den OIDC-Backchannel-Logout aus, löscht die Redis-Session und zeigt eine
animierte Bestätigung im Terminal-Stil, bevor sie zur Domain zurückleitet.

---

## OIDC-Provider einrichten

### Keycloak

1. **Clients** → **Create client** öffnen
2. **Client ID** auf den Wert von `OIDC_CLIENT_ID` setzen (Standard: `Proxy`)
3. **Client authentication** aktivieren (vertraulicher Client)
4. Unter **Valid redirect URIs** eintragen: `https://*.example.com/protected`
5. Das **Client secret** als `OIDC_CLIENT_SECRET` in `.env` übernehmen
6. `OIDC_PROVIDER_METADATA_URL` setzen auf:
   `https://<keycloak-host>/realms/<realm>/.well-known/openid-configuration`

Für die Keycloak-Funktionen der Admin-Oberfläche einen zweiten vertraulichen
Client mit **Service accounts roles** anlegen, ihm die unter
[Keycloak-Benutzerverwaltung](#keycloak-benutzerverwaltung) genannten
`realm-management`-Rollen geben und `KEYCLOAK_API_CLIENT_ID` /
`KEYCLOAK_API_CLIENT_SECRET` setzen.

Einen fertig vorbereiteten lokalen Test-Stack mit Realm-Import und Beispielbenutzern
gibt es unter [`examples/keycloak/`](examples/keycloak/README.md).

### Andere Provider

Jeder OIDC-konforme Provider funktioniert (Authentik, Dex, Azure AD, Google, …).
`OIDC_PROVIDER_METADATA_URL` auf den Discovery-Endpunkt des Providers setzen und
als Redirect-URI `https://*.example.com/<OIDC_REDIRECT_PATH>` eintragen.
Die Keycloak-spezifischen Admin-Funktionen stehen dann nicht zur Verfügung.

---

## Betrieb

```bash
# Starten
docker compose up -d

# Logs verfolgen
docker compose logs -f proxy

# Apache-Konfiguration testen ohne Neustart
docker compose exec proxy apache2ctl configtest

# Apache sanft neu laden (benötigt cap_add KILL, siehe Container Registry unten);
# „Anwenden“ in der Admin-Oberfläche macht dasselbe plus configtest und Keycloak-Abgleich
docker compose exec proxy apache2ctl -k graceful

# Kompletter Neustart über tini (Entrypoint läuft neu)
docker compose exec proxy kill -TERM 1

# Stoppen
docker compose down
```

---

## Container Registry

Das Image wird bei jedem Push auf `master` per GitHub Actions gebaut und in der
GitHub Container Registry veröffentlicht. (Das alte Docker-Hub-Repository wird
nicht mehr aktualisiert.)

```bash
docker pull ghcr.io/xtralarge/secure-reverse-proxy:latest
```

Um das fertige Image statt eines lokalen Builds zu nutzen, in `docker-compose.yml`
`image:` setzen:

```yaml
services:
  proxy:
    image: ghcr.io/xtralarge/secure-reverse-proxy:latest
    cap_add:
      - CHOWN
      - KILL              # graceful reload: der root-Master muss den www-data-mod_cgid-Daemon signalisieren
      - NET_BIND_SERVICE
      - SETGID
      - SETUID
```

> `CHOWN`, `SETGID` und `SETUID` sind nötig, damit Apache nach dem Binden an
> Port 80/443 von `root` zu `www-data` wechseln kann. Ohne sie startet der Proxy
> zwar, CGI-Endpunkte (z. B. `toc.<domain>/cgi/echo.pl`) schlagen aber zur Laufzeit fehl.

---

## Entwicklung / lokaler Build

```bash
docker build -t secure-reverse-proxy:local .
tests/run-tests.sh secure-reverse-proxy:local
```
