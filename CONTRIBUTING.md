# Contributing

## Öffentliches Repository — keine internen Netz-Werte

Dies ist ein **öffentliches** Repository. Interne Netz- und Hostnamen gehören
nicht hierher. Verboten sind insbesondere:

- interne IP-Bereiche `10.10.x.x` <!-- naming-guard:allow -->
- interne Hostnamen / lokale Domains `*.fritz.box` <!-- naming-guard:allow -->
- die interne Organisations-Domain `derwerres.de` <!-- naming-guard:allow -->

Verwende stattdessen Platzhalter (`example.net`, `<host>`).

### Erzwungen durch `naming-guard`

- **CI-Gate (maßgeblich):** `.github/workflows/naming-guard.yml` führt bei jedem
  Push/PR `scripts/naming-guard.sh` aus — bei Treffer wird der Check **rot**.
- **Pre-Commit-Hook (Zusatz, empfohlen):** lokal vor dem Push abfangen:
  ```sh
  pip install pre-commit && pre-commit install
  ```
  (Konfiguration: `.pre-commit-config.yaml`.)

### Bewusste Ausnahme

Falls ein Treffer beabsichtigt und unkritisch ist:
- Zeilen-Marker `naming-guard:allow` am Zeilenende (z.B. als HTML-Kommentar in Markdown), **oder**
- eine erweiterte Regex in `.naming-guard-allow`.

(Die Beispiele oben nutzen genau diesen Marker.)
