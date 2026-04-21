FROM debian:bookworm-slim

LABEL org.opencontainers.image.title="apache-oidc-proxy"
LABEL org.opencontainers.image.description="Apache reverse proxy with mod_auth_openidc, mod_macro, GeoIP and Redis session cache"
LABEL org.opencontainers.image.source="https://github.com/XtraLarge/apache-oidc-proxy"

RUN apt-get update && apt-get install -y --no-install-recommends \
    tini \
    apache2 \
    libapache2-mod-auth-openidc \
    libapache2-mod-geoip \
    geoip-database \
    libapache2-mod-evasive \
    certbot \
    gettext-base \
    ca-certificates \
    cron \
    curl \
    logrotate \
    lua5.4 \
    lua-socket \
    lua-filesystem \
    lua-posix \
    openssl \
    perl \
    rsyslog \
    && rm -rf /var/lib/apt/lists/* \
    && sed -i 's|^module(load="imklog".*|# imklog disabled — /proc/kmsg not available inside containers|' /etc/rsyslog.conf

# Enable required Apache modules
RUN a2enmod \
    macro \
    auth_openidc \
    evasive \
    geoip \
    http2 \
    lua \
    cgid \
    proxy \
    proxy_http \
    proxy_wstunnel \
    rewrite \
    ssl \
    headers \
    remoteip \
    socache_shmcb \
    substitute \
    && a2dissite 000-default default-ssl 2>/dev/null || true

# Macro definitions — static base macros (LOGGING, SSL, PROXY, etc.)
COPY conf/macro/ /etc/apache2/macro/

# Config templates — processed at container start via envsubst
COPY conf/conf-available/ /etc/apache2/conf-available/

# Example site configs with documentation
COPY conf/sites-available/ /etc/apache2/sites-available/

COPY conf/ports.conf /etc/apache2/ports.conf

RUN a2enconf server-security macro cgid-runtime evasive sites-admin acme-webroot logging

COPY conf/rsyslog/  /etc/rsyslog.d/
COPY conf/logrotate/ /etc/logrotate.d/

# TOC page (Lua), logout animation page, CGI env-dump, TableFilter JS library
COPY www/toc.lua       /var/www/html/toc.lua
COPY www/admin.lua     /var/www/html/admin.lua
COPY www/admin-kc.lua  /var/www/html/admin-kc.lua
COPY www/help/         /var/www/help/
COPY www/cgi/          /var/www/cgi/
COPY www/res/          /var/www/res/
RUN chmod +x /var/www/cgi/echo.pl

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Daily OIDC passphrase rotation + weekly ACME renewal
COPY rotate-oidc-key.sh /usr/local/bin/rotate-oidc-key.sh
RUN chmod +x /usr/local/bin/rotate-oidc-key.sh
COPY acme-init.sh /usr/local/bin/acme-init.sh
RUN chmod +x /usr/local/bin/acme-init.sh
COPY cron.d/rotate-oidc-key       /etc/cron.d/rotate-oidc-key
COPY cron.d/geoip-update          /etc/cron.d/geoip-update
COPY cron.d/acme-renew            /etc/cron.d/acme-renew
COPY cron.d/logrotate             /etc/cron.d/logrotate-apache
RUN chmod 0644 /etc/cron.d/rotate-oidc-key /etc/cron.d/geoip-update /etc/cron.d/acme-renew /etc/cron.d/logrotate-apache

# Runtime directory for generated configs; sites-admin/ for admin-managed domain configs
# acme-webroot/ serves ACME HTTP-01 challenge tokens (certbot --webroot -w /var/www/acme-webroot)
RUN mkdir -p /etc/apache2/conf-runtime /etc/apache2/sites-admin /var/www/acme-webroot

# ── Volumes ──────────────────────────────────────────────────────────────────
# ssl/              Manual TLS certificates, one subdir per domain:
#                   ssl/<domain>/{cert.pem, key.pem, fullchain.pem}
#                   Not needed when ACME_EMAIL is set (LE certs used instead).
#
# letsencrypt/      Let's Encrypt certificate store (certbot).
#                   Populated automatically when ACME_EMAIL is set.
#                   Maps to /etc/letsencrypt inside the container.
#
# sites-enabled/    Apache vhost configs using the provided macros.
#                   Mount your own — see conf/sites-available/example.conf
#
# sites-admin/      Domain configs managed via the admin web UI.
#
# AddOn/            Optional per-vhost include snippets.
#
# acme-webroot/     ACME challenge token directory — must be writable by the
#                   container.  certbot writes tokens here; Apache serves them
#                   at /.well-known/acme-challenge/ on port 80.
VOLUME ["/etc/apache2/ssl", "/etc/letsencrypt", "/etc/apache2/sites-enabled", "/etc/apache2/sites-admin", "/etc/apache2/AddOn", "/var/www/acme-webroot"]

EXPOSE 80 443

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s \
    CMD curl -fsS http://localhost/ -o /dev/null || exit 1

ENTRYPOINT ["/usr/bin/tini", "--", "/entrypoint.sh"]
CMD ["apache2ctl", "-D", "FOREGROUND"]
