FROM debian:bookworm-slim

LABEL org.opencontainers.image.title="apache-oidc-proxy"
LABEL org.opencontainers.image.description="Apache reverse proxy with mod_auth_openidc, mod_macro, GeoIP and Redis session cache"
LABEL org.opencontainers.image.source="https://github.com/XtraLarge/apache-oidc-proxy"

RUN apt-get update && apt-get install -y --no-install-recommends \
    apache2 \
    libapache2-mod-auth-openidc \
    libapache2-mod-geoip \
    geoip-database \
    libapache2-mod-evasive \
    gettext-base \
    ca-certificates \
    cron \
    curl \
    geoipupdate \
    lua5.4 \
    lua-socket \
    openssl \
    perl \
    && rm -rf /var/lib/apt/lists/*

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

RUN a2enconf server-security macro cgid-runtime evasive

# TOC page (Lua), logout animation page, CGI env-dump, TableFilter JS library
COPY www/toc.lua       /var/www/html/toc.lua
COPY www/help/         /var/www/help/
COPY www/cgi/          /var/www/cgi/
COPY www/res/          /var/www/res/
RUN chmod +x /var/www/cgi/echo.pl

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Daily OIDC passphrase rotation
COPY rotate-oidc-key.sh /usr/local/bin/rotate-oidc-key.sh
RUN chmod +x /usr/local/bin/rotate-oidc-key.sh
COPY cron.d/rotate-oidc-key /etc/cron.d/rotate-oidc-key
COPY cron.d/geoip-update    /etc/cron.d/geoip-update
RUN chmod 0644 /etc/cron.d/rotate-oidc-key /etc/cron.d/geoip-update

# Placeholder GeoIP.conf so geoipupdate does not complain about missing file.
# Overwritten at startup if GEOIP_ACCOUNT_ID / GEOIP_LICENSE_KEY are set.
RUN printf 'AccountID 0\nLicenseKey 000000000000\nEditionIDs GeoLite2-Country\nDatabaseDirectory /usr/share/GeoIP\n' \
    > /etc/GeoIP.conf

# Runtime directory for generated configs (internal networks include, etc.)
RUN mkdir -p /etc/apache2/conf-runtime

# ── Volumes ──────────────────────────────────────────────────────────────────
# ssl/          TLS certificates, one subdir per domain:
#               ssl/<domain>/{cert.pem, key.pem, fullchain.pem}
#
# sites-enabled/ Apache vhost configs using the provided macros.
#               Mount your own — see conf/sites-available/example.conf
#
# AddOn/        Optional per-vhost include snippets referenced via
#               IncludeOptional /etc/apache2/AddOn/<domain>/<site>.pre*
VOLUME ["/etc/apache2/ssl", "/etc/apache2/sites-enabled", "/etc/apache2/AddOn"]

EXPOSE 80 443

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s \
    CMD curl -fsS http://localhost/ -o /dev/null || exit 1

ENTRYPOINT ["/entrypoint.sh"]
CMD ["apache2ctl", "-D", "FOREGROUND"]
