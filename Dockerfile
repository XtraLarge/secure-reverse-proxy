FROM debian:bookworm-slim

LABEL org.opencontainers.image.title="apache-oidc-proxy"
LABEL org.opencontainers.image.description="Apache reverse proxy with mod_auth_openidc, mod_macro, GeoIP and Redis session cache"
LABEL org.opencontainers.image.source="https://github.com/XtraLarge/apache-oidc-proxy"

RUN apt-get update && apt-get install -y --no-install-recommends \
    apache2 \
    libapache2-mod-auth-openidc \
    libapache2-mod-geoip \
    geoip-database \
    gettext-base \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Enable required Apache modules
RUN a2enmod \
    macro \
    auth_openidc \
    geoip \
    proxy \
    proxy_http \
    proxy_wstunnel \
    rewrite \
    ssl \
    headers \
    remoteip \
    socache_shmcb \
    && a2dissite 000-default default-ssl 2>/dev/null || true

# Macro definitions — static base macros (LOGGING, SSL, PROXY, etc.)
COPY conf/macro/ /etc/apache2/macro/

# Config templates — processed at container start via envsubst
COPY conf/conf-available/ /etc/apache2/conf-available/

# Example site configs with documentation
COPY conf/sites-available/ /etc/apache2/sites-available/

COPY conf/ports.conf /etc/apache2/ports.conf

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

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
    CMD apache2ctl status 2>/dev/null | grep -q "Server uptime" || exit 1

ENTRYPOINT ["/entrypoint.sh"]
CMD ["apache2ctl", "-D", "FOREGROUND"]
