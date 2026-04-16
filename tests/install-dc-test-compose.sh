#!/bin/bash
set -euo pipefail

COMPOSE_DIR="${1:-/data/_DockerCreate/compose}"
ASSET_ROOT="${2:-/data/oidcproxy-test}"
PROJECT_NAME="${3:-oidcproxy}"

mkdir -p "${COMPOSE_DIR}"

cat > "${COMPOSE_DIR}/${PROJECT_NAME}.yaml" <<EOF
services:
    proxy:
        container_name: \${COMPOSE_PROJECT_NAME}-\${NAME}
        hostname: \${NAME}
        restart: unless-stopped
        image: apache-oidc-proxy:test
        depends_on:
            redis:
                condition: service_healthy
        ports:
            - \${PROXY_HTTP_PORT:-18080}:80
            - \${PROXY_HTTPS_PORT:-18443}:443
        env_file:
            - ${ASSET_ROOT}/.env
        environment:
            - TZ=Europe/Berlin
            - APACHE_SERVER_NAME=\${APACHE_SERVER_NAME:-localhost}
        volumes:
            - ${ASSET_ROOT}/ssl:/etc/apache2/ssl:ro
            - ${ASSET_ROOT}/sites-enabled:/etc/apache2/sites-enabled:ro
            - ${ASSET_ROOT}/AddOn:/etc/apache2/AddOn:ro
        security_opt:
            - no-new-privileges:true
        cap_drop:
            - ALL
        cap_add:
            - CHOWN
            - NET_BIND_SERVICE
            - SETGID
            - SETUID
        healthcheck:
            test: ["CMD-SHELL", "test -f /var/run/apache2/apache2.pid && kill -0 \$\$(cat /var/run/apache2/apache2.pid) 2>/dev/null"]
            interval: 30s
            timeout: 5s
            retries: 3
            start_period: 15s

    redis:
        container_name: \${COMPOSE_PROJECT_NAME}-redis
        hostname: redis
        restart: unless-stopped
        image: redis:7-alpine
        environment:
            - TZ=Europe/Berlin
            - REDIS_PASSWORD=\${REDIS_PASSWORD:-}
        command: >
            sh -c "exec redis-server --save '' --appendonly no
            --maxmemory 128mb --maxmemory-policy allkeys-lru
            \$\${REDIS_PASSWORD:+--requirepass \$\$REDIS_PASSWORD}"
        healthcheck:
            test: ["CMD-SHELL", "redis-cli \$\${REDIS_PASSWORD:+-a \$\$REDIS_PASSWORD} ping"]
            interval: 10s
            timeout: 3s
            retries: 5

    keycloak:
        container_name: \${COMPOSE_PROJECT_NAME}-keycloak
        hostname: keycloak
        restart: unless-stopped
        profiles:
            - keycloak
        image: \${KEYCLOAK_IMAGE:-quay.io/keycloak/keycloak:26.1}
        command:
            - start-dev
            - --import-realm
            - --hostname=https://\${KEYCLOAK_HOST:-keycloak.example.com}
            - --proxy-headers=xforwarded
        environment:
            - TZ=Europe/Berlin
            - KEYCLOAK_ADMIN=\${KEYCLOAK_ADMIN:-admin}
            - KEYCLOAK_ADMIN_PASSWORD=\${KEYCLOAK_ADMIN_PASSWORD:-admin}
        volumes:
            - ${ASSET_ROOT}/keycloak:/opt/keycloak/data/import:ro
EOF

cat > "${COMPOSE_DIR}/${PROJECT_NAME}.env" <<EOF
NAME=proxy
PROXY_HTTP_PORT=18080
PROXY_HTTPS_PORT=18443
APACHE_SERVER_NAME=localhost
KEYCLOAK_IMAGE=quay.io/keycloak/keycloak:26.1
KEYCLOAK_ADMIN=admin
KEYCLOAK_ADMIN_PASSWORD=admin
KEYCLOAK_HOST=keycloak.example.com
EOF

echo "Installed:"
echo "  ${COMPOSE_DIR}/${PROJECT_NAME}.yaml"
echo "  ${COMPOSE_DIR}/${PROJECT_NAME}.env"
