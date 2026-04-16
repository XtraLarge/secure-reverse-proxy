#!/bin/bash
set -euo pipefail

COMPOSE_DIR="${1:-/data/_DockerCreate/compose}"
PROJECT_ROOT="${2:-/data/proxy}"
PROJECT_NAME="${3:-proxy}"
PROJECT_IP="${4:-10.0.0.1}"
PROJECT_SERVER_NAME="${5:-example.com}"

mkdir -p "${COMPOSE_DIR}"

cat > "${COMPOSE_DIR}/${PROJECT_NAME}.yaml" <<EOF
services:
    proxy:
        container_name: \${COMPOSE_PROJECT_NAME}
        hostname: \${NAME}
        restart: unless-stopped
        image: apache-oidc-proxy:test
        depends_on:
            redis:
                condition: service_healthy
        networks:
            VLan10:
                ipv4_address: \${IP}
            backend:
        env_file:
            - ${PROJECT_ROOT}/.env
        environment:
            - TZ=Europe/Berlin
            - APACHE_SERVER_NAME=\${APACHE_SERVER_NAME:-localhost}
        volumes:
            - /Cert:/etc/apache2/ssl:ro
            - ${PROJECT_ROOT}/sites-enabled:/etc/apache2/sites-enabled:ro
            - ${PROJECT_ROOT}/AddOn:/etc/apache2/AddOn:ro
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
            test: ["CMD-SHELL", "ps -C apache2 >/dev/null"]
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
        networks:
            - backend
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
            - ${PROJECT_ROOT}/keycloak:/opt/keycloak/data/import:ro
        networks:
            - backend

networks:
    VLan10:
        external: true
        name: VLan10
    backend:
        driver: bridge
        internal: true
EOF

cat > "${COMPOSE_DIR}/${PROJECT_NAME}.env" <<EOF
NAME=${PROJECT_NAME}
IP=${PROJECT_IP}
APACHE_SERVER_NAME=${PROJECT_SERVER_NAME}
KEYCLOAK_IMAGE=quay.io/keycloak/keycloak:26.1
KEYCLOAK_ADMIN=admin
KEYCLOAK_ADMIN_PASSWORD=admin
KEYCLOAK_HOST=keycloak.example.com
EOF

echo "Installed:"
echo "  ${COMPOSE_DIR}/${PROJECT_NAME}.yaml"
echo "  ${COMPOSE_DIR}/${PROJECT_NAME}.env"
echo ""
echo "Optional Keycloak start:"
echo "  docker compose -f ${COMPOSE_DIR}/${PROJECT_NAME}.yaml --env-file ${COMPOSE_DIR}/.env --env-file ${COMPOSE_DIR}/${PROJECT_NAME}.env -p ${PROJECT_NAME} --profile keycloak up -d"
