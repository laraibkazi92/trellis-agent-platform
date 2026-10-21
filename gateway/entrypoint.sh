#!/bin/sh
# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

set -e

SSL_ENABLED=${SSL_ENABLED:-False}
SSL_DNS_NAME=${SSL_DNS_NAME:-_}

# Edge-tunnel ingress limits. Connection-level flood protection for /edge happens
# here; per-site call rate limiting is the relay's job (it knows which site a call
# belongs to, nginx only sees an IP).
EDGE_RATE_RPS=${EDGE_RATE_LIMIT_RPS:-30}
EDGE_RATE_BURST=${EDGE_RATE_LIMIT_BURST:-20}
# These land verbatim in nginx config: a typo would fail nginx -t and take the whole
# ingress (dashboard and API too) down, so validate and fall back instead.
# 0 is rejected by nginx ("invalid rate"), so it cannot mean "disabled" here.
case "$EDGE_RATE_RPS" in
    ''|0|*[!0-9]*) echo "WARNING: invalid EDGE_RATE_LIMIT_RPS='$EDGE_RATE_RPS'; using 30."; EDGE_RATE_RPS=30 ;;
esac
case "$EDGE_RATE_BURST" in
    ''|0|*[!0-9]*) echo "WARNING: invalid EDGE_RATE_LIMIT_BURST='$EDGE_RATE_BURST'; using 20."; EDGE_RATE_BURST=20 ;;
esac

# Optional mutual TLS for edge nodes. EDGE_MTLS_CA points at a PEM CA bundle; when
# it is present the server *requests* a client certificate (optional, so browsers
# and API clients are unaffected) and the /edge location refuses any request whose
# certificate did not verify.
EDGE_MTLS_SERVER=""
EDGE_MTLS_LOCATION=""
EDGE_MTLS_REQUESTED=""
if [ -n "$EDGE_MTLS_CA" ]; then
    EDGE_MTLS_REQUESTED="yes"
    if [ "$SSL_ENABLED" != "True" ] && [ "$SSL_ENABLED" != "true" ]; then
        # The location check reads $ssl_client_verify, which is empty on a plain
        # HTTP listener: rendering it there would 403 every edge silently.
        echo "ERROR: EDGE_MTLS_CA is set but SSL_ENABLED is not true. Client"
        echo "       certificates require TLS; refusing to render a config that"
        echo "       would reject every edge tunnel. Enable SSL or unset EDGE_MTLS_CA."
        exit 1
    fi
    if [ -f "$EDGE_MTLS_CA" ]; then
        EDGE_MTLS_SERVER="
    ssl_client_certificate $EDGE_MTLS_CA;
    ssl_verify_client optional;"
        EDGE_MTLS_LOCATION='
        if ($ssl_client_verify != SUCCESS) {
            return 403;
        }'
    else
        echo "ERROR: EDGE_MTLS_CA=$EDGE_MTLS_CA does not exist inside the container."
        echo "       Mount the CA bundle (see the SSL volume in docker-compose.yml)."
        exit 1
    fi
fi

# Base routing locations with DNS resolution and large payload support
ROUTES="
    client_max_body_size 100M;
    resolver 127.0.0.11 valid=30s;

    location / {
        set \$upstream_ui http://ui:8080;
        proxy_pass \$upstream_ui;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \$connection_upgrade;
    }

    location /v1 {
        set \$upstream_host http://host:8000;
        proxy_pass \$upstream_host;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        
        # SSE & Streaming optimizations for OpenAI API compatibility
        proxy_cache off;
        proxy_buffering off;
        proxy_set_header X-Accel-Buffering no;
        chunked_transfer_encoding off;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }

    location /webhooks {
        set \$upstream_host http://host:8000;
        proxy_pass \$upstream_host;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    location ~ ^/mcp(/|$) {
        set \$upstream_gateway http://gateway:8002;
        proxy_pass \$upstream_gateway;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \$connection_upgrade;
        proxy_set_header Host \$host;
        
        # SSE & Long-lived connection optimizations
        proxy_cache off;
        proxy_buffering off;
        proxy_set_header X-Accel-Buffering no;
        chunked_transfer_encoding off;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }

    # Edge nodes (trellis-proxy): the only internet-facing endpoint for them. It
    # carries WebSocket tunnel traffic only -- the edge dials out here, and the relay
    # behind it is never published directly.
    location /edge {
        set \$upstream_edge_relay http://edge-relay:8100;
        proxy_pass \$upstream_edge_relay;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \$connection_upgrade;
        proxy_set_header Host \$host;
        # The relay caps a frame at 10 MB; 12m leaves headroom without inheriting the
        # 100M global used by the UI/API routes.
        client_max_body_size 12m;

        # Connection-level flood protection; the relay enforces per-site call rates.
        limit_req zone=edge_tunnel burst=$EDGE_RATE_BURST nodelay;
$EDGE_MTLS_LOCATION

        # WebSocket tunnel: never buffer, never time out mid-session
        proxy_cache off;
        proxy_buffering off;
        proxy_set_header X-Accel-Buffering no;
        chunked_transfer_encoding off;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }
"

# Check SSL if enabled
if [ "$SSL_ENABLED" = "True" ] || [ "$SSL_ENABLED" = "true" ]; then
    if [ -f "/etc/nginx/ssl/cert.pem" ] && [ -f "/etc/nginx/ssl/key.pem" ]; then
        echo "SSL is enabled and certificates found. Configuring HTTPS."
        cat <<EOF > /etc/nginx/conf.d/default.conf
map \$http_upgrade \$connection_upgrade {
    default upgrade;
    ''      close;
}

limit_req_zone \$binary_remote_addr zone=edge_tunnel:10m rate=${EDGE_RATE_RPS}r/s;

server {
    listen 80;
    server_name $SSL_DNS_NAME;
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl;
    server_name $SSL_DNS_NAME;

    ssl_certificate /etc/nginx/ssl/cert.pem;
    ssl_certificate_key /etc/nginx/ssl/key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;$EDGE_MTLS_SERVER

    include /etc/nginx/mime.types;

$ROUTES
}
EOF
    else
        echo "WARNING: SSL_ENABLED is true but certificates are missing or unreadable in /etc/nginx/ssl/. Falling back to HTTP."
        SSL_ENABLED="False"
    fi
fi

if [ -n "$EDGE_MTLS_REQUESTED" ] && [ "$SSL_ENABLED" != "True" ] && [ "$SSL_ENABLED" != "true" ]; then
    echo "ERROR: edge mTLS was requested but TLS is unavailable (missing certificates)."
    echo "       Refusing to start without the control the operator asked for."
    exit 1
fi

if [ "$SSL_ENABLED" != "True" ] && [ "$SSL_ENABLED" != "true" ]; then
    echo "Configuring HTTP only."
    cat <<EOF > /etc/nginx/conf.d/default.conf
map \$http_upgrade \$connection_upgrade {
    default upgrade;
    ''      close;
}

limit_req_zone \$binary_remote_addr zone=edge_tunnel:10m rate=${EDGE_RATE_RPS}r/s;

server {
    listen 80;
    server_name $SSL_DNS_NAME;

    include /etc/nginx/mime.types;

$ROUTES
}
EOF
fi

echo "Starting Nginx..."
exec nginx -g 'daemon off;'
