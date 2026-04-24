#!/bin/sh
set -e

SSL_ENABLED=${SSL_ENABLED:-False}
SSL_DNS_NAME=${SSL_DNS_NAME:-_}

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

    location /mcp {
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
    ssl_ciphers HIGH:!aNULL:!MD5;

    include /etc/nginx/mime.types;

$ROUTES
}
EOF
    else
        echo "WARNING: SSL_ENABLED is true but certificates are missing or unreadable in /etc/nginx/ssl/. Falling back to HTTP."
        SSL_ENABLED="False"
    fi
fi

if [ "$SSL_ENABLED" != "True" ] && [ "$SSL_ENABLED" != "true" ]; then
    echo "Configuring HTTP only."
    cat <<EOF > /etc/nginx/conf.d/default.conf
map \$http_upgrade \$connection_upgrade {
    default upgrade;
    ''      close;
}

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
