# Nginx config: redirect HTTP->HTTPS and proxy HTTPS to web:8050
server {
    listen 80;
    server_name _;
    # Redirect all HTTP to HTTPS
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name _;

    ssl_certificate     /etc/nginx/certs/fullchain.pem;
    ssl_certificate_key /etc/nginx/certs/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options SAMEORIGIN;
    add_header X-Content-Type-Options nosniff;

    client_max_body_size 50M;

    location / {
        proxy_pass http://web:8050;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        # WebSocket support (if needed)
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
    }

    # static files (optional): if your app serves static files from /static,
    # you can add caching here. If not using, proxy will handle it.
    #location /static/ {
    #    proxy_pass http://web:8050/static/;
    #}
}

# map Connection header for WebSocket handling
map $http_connection $connection_upgrade {
    default upgrade;
    ''      close;
}
