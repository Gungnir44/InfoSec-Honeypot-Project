#!/bin/bash

# Let's Encrypt SSL Setup Script
# This script installs Certbot and obtains SSL certificates for your honeypot dashboard
# Run as root or with sudo

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}================================================${NC}"
echo -e "${CYAN}   Let's Encrypt SSL Setup for Honeypot Dashboard${NC}"
echo -e "${CYAN}================================================${NC}"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run as root or with sudo${NC}"
    exit 1
fi

# Get domain name
read -p "Enter your domain name (e.g., honeypot.example.com): " DOMAIN
if [ -z "$DOMAIN" ]; then
    echo -e "${RED}Domain name is required${NC}"
    exit 1
fi

# Get email for Let's Encrypt notifications
read -p "Enter your email for Let's Encrypt notifications: " EMAIL
if [ -z "$EMAIL" ]; then
    echo -e "${RED}Email is required for Let's Encrypt${NC}"
    exit 1
fi

echo ""
echo -e "${YELLOW}Configuration:${NC}"
echo "  Domain: $DOMAIN"
echo "  Email: $EMAIL"
echo ""
read -p "Is this correct? (y/n): " CONFIRM
if [ "$CONFIRM" != "y" ] && [ "$CONFIRM" != "Y" ]; then
    echo "Cancelled."
    exit 0
fi

echo ""
echo -e "${GREEN}[1/6] Installing Certbot...${NC}"

# Detect OS and install Certbot
if [ -f /etc/debian_version ]; then
    # Debian/Ubuntu
    apt update
    apt install -y certbot python3-certbot-nginx
elif [ -f /etc/redhat-release ]; then
    # RHEL/CentOS/Fedora
    dnf install -y certbot python3-certbot-nginx
else
    echo -e "${RED}Unsupported OS. Please install Certbot manually.${NC}"
    exit 1
fi

echo -e "${GREEN}[2/6] Creating webroot directory...${NC}"
mkdir -p /var/www/certbot
chown -R www-data:www-data /var/www/certbot 2>/dev/null || chown -R nginx:nginx /var/www/certbot

echo -e "${GREEN}[3/6] Setting up initial Nginx configuration...${NC}"

# Backup existing config if present
if [ -f /etc/nginx/sites-enabled/honeypot ]; then
    cp /etc/nginx/sites-enabled/honeypot /etc/nginx/sites-enabled/honeypot.backup
fi

# Copy HTTP config for initial certificate request
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$SCRIPT_DIR/nginx/honeypot-http.conf" ]; then
    cp "$SCRIPT_DIR/nginx/honeypot-http.conf" /etc/nginx/sites-available/honeypot
else
    # Create inline if file not found
    cat > /etc/nginx/sites-available/honeypot << 'NGINX_HTTP'
upstream honeypot_backend {
    server 127.0.0.1:5000;
    keepalive 32;
}

server {
    listen 80;
    listen [::]:80;
    server_name _;

    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }

    location / {
        proxy_pass http://honeypot_backend;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
NGINX_HTTP
fi

# Update server_name in config
sed -i "s/server_name _;/server_name $DOMAIN;/" /etc/nginx/sites-available/honeypot

# Enable site
ln -sf /etc/nginx/sites-available/honeypot /etc/nginx/sites-enabled/

# Remove default site if exists
rm -f /etc/nginx/sites-enabled/default

# Test and reload Nginx
nginx -t
systemctl reload nginx

echo -e "${GREEN}[4/6] Obtaining SSL certificate from Let's Encrypt...${NC}"
echo ""

# Request certificate
certbot certonly \
    --webroot \
    --webroot-path=/var/www/certbot \
    --email "$EMAIL" \
    --agree-tos \
    --no-eff-email \
    --domain "$DOMAIN" \
    --non-interactive

# Check if certificate was obtained
if [ ! -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ]; then
    echo -e "${RED}Failed to obtain SSL certificate${NC}"
    exit 1
fi

echo -e "${GREEN}[5/6] Configuring HTTPS in Nginx...${NC}"

# Copy HTTPS config
if [ -f "$SCRIPT_DIR/nginx/honeypot-https.conf" ]; then
    cp "$SCRIPT_DIR/nginx/honeypot-https.conf" /etc/nginx/sites-available/honeypot
else
    # Create inline if file not found
    cat > /etc/nginx/sites-available/honeypot << 'NGINX_HTTPS'
upstream honeypot_backend {
    server 127.0.0.1:5000;
    keepalive 32;
}

server {
    listen 80;
    listen [::]:80;
    server_name YOUR_DOMAIN;

    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }

    location / {
        return 301 https://$host$request_uri;
    }
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name YOUR_DOMAIN;

    ssl_certificate /etc/letsencrypt/live/YOUR_DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/YOUR_DOMAIN/privkey.pem;
    ssl_trusted_certificate /etc/letsencrypt/live/YOUR_DOMAIN/chain.pem;

    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:50m;
    ssl_session_tickets off;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;

    ssl_stapling on;
    ssl_stapling_verify on;
    resolver 8.8.8.8 8.8.4.4 valid=300s;
    resolver_timeout 5s;

    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;

    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types text/plain text/css text/xml application/json application/javascript application/xml+rss application/atom+xml image/svg+xml;

    location / {
        proxy_pass http://honeypot_backend;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Connection "";
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }

    location /api/ {
        proxy_pass http://honeypot_backend;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_connect_timeout 120s;
        proxy_send_timeout 120s;
        proxy_read_timeout 120s;
    }

    location /api/honeypots/ {
        proxy_pass http://honeypot_backend;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        client_max_body_size 10M;
    }

    location /static/ {
        alias /home/honeypot/honeypot-project/dashboard/static/;
        expires 30d;
        add_header Cache-Control "public, immutable";
    }

    location ~ /\. {
        deny all;
    }

    access_log /var/log/nginx/honeypot_access.log;
    error_log /var/log/nginx/honeypot_error.log;
}
NGINX_HTTPS
fi

# Replace domain placeholder with actual domain
sed -i "s/YOUR_DOMAIN/$DOMAIN/g" /etc/nginx/sites-available/honeypot

# Test and reload Nginx
nginx -t
systemctl reload nginx

echo -e "${GREEN}[6/6] Setting up automatic certificate renewal...${NC}"

# Create renewal hook to reload Nginx
mkdir -p /etc/letsencrypt/renewal-hooks/deploy
cat > /etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh << 'EOF'
#!/bin/bash
systemctl reload nginx
EOF
chmod +x /etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh

# Set up systemd timer for auto-renewal (if not already set up by certbot)
if ! systemctl is-enabled certbot.timer &>/dev/null; then
    systemctl enable certbot.timer
    systemctl start certbot.timer
fi

# Test renewal
echo ""
echo -e "${YELLOW}Testing certificate renewal (dry run)...${NC}"
certbot renew --dry-run

echo ""
echo -e "${CYAN}================================================${NC}"
echo -e "${GREEN}   SSL Setup Complete!${NC}"
echo -e "${CYAN}================================================${NC}"
echo ""
echo -e "${GREEN}Your honeypot dashboard is now secured with HTTPS!${NC}"
echo ""
echo -e "${YELLOW}Details:${NC}"
echo "  URL: https://$DOMAIN"
echo "  Certificate: /etc/letsencrypt/live/$DOMAIN/"
echo "  Expires: $(openssl x509 -enddate -noout -in /etc/letsencrypt/live/$DOMAIN/fullchain.pem | cut -d= -f2)"
echo ""
echo -e "${YELLOW}Auto-Renewal:${NC}"
echo "  Certbot timer is enabled for automatic renewal"
echo "  Certificates will renew automatically before expiration"
echo ""
echo -e "${YELLOW}To manually renew:${NC}"
echo "  sudo certbot renew"
echo ""
echo -e "${YELLOW}To check certificate status:${NC}"
echo "  sudo certbot certificates"
echo ""
echo -e "${CYAN}Security Features Enabled:${NC}"
echo "  - TLS 1.2 and TLS 1.3 only"
echo "  - Modern cipher suites"
echo "  - HSTS (HTTP Strict Transport Security)"
echo "  - OCSP Stapling"
echo "  - Security headers (X-Frame-Options, X-Content-Type-Options, etc.)"
echo ""
