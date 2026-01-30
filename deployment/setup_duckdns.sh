#!/bin/bash

# DuckDNS + Let's Encrypt Setup Script
# 100% FREE permanent HTTPS for your honeypot dashboard
# Run as root or with sudo

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${CYAN}================================================${NC}"
echo -e "${CYAN}   DuckDNS + Let's Encrypt Setup (100% FREE)${NC}"
echo -e "${CYAN}================================================${NC}"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run as root or with sudo${NC}"
    exit 1
fi

# Step 1: Get DuckDNS info
echo -e "${BOLD}STEP 1: DuckDNS Setup${NC}"
echo -e "${YELLOW}----------------------------------------${NC}"
echo ""
echo -e "First, you need a DuckDNS account and subdomain."
echo ""
echo -e "${CYAN}If you haven't already:${NC}"
echo "  1. Go to ${BOLD}https://www.duckdns.org${NC}"
echo "  2. Sign in with Google, GitHub, Twitter, or Reddit"
echo "  3. Create a subdomain (e.g., 'myhoneypot')"
echo "  4. Copy your token from the DuckDNS page"
echo ""
read -p "Press Enter when you have your DuckDNS subdomain and token..."
echo ""

# Get subdomain
read -p "Enter your DuckDNS subdomain (without .duckdns.org): " SUBDOMAIN
if [ -z "$SUBDOMAIN" ]; then
    echo -e "${RED}Subdomain is required${NC}"
    exit 1
fi
DOMAIN="${SUBDOMAIN}.duckdns.org"

# Get token
read -p "Enter your DuckDNS token: " TOKEN
if [ -z "$TOKEN" ]; then
    echo -e "${RED}Token is required${NC}"
    exit 1
fi

# Get email for Let's Encrypt
read -p "Enter your email (for Let's Encrypt notifications): " EMAIL
if [ -z "$EMAIL" ]; then
    echo -e "${RED}Email is required${NC}"
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
echo -e "${BOLD}STEP 2: Updating DuckDNS IP${NC}"
echo -e "${YELLOW}----------------------------------------${NC}"

# Get server's public IP
PUBLIC_IP=$(curl -s https://api.ipify.org || curl -s https://ifconfig.me || curl -s https://icanhazip.com)
echo "Your server's public IP: $PUBLIC_IP"

# Update DuckDNS
echo "Updating DuckDNS..."
RESPONSE=$(curl -s "https://www.duckdns.org/update?domains=${SUBDOMAIN}&token=${TOKEN}&ip=${PUBLIC_IP}")

if [ "$RESPONSE" = "OK" ]; then
    echo -e "${GREEN}DuckDNS updated successfully!${NC}"
else
    echo -e "${RED}Failed to update DuckDNS. Response: $RESPONSE${NC}"
    echo "Please check your subdomain and token."
    exit 1
fi

# Set up DuckDNS cron job to keep IP updated
echo ""
echo -e "${BOLD}STEP 3: Setting up automatic IP updates${NC}"
echo -e "${YELLOW}----------------------------------------${NC}"

mkdir -p /opt/duckdns
cat > /opt/duckdns/duck.sh << EOF
#!/bin/bash
echo url="https://www.duckdns.org/update?domains=${SUBDOMAIN}&token=${TOKEN}&ip=" | curl -k -o /opt/duckdns/duck.log -K -
EOF
chmod 700 /opt/duckdns/duck.sh

# Add cron job (every 5 minutes)
(crontab -l 2>/dev/null | grep -v "duckdns"; echo "*/5 * * * * /opt/duckdns/duck.sh >/dev/null 2>&1") | crontab -
echo -e "${GREEN}Cron job added - IP will update every 5 minutes${NC}"

echo ""
echo -e "${BOLD}STEP 4: Installing Certbot${NC}"
echo -e "${YELLOW}----------------------------------------${NC}"

apt update
apt install -y certbot python3-certbot-nginx nginx

echo -e "${GREEN}Certbot installed${NC}"

echo ""
echo -e "${BOLD}STEP 5: Configuring Nginx${NC}"
echo -e "${YELLOW}----------------------------------------${NC}"

# Create initial HTTP config for certificate request
cat > /etc/nginx/sites-available/honeypot << EOF
upstream honeypot_backend {
    server 127.0.0.1:5000;
    keepalive 32;
}

server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN};

    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }

    location / {
        proxy_pass http://honeypot_backend;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF

# Enable site
ln -sf /etc/nginx/sites-available/honeypot /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

# Create certbot webroot
mkdir -p /var/www/certbot

# Test and reload nginx
nginx -t
systemctl reload nginx

echo -e "${GREEN}Nginx configured${NC}"

echo ""
echo -e "${BOLD}STEP 6: Obtaining SSL Certificate${NC}"
echo -e "${YELLOW}----------------------------------------${NC}"

# Wait a moment for DNS propagation
echo "Waiting 10 seconds for DNS propagation..."
sleep 10

# Get certificate
certbot certonly \
    --webroot \
    --webroot-path=/var/www/certbot \
    --email "$EMAIL" \
    --agree-tos \
    --no-eff-email \
    --domain "$DOMAIN" \
    --non-interactive

# Check if certificate was obtained
if [ ! -f "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" ]; then
    echo -e "${RED}Failed to obtain SSL certificate${NC}"
    echo "This might be because:"
    echo "  - DNS hasn't propagated yet (wait a few minutes and try again)"
    echo "  - Port 80 is not open in your firewall"
    echo ""
    echo "To retry manually:"
    echo "  sudo certbot --nginx -d ${DOMAIN}"
    exit 1
fi

echo -e "${GREEN}SSL certificate obtained!${NC}"

echo ""
echo -e "${BOLD}STEP 7: Configuring HTTPS${NC}"
echo -e "${YELLOW}----------------------------------------${NC}"

# Create full HTTPS config
cat > /etc/nginx/sites-available/honeypot << EOF
upstream honeypot_backend {
    server 127.0.0.1:5000;
    keepalive 32;
}

# Redirect HTTP to HTTPS
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN};

    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }

    location / {
        return 301 https://\$host\$request_uri;
    }
}

# HTTPS Server
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name ${DOMAIN};

    # SSL Certificate
    ssl_certificate /etc/letsencrypt/live/${DOMAIN}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${DOMAIN}/privkey.pem;

    # Modern SSL Configuration
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:50m;
    ssl_session_tickets off;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;

    # OCSP Stapling
    ssl_stapling on;
    ssl_stapling_verify on;
    resolver 8.8.8.8 8.8.4.4 valid=300s;

    # Security Headers
    add_header Strict-Transport-Security "max-age=63072000" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;

    # Gzip
    gzip on;
    gzip_vary on;
    gzip_types text/plain text/css application/json application/javascript;

    # Main application
    location / {
        proxy_pass http://honeypot_backend;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
    }

    # API endpoints
    location /api/ {
        proxy_pass http://honeypot_backend;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_connect_timeout 120s;
        proxy_send_timeout 120s;
        proxy_read_timeout 120s;
    }

    # Static files
    location /static/ {
        alias /home/honeypot/honeypot-project/dashboard/static/;
        expires 30d;
        add_header Cache-Control "public, immutable";
    }

    # Deny sensitive files
    location ~ /\. {
        deny all;
    }

    # Logging
    access_log /var/log/nginx/honeypot_access.log;
    error_log /var/log/nginx/honeypot_error.log;
}
EOF

# Test and reload nginx
nginx -t
systemctl reload nginx

echo -e "${GREEN}HTTPS configured${NC}"

echo ""
echo -e "${BOLD}STEP 8: Setting up auto-renewal${NC}"
echo -e "${YELLOW}----------------------------------------${NC}"

# Enable certbot timer
systemctl enable certbot.timer
systemctl start certbot.timer

# Test renewal
echo "Testing certificate renewal..."
certbot renew --dry-run

echo ""
echo -e "${CYAN}================================================${NC}"
echo -e "${GREEN}${BOLD}   Setup Complete!${NC}"
echo -e "${CYAN}================================================${NC}"
echo ""
echo -e "${GREEN}Your honeypot dashboard is now available at:${NC}"
echo ""
echo -e "   ${BOLD}${CYAN}https://${DOMAIN}${NC}"
echo ""
echo -e "${CYAN}================================================${NC}"
echo ""
echo -e "${YELLOW}What you got (100% FREE):${NC}"
echo "  [x] Permanent subdomain: ${DOMAIN}"
echo "  [x] Valid SSL certificate from Let's Encrypt"
echo "  [x] Auto-renewal (certificates renew automatically)"
echo "  [x] Auto IP update (if your IP changes)"
echo "  [x] Modern TLS 1.2/1.3 security"
echo "  [x] Security headers (HSTS, etc.)"
echo ""
echo -e "${YELLOW}Useful commands:${NC}"
echo "  Check Nginx:      sudo systemctl status nginx"
echo "  Check cert:       sudo certbot certificates"
echo "  View logs:        sudo tail -f /var/log/nginx/honeypot_access.log"
echo "  Renew cert:       sudo certbot renew"
echo ""
echo -e "${YELLOW}Certificate expires:${NC}"
openssl x509 -enddate -noout -in /etc/letsencrypt/live/${DOMAIN}/fullchain.pem | cut -d= -f2
echo "(Will auto-renew before expiration)"
echo ""
