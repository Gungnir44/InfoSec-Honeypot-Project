#!/bin/bash

# SSL Certificate Status Check Script
# Run this to check your SSL certificate status and configuration

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}================================================${NC}"
echo -e "${CYAN}   SSL Certificate Status Check${NC}"
echo -e "${CYAN}================================================${NC}"
echo ""

# Check if certbot is installed
if ! command -v certbot &> /dev/null; then
    echo -e "${RED}Certbot is not installed${NC}"
    exit 1
fi

# List all certificates
echo -e "${GREEN}[1] Certificate Status:${NC}"
echo "----------------------------------------"
certbot certificates
echo ""

# Check renewal timer
echo -e "${GREEN}[2] Auto-Renewal Status:${NC}"
echo "----------------------------------------"
if systemctl is-enabled certbot.timer &>/dev/null; then
    echo -e "Certbot timer: ${GREEN}Enabled${NC}"
    echo ""
    echo "Timer details:"
    systemctl status certbot.timer --no-pager | head -10
else
    echo -e "Certbot timer: ${RED}Disabled${NC}"
    echo "Run: sudo systemctl enable certbot.timer && sudo systemctl start certbot.timer"
fi
echo ""

# Check Nginx status
echo -e "${GREEN}[3] Nginx Status:${NC}"
echo "----------------------------------------"
if systemctl is-active nginx &>/dev/null; then
    echo -e "Nginx: ${GREEN}Running${NC}"
else
    echo -e "Nginx: ${RED}Not Running${NC}"
fi
echo ""

# Test Nginx configuration
echo -e "${GREEN}[4] Nginx Configuration Test:${NC}"
echo "----------------------------------------"
nginx -t 2>&1
echo ""

# Check SSL configuration with openssl (if domain is available)
if [ -n "$1" ]; then
    DOMAIN=$1
    echo -e "${GREEN}[5] SSL Test for $DOMAIN:${NC}"
    echo "----------------------------------------"

    # Test connection
    echo "Testing SSL connection..."
    echo | openssl s_client -connect "$DOMAIN:443" -servername "$DOMAIN" 2>/dev/null | openssl x509 -noout -dates -subject -issuer 2>/dev/null

    echo ""
    echo "Certificate chain:"
    echo | openssl s_client -connect "$DOMAIN:443" -servername "$DOMAIN" 2>/dev/null | grep -E "^(Certificate chain| [0-9]+ s:)"

    echo ""
    echo "TLS Version and Cipher:"
    echo | openssl s_client -connect "$DOMAIN:443" -servername "$DOMAIN" 2>/dev/null | grep -E "(Protocol|Cipher)"
else
    echo -e "${YELLOW}[5] To test SSL for a specific domain:${NC}"
    echo "    $0 yourdomain.com"
fi

echo ""
echo -e "${CYAN}================================================${NC}"
echo -e "${GREEN}   Check Complete${NC}"
echo -e "${CYAN}================================================${NC}"
echo ""
echo -e "${YELLOW}Useful Commands:${NC}"
echo "  Renew certificates:     sudo certbot renew"
echo "  Dry run renewal:        sudo certbot renew --dry-run"
echo "  Force renewal:          sudo certbot renew --force-renewal"
echo "  View certificate:       sudo certbot certificates"
echo "  Revoke certificate:     sudo certbot revoke --cert-path /path/to/cert.pem"
echo ""
