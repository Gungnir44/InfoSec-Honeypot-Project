#!/bin/bash

# Cloudflare Tunnel Setup Script
# Provides free HTTPS without a domain name
# Run as root or with sudo

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}================================================${NC}"
echo -e "${CYAN}   Cloudflare Tunnel Setup for Honeypot Dashboard${NC}"
echo -e "${CYAN}================================================${NC}"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run as root or with sudo${NC}"
    exit 1
fi

echo -e "${GREEN}[1/5] Installing cloudflared...${NC}"

# Detect architecture
ARCH=$(uname -m)
case $ARCH in
    x86_64)
        ARCH="amd64"
        ;;
    aarch64|arm64)
        ARCH="arm64"
        ;;
    armv7l)
        ARCH="arm"
        ;;
    *)
        echo -e "${RED}Unsupported architecture: $ARCH${NC}"
        exit 1
        ;;
esac

# Download and install cloudflared
if ! command -v cloudflared &> /dev/null; then
    echo "Downloading cloudflared for $ARCH..."

    # For Debian/Ubuntu
    if [ -f /etc/debian_version ]; then
        curl -L --output cloudflared.deb "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${ARCH}.deb"
        dpkg -i cloudflared.deb
        rm cloudflared.deb
    # For RHEL/CentOS
    elif [ -f /etc/redhat-release ]; then
        curl -L --output cloudflared.rpm "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${ARCH}.rpm"
        rpm -i cloudflared.rpm
        rm cloudflared.rpm
    else
        # Generic installation
        curl -L --output /usr/local/bin/cloudflared "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${ARCH}"
        chmod +x /usr/local/bin/cloudflared
    fi

    echo -e "${GREEN}cloudflared installed successfully${NC}"
else
    echo -e "${YELLOW}cloudflared is already installed${NC}"
fi

# Verify installation
cloudflared --version

echo ""
echo -e "${GREEN}[2/5] Authenticating with Cloudflare...${NC}"
echo ""
echo -e "${YELLOW}This will open a browser window to log in to Cloudflare.${NC}"
echo -e "${YELLOW}If you don't have an account, create one at https://dash.cloudflare.com/sign-up${NC}"
echo ""
read -p "Press Enter to continue..."

# Authenticate
cloudflared tunnel login

echo ""
echo -e "${GREEN}[3/5] Creating tunnel...${NC}"

# Generate tunnel name
TUNNEL_NAME="honeypot-$(date +%s)"
read -p "Enter tunnel name (default: $TUNNEL_NAME): " INPUT_NAME
TUNNEL_NAME=${INPUT_NAME:-$TUNNEL_NAME}

# Create tunnel
cloudflared tunnel create "$TUNNEL_NAME"

# Get tunnel ID
TUNNEL_ID=$(cloudflared tunnel list | grep "$TUNNEL_NAME" | awk '{print $1}')
echo -e "${GREEN}Tunnel created: $TUNNEL_NAME (ID: $TUNNEL_ID)${NC}"

echo ""
echo -e "${GREEN}[4/5] Configuring tunnel...${NC}"

# Create config directory
mkdir -p /etc/cloudflared

# Create config file
cat > /etc/cloudflared/config.yml << EOF
tunnel: $TUNNEL_ID
credentials-file: /root/.cloudflared/${TUNNEL_ID}.json

ingress:
  # Honeypot Dashboard
  - service: http://localhost:5000
EOF

echo -e "${GREEN}Configuration saved to /etc/cloudflared/config.yml${NC}"

echo ""
echo -e "${GREEN}[5/5] Setting up DNS route...${NC}"
echo ""
echo -e "${YELLOW}You need a domain in Cloudflare to create a DNS route.${NC}"
echo -e "${YELLOW}Options:${NC}"
echo "  1. Use a free subdomain from a domain you add to Cloudflare"
echo "  2. Use Cloudflare's TryCloudflare (temporary URL, no setup needed)"
echo ""
read -p "Do you have a domain in Cloudflare? (y/n): " HAS_DOMAIN

if [ "$HAS_DOMAIN" = "y" ] || [ "$HAS_DOMAIN" = "Y" ]; then
    read -p "Enter your full hostname (e.g., honeypot.yourdomain.com): " HOSTNAME

    # Route DNS to tunnel
    cloudflared tunnel route dns "$TUNNEL_NAME" "$HOSTNAME"

    echo ""
    echo -e "${GREEN}DNS route created!${NC}"

    # Update config with hostname
    cat > /etc/cloudflared/config.yml << EOF
tunnel: $TUNNEL_ID
credentials-file: /root/.cloudflared/${TUNNEL_ID}.json

ingress:
  # Honeypot Dashboard
  - hostname: $HOSTNAME
    service: http://localhost:5000
  # Catch-all (required)
  - service: http_status:404
EOF

    # Install as service
    cloudflared service install
    systemctl enable cloudflared
    systemctl start cloudflared

    echo ""
    echo -e "${CYAN}================================================${NC}"
    echo -e "${GREEN}   Cloudflare Tunnel Setup Complete!${NC}"
    echo -e "${CYAN}================================================${NC}"
    echo ""
    echo -e "${GREEN}Your honeypot dashboard is now available at:${NC}"
    echo -e "${CYAN}   https://$HOSTNAME${NC}"
    echo ""
    echo -e "${YELLOW}Benefits:${NC}"
    echo "  - Free HTTPS with valid certificate"
    echo "  - DDoS protection"
    echo "  - Your server IP is hidden"
    echo "  - No need to open ports 80/443"
    echo ""
    echo -e "${YELLOW}Manage tunnel:${NC}"
    echo "  Status:  systemctl status cloudflared"
    echo "  Logs:    journalctl -u cloudflared -f"
    echo "  Restart: systemctl restart cloudflared"
    echo ""
else
    echo ""
    echo -e "${YELLOW}Using TryCloudflare (Quick Tunnel)...${NC}"
    echo ""
    echo -e "${GREEN}Starting tunnel in quick mode...${NC}"
    echo -e "${YELLOW}Note: This URL is temporary and changes each restart.${NC}"
    echo -e "${YELLOW}For a permanent URL, add a domain to Cloudflare (free).${NC}"
    echo ""

    # Create a simple systemd service for quick tunnel
    cat > /etc/systemd/system/cloudflared-quick.service << EOF
[Unit]
Description=Cloudflare Quick Tunnel for Honeypot
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/cloudflared tunnel --url http://localhost:5000
Restart=always
RestartSec=5
StandardOutput=append:/var/log/cloudflared.log
StandardError=append:/var/log/cloudflared.log

[Install]
WantedBy=multi-user.target
EOF

    # Fix path if installed via package
    if [ -f /usr/bin/cloudflared ]; then
        sed -i 's|/usr/local/bin/cloudflared|/usr/bin/cloudflared|' /etc/systemd/system/cloudflared-quick.service
    fi

    systemctl daemon-reload
    systemctl enable cloudflared-quick
    systemctl start cloudflared-quick

    # Wait for tunnel to start and get URL
    echo "Waiting for tunnel to start..."
    sleep 5

    echo ""
    echo -e "${CYAN}================================================${NC}"
    echo -e "${GREEN}   Quick Tunnel Started!${NC}"
    echo -e "${CYAN}================================================${NC}"
    echo ""
    echo -e "${YELLOW}To get your tunnel URL, run:${NC}"
    echo "  grep -o 'https://.*trycloudflare.com' /var/log/cloudflared.log | tail -1"
    echo ""
    echo -e "${YELLOW}Or check the logs:${NC}"
    echo "  tail -f /var/log/cloudflared.log"
    echo ""
    echo -e "${YELLOW}Manage tunnel:${NC}"
    echo "  Status:  systemctl status cloudflared-quick"
    echo "  Logs:    tail -f /var/log/cloudflared.log"
    echo "  Restart: systemctl restart cloudflared-quick"
    echo ""
    echo -e "${RED}Note: Quick tunnel URL changes on restart!${NC}"
    echo -e "${YELLOW}For a permanent URL, add a free domain to Cloudflare.${NC}"
fi
