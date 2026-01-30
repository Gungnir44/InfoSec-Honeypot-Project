#!/bin/bash

# Quick HTTPS Setup - Zero Configuration Required!
# Uses Cloudflare's TryCloudflare for instant free HTTPS
# No account, no domain, no configuration needed!

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${CYAN}================================================${NC}"
echo -e "${CYAN}   Quick HTTPS - Instant Secure Access${NC}"
echo -e "${CYAN}================================================${NC}"
echo ""
echo -e "${YELLOW}This will give you a free HTTPS URL instantly.${NC}"
echo -e "${YELLOW}No account or domain required!${NC}"
echo ""

# Check if running as root for installation
NEED_SUDO=""
if [ "$EUID" -ne 0 ]; then
    NEED_SUDO="sudo"
fi

# Check if cloudflared is installed
if ! command -v cloudflared &> /dev/null; then
    echo -e "${GREEN}Installing cloudflared...${NC}"

    # Detect OS and architecture
    ARCH=$(uname -m)
    case $ARCH in
        x86_64) ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        armv7l) ARCH="arm" ;;
    esac

    if [ -f /etc/debian_version ]; then
        curl -sL -o /tmp/cloudflared.deb "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${ARCH}.deb"
        $NEED_SUDO dpkg -i /tmp/cloudflared.deb
        rm /tmp/cloudflared.deb
    elif [ -f /etc/redhat-release ]; then
        curl -sL -o /tmp/cloudflared.rpm "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${ARCH}.rpm"
        $NEED_SUDO rpm -i /tmp/cloudflared.rpm
        rm /tmp/cloudflared.rpm
    else
        curl -sL -o /tmp/cloudflared "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${ARCH}"
        $NEED_SUDO mv /tmp/cloudflared /usr/local/bin/
        $NEED_SUDO chmod +x /usr/local/bin/cloudflared
    fi

    echo -e "${GREEN}cloudflared installed!${NC}"
fi

# Default port
PORT=${1:-5000}

echo ""
echo -e "${GREEN}Starting tunnel to localhost:${PORT}...${NC}"
echo ""
echo -e "${YELLOW}Press Ctrl+C to stop${NC}"
echo ""
echo -e "${CYAN}================================================${NC}"

# Run cloudflared and capture the URL
cloudflared tunnel --url "http://localhost:${PORT}" 2>&1 | while read line; do
    echo "$line"
    # Extract and highlight the URL
    if [[ $line == *"trycloudflare.com"* ]]; then
        URL=$(echo "$line" | grep -oE 'https://[a-zA-Z0-9-]+\.trycloudflare\.com')
        if [ -n "$URL" ]; then
            echo ""
            echo -e "${CYAN}================================================${NC}"
            echo -e "${BOLD}${GREEN}Your HTTPS URL:${NC}"
            echo ""
            echo -e "   ${BOLD}${CYAN}$URL${NC}"
            echo ""
            echo -e "${CYAN}================================================${NC}"
            echo ""
            echo -e "${YELLOW}Share this URL to access your honeypot dashboard!${NC}"
            echo -e "${YELLOW}URL is valid until you stop this script.${NC}"
            echo ""
        fi
    fi
done
