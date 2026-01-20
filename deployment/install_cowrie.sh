#!/bin/bash

# Cowrie Honeypot Installation Script
# Installs and configures Cowrie SSH/Telnet honeypot
# Run as the honeypot user (not root)

set -e

echo "================================================"
echo "Cowrie Honeypot Installation"
echo "================================================"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Check we're not running as root
if [ "$EUID" -eq 0 ]; then
    echo -e "${RED}Do not run this script as root!${NC}"
    echo -e "${YELLOW}Run as the honeypot user: sudo -u honeypot bash install_cowrie.sh${NC}"
    exit 1
fi

INSTALL_DIR="$HOME/cowrie"

echo -e "${GREEN}[1/6] Installing Cowrie dependencies...${NC}"
sudo apt install -y \
    git \
    python3-virtualenv \
    libssl-dev \
    libffi-dev \
    build-essential \
    libpython3-dev \
    python3-minimal \
    authbind

echo -e "${GREEN}[2/6] Cloning Cowrie from GitHub...${NC}"
if [ -d "$INSTALL_DIR" ]; then
    echo -e "${YELLOW}Cowrie directory already exists. Backing up...${NC}"
    mv "$INSTALL_DIR" "$INSTALL_DIR.backup.$(date +%s)"
fi

git clone https://github.com/cowrie/cowrie "$INSTALL_DIR"
cd "$INSTALL_DIR"

echo -e "${GREEN}[3/6] Setting up Python virtual environment...${NC}"
python3 -m venv cowrie-env
source cowrie-env/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

echo -e "${GREEN}[4/6] Configuring Cowrie...${NC}"
cp etc/cowrie.cfg.dist etc/cowrie.cfg

# Configure Cowrie to use JSON logging
cat >> etc/cowrie.cfg << 'EOF'

# Custom configuration for honeypot project
[output_jsonlog]
enabled = true
logfile = var/log/cowrie/cowrie.json

[honeypot]
hostname = server01
sensor_name = honeypot1

# SSH Configuration
[ssh]
enabled = true
listen_port = 2222
version = SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7

# Telnet Configuration
[telnet]
enabled = true
listen_port = 2223

# Enable malware downloads
[output_virustotal]
enabled = false

# You can enable VirusTotal later by adding your API key
# api_key = YOUR_VIRUSTOTAL_API_KEY
EOF

echo -e "${GREEN}[5/6] Setting up port redirection (optional)...${NC}"
echo -e "${YELLOW}To make honeypot listen on real SSH port 22:${NC}"
echo "Run these commands as root:"
echo "  sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222"
echo "  sudo iptables -t nat -A PREROUTING -p tcp --dport 23 -j REDIRECT --to-port 2223"
echo ""
echo "To make persistent:"
echo "  sudo apt install iptables-persistent"
echo "  sudo netfilter-persistent save"

echo -e "${GREEN}[6/6] Testing Cowrie...${NC}"
# Quick start test
timeout 5s bin/cowrie start || true
sleep 2
bin/cowrie status

echo -e "${GREEN}================================================${NC}"
echo -e "${GREEN}Cowrie Installation Complete!${NC}"
echo -e "${GREEN}================================================${NC}"
echo ""
echo -e "${YELLOW}Cowrie Commands:${NC}"
echo "  Start:    $INSTALL_DIR/bin/cowrie start"
echo "  Stop:     $INSTALL_DIR/bin/cowrie stop"
echo "  Status:   $INSTALL_DIR/bin/cowrie status"
echo "  Logs:     tail -f $INSTALL_DIR/var/log/cowrie/cowrie.json"
echo ""
echo -e "${YELLOW}Configuration file:${NC}"
echo "  $INSTALL_DIR/etc/cowrie.cfg"
echo ""
echo -e "${YELLOW}Next steps:${NC}"
echo "1. Review configuration in etc/cowrie.cfg"
echo "2. Start Cowrie: bin/cowrie start"
echo "3. Test connection: ssh -p 2222 root@localhost"
echo "4. Set up systemd service (see deployment/systemd/cowrie.service)"
echo ""
