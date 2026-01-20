#!/bin/bash

# Honeypot VPS Setup Script
# This script sets up a fresh Ubuntu 22.04 server for honeypot deployment
# Run as root or with sudo

set -e  # Exit on error

echo "================================================"
echo "Honeypot VPS Setup Script"
echo "================================================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run as root or with sudo${NC}"
    exit 1
fi

echo -e "${GREEN}[1/8] Updating system packages...${NC}"
apt update && apt upgrade -y

echo -e "${GREEN}[2/8] Installing system dependencies...${NC}"
apt install -y \
    python3 \
    python3-pip \
    python3-venv \
    git \
    postgresql \
    postgresql-contrib \
    nginx \
    ufw \
    fail2ban \
    curl \
    wget \
    build-essential \
    libssl-dev \
    libffi-dev \
    python3-dev \
    libpq-dev

echo -e "${GREEN}[3/8] Configuring firewall (UFW)...${NC}"
# Disable UFW first to avoid lockout
ufw --force disable

# Allow SSH on custom port (change 22 to your SSH port if different)
read -p "Enter your SSH port (default: 22): " SSH_PORT
SSH_PORT=${SSH_PORT:-22}
ufw allow $SSH_PORT/tcp comment 'SSH'

# Allow honeypot ports
ufw allow 2222/tcp comment 'Cowrie SSH'
ufw allow 23/tcp comment 'Cowrie Telnet'

# Allow HTTP/HTTPS for dashboard
ufw allow 80/tcp comment 'HTTP Dashboard'
ufw allow 443/tcp comment 'HTTPS Dashboard'

# Enable UFW
ufw --force enable
echo -e "${YELLOW}Firewall configured. Make sure you can SSH on port $SSH_PORT before disconnecting!${NC}"

echo -e "${GREEN}[4/8] Setting up PostgreSQL...${NC}"
systemctl start postgresql
systemctl enable postgresql

# Create database and user
sudo -u postgres psql << EOF
CREATE DATABASE honeypot_db;
CREATE USER honeypot_user WITH ENCRYPTED PASSWORD 'change_this_password';
GRANT ALL PRIVILEGES ON DATABASE honeypot_db TO honeypot_user;
\q
EOF

echo -e "${YELLOW}PostgreSQL database 'honeypot_db' created${NC}"
echo -e "${YELLOW}Default password: change_this_password${NC}"
echo -e "${RED}IMPORTANT: Change the database password in production!${NC}"

echo -e "${GREEN}[5/8] Creating honeypot user...${NC}"
# Create dedicated user for honeypot (security best practice)
if ! id -u honeypot > /dev/null 2>&1; then
    useradd -m -s /bin/bash honeypot
    echo -e "${GREEN}User 'honeypot' created${NC}"
else
    echo -e "${YELLOW}User 'honeypot' already exists${NC}"
fi

echo -e "${GREEN}[6/8] Setting up Python virtual environment...${NC}"
sudo -u honeypot python3 -m venv /home/honeypot/venv
sudo -u honeypot /home/honeypot/venv/bin/pip install --upgrade pip

echo -e "${GREEN}[7/8] Configuring fail2ban for real SSH...${NC}"
cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5

[sshd]
enabled = true
port = ssh
logpath = %(sshd_log)s
backend = %(sshd_backend)s
EOF

systemctl restart fail2ban
systemctl enable fail2ban

echo -e "${GREEN}[8/8] Setting up log rotation...${NC}"
cat > /etc/logrotate.d/honeypot << 'EOF'
/var/log/honeypot/*.log {
    daily
    rotate 30
    compress
    delaycompress
    notifempty
    create 0640 honeypot honeypot
    sharedscripts
    postrotate
        systemctl reload cowrie > /dev/null 2>&1 || true
    endscript
}
EOF

mkdir -p /var/log/honeypot
chown honeypot:honeypot /var/log/honeypot

echo -e "${GREEN}================================================${NC}"
echo -e "${GREEN}VPS Setup Complete!${NC}"
echo -e "${GREEN}================================================${NC}"
echo ""
echo -e "${YELLOW}Next steps:${NC}"
echo "1. Run install_cowrie.sh to install the honeypot"
echo "2. Run install_deps.sh to install Python dependencies"
echo "3. Configure your .env file with database credentials"
echo "4. Deploy the dashboard"
echo ""
echo -e "${RED}SECURITY REMINDERS:${NC}"
echo "- Change the PostgreSQL password"
echo "- Configure SSH key authentication"
echo "- Disable password authentication in /etc/ssh/sshd_config"
echo "- Review firewall rules: ufw status"
echo ""
echo -e "${GREEN}System Information:${NC}"
echo "- Python version: $(python3 --version)"
echo "- PostgreSQL status: $(systemctl is-active postgresql)"
echo "- Firewall status: $(ufw status | head -n1)"
echo ""
