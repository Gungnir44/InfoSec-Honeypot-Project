# Setup Guide

Complete step-by-step setup instructions for the Honeypot Attack Analysis System.

## Prerequisites

- VPS or cloud instance (minimum 1GB RAM, 20GB storage)
- Ubuntu 22.04 LTS (recommended) or similar Linux distribution
- Python 3.9 or higher
- PostgreSQL 13+ (or SQLite for development)
- Git
- Domain name (optional, for HTTPS dashboard)

## Quick Start (Development)

For local development and testing:

```bash
# Clone the repository
git clone <your-repo-url>
cd honeypot-project

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Create environment file
cp .env.example .env
# Edit .env with your settings

# Initialize database (SQLite for development)
python scripts/setup_database.py

# Run dashboard
python dashboard/app.py
```

Dashboard will be available at `http://localhost:5000`

## Production Deployment

### Step 1: VPS Setup

Provision a VPS from a provider:
- DigitalOcean (recommended): $6/month droplet
- AWS EC2: t2.micro or t2.small
- Linode: Nanode or shared CPU instance
- Vultr: $6/month plan

**Important**: Use a dedicated, isolated server. Never deploy on production networks or systems with sensitive data.

### Step 2: Run Initial Setup Script

SSH into your VPS and run:

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Download and run setup script
wget https://raw.githubusercontent.com/yourusername/honeypot-project/main/deployment/setup_vps.sh
sudo bash setup_vps.sh
```

This script will:
- Install system dependencies
- Configure firewall (UFW)
- Set up PostgreSQL
- Create honeypot user
- Install fail2ban for SSH protection

### Step 3: Install Cowrie Honeypot

```bash
# Switch to honeypot user
sudo su - honeypot

# Download and run Cowrie install script
wget https://raw.githubusercontent.com/yourusername/honeypot-project/main/deployment/install_cowrie.sh
bash install_cowrie.sh

# Start Cowrie
cd cowrie
bin/cowrie start

# Test it works
bin/cowrie status
```

Test the honeypot from your local machine:
```bash
ssh -p 2222 root@your-vps-ip
# Try any password - it should accept common credentials
```

### Step 4: Deploy Analysis Backend

```bash
# Clone project repository
cd /home/honeypot
git clone <your-repo-url> honeypot-project
cd honeypot-project

# Create virtual environment
python3 -m venv /home/honeypot/venv
source /home/honeypot/venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
nano .env  # Edit with your settings
```

Important `.env` settings:
```bash
DB_PASSWORD=your_secure_password_here
COWRIE_LOG_PATH=/home/honeypot/cowrie/var/log/cowrie/cowrie.json
DASHBOARD_SECRET_KEY=your_random_secret_key
```

```bash
# Initialize database
python scripts/setup_database.py

# Test log processing
python scripts/process_logs.py --from-beginning
```

### Step 5: Set Up Systemd Services

```bash
# Exit honeypot user
exit

# Copy systemd service files
sudo cp /home/honeypot/honeypot-project/deployment/systemd/cowrie.service /etc/systemd/system/
sudo cp /home/honeypot/honeypot-project/deployment/systemd/dashboard.service /etc/systemd/system/

# Enable and start services
sudo systemctl daemon-reload
sudo systemctl enable cowrie dashboard
sudo systemctl start cowrie dashboard

# Check status
sudo systemctl status cowrie
sudo systemctl status dashboard
```

### Step 6: Configure Nginx Reverse Proxy

```bash
# Install Nginx
sudo apt install nginx -y

# Create Nginx config
sudo nano /etc/nginx/sites-available/honeypot-dashboard
```

Add this configuration:
```nginx
server {
    listen 80;
    server_name your-domain.com;  # Or use IP address

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Enable the site:
```bash
sudo ln -s /etc/nginx/sites-available/honeypot-dashboard /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

### Step 7: Set Up HTTPS (Optional but Recommended)

```bash
# Install Certbot
sudo apt install certbot python3-certbot-nginx -y

# Get SSL certificate
sudo certbot --nginx -d your-domain.com

# Auto-renewal is configured automatically
```

### Step 8: Configure Log Processing

Set up automated log processing:

```bash
# Create a systemd timer for log processing
sudo nano /etc/systemd/system/honeypot-logprocessing.service
```

Add:
```ini
[Unit]
Description=Honeypot Log Processing
After=network.target postgresql.service

[Service]
Type=oneshot
User=honeypot
WorkingDirectory=/home/honeypot/honeypot-project
Environment="PATH=/home/honeypot/venv/bin"
ExecStart=/home/honeypot/venv/bin/python scripts/process_logs.py
```

Create timer:
```bash
sudo nano /etc/systemd/system/honeypot-logprocessing.timer
```

Add:
```ini
[Unit]
Description=Process honeypot logs every 5 minutes

[Timer]
OnBootSec=5min
OnUnitActiveSec=5min

[Install]
WantedBy=timers.target
```

Enable timer:
```bash
sudo systemctl daemon-reload
sudo systemctl enable honeypot-logprocessing.timer
sudo systemctl start honeypot-logprocessing.timer
```

## Verification

### Check Cowrie is Running
```bash
sudo -u honeypot /home/honeypot/cowrie/bin/cowrie status
tail -f /home/honeypot/cowrie/var/log/cowrie/cowrie.json
```

### Check Dashboard is Running
```bash
sudo systemctl status dashboard
curl http://localhost:5000/health
```

### Test End-to-End
1. SSH to honeypot: `ssh -p 2222 root@your-vps-ip`
2. Try logging in with: `root/password`
3. Run some commands: `whoami`, `uname -a`, `ls`
4. Wait 5 minutes for log processing
5. Check dashboard: `http://your-vps-ip` or `https://your-domain.com`

## Troubleshooting

### Cowrie Not Starting
```bash
# Check logs
sudo -u honeypot cat /home/honeypot/cowrie/var/log/cowrie/cowrie.log

# Check permissions
ls -la /home/honeypot/cowrie
```

### Dashboard Connection Errors
```bash
# Check if service is running
sudo systemctl status dashboard

# Check logs
sudo journalctl -u dashboard -f

# Test database connection
sudo -u honeypot psql -U honeypot_user -d honeypot_db -c "SELECT COUNT(*) FROM attacks;"
```

### No Attacks Appearing
- Wait 24-48 hours - automated scanners will find you
- Make sure port 2222 is open: `sudo ufw status`
- Check if Cowrie is logging: `tail -f /home/honeypot/cowrie/var/log/cowrie/cowrie.json`
- Manually trigger log processing: `python scripts/process_logs.py --from-beginning`

### GeoIP Not Working
Download free GeoLite2 database:
```bash
# Sign up at https://www.maxmind.com/en/geolite2/signup
# Download GeoLite2-City.mmdb
mkdir -p /home/honeypot/honeypot-project/data
# Upload GeoLite2-City.mmdb to this directory
# Update GEOIP_DB_PATH in .env
```

## Security Hardening

### Change SSH Port
```bash
sudo nano /etc/ssh/sshd_config
# Change Port 22 to Port 5022
sudo systemctl restart sshd
# Update firewall
sudo ufw allow 5022/tcp
```

### Disable Password Authentication
```bash
sudo nano /etc/ssh/sshd_config
# Set: PasswordAuthentication no
# Set: PubkeyAuthentication yes
sudo systemctl restart sshd
```

### Enable Automatic Updates
```bash
sudo apt install unattended-upgrades -y
sudo dpkg-reconfigure -plow unattended-upgrades
```

## Maintenance

### Backup Database
```bash
# Run backup script
python scripts/backup_db.py

# Or manual PostgreSQL backup
sudo -u postgres pg_dump honeypot_db > backup_$(date +%Y%m%d).sql
```

### Monitor Resource Usage
```bash
# Check disk space
df -h

# Check memory
free -h

# Check service logs
sudo journalctl -u cowrie -f
sudo journalctl -u dashboard -f
```

### Update Project
```bash
cd /home/honeypot/honeypot-project
git pull
source /home/honeypot/venv/bin/activate
pip install -r requirements.txt --upgrade
sudo systemctl restart dashboard
```

## Next Steps

- Review [DEPLOYMENT.md](DEPLOYMENT.md) for production best practices
- Check [API.md](API.md) for API documentation
- Read [SECURITY.md](SECURITY.md) for security considerations
- Explore advanced features in [ARCHITECTURE.md](../ARCHITECTURE.md)

## Getting Help

- Check GitHub Issues: https://github.com/yourusername/honeypot-project/issues
- Review Cowrie documentation: https://github.com/cowrie/cowrie
- Join community Discord/Slack (if available)
