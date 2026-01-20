# Production Deployment Guide

Complete guide for deploying the honeypot system to production with all ML features enabled.

## Quick Deployment with Docker

### Prerequisites
- Docker & Docker Compose installed
- VPS or cloud instance (2GB RAM minimum for ML features)
- Domain name (optional for HTTPS)

### Step 1: Clone and Configure

```bash
# Clone repository
git clone <your-repo-url>
cd honeypot-project

# Create environment file
cp .env.example .env

# Edit configuration
nano .env
```

Update `.env` with secure passwords:
```bash
DB_PASSWORD=your_secure_password_here
DASHBOARD_SECRET_KEY=your_random_secret_key_32_chars
FLASK_ENV=production
```

### Step 2: Deploy with Docker Compose

```bash
# Build and start all services
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f dashboard
```

Services running:
- PostgreSQL database on port 5432
- Dashboard on port 5000

### Step 3: Initialize Database

```bash
# Initialize database tables
docker-compose exec dashboard python scripts/setup_database.py

# Add sample data (optional for testing)
docker-compose exec dashboard python scripts/add_sample_data.py --count 100
```

### Step 4: Deploy Cowrie Honeypot

Cowrie runs outside Docker for security isolation:

```bash
# Install Cowrie (as honeypot user)
sudo su - honeypot
bash /path/to/deployment/install_cowrie.sh

# Start Cowrie
cd cowrie
bin/cowrie start
```

### Step 5: Set Up Log Processing

```bash
# Create systemd timer for log processing
sudo cp deployment/systemd/honeypot-logprocessing.* /etc/systemd/system/
sudo systemctl enable honeypot-logprocessing.timer
sudo systemctl start honeypot-logprocessing.timer
```

### Step 6: Configure Nginx Reverse Proxy

```bash
# Install Nginx
sudo apt install nginx -y

# Configure
sudo nano /etc/nginx/sites-available/honeypot
```

Add configuration:
```nginx
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://localhost:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

Enable and restart:
```bash
sudo ln -s /etc/nginx/sites-available/honeypot /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

### Step 7: Set Up HTTPS with Let's Encrypt

```bash
sudo apt install certbot python3-certbot-nginx -y
sudo certbot --nginx -d your-domain.com
```

## Machine Learning Setup

### Train Initial Models

After collecting attack data for 1-2 weeks:

```bash
# Train ML models
docker-compose exec dashboard python backend/ml/training.py --mode both

# Export dataset for research
docker-compose exec dashboard python backend/ml/training.py --mode export
```

Models saved to `models/` directory.

### Enable ML in Dashboard

Update `dashboard/routes/api.py` to use ML predictions (examples included).

### Retrain Models

Set up weekly retraining:

```bash
# Create cron job
echo "0 2 * * 0 cd /path/to/honeypot-project && docker-compose exec -T dashboard python backend/ml/training.py --mode both" | sudo crontab -
```

## Alert Configuration

### Email Alerts

Update `.env`:
```bash
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password
ALERT_EMAIL=security-team@example.com
```

### Slack Alerts

1. Create Slack webhook: https://api.slack.com/messaging/webhooks
2. Update `.env`:
```bash
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
```

### Configure Alert Manager

In `scripts/process_logs.py`, add:

```python
from backend.alerting import AlertManager
from backend.alerting.notifiers import SlackNotifier, EmailNotifier

# Initialize alert manager
alert_manager = AlertManager()

# Add notifiers
alert_manager.add_notifier(SlackNotifier(config.SLACK_WEBHOOK_URL))
# alert_manager.add_notifier(EmailNotifier(...))

# Check for alerts during log processing
alerts = alert_manager.check_session(session_data, features, ml_predictions)
```

## Monitoring and Maintenance

### Health Checks

```bash
# Dashboard health
curl http://localhost:5000/health

# Database connection
docker-compose exec postgres psql -U honeypot_user -d honeypot_db -c "SELECT COUNT(*) FROM attacks;"

# Cowrie status
sudo -u honeypot /home/honeypot/cowrie/bin/cowrie status
```

### View Logs

```bash
# Dashboard logs
docker-compose logs -f dashboard

# Cowrie logs
tail -f /home/honeypot/cowrie/var/log/cowrie/cowrie.json

# PostgreSQL logs
docker-compose logs -f postgres
```

### Backup

```bash
# Backup database
docker-compose exec postgres pg_dump -U honeypot_user honeypot_db > backup_$(date +%Y%m%d).sql

# Backup ML models
tar -czf models_backup_$(date +%Y%m%d).tar.gz models/
```

### Update

```bash
# Pull latest changes
git pull

# Rebuild and restart
docker-compose down
docker-compose build --no-cache
docker-compose up -d
```

## Performance Tuning

### For High-Volume Attacks (>1000/day)

1. **Increase resources:**
```yaml
# docker-compose.yml
services:
  dashboard:
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 4G
```

2. **Add Redis caching:**
```bash
# Add to docker-compose.yml
redis:
  image: redis:alpine
  ports:
    - "6379:6379"
```

3. **Optimize database:**
```sql
-- Create indexes
CREATE INDEX idx_attacks_timestamp ON attacks(timestamp DESC);
CREATE INDEX idx_attacks_country ON attacks(country);
CREATE INDEX idx_commands_category ON commands(category);
```

## Security Hardening

### Firewall Rules

```bash
# Allow only necessary ports
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp    # SSH (use non-standard port)
sudo ufw allow 2222/tcp  # Honeypot
sudo ufw allow 80/tcp    # HTTP
sudo ufw allow 443/tcp   # HTTPS
sudo ufw enable
```

### Dashboard Authentication

Add basic auth to Nginx:

```bash
sudo apt install apache2-utils
sudo htpasswd -c /etc/nginx/.htpasswd admin

# Add to nginx config
location / {
    auth_basic "Honeypot Dashboard";
    auth_basic_user_file /etc/nginx/.htpasswd;
    proxy_pass http://localhost:5000;
}
```

### Docker Security

```bash
# Run containers with limited privileges
# Add to docker-compose.yml
services:
  dashboard:
    security_opt:
      - no-new-privileges:true
    read_only: true
    tmpfs:
      - /tmp
```

## Troubleshooting

### Dashboard won't start
```bash
# Check logs
docker-compose logs dashboard

# Verify database connection
docker-compose exec dashboard python -c "from backend.database.db_manager import DatabaseManager; db = DatabaseManager(); print('OK')"
```

### No attacks appearing
```bash
# Check Cowrie is running
sudo -u honeypot /home/honeypot/cowrie/bin/cowrie status

# Verify port is open
nmap -p 2222 your-vps-ip

# Test manually
ssh -p 2222 root@your-vps-ip
```

### ML training fails
```bash
# Check data availability
docker-compose exec dashboard python -c "from backend.ml.training import ModelTrainer; t = ModelTrainer(); print(len(t.load_training_data()))"

# Minimum 10-20 sessions needed
# Collect more data or use sample data
```

## Scaling

### Multiple Honeypots

Deploy honeypots in different regions, centralize data:

```yaml
# Central database setup
services:
  postgres:
    ports:
      - "5432:5432"  # Expose to other honeypots

  dashboard:
    environment:
      ACCEPT_REMOTE_LOGS: "true"
```

### Load Balancing

For high traffic dashboards:

```nginx
upstream dashboard_backend {
    server localhost:5000;
    server localhost:5001;
    server localhost:5002;
}

server {
    location / {
        proxy_pass http://dashboard_backend;
    }
}
```

## Production Checklist

Before going live:

- [ ] Changed all default passwords
- [ ] Configured firewall rules
- [ ] Set up HTTPS with SSL certificate
- [ ] Configured automated backups
- [ ] Set up monitoring and alerts
- [ ] Tested honeypot attracts attacks
- [ ] Verified log processing works
- [ ] Dashboard is accessible
- [ ] ML models will retrain automatically
- [ ] Documentation is up to date

## Support

- Check [TROUBLESHOOTING.md](TROUBLESHOOTING.md)
- Review [ML_CAPABILITIES.md](ML_CAPABILITIES.md)
- GitHub Issues: https://github.com/yourusername/honeypot-project/issues
