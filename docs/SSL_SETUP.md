# HTTPS Setup Guide

This guide explains how to secure your honeypot dashboard with HTTPS. Choose the option that works best for you.

## Option 1: Quick HTTPS (No Domain Required)

**Best for**: Testing, demos, quick access - zero configuration!

```bash
# On your server, just run:
bash deployment/quick_https.sh

# You'll instantly get a URL like:
# https://random-words-here.trycloudflare.com
```

That's it! Share the URL to access your dashboard securely.

**Note**: The URL changes each time you restart the script.

---

## Option 2: Cloudflare Tunnel (Recommended - No Domain Required)

**Best for**: Permanent HTTPS URL, hides server IP, DDoS protection

```bash
sudo bash deployment/setup_cloudflare_tunnel.sh
```

**Benefits**:
- Free HTTPS with valid certificate
- Hides your server's real IP address
- Built-in DDoS protection
- No need to open ports 80/443
- Works without a domain (use TryCloudflare)
- Optional: Add a free domain later for a custom URL

---

## Option 3: Let's Encrypt (Requires Domain)

**Best for**: Production deployments with a custom domain

### Prerequisites

- A registered domain name pointing to your server's IP address
- Root/sudo access to your server
- Ports 80 and 443 open in your firewall
- Nginx installed and running

### Quick Setup

### 1. Run the SSL Setup Script

```bash
cd /path/to/honeypot-project
sudo bash deployment/setup_ssl.sh
```

The script will:
1. Install Certbot
2. Obtain SSL certificate from Let's Encrypt
3. Configure Nginx for HTTPS
4. Set up automatic certificate renewal

### 2. Verify Setup

```bash
sudo bash deployment/check_ssl.sh yourdomain.com
```

## Manual Setup

If you prefer to set up SSL manually:

### Step 1: Install Certbot

**Debian/Ubuntu:**
```bash
sudo apt update
sudo apt install -y certbot python3-certbot-nginx
```

**RHEL/CentOS:**
```bash
sudo dnf install -y certbot python3-certbot-nginx
```

### Step 2: Configure Initial HTTP

Copy the HTTP Nginx configuration:
```bash
sudo cp deployment/nginx/honeypot-http.conf /etc/nginx/sites-available/honeypot
sudo ln -sf /etc/nginx/sites-available/honeypot /etc/nginx/sites-enabled/
sudo sed -i 's/server_name _;/server_name yourdomain.com;/' /etc/nginx/sites-available/honeypot
sudo nginx -t && sudo systemctl reload nginx
```

### Step 3: Obtain Certificate

```bash
sudo mkdir -p /var/www/certbot
sudo certbot certonly \
    --webroot \
    --webroot-path=/var/www/certbot \
    --email your-email@example.com \
    --agree-tos \
    --no-eff-email \
    --domain yourdomain.com
```

### Step 4: Configure HTTPS

```bash
sudo cp deployment/nginx/honeypot-https.conf /etc/nginx/sites-available/honeypot
sudo sed -i 's/YOUR_DOMAIN/yourdomain.com/g' /etc/nginx/sites-available/honeypot
sudo nginx -t && sudo systemctl reload nginx
```

### Step 5: Enable Auto-Renewal

```bash
sudo systemctl enable certbot.timer
sudo systemctl start certbot.timer
```

## Certificate Management

### Check Certificate Status
```bash
sudo certbot certificates
```

### Test Renewal (Dry Run)
```bash
sudo certbot renew --dry-run
```

### Force Renewal
```bash
sudo certbot renew --force-renewal
```

### Revoke Certificate
```bash
sudo certbot revoke --cert-path /etc/letsencrypt/live/yourdomain.com/cert.pem
```

## Security Features

The HTTPS configuration includes:

### TLS Configuration
- **Protocols**: TLS 1.2 and TLS 1.3 only (no SSLv3, TLS 1.0, TLS 1.1)
- **Ciphers**: Modern AEAD ciphers only
- **OCSP Stapling**: Enabled for faster certificate validation

### Security Headers
- **HSTS**: HTTP Strict Transport Security (2 years, includes subdomains)
- **X-Frame-Options**: SAMEORIGIN (clickjacking protection)
- **X-Content-Type-Options**: nosniff (MIME sniffing protection)
- **X-XSS-Protection**: Enabled with block mode
- **Referrer-Policy**: strict-origin-when-cross-origin
- **Content-Security-Policy**: Restrictive CSP for dashboard

### Additional Security
- Gzip compression for performance
- Static file caching
- Denial of sensitive files (`.env`, `.py`, etc.)
- Separate logging for access and errors

## Nginx Configuration Files

| File | Purpose |
|------|---------|
| `deployment/nginx/honeypot-http.conf` | Initial HTTP config (before SSL) |
| `deployment/nginx/honeypot-https.conf` | Full HTTPS config (after SSL setup) |

## Troubleshooting

### Certificate Not Renewing
```bash
# Check certbot logs
sudo journalctl -u certbot

# Check timer status
sudo systemctl status certbot.timer
```

### Nginx Won't Start
```bash
# Test configuration
sudo nginx -t

# Check error logs
sudo tail -f /var/log/nginx/error.log
```

### SSL Test Failed
Use online tools to test your SSL configuration:
- [SSL Labs](https://www.ssllabs.com/ssltest/)
- [Security Headers](https://securityheaders.com/)

### Certificate Expired
```bash
# Force immediate renewal
sudo certbot renew --force-renewal
sudo systemctl reload nginx
```

## DNS Configuration

Ensure your domain's DNS is properly configured:

```
Type    Name              Value
A       yourdomain.com    YOUR_SERVER_IP
A       www               YOUR_SERVER_IP (optional)
```

DNS propagation can take up to 48 hours, but usually completes within minutes.

## Firewall Rules

Ensure ports 80 and 443 are open:

```bash
# UFW (Ubuntu)
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# firewalld (CentOS/RHEL)
sudo firewall-cmd --permanent --add-service=http
sudo firewall-cmd --permanent --add-service=https
sudo firewall-cmd --reload

# GCP Firewall
gcloud compute firewall-rules create allow-https \
    --direction=INGRESS --priority=1000 --network=default \
    --action=ALLOW --rules=tcp:443 --source-ranges=0.0.0.0/0 \
    --target-tags=honeypot
```

## Let's Encrypt Rate Limits

Be aware of Let's Encrypt rate limits:
- **Certificates per Domain**: 50 per week
- **Duplicate Certificates**: 5 per week
- **Failed Validations**: 5 failures per account per hostname per hour

For testing, use the staging environment:
```bash
certbot certonly --staging ...
```

## Remote Honeypot Agents

After enabling HTTPS, update your honeypot agents to use HTTPS:

```bash
python honeypot_agent.py \
    --server https://yourdomain.com \
    --honeypot-id HP123 \
    --api-key YOUR_API_KEY
```

## Useful Commands

```bash
# View certificate details
openssl x509 -in /etc/letsencrypt/live/yourdomain.com/cert.pem -text -noout

# Test SSL connection
openssl s_client -connect yourdomain.com:443 -servername yourdomain.com

# Check certificate expiration
echo | openssl s_client -connect yourdomain.com:443 2>/dev/null | openssl x509 -noout -dates

# Monitor Nginx
sudo tail -f /var/log/nginx/honeypot_access.log
sudo tail -f /var/log/nginx/honeypot_error.log
```
