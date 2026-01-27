# Honeypot Attack Analysis System with ML

A production-grade honeypot deployment and analysis platform with advanced machine learning capabilities for detecting, classifying, and analyzing real-world cyber attacks.

## Project Overview

This project implements an intelligent honeypot system that:
- **Captures Real Attacks**: Simulates vulnerable SSH/Telnet services using Cowrie
- **ML-Powered Analysis**: Classifies attacks and detects anomalies using machine learning
- **Smart Intelligence**: Extracts 30+ behavioral features for deep attack analysis
- **Real-Time Visualization**: Interactive dashboard with maps, charts, and statistics
- **Production Ready**: Docker support, testing suite, and comprehensive documentation
- **Research Capable**: Export datasets for ML research and training

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         VPS/Cloud Server                     │
│  ┌─────────────────────────────────────────────────────┐   │
│  │                  Cowrie Honeypot                     │   │
│  │           (SSH/Telnet Simulation)                    │   │
│  └──────────────────┬──────────────────────────────────┘   │
│                     │ Logs                                  │
│  ┌──────────────────▼──────────────────────────────────┐   │
│  │              Log Aggregation                         │   │
│  │         (JSON logs, captured sessions)               │   │
│  └──────────────────┬──────────────────────────────────┘   │
│                     │                                       │
│  ┌──────────────────▼──────────────────────────────────┐   │
│  │           Analysis Backend (Python)                  │   │
│  │  • Pattern recognition • IP geolocation              │   │
│  │  • Credential analysis • Command analysis            │   │
│  └──────────────────┬──────────────────────────────────┘   │
│                     │                                       │
│  ┌──────────────────▼──────────────────────────────────┐   │
│  │              PostgreSQL Database                     │   │
│  │        (Attack data, statistics, sessions)           │   │
│  └──────────────────┬──────────────────────────────────┘   │
│                     │                                       │
│  ┌──────────────────▼──────────────────────────────────┐   │
│  │         Web Dashboard (Flask + Chart.js)             │   │
│  │  • Real-time attack map • Statistics                 │   │
│  │  • Top attackers • Command analysis                  │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

## Features

### 🎯 Honeypot Capabilities
- SSH honeypot on port 2222 (or 22)
- Telnet honeypot
- Fake filesystem emulation
- Session recording and playback
- Malware download capture
- Custom service responses

### 🤖 Machine Learning Features
- **Attack Classification**: Categorizes attacks into 6 types (brute force, reconnaissance, malware deployment, persistence, bot, advanced)
- **Anomaly Detection**: Identifies unusual attack patterns using Isolation Forest
- **Feature Engineering**: Extracts 30+ behavioral features from sessions
- **Model Training Pipeline**: End-to-end training with automated labeling
- **Dataset Export**: Export data in CSV/JSON for external ML tools
- **Jupyter Notebooks**: Interactive analysis and visualization

### 📊 Analysis Features
- Real-time log parsing and analysis
- Credential pattern analysis (most common usernames/passwords)
- Command categorization (reconnaissance, download, execution, persistence)
- Attack source geolocation (country, city, ISP)
- Temporal analysis (attack patterns over time)
- Attack sophistication scoring
- Bot vs human detection

### 📈 Visualization Dashboard
- Interactive world map showing attack origins
- Real-time attack feed
- Top 10 attacking IPs
- Most common credentials used
- Command execution timeline
- Attack statistics and graphs
- ML model insights

### 🔔 Alerting System
- Real-time security alerts
- Multiple notification channels (Email, Slack, Webhook)
- Configurable alert thresholds
- Severity-based routing

## Technology Stack

### Core Components
- **Honeypot**: Cowrie (Python-based SSH/Telnet honeypot)
- **Backend**: Python 3.9+
- **Database**: PostgreSQL 13+ (or SQLite for development)
- **Web Framework**: Flask
- **Frontend**: HTML5, CSS3, JavaScript, Chart.js, Leaflet.js

### Python Libraries
- `cowrie` - Honeypot engine
- `flask` - Web framework
- `psycopg2` - PostgreSQL adapter
- `geoip2` - IP geolocation
- `pandas` - Data analysis
- `plotly` or `matplotlib` - Data visualization
- `APScheduler` - Background task scheduling

## Project Structure

```
honeypot-project/
├── README.md                   # This file
├── ARCHITECTURE.md             # Detailed architecture documentation
├── requirements.txt            # Python dependencies
├── .gitignore                  # Git ignore file
│
├── deployment/                 # Deployment scripts and configs
│   ├── setup_vps.sh           # Initial VPS setup script
│   ├── install_cowrie.sh      # Cowrie installation
│   ├── install_deps.sh        # System dependencies
│   ├── nginx.conf             # Nginx configuration
│   └── systemd/               # Systemd service files
│       ├── cowrie.service
│       └── dashboard.service
│
├── cowrie-config/             # Cowrie configuration
│   ├── cowrie.cfg             # Main Cowrie config
│   └── userdb.txt             # Fake user database
│
├── backend/                   # Analysis backend
│   ├── __init__.py
│   ├── config.py              # Configuration management
│   ├── database/
│   │   ├── __init__.py
│   │   ├── models.py          # Database models
│   │   └── db_manager.py      # Database operations
│   ├── analyzers/
│   │   ├── __init__.py
│   │   ├── log_parser.py      # Parse Cowrie logs
│   │   ├── geo_analyzer.py    # IP geolocation
│   │   ├── pattern_analyzer.py # Pattern detection
│   │   └── command_analyzer.py # Command analysis
│   └── utils/
│       ├── __init__.py
│       └── helpers.py         # Utility functions
│
├── dashboard/                 # Web dashboard
│   ├── app.py                 # Flask application
│   ├── routes/
│   │   ├── __init__.py
│   │   ├── api.py             # API endpoints
│   │   └── views.py           # Page routes
│   ├── static/
│   │   ├── css/
│   │   │   └── style.css
│   │   ├── js/
│   │   │   ├── dashboard.js   # Dashboard logic
│   │   │   ├── map.js         # Attack map
│   │   │   └── charts.js      # Chart rendering
│   │   └── images/
│   └── templates/
│       ├── base.html
│       ├── dashboard.html
│       ├── attacks.html
│       └── analytics.html
│
├── scripts/                   # Utility scripts
│   ├── import_logs.py         # Import existing logs
│   ├── generate_report.py     # Generate attack reports
│   └── backup_db.py           # Database backup
│
├── docs/                      # Documentation
│   ├── SETUP.md               # Setup instructions
│   ├── DEPLOYMENT.md          # Deployment guide
│   ├── API.md                 # API documentation
│   └── SECURITY.md            # Security considerations
│
└── tests/                     # Unit tests
    ├── test_parsers.py
    ├── test_analyzers.py
    └── test_api.py
```

## Security Considerations

### Isolation
- Deploy on dedicated VPS, never on production network
- Use separate, isolated VM or cloud instance
- Implement strict firewall rules
- No sensitive data on honeypot server

### Monitoring
- Monitor resource usage (CPU, memory, bandwidth)
- Implement rate limiting to prevent abuse
- Set up alerts for unusual activity
- Regular security audits of honeypot host

### Data Handling
- Sanitize all captured data before analysis
- Never execute captured malware samples on analysis machine
- Implement proper access controls for dashboard
- Encrypt sensitive logs

### Legal Considerations
- Ensure compliance with local laws
- Add appropriate disclaimers
- Don't use for entrapment
- Consider data retention policies

## Implementation Status

### Phase 1: Environment Setup ✅
- [x] Provision Google Cloud Platform Compute Engine VM
- [x] Install and harden base OS (Debian 12)
- [x] Configure GCP firewall rules
- [x] Set up SSH key authentication
- [x] Install system dependencies

### Phase 2: Honeypot Deployment ✅
- [x] Install Cowrie honeypot
- [x] Configure Cowrie (SSH on port 2222)
- [x] Set up systemd service for auto-restart
- [x] Test honeypot functionality
- [x] Verified attacks are being logged

### Phase 3: Database Setup ✅
- [x] Install PostgreSQL 15
- [x] Design database schema
- [x] Create tables and indexes
- [x] Implement data models (SQLAlchemy)
- [x] Test data insertion and queries

### Phase 4: Analysis Backend ✅
- [x] Build log parser for Cowrie JSON logs
- [x] Implement geolocation service (IP-API)
- [x] Create pattern analysis algorithms
- [x] Build command analysis module
- [x] Set up automated log processing (every 5 minutes)

### Phase 5: Web Dashboard ✅
- [x] Set up Flask application with Gunicorn
- [x] Create REST API endpoints
- [x] Build frontend interface
- [x] Implement real-time updates
- [x] Add interactive visualizations
- [x] Create attack map with Leaflet.js
- [x] Configure Nginx reverse proxy

### Phase 6: ML & Production ✅
- [x] Implement ML feature engineering (30+ features)
- [x] Build attack classifier (Random Forest)
- [x] Add anomaly detection (Isolation Forest)
- [x] Create alerting system
- [x] Deploy to production on GCP

## Getting Started

### Prerequisites
- VPS or cloud instance (1-2GB RAM, 20GB storage minimum)
- Python 3.9+
- PostgreSQL 13+ (or SQLite for development)
- Domain name (optional, for HTTPS dashboard)

### Quick Start
```bash
# Clone the repository
git clone <your-repo-url>
cd honeypot-project

# Install dependencies
pip install -r requirements.txt

# Set up database
python scripts/setup_database.py

# Configure environment
cp .env.example .env
# Edit .env with your configuration

# Run locally for testing
python dashboard/app.py
```

See [SETUP.md](docs/SETUP.md) for detailed setup instructions.

## Usage

### Accessing the Dashboard
```
http://your-vps-ip:5000
```

### Analyzing Logs Manually
```bash
python scripts/import_logs.py --log-file /path/to/cowrie.json
```

### Generating Reports
```bash
python scripts/generate_report.py --start-date 2024-01-01 --end-date 2024-01-31
```

## API Endpoints

- `GET /api/attacks/recent` - Get recent attacks
- `GET /api/attacks/by-country` - Attack distribution by country
- `GET /api/credentials/top` - Most common credentials
- `GET /api/commands/top` - Most executed commands
- `GET /api/stats/summary` - Overall statistics

See [API.md](docs/API.md) for complete API documentation.

## Deployment

### Development (Local)
```bash
python dashboard/app.py
```

### Production (with Gunicorn + Nginx)
```bash
gunicorn -w 4 -b 127.0.0.1:5000 dashboard.app:app
```

### Google Cloud Platform Deployment

This project is deployed on GCP Compute Engine. Here's how to replicate:

#### 1. Create GCP VM
```bash
gcloud compute instances create honeypot-vm \
    --zone=us-central1-a \
    --machine-type=e2-small \
    --image-family=debian-12 \
    --image-project=debian-cloud \
    --boot-disk-size=20GB \
    --tags=honeypot
```

#### 2. Configure Firewall Rules
```bash
# Allow honeypot SSH (port 2222)
gcloud compute firewall-rules create allow-honeypot-ssh \
    --direction=INGRESS --priority=1000 --network=default \
    --action=ALLOW --rules=tcp:2222 --source-ranges=0.0.0.0/0 \
    --target-tags=honeypot

# Allow dashboard (HTTP)
gcloud compute firewall-rules create allow-dashboard \
    --direction=INGRESS --priority=1000 --network=default \
    --action=ALLOW --rules=tcp:80,tcp:443 --source-ranges=0.0.0.0/0 \
    --target-tags=honeypot
```

#### 3. Install Dependencies (on VM)
```bash
sudo apt update && sudo apt install -y python3-pip python3-venv git postgresql nginx
```

#### 4. Clone and Configure
```bash
git clone https://github.com/Gungnir44/InfoSec-Honeypot-Project.git
cd InfoSec-Honeypot-Project
python3 -m venv venv
./venv/bin/pip install -r requirements.txt
cp .env.example .env
# Edit .env with your database credentials
```

#### 5. Setup Systemd Services
The project includes systemd service files for:
- `cowrie.service` - Honeypot daemon
- `honeypot-dashboard.service` - Web dashboard
- `honeypot-processor.timer` - Log processor (runs every 5 minutes)

```bash
sudo systemctl enable cowrie honeypot-dashboard honeypot-processor.timer
sudo systemctl start cowrie honeypot-dashboard honeypot-processor.timer
```

See [docs/SETUP.md](docs/SETUP.md) for detailed setup instructions.

## Expected Results

After deployment, you should observe:
- Automated brute-force login attempts (within hours)
- Common credentials: admin/admin, root/root, root/password
- Reconnaissance commands: `uname -a`, `cat /proc/cpuinfo`, `wget`
- Malware download attempts
- Cryptocurrency miners
- DDoS bot recruitment attempts

## Skills Demonstrated

This project showcases:
- **Network Security**: Understanding of attack vectors and defensive strategies
- **System Administration**: Linux server management, service deployment
- **Data Analysis**: Pattern recognition, statistical analysis
- **Full-Stack Development**: Backend Python, frontend JavaScript, database design
- **Security Operations**: Log analysis, threat intelligence
- **Documentation**: Technical writing, architecture documentation

## Future Enhancements

- [x] ~~Machine learning for anomaly detection~~ ✅ Implemented
- [x] ~~Email alerts for significant attacks~~ ✅ Implemented
- [ ] Integration with threat intelligence feeds (AbuseIPDB, Shodan)
- [ ] Multi-honeypot coordination
- [ ] Automated attacker profiling
- [ ] Malware analysis integration (VirusTotal API)
- [ ] Elasticsearch + Kibana for advanced log analysis
- [ ] HTTPS with Let's Encrypt SSL certificate

## Contributing

This is an academic project, but suggestions and improvements are welcome.

## License

MIT License - See LICENSE file for details

## Acknowledgments

- Cowrie Honeypot Project
- MaxMind GeoIP2
- OWASP for security best practices

## Live Demo

The honeypot is currently deployed and collecting real attack data:
- **Dashboard**: Accessible to project reviewers (contact for access)
- **Data Collection**: Actively capturing SSH brute-force attacks
- **ML Training**: Collecting data for model training

## Contact

Joshua
GitHub: [@Gungnir44](https://github.com/Gungnir44)

---

**Disclaimer**: This honeypot is for educational and research purposes only. Ensure compliance with all applicable laws and regulations in your jurisdiction. The author is not responsible for any misuse of this project.
