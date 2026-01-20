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

## Implementation Phases

### Phase 1: Environment Setup (Week 1)
- [ ] Provision VPS (DigitalOcean, AWS, Linode)
- [ ] Install and harden base OS (Ubuntu 22.04 LTS)
- [ ] Configure firewall rules
- [ ] Set up SSH key authentication
- [ ] Install Docker (optional, for containerized deployment)

### Phase 2: Honeypot Deployment (Week 1-2)
- [ ] Install Cowrie honeypot
- [ ] Configure Cowrie (ports, filesystem, responses)
- [ ] Set up log rotation
- [ ] Test honeypot functionality
- [ ] Expose to internet and verify attacks are being logged

### Phase 3: Database Setup (Week 2)
- [ ] Install PostgreSQL
- [ ] Design database schema
- [ ] Create tables and indexes
- [ ] Implement data models
- [ ] Test data insertion and queries

### Phase 4: Analysis Backend (Week 2-3)
- [ ] Build log parser for Cowrie JSON logs
- [ ] Implement geolocation service
- [ ] Create pattern analysis algorithms
- [ ] Build command analysis module
- [ ] Set up automated log processing

### Phase 5: Web Dashboard (Week 3-4)
- [ ] Set up Flask application
- [ ] Create REST API endpoints
- [ ] Build frontend interface
- [ ] Implement real-time updates
- [ ] Add interactive visualizations
- [ ] Create attack map with Leaflet.js

### Phase 6: Testing & Documentation (Week 4)
- [ ] Write unit tests
- [ ] Perform security audit
- [ ] Write comprehensive documentation
- [ ] Create demo screenshots/videos
- [ ] Prepare presentation materials

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

### Development
```bash
python dashboard/app.py
```

### Production (with Gunicorn + Nginx)
```bash
gunicorn -w 4 -b 127.0.0.1:5000 dashboard.app:app
```

See [DEPLOYMENT.md](docs/DEPLOYMENT.md) for production deployment guide.

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

- [ ] Machine learning for anomaly detection
- [ ] Integration with threat intelligence feeds (AbuseIPDB, Shodan)
- [ ] Multi-honeypot coordination
- [ ] Automated attacker profiling
- [ ] Email alerts for significant attacks
- [ ] Malware analysis integration (VirusTotal API)
- [ ] Elasticsearch + Kibana for advanced log analysis

## Contributing

This is an academic project, but suggestions and improvements are welcome.

## License

MIT License - See LICENSE file for details

## Acknowledgments

- Cowrie Honeypot Project
- MaxMind GeoIP2
- OWASP for security best practices

## Contact

Joshua [Your Last Name]
[Your Email or GitHub]

---

**Disclaimer**: This honeypot is for educational and research purposes only. Ensure compliance with all applicable laws and regulations in your jurisdiction. The author is not responsible for any misuse of this project.
