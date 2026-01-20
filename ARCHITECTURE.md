# Honeypot System Architecture

## System Overview

This document provides detailed technical architecture for the Honeypot Attack Analysis System.

## Component Architecture

### 1. Cowrie Honeypot Layer

**Purpose**: Simulate vulnerable SSH/Telnet services to attract attackers

**Technology**: Cowrie (Python-based medium-interaction honeypot)

**Configuration**:
- Listens on port 2222 (can be changed to 22)
- Emulates a Linux system with fake filesystem
- Logs all interactions in JSON format
- Captures malware downloads
- Records full session replays

**Log Output**:
```json
{
  "eventid": "cowrie.login.success",
  "username": "root",
  "password": "password",
  "message": "login attempt [root/password] succeeded",
  "sensor": "honeypot1",
  "timestamp": "2024-01-13T10:30:00.123456Z",
  "src_ip": "192.168.1.100",
  "session": "a1b2c3d4"
}
```

### 2. Log Aggregation Layer

**Purpose**: Collect and consolidate all honeypot logs

**Implementation**:
- Cowrie writes logs to `/var/log/cowrie/cowrie.json`
- Log rotation configured via logrotate
- Real-time log tailing for immediate analysis
- Historical log retention for trend analysis

**Log Types Captured**:
- Login attempts (success/failure)
- Command executions
- File downloads
- Connection metadata
- Session data

### 3. Analysis Backend

**Purpose**: Parse logs, extract insights, and store structured data

#### 3.1 Log Parser (`backend/analyzers/log_parser.py`)

Responsibilities:
- Read Cowrie JSON logs
- Parse and validate log entries
- Extract relevant fields
- Handle malformed entries gracefully

Key Functions:
```python
def parse_cowrie_log(log_line: str) -> dict
def extract_login_attempt(entry: dict) -> LoginAttempt
def extract_command(entry: dict) -> Command
def extract_session(entry: dict) -> Session
```

#### 3.2 Geolocation Analyzer (`backend/analyzers/geo_analyzer.py`)

Responsibilities:
- Resolve IP addresses to geographic locations
- Identify ISP and organization
- Cache results to minimize API calls

Technology:
- MaxMind GeoIP2 database (or GeoLite2 free version)
- Alternative: ipapi.co, ip-api.com

Data Extracted:
- Country, city, coordinates
- ISP, organization, AS number
- Connection type

#### 3.3 Pattern Analyzer (`backend/analyzers/pattern_analyzer.py`)

Responsibilities:
- Identify attack patterns
- Detect credential stuffing attempts
- Recognize common attack tools
- Flag suspicious behavior

Patterns Detected:
- Brute force attacks (rapid login attempts)
- Dictionary attacks (sequential common passwords)
- Bot behavior (predictable command sequences)
- Reconnaissance activity
- Malware deployment attempts

#### 3.4 Command Analyzer (`backend/analyzers/command_analyzer.py`)

Responsibilities:
- Categorize executed commands
- Identify malicious intent
- Track command sequences

Command Categories:
- Reconnaissance: `uname`, `whoami`, `ifconfig`
- Persistence: `crontab`, `systemctl`, startup scripts
- Download: `wget`, `curl`, `tftp`
- Execution: `sh`, `bash`, `python`
- Cryptocurrency: Mining pool connections
- DDoS: HOIC/LOIC patterns

### 4. Database Layer

**Purpose**: Persistent storage for all attack data and analytics

**Schema Design**:

#### Table: `attacks`
```sql
CREATE TABLE attacks (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP NOT NULL,
    src_ip INET NOT NULL,
    src_port INTEGER,
    dst_port INTEGER,
    session_id VARCHAR(255),
    country VARCHAR(100),
    city VARCHAR(100),
    isp VARCHAR(255),
    latitude DECIMAL(10, 8),
    longitude DECIMAL(11, 8),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_timestamp (timestamp),
    INDEX idx_src_ip (src_ip),
    INDEX idx_country (country)
);
```

#### Table: `login_attempts`
```sql
CREATE TABLE login_attempts (
    id SERIAL PRIMARY KEY,
    attack_id INTEGER REFERENCES attacks(id),
    username VARCHAR(255),
    password VARCHAR(255),
    success BOOLEAN,
    timestamp TIMESTAMP NOT NULL,
    INDEX idx_username (username),
    INDEX idx_timestamp (timestamp)
);
```

#### Table: `commands`
```sql
CREATE TABLE commands (
    id SERIAL PRIMARY KEY,
    attack_id INTEGER REFERENCES attacks(id),
    command TEXT,
    category VARCHAR(50),
    timestamp TIMESTAMP NOT NULL,
    success BOOLEAN,
    INDEX idx_command (command(100)),
    INDEX idx_category (category)
);
```

#### Table: `sessions`
```sql
CREATE TABLE sessions (
    id SERIAL PRIMARY KEY,
    session_id VARCHAR(255) UNIQUE,
    attack_id INTEGER REFERENCES attacks(id),
    start_time TIMESTAMP,
    end_time TIMESTAMP,
    duration INTEGER,
    commands_count INTEGER,
    downloads_count INTEGER
);
```

#### Table: `downloads`
```sql
CREATE TABLE downloads (
    id SERIAL PRIMARY KEY,
    attack_id INTEGER REFERENCES attacks(id),
    url TEXT,
    filename VARCHAR(255),
    file_hash VARCHAR(64),
    file_size INTEGER,
    timestamp TIMESTAMP,
    malware_detected BOOLEAN
);
```

### 5. Web Dashboard

**Purpose**: Visualize attack data and provide real-time monitoring

#### 5.1 Backend (Flask)

**Routes**:
- `/` - Main dashboard
- `/attacks` - Attack details page
- `/analytics` - Advanced analytics
- `/api/attacks/recent` - Recent attacks JSON
- `/api/stats/summary` - Summary statistics
- `/api/attacks/map` - Geographic data for map

**API Response Example**:
```json
{
  "recent_attacks": [
    {
      "timestamp": "2024-01-13T10:30:00Z",
      "src_ip": "192.168.1.100",
      "country": "China",
      "username": "root",
      "password": "admin",
      "commands": ["whoami", "uname -a"]
    }
  ],
  "stats": {
    "total_attacks": 15234,
    "unique_ips": 3421,
    "countries": 87,
    "top_country": "China"
  }
}
```

#### 5.2 Frontend

**Technologies**:
- Chart.js for graphs and statistics
- Leaflet.js for interactive map
- DataTables for attack logs
- WebSocket (optional) for real-time updates

**Dashboard Components**:

1. **Attack Map**:
   - Heatmap of attack origins
   - Click markers for details
   - Filter by date range

2. **Real-Time Feed**:
   - Latest attacks scrolling
   - Color-coded by severity
   - Click to expand details

3. **Statistics Cards**:
   - Total attacks
   - Unique attackers
   - Success rate
   - Top attack country

4. **Charts**:
   - Attacks over time (line chart)
   - Top 10 attacking countries (bar chart)
   - Top credentials used (horizontal bar)
   - Common commands (word cloud or bar chart)

5. **Tables**:
   - Recent attacks (paginated)
   - Top attacking IPs
   - Malware samples captured

## Data Flow

```
1. Attacker connects to honeypot
        ↓
2. Cowrie logs interaction → /var/log/cowrie/cowrie.json
        ↓
3. Log Parser reads new entries (tail -f or scheduled task)
        ↓
4. Analyzers process:
   - Geo Analyzer: IP → Location
   - Pattern Analyzer: Detect attack type
   - Command Analyzer: Categorize commands
        ↓
5. Structured data inserted into PostgreSQL
        ↓
6. Dashboard queries database via API
        ↓
7. Frontend renders visualizations
        ↓
8. User views attack intelligence
```

## Deployment Architecture

### Development Environment
```
Local Machine
├── SQLite database
├── Flask development server
└── Test Cowrie instance (containerized)
```

### Production Environment
```
VPS/Cloud Instance (Ubuntu 22.04)
├── Cowrie (systemd service)
├── PostgreSQL (systemd service)
├── Gunicorn + Flask (systemd service)
├── Nginx (reverse proxy)
└── Firewall (ufw)
```

**Ports**:
- 22: Real SSH (key-based authentication only)
- 2222: Cowrie SSH honeypot (or redirect 22 → 2222)
- 80/443: Nginx → Flask dashboard
- 5432: PostgreSQL (localhost only)

## Security Hardening

### Honeypot Host
1. **Firewall Rules**:
   ```bash
   # Allow SSH (real, on non-standard port)
   ufw allow 5022/tcp

   # Allow honeypot
   ufw allow 2222/tcp
   ufw allow 23/tcp

   # Allow web dashboard (restrict to your IP)
   ufw allow from YOUR_IP to any port 80
   ufw allow from YOUR_IP to any port 443

   # Enable firewall
   ufw enable
   ```

2. **SSH Hardening**:
   - Disable password authentication
   - Use key-based auth only
   - Change default port
   - Use fail2ban on real SSH

3. **Resource Limits**:
   ```bash
   # Limit Cowrie CPU and memory
   systemctl edit cowrie
   # Add:
   [Service]
   CPUQuota=50%
   MemoryLimit=512M
   ```

4. **Network Isolation**:
   - Deploy on separate VLAN/VPC
   - No access to internal networks
   - Rate limiting on honeypot ports

### Dashboard Security
1. **Authentication**:
   - Implement login system
   - Use environment variables for secrets
   - Session management

2. **HTTPS**:
   - Let's Encrypt SSL certificate
   - Redirect HTTP → HTTPS
   - HSTS headers

3. **Input Sanitization**:
   - Validate all API inputs
   - Escape output data
   - Prevent SQL injection (use parameterized queries)

## Scaling Considerations

### Single Honeypot (Class Project)
- 1 VPS instance
- PostgreSQL on same host
- Handles ~100-500 attacks/day

### Multiple Honeypots (Future)
- Distributed honeypots (different geolocations)
- Centralized database
- Load balancer for dashboard
- Message queue for log processing (RabbitMQ/Redis)

## Monitoring and Maintenance

### Health Checks
- Monitor Cowrie service status
- Database connection health
- Disk space usage
- Log rotation

### Alerts
- Email notifications for interesting attacks
- Slack/Discord webhooks
- High-volume attack detection

### Backup
- Daily database dumps
- Malware sample preservation
- Configuration backups

## Performance Optimization

1. **Database**:
   - Index frequently queried columns
   - Partition large tables by date
   - Archive old data

2. **Caching**:
   - Redis for API response caching
   - Cache geolocation results
   - Memoize expensive computations

3. **Asynchronous Processing**:
   - Background workers for log processing
   - Celery for task queue
   - Periodic batch processing vs real-time

## Testing Strategy

### Unit Tests
- Log parser accuracy
- Analyzer logic
- Database operations
- API endpoints

### Integration Tests
- End-to-end log processing
- Dashboard rendering
- Database queries

### Security Tests
- SQL injection attempts
- XSS prevention
- Authentication bypass tests

## Technology Alternatives

| Component | Primary Choice | Alternatives |
|-----------|---------------|--------------|
| Honeypot | Cowrie | Kippo, Dionaea, T-Pot |
| Database | PostgreSQL | MySQL, SQLite, MongoDB |
| Web Framework | Flask | Django, FastAPI |
| Frontend | Vanilla JS + Chart.js | React, Vue.js |
| Deployment | VPS | Docker, Kubernetes |
| Web Server | Nginx + Gunicorn | Apache, uWSGI |

## References

- [Cowrie Documentation](https://github.com/cowrie/cowrie)
- [OWASP Honeypot Project](https://owasp.org/www-community/Honeypots)
- [MaxMind GeoIP2](https://www.maxmind.com/en/geoip2-services-and-databases)
- [Flask Documentation](https://flask.palletsprojects.com/)
- [Leaflet.js](https://leafletjs.com/)
- [Chart.js](https://www.chartjs.org/)
