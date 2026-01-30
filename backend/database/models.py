"""
Database models for honeypot data

These SQLAlchemy models represent the structure of attack data
collected by the honeypot system.
"""
from datetime import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Text, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

Base = declarative_base()


class Honeypot(Base):
    """Registered honeypot deployments"""
    __tablename__ = 'honeypots'

    id = Column(Integer, primary_key=True)
    honeypot_id = Column(String(16), unique=True, nullable=False, index=True)
    name = Column(String(100), nullable=False)
    location = Column(String(100))  # Geographic location
    ip_address = Column(String(45))  # Public IP
    honeypot_type = Column(String(50), default='cowrie')  # cowrie, dionaea, etc.
    description = Column(Text)
    api_key_hash = Column(String(64))  # SHA256 hash of API key
    status = Column(String(20), default='active')  # active, inactive, maintenance
    registered_at = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime)
    attack_count = Column(Integer, default=0)

    def __repr__(self):
        return f"<Honeypot {self.name} ({self.honeypot_id})>"


class Attack(Base):
    """Main attack/session table"""
    __tablename__ = 'attacks'

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, nullable=False, index=True)
    src_ip = Column(String(45), nullable=False, index=True)  # IPv4 or IPv6
    src_port = Column(Integer)
    dst_port = Column(Integer)
    session_id = Column(String(255), unique=True, index=True)
    honeypot_id = Column(String(16), index=True)  # Link to reporting honeypot

    # Geolocation data
    country = Column(String(100), index=True)
    country_code = Column(String(10))
    city = Column(String(100))
    region = Column(String(100))
    latitude = Column(Float)
    longitude = Column(Float)
    isp = Column(String(255))
    organization = Column(String(255))
    asn = Column(String(50))

    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    login_attempts = relationship('LoginAttempt', back_populates='attack', cascade='all, delete-orphan')
    commands = relationship('Command', back_populates='attack', cascade='all, delete-orphan')
    sessions = relationship('Session', back_populates='attack', cascade='all, delete-orphan')
    downloads = relationship('Download', back_populates='attack', cascade='all, delete-orphan')

    def __repr__(self):
        return f"<Attack {self.src_ip} at {self.timestamp}>"


class LoginAttempt(Base):
    """Login attempts (successful and failed)"""
    __tablename__ = 'login_attempts'

    id = Column(Integer, primary_key=True)
    attack_id = Column(Integer, ForeignKey('attacks.id'), nullable=False)
    username = Column(String(255), index=True)
    password = Column(String(255), index=True)
    success = Column(Boolean, default=False)
    timestamp = Column(DateTime, nullable=False, index=True)

    attack = relationship('Attack', back_populates='login_attempts')

    def __repr__(self):
        status = "SUCCESS" if self.success else "FAILED"
        return f"<LoginAttempt {self.username}:{self.password} {status}>"


class Command(Base):
    """Commands executed in honeypot"""
    __tablename__ = 'commands'

    id = Column(Integer, primary_key=True)
    attack_id = Column(Integer, ForeignKey('attacks.id'), nullable=False)
    command = Column(Text, nullable=False)
    category = Column(String(50), index=True)  # reconnaissance, download, persistence, etc.
    timestamp = Column(DateTime, nullable=False, index=True)
    success = Column(Boolean, default=True)

    attack = relationship('Attack', back_populates='commands')

    def __repr__(self):
        return f"<Command '{self.command[:50]}' [{self.category}]>"


class Session(Base):
    """Session metadata"""
    __tablename__ = 'sessions'

    id = Column(Integer, primary_key=True)
    session_id = Column(String(255), unique=True, index=True)
    attack_id = Column(Integer, ForeignKey('attacks.id'), nullable=False)
    start_time = Column(DateTime)
    end_time = Column(DateTime)
    duration = Column(Integer)  # seconds
    commands_count = Column(Integer, default=0)
    downloads_count = Column(Integer, default=0)
    login_attempts_count = Column(Integer, default=0)

    attack = relationship('Attack', back_populates='sessions')

    def __repr__(self):
        return f"<Session {self.session_id} duration={self.duration}s>"


class Download(Base):
    """Files downloaded by attackers"""
    __tablename__ = 'downloads'

    id = Column(Integer, primary_key=True)
    attack_id = Column(Integer, ForeignKey('attacks.id'), nullable=False)
    url = Column(Text)
    filename = Column(String(255))
    file_hash = Column(String(64), index=True)  # SHA256
    file_size = Column(Integer)
    timestamp = Column(DateTime, nullable=False)
    malware_detected = Column(Boolean, default=False)
    virustotal_score = Column(String(50))  # e.g., "45/70"

    attack = relationship('Attack', back_populates='downloads')

    def __repr__(self):
        return f"<Download {self.filename} hash={self.file_hash[:16]}>"


class AttackerProfile(Base):
    """Automated attacker profiles"""
    __tablename__ = 'attacker_profiles'

    id = Column(Integer, primary_key=True)
    ip_address = Column(String(45), unique=True, nullable=False, index=True)

    # Statistics
    total_sessions = Column(Integer, default=0)
    total_login_attempts = Column(Integer, default=0)
    successful_logins = Column(Integer, default=0)
    total_commands = Column(Integer, default=0)
    total_downloads = Column(Integer, default=0)
    first_seen = Column(DateTime)
    last_seen = Column(DateTime)
    active_days = Column(Integer, default=0)

    # Classification
    sophistication_level = Column(String(20))  # script_kiddie, basic, intermediate, advanced
    sophistication_score = Column(Integer)
    primary_objective = Column(String(50))
    all_objectives = Column(Text)  # JSON

    # Risk assessment
    risk_level = Column(String(20), index=True)  # low, medium, high, critical
    risk_score = Column(Integer)
    risk_factors = Column(Text)  # JSON

    # Behavioral traits
    behavioral_traits = Column(Text)  # JSON array
    detected_tools = Column(Text)  # JSON array
    credential_patterns = Column(Text)  # JSON array

    # Temporal patterns
    appears_automated = Column(Boolean, default=False)
    peak_hour = Column(Integer)
    peak_day = Column(String(20))

    # Flags
    has_malware = Column(Boolean, default=False)
    uses_obfuscation = Column(Boolean, default=False)
    is_persistent = Column(Boolean, default=False)

    # Recommendations
    recommendations = Column(Text)  # JSON array

    # Metadata
    profile_generated = Column(DateTime, default=datetime.utcnow)
    last_updated = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f"<AttackerProfile {self.ip_address} risk={self.risk_level}>"


class ThreatIntel(Base):
    """Threat intelligence data for IP addresses"""
    __tablename__ = 'threat_intel'

    id = Column(Integer, primary_key=True)
    ip_address = Column(String(45), unique=True, nullable=False, index=True)

    # AbuseIPDB data
    abuse_confidence_score = Column(Integer)  # 0-100
    abuse_total_reports = Column(Integer)
    abuse_last_reported = Column(DateTime)
    is_tor_exit = Column(Boolean, default=False)
    abuse_isp = Column(String(255))
    abuse_domain = Column(String(255))
    abuse_usage_type = Column(String(100))

    # Shodan data
    shodan_ports = Column(Text)  # JSON array of ports
    shodan_vulns_count = Column(Integer)
    shodan_os = Column(String(100))
    shodan_org = Column(String(255))
    shodan_hostnames = Column(Text)  # JSON array

    # Overall assessment
    threat_level = Column(String(20))  # critical, high, medium, low, clean
    threat_score = Column(Integer)  # 0-100
    threat_indicators = Column(Text)  # JSON array

    # Metadata
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_updated = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    enrichment_sources = Column(String(100))  # e.g., "abuseipdb,shodan"

    def __repr__(self):
        return f"<ThreatIntel {self.ip_address} score={self.threat_score}>"
