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


class Attack(Base):
    """Main attack/session table"""
    __tablename__ = 'attacks'

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, nullable=False, index=True)
    src_ip = Column(String(45), nullable=False, index=True)  # IPv4 or IPv6
    src_port = Column(Integer)
    dst_port = Column(Integer)
    session_id = Column(String(255), unique=True, index=True)

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
