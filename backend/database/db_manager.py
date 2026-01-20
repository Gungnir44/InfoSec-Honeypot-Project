"""
Database manager for honeypot data

Handles database connections, queries, and CRUD operations.
"""
from sqlalchemy import create_engine, func, desc, and_, or_
from sqlalchemy.orm import sessionmaker, Session as DBSession
from sqlalchemy.exc import SQLAlchemyError
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Tuple
import logging

from .models import Base, Attack, LoginAttempt, Command, Session, Download
from ..config import config

logger = logging.getLogger(__name__)


class DatabaseManager:
    """Manages database operations for honeypot data"""

    def __init__(self, database_uri: str = None):
        """Initialize database connection"""
        self.database_uri = database_uri or config.DATABASE_URI
        self.engine = create_engine(self.database_uri, echo=False)
        self.SessionLocal = sessionmaker(bind=self.engine)

    def create_tables(self):
        """Create all tables if they don't exist"""
        try:
            Base.metadata.create_all(self.engine)
            logger.info("Database tables created successfully")
        except SQLAlchemyError as e:
            logger.error(f"Error creating tables: {e}")
            raise

    def drop_tables(self):
        """Drop all tables (use with caution!)"""
        Base.metadata.drop_all(self.engine)
        logger.warning("All tables dropped")

    def get_session(self) -> DBSession:
        """Get a new database session"""
        return self.SessionLocal()

    # ===== Attack Operations =====

    def add_attack(self, attack_data: Dict) -> Optional[Attack]:
        """Add a new attack record"""
        session = self.get_session()
        try:
            attack = Attack(**attack_data)
            session.add(attack)
            session.commit()
            session.refresh(attack)
            return attack
        except SQLAlchemyError as e:
            session.rollback()
            logger.error(f"Error adding attack: {e}")
            return None
        finally:
            session.close()

    def get_attack_by_session(self, session_id: str) -> Optional[Attack]:
        """Get attack by session ID"""
        session = self.get_session()
        try:
            return session.query(Attack).filter(Attack.session_id == session_id).first()
        finally:
            session.close()

    def get_recent_attacks(self, limit: int = 100) -> List[Attack]:
        """Get most recent attacks"""
        session = self.get_session()
        try:
            return session.query(Attack).order_by(desc(Attack.timestamp)).limit(limit).all()
        finally:
            session.close()

    # ===== Login Attempt Operations =====

    def add_login_attempt(self, login_data: Dict) -> Optional[LoginAttempt]:
        """Add a login attempt"""
        session = self.get_session()
        try:
            login = LoginAttempt(**login_data)
            session.add(login)
            session.commit()
            session.refresh(login)
            return login
        except SQLAlchemyError as e:
            session.rollback()
            logger.error(f"Error adding login attempt: {e}")
            return None
        finally:
            session.close()

    def get_top_credentials(self, limit: int = 20) -> List[Tuple]:
        """Get most common username/password combinations"""
        session = self.get_session()
        try:
            return (
                session.query(
                    LoginAttempt.username,
                    LoginAttempt.password,
                    func.count(LoginAttempt.id).label('count')
                )
                .group_by(LoginAttempt.username, LoginAttempt.password)
                .order_by(desc('count'))
                .limit(limit)
                .all()
            )
        finally:
            session.close()

    def get_top_usernames(self, limit: int = 20) -> List[Tuple]:
        """Get most common usernames"""
        session = self.get_session()
        try:
            return (
                session.query(
                    LoginAttempt.username,
                    func.count(LoginAttempt.id).label('count')
                )
                .group_by(LoginAttempt.username)
                .order_by(desc('count'))
                .limit(limit)
                .all()
            )
        finally:
            session.close()

    # ===== Command Operations =====

    def add_command(self, command_data: Dict) -> Optional[Command]:
        """Add a command execution record"""
        session = self.get_session()
        try:
            command = Command(**command_data)
            session.add(command)
            session.commit()
            session.refresh(command)
            return command
        except SQLAlchemyError as e:
            session.rollback()
            logger.error(f"Error adding command: {e}")
            return None
        finally:
            session.close()

    def get_top_commands(self, limit: int = 20) -> List[Tuple]:
        """Get most executed commands"""
        session = self.get_session()
        try:
            return (
                session.query(
                    Command.command,
                    func.count(Command.id).label('count')
                )
                .group_by(Command.command)
                .order_by(desc('count'))
                .limit(limit)
                .all()
            )
        finally:
            session.close()

    def get_commands_by_category(self) -> List[Tuple]:
        """Get command distribution by category"""
        session = self.get_session()
        try:
            return (
                session.query(
                    Command.category,
                    func.count(Command.id).label('count')
                )
                .group_by(Command.category)
                .order_by(desc('count'))
                .all()
            )
        finally:
            session.close()

    # ===== Statistics and Analytics =====

    def get_attack_stats(self) -> Dict:
        """Get overall attack statistics"""
        session = self.get_session()
        try:
            total_attacks = session.query(func.count(Attack.id)).scalar()
            unique_ips = session.query(func.count(func.distinct(Attack.src_ip))).scalar()
            unique_countries = session.query(func.count(func.distinct(Attack.country))).scalar()

            # Top attacking country
            top_country = (
                session.query(Attack.country, func.count(Attack.id).label('count'))
                .group_by(Attack.country)
                .order_by(desc('count'))
                .first()
            )

            # Time range
            first_attack = session.query(func.min(Attack.timestamp)).scalar()
            last_attack = session.query(func.max(Attack.timestamp)).scalar()

            return {
                'total_attacks': total_attacks or 0,
                'unique_ips': unique_ips or 0,
                'unique_countries': unique_countries or 0,
                'top_country': top_country[0] if top_country else 'N/A',
                'top_country_count': top_country[1] if top_country else 0,
                'first_attack': first_attack,
                'last_attack': last_attack,
            }
        finally:
            session.close()

    def get_attacks_by_country(self) -> List[Tuple]:
        """Get attack distribution by country"""
        session = self.get_session()
        try:
            return (
                session.query(
                    Attack.country,
                    Attack.country_code,
                    func.count(Attack.id).label('count')
                )
                .filter(Attack.country.isnot(None))
                .group_by(Attack.country, Attack.country_code)
                .order_by(desc('count'))
                .all()
            )
        finally:
            session.close()

    def get_attacks_over_time(self, days: int = 30, interval: str = 'day') -> List[Tuple]:
        """Get attack timeline"""
        session = self.get_session()
        try:
            start_date = datetime.utcnow() - timedelta(days=days)

            if interval == 'hour':
                date_trunc = func.date_trunc('hour', Attack.timestamp)
            elif interval == 'day':
                date_trunc = func.date_trunc('day', Attack.timestamp)
            else:  # week
                date_trunc = func.date_trunc('week', Attack.timestamp)

            return (
                session.query(
                    date_trunc.label('time_bucket'),
                    func.count(Attack.id).label('count')
                )
                .filter(Attack.timestamp >= start_date)
                .group_by('time_bucket')
                .order_by('time_bucket')
                .all()
            )
        finally:
            session.close()

    def get_top_attacking_ips(self, limit: int = 20) -> List[Tuple]:
        """Get most active attacking IPs"""
        session = self.get_session()
        try:
            return (
                session.query(
                    Attack.src_ip,
                    Attack.country,
                    func.count(Attack.id).label('count')
                )
                .group_by(Attack.src_ip, Attack.country)
                .order_by(desc('count'))
                .limit(limit)
                .all()
            )
        finally:
            session.close()

    def get_map_data(self) -> List[Dict]:
        """Get data for attack map visualization"""
        session = self.get_session()
        try:
            attacks = (
                session.query(
                    Attack.latitude,
                    Attack.longitude,
                    Attack.country,
                    Attack.city,
                    func.count(Attack.id).label('count')
                )
                .filter(
                    and_(
                        Attack.latitude.isnot(None),
                        Attack.longitude.isnot(None)
                    )
                )
                .group_by(Attack.latitude, Attack.longitude, Attack.country, Attack.city)
                .all()
            )

            return [
                {
                    'lat': float(lat),
                    'lng': float(lng),
                    'country': country,
                    'city': city,
                    'count': count
                }
                for lat, lng, country, city, count in attacks
                if lat and lng
            ]
        finally:
            session.close()

    # ===== Search and Filtering =====

    def search_attacks(
        self,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        country: Optional[str] = None,
        src_ip: Optional[str] = None,
        limit: int = 100
    ) -> List[Attack]:
        """Search attacks with filters"""
        session = self.get_session()
        try:
            query = session.query(Attack)

            if start_date:
                query = query.filter(Attack.timestamp >= start_date)
            if end_date:
                query = query.filter(Attack.timestamp <= end_date)
            if country:
                query = query.filter(Attack.country == country)
            if src_ip:
                query = query.filter(Attack.src_ip == src_ip)

            return query.order_by(desc(Attack.timestamp)).limit(limit).all()
        finally:
            session.close()
