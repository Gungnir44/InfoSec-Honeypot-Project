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

from .models import Base, Attack, LoginAttempt, Command, Session, Download, ThreatIntel, AttackerProfile, Honeypot
import json
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

    # ===== Download/Malware Operations =====

    def add_download(self, download_data: Dict) -> Optional[Download]:
        """Add a download record"""
        session = self.get_session()
        try:
            download = Download(**download_data)
            session.add(download)
            session.commit()
            session.refresh(download)
            return download
        except SQLAlchemyError as e:
            session.rollback()
            logger.error(f"Error adding download: {e}")
            return None
        finally:
            session.close()

    def get_download_by_hash(self, file_hash: str) -> Optional[Download]:
        """Get download by file hash"""
        session = self.get_session()
        try:
            return session.query(Download).filter(Download.file_hash == file_hash).first()
        finally:
            session.close()

    def update_download_virustotal(
        self,
        download_id: int,
        malware_detected: bool,
        virustotal_score: str
    ) -> bool:
        """Update download with VirusTotal results"""
        session = self.get_session()
        try:
            download = session.query(Download).filter(Download.id == download_id).first()
            if download:
                download.malware_detected = malware_detected
                download.virustotal_score = virustotal_score
                session.commit()
                return True
            return False
        except SQLAlchemyError as e:
            session.rollback()
            logger.error(f"Error updating download: {e}")
            return False
        finally:
            session.close()

    def get_recent_downloads(self, limit: int = 50) -> List[Download]:
        """Get recent downloads"""
        session = self.get_session()
        try:
            return (
                session.query(Download)
                .order_by(desc(Download.timestamp))
                .limit(limit)
                .all()
            )
        finally:
            session.close()

    def get_malware_downloads(self, limit: int = 50) -> List[Download]:
        """Get downloads detected as malware"""
        session = self.get_session()
        try:
            return (
                session.query(Download)
                .filter(Download.malware_detected == True)
                .order_by(desc(Download.timestamp))
                .limit(limit)
                .all()
            )
        finally:
            session.close()

    def get_unscanned_downloads(self, limit: int = 100) -> List[Download]:
        """Get downloads not yet scanned by VirusTotal"""
        session = self.get_session()
        try:
            return (
                session.query(Download)
                .filter(
                    and_(
                        Download.file_hash.isnot(None),
                        Download.virustotal_score.is_(None)
                    )
                )
                .limit(limit)
                .all()
            )
        finally:
            session.close()

    def get_download_stats(self) -> Dict:
        """Get download/malware statistics"""
        session = self.get_session()
        try:
            total_downloads = session.query(func.count(Download.id)).scalar() or 0
            malware_count = (
                session.query(func.count(Download.id))
                .filter(Download.malware_detected == True)
                .scalar() or 0
            )
            scanned_count = (
                session.query(func.count(Download.id))
                .filter(Download.virustotal_score.isnot(None))
                .scalar() or 0
            )
            unique_hashes = (
                session.query(func.count(func.distinct(Download.file_hash)))
                .scalar() or 0
            )

            return {
                'total_downloads': total_downloads,
                'malware_detected': malware_count,
                'scanned_count': scanned_count,
                'unscanned_count': total_downloads - scanned_count,
                'unique_files': unique_hashes,
                'malware_rate': round(malware_count / scanned_count * 100, 1) if scanned_count > 0 else 0
            }
        finally:
            session.close()

    def get_downloads_with_attack_info(self, limit: int = 50) -> List[Dict]:
        """Get downloads with associated attack information"""
        session = self.get_session()
        try:
            results = (
                session.query(Download, Attack)
                .join(Attack, Download.attack_id == Attack.id)
                .order_by(desc(Download.timestamp))
                .limit(limit)
                .all()
            )

            return [
                {
                    'id': download.id,
                    'url': download.url,
                    'filename': download.filename,
                    'file_hash': download.file_hash,
                    'file_size': download.file_size,
                    'timestamp': download.timestamp,
                    'malware_detected': download.malware_detected,
                    'virustotal_score': download.virustotal_score,
                    'src_ip': attack.src_ip,
                    'country': attack.country,
                    'session_id': attack.session_id
                }
                for download, attack in results
            ]
        finally:
            session.close()

    # ===== Threat Intelligence Operations =====

    def get_threat_intel(self, ip_address: str) -> Optional[ThreatIntel]:
        """Get threat intel for an IP address"""
        session = self.get_session()
        try:
            return session.query(ThreatIntel).filter(
                ThreatIntel.ip_address == ip_address
            ).first()
        finally:
            session.close()

    def save_threat_intel(self, intel_data: Dict) -> Optional[ThreatIntel]:
        """Save or update threat intelligence for an IP"""
        session = self.get_session()
        try:
            ip_address = intel_data.get('ip')
            if not ip_address:
                return None

            # Check if exists
            existing = session.query(ThreatIntel).filter(
                ThreatIntel.ip_address == ip_address
            ).first()

            if existing:
                # Update existing record
                for key, value in intel_data.items():
                    if hasattr(existing, key) and key != 'id':
                        setattr(existing, key, value)
                existing.last_updated = datetime.utcnow()
                session.commit()
                session.refresh(existing)
                return existing
            else:
                # Create new record
                threat_intel = ThreatIntel(
                    ip_address=ip_address,
                    abuse_confidence_score=intel_data.get('abuse_confidence_score'),
                    abuse_total_reports=intel_data.get('abuse_total_reports'),
                    abuse_last_reported=intel_data.get('abuse_last_reported'),
                    is_tor_exit=intel_data.get('is_tor_exit', False),
                    abuse_isp=intel_data.get('abuse_isp'),
                    abuse_domain=intel_data.get('abuse_domain'),
                    abuse_usage_type=intel_data.get('abuse_usage_type'),
                    shodan_ports=json.dumps(intel_data.get('shodan_ports', [])),
                    shodan_vulns_count=intel_data.get('shodan_vulns_count'),
                    shodan_os=intel_data.get('shodan_os'),
                    shodan_org=intel_data.get('shodan_org'),
                    shodan_hostnames=json.dumps(intel_data.get('shodan_hostnames', [])),
                    threat_level=intel_data.get('threat_level'),
                    threat_score=intel_data.get('threat_score'),
                    threat_indicators=json.dumps(intel_data.get('threat_indicators', [])),
                    enrichment_sources=intel_data.get('enrichment_sources', '')
                )
                session.add(threat_intel)
                session.commit()
                session.refresh(threat_intel)
                return threat_intel

        except SQLAlchemyError as e:
            session.rollback()
            logger.error(f"Error saving threat intel: {e}")
            return None
        finally:
            session.close()

    def get_high_threat_ips(self, min_score: int = 50, limit: int = 50) -> List[ThreatIntel]:
        """Get IPs with high threat scores"""
        session = self.get_session()
        try:
            return (
                session.query(ThreatIntel)
                .filter(ThreatIntel.threat_score >= min_score)
                .order_by(desc(ThreatIntel.threat_score))
                .limit(limit)
                .all()
            )
        finally:
            session.close()

    def get_tor_exit_nodes(self) -> List[ThreatIntel]:
        """Get IPs identified as Tor exit nodes"""
        session = self.get_session()
        try:
            return (
                session.query(ThreatIntel)
                .filter(ThreatIntel.is_tor_exit == True)
                .all()
            )
        finally:
            session.close()

    def get_unenriched_ips(self, limit: int = 100, cache_hours: int = 24) -> List[str]:
        """Get attacking IPs not yet enriched or with stale data"""
        session = self.get_session()
        try:
            # Get all unique attacking IPs
            attacking_ips = (
                session.query(Attack.src_ip)
                .distinct()
                .all()
            )
            attacking_ips = [ip[0] for ip in attacking_ips]

            # Get recently enriched IPs
            cache_cutoff = datetime.utcnow() - timedelta(hours=cache_hours)
            enriched_ips = (
                session.query(ThreatIntel.ip_address)
                .filter(ThreatIntel.last_updated >= cache_cutoff)
                .all()
            )
            enriched_ips = set(ip[0] for ip in enriched_ips)

            # Return IPs that need enrichment
            unenriched = [ip for ip in attacking_ips if ip not in enriched_ips]
            return unenriched[:limit]

        finally:
            session.close()

    def get_threat_intel_stats(self) -> Dict:
        """Get threat intelligence statistics"""
        session = self.get_session()
        try:
            total_enriched = session.query(func.count(ThreatIntel.id)).scalar() or 0

            critical_count = (
                session.query(func.count(ThreatIntel.id))
                .filter(ThreatIntel.threat_level == 'critical')
                .scalar() or 0
            )

            high_count = (
                session.query(func.count(ThreatIntel.id))
                .filter(ThreatIntel.threat_level == 'high')
                .scalar() or 0
            )

            tor_count = (
                session.query(func.count(ThreatIntel.id))
                .filter(ThreatIntel.is_tor_exit == True)
                .scalar() or 0
            )

            avg_score = (
                session.query(func.avg(ThreatIntel.threat_score))
                .scalar() or 0
            )

            # Count unique attacking IPs
            total_attacking_ips = (
                session.query(func.count(func.distinct(Attack.src_ip)))
                .scalar() or 0
            )

            return {
                'total_enriched': total_enriched,
                'total_attacking_ips': total_attacking_ips,
                'enrichment_coverage': round(total_enriched / total_attacking_ips * 100, 1) if total_attacking_ips > 0 else 0,
                'critical_threats': critical_count,
                'high_threats': high_count,
                'tor_exit_nodes': tor_count,
                'average_threat_score': round(float(avg_score), 1)
            }
        finally:
            session.close()

    def get_attacks_with_threat_intel(self, limit: int = 50) -> List[Dict]:
        """Get recent attacks with associated threat intelligence"""
        session = self.get_session()
        try:
            # Left join to include attacks without threat intel
            results = (
                session.query(Attack, ThreatIntel)
                .outerjoin(ThreatIntel, Attack.src_ip == ThreatIntel.ip_address)
                .order_by(desc(Attack.timestamp))
                .limit(limit)
                .all()
            )

            return [
                {
                    'attack_id': attack.id,
                    'timestamp': attack.timestamp,
                    'src_ip': attack.src_ip,
                    'country': attack.country,
                    'city': attack.city,
                    'session_id': attack.session_id,
                    'threat_score': intel.threat_score if intel else None,
                    'threat_level': intel.threat_level if intel else None,
                    'abuse_score': intel.abuse_confidence_score if intel else None,
                    'is_tor': intel.is_tor_exit if intel else False,
                    'vuln_count': intel.shodan_vulns_count if intel else None
                }
                for attack, intel in results
            ]
        finally:
            session.close()

    # ===== Attacker Profile Operations =====

    def save_attacker_profile(self, profile_data: Dict) -> Optional[AttackerProfile]:
        """Save or update an attacker profile"""
        session = self.get_session()
        try:
            ip_address = profile_data.get('ip_address')
            if not ip_address:
                return None

            existing = session.query(AttackerProfile).filter(
                AttackerProfile.ip_address == ip_address
            ).first()

            stats = profile_data.get('statistics', {})
            objectives = profile_data.get('objectives', {})
            sophistication = profile_data.get('sophistication', {})
            risk = profile_data.get('risk_assessment', {})
            temporal = profile_data.get('temporal_patterns', {})
            creds = profile_data.get('credential_patterns', {})
            commands = profile_data.get('command_patterns', {})

            profile_dict = {
                'ip_address': ip_address,
                'total_sessions': stats.get('total_sessions', 0),
                'total_login_attempts': stats.get('total_login_attempts', 0),
                'successful_logins': stats.get('successful_logins', 0),
                'total_commands': stats.get('total_commands', 0),
                'total_downloads': stats.get('total_downloads', 0),
                'active_days': stats.get('active_days', 0),
                'sophistication_level': sophistication.get('level'),
                'sophistication_score': sophistication.get('score'),
                'primary_objective': objectives.get('primary_objective'),
                'all_objectives': json.dumps(objectives.get('all_objectives', {})),
                'risk_level': risk.get('level'),
                'risk_score': risk.get('score'),
                'risk_factors': json.dumps(risk.get('factors', [])),
                'behavioral_traits': json.dumps(profile_data.get('behavioral_traits', [])),
                'detected_tools': json.dumps(profile_data.get('detected_tools', [])),
                'credential_patterns': json.dumps(creds.get('detected_patterns', [])),
                'appears_automated': temporal.get('appears_automated', False),
                'peak_hour': temporal.get('peak_hour'),
                'peak_day': temporal.get('peak_day'),
                'has_malware': objectives.get('has_malware', False),
                'uses_obfuscation': commands.get('uses_obfuscation', False),
                'is_persistent': 'persistent' in profile_data.get('behavioral_traits', []),
                'recommendations': json.dumps(profile_data.get('recommendations', []))
            }

            # Parse dates
            if stats.get('first_seen'):
                try:
                    profile_dict['first_seen'] = datetime.fromisoformat(stats['first_seen'].replace('Z', '+00:00'))
                except (ValueError, AttributeError):
                    pass

            if stats.get('last_seen'):
                try:
                    profile_dict['last_seen'] = datetime.fromisoformat(stats['last_seen'].replace('Z', '+00:00'))
                except (ValueError, AttributeError):
                    pass

            if existing:
                for key, value in profile_dict.items():
                    if key != 'ip_address':
                        setattr(existing, key, value)
                existing.last_updated = datetime.utcnow()
                session.commit()
                session.refresh(existing)
                return existing
            else:
                profile = AttackerProfile(**profile_dict)
                session.add(profile)
                session.commit()
                session.refresh(profile)
                return profile

        except SQLAlchemyError as e:
            session.rollback()
            logger.error(f"Error saving attacker profile: {e}")
            return None
        finally:
            session.close()

    def get_attacker_profile(self, ip_address: str) -> Optional[AttackerProfile]:
        """Get attacker profile by IP"""
        session = self.get_session()
        try:
            return session.query(AttackerProfile).filter(
                AttackerProfile.ip_address == ip_address
            ).first()
        finally:
            session.close()

    def get_high_risk_profiles(self, min_score: int = 50, limit: int = 50) -> List[AttackerProfile]:
        """Get high-risk attacker profiles"""
        session = self.get_session()
        try:
            return (
                session.query(AttackerProfile)
                .filter(AttackerProfile.risk_score >= min_score)
                .order_by(desc(AttackerProfile.risk_score))
                .limit(limit)
                .all()
            )
        finally:
            session.close()

    def get_profiles_by_objective(self, objective: str, limit: int = 50) -> List[AttackerProfile]:
        """Get profiles with a specific primary objective"""
        session = self.get_session()
        try:
            return (
                session.query(AttackerProfile)
                .filter(AttackerProfile.primary_objective == objective)
                .order_by(desc(AttackerProfile.risk_score))
                .limit(limit)
                .all()
            )
        finally:
            session.close()

    def get_profiles_by_sophistication(self, level: str, limit: int = 50) -> List[AttackerProfile]:
        """Get profiles with a specific sophistication level"""
        session = self.get_session()
        try:
            return (
                session.query(AttackerProfile)
                .filter(AttackerProfile.sophistication_level == level)
                .order_by(desc(AttackerProfile.risk_score))
                .limit(limit)
                .all()
            )
        finally:
            session.close()

    def get_unprofiled_ips(self, limit: int = 100) -> List[str]:
        """Get attacking IPs that haven't been profiled yet"""
        session = self.get_session()
        try:
            attacking_ips = (
                session.query(Attack.src_ip)
                .distinct()
                .all()
            )
            attacking_ips = set(ip[0] for ip in attacking_ips)

            profiled_ips = (
                session.query(AttackerProfile.ip_address)
                .all()
            )
            profiled_ips = set(ip[0] for ip in profiled_ips)

            unprofiled = list(attacking_ips - profiled_ips)
            return unprofiled[:limit]
        finally:
            session.close()

    def get_attacker_profile_stats(self) -> Dict:
        """Get attacker profiling statistics"""
        session = self.get_session()
        try:
            total_profiles = session.query(func.count(AttackerProfile.id)).scalar() or 0
            total_attacking_ips = session.query(func.count(func.distinct(Attack.src_ip))).scalar() or 0

            critical_count = session.query(func.count(AttackerProfile.id)).filter(
                AttackerProfile.risk_level == 'critical'
            ).scalar() or 0

            high_count = session.query(func.count(AttackerProfile.id)).filter(
                AttackerProfile.risk_level == 'high'
            ).scalar() or 0

            advanced_count = session.query(func.count(AttackerProfile.id)).filter(
                AttackerProfile.sophistication_level == 'advanced'
            ).scalar() or 0

            malware_count = session.query(func.count(AttackerProfile.id)).filter(
                AttackerProfile.has_malware == True
            ).scalar() or 0

            automated_count = session.query(func.count(AttackerProfile.id)).filter(
                AttackerProfile.appears_automated == True
            ).scalar() or 0

            # Get objective distribution
            objectives = session.query(
                AttackerProfile.primary_objective,
                func.count(AttackerProfile.id)
            ).group_by(AttackerProfile.primary_objective).all()

            return {
                'total_profiles': total_profiles,
                'total_attacking_ips': total_attacking_ips,
                'coverage': round(total_profiles / total_attacking_ips * 100, 1) if total_attacking_ips > 0 else 0,
                'critical_risk': critical_count,
                'high_risk': high_count,
                'advanced_attackers': advanced_count,
                'malware_deployers': malware_count,
                'automated_attacks': automated_count,
                'objective_distribution': {obj: count for obj, count in objectives if obj}
            }
        finally:
            session.close()

    # ===== Honeypot Management Operations =====

    def save_honeypot(self, honeypot_data: Dict) -> Optional[Honeypot]:
        """Save a new honeypot registration"""
        session = self.get_session()
        try:
            honeypot = Honeypot(
                honeypot_id=honeypot_data['honeypot_id'],
                name=honeypot_data['name'],
                location=honeypot_data.get('location'),
                ip_address=honeypot_data.get('ip_address'),
                honeypot_type=honeypot_data.get('honeypot_type', 'cowrie'),
                description=honeypot_data.get('description'),
                api_key_hash=honeypot_data.get('api_key_hash'),
                status=honeypot_data.get('status', 'active'),
                registered_at=honeypot_data.get('registered_at', datetime.utcnow()),
                last_seen=honeypot_data.get('last_seen')
            )
            session.add(honeypot)
            session.commit()
            session.refresh(honeypot)
            return honeypot
        except SQLAlchemyError as e:
            session.rollback()
            logger.error(f"Error saving honeypot: {e}")
            return None
        finally:
            session.close()

    def get_honeypot(self, honeypot_id: str) -> Optional[Honeypot]:
        """Get honeypot by ID"""
        session = self.get_session()
        try:
            return session.query(Honeypot).filter(
                Honeypot.honeypot_id == honeypot_id
            ).first()
        finally:
            session.close()

    def get_honeypot_by_name(self, name: str) -> Optional[Honeypot]:
        """Get honeypot by name"""
        session = self.get_session()
        try:
            return session.query(Honeypot).filter(
                Honeypot.name == name
            ).first()
        finally:
            session.close()

    def get_all_honeypots(self) -> List[Honeypot]:
        """Get all registered honeypots"""
        session = self.get_session()
        try:
            return session.query(Honeypot).order_by(Honeypot.name).all()
        finally:
            session.close()

    def update_honeypot_heartbeat(self, honeypot_id: str) -> bool:
        """Update honeypot last seen timestamp"""
        session = self.get_session()
        try:
            honeypot = session.query(Honeypot).filter(
                Honeypot.honeypot_id == honeypot_id
            ).first()
            if honeypot:
                honeypot.last_seen = datetime.utcnow()
                session.commit()
                return True
            return False
        except SQLAlchemyError as e:
            session.rollback()
            logger.error(f"Error updating heartbeat: {e}")
            return False
        finally:
            session.close()

    def update_honeypot_status(self, honeypot_id: str, status: str) -> bool:
        """Update honeypot status"""
        session = self.get_session()
        try:
            honeypot = session.query(Honeypot).filter(
                Honeypot.honeypot_id == honeypot_id
            ).first()
            if honeypot:
                honeypot.status = status
                session.commit()
                return True
            return False
        except SQLAlchemyError as e:
            session.rollback()
            logger.error(f"Error updating status: {e}")
            return False
        finally:
            session.close()

    def increment_honeypot_attack_count(self, honeypot_id: str, count: int = 1) -> bool:
        """Increment attack count for a honeypot"""
        session = self.get_session()
        try:
            honeypot = session.query(Honeypot).filter(
                Honeypot.honeypot_id == honeypot_id
            ).first()
            if honeypot:
                honeypot.attack_count = (honeypot.attack_count or 0) + count
                session.commit()
                return True
            return False
        except SQLAlchemyError as e:
            session.rollback()
            logger.error(f"Error incrementing attack count: {e}")
            return False
        finally:
            session.close()

    def delete_honeypot(self, honeypot_id: str) -> bool:
        """Delete a honeypot registration"""
        session = self.get_session()
        try:
            honeypot = session.query(Honeypot).filter(
                Honeypot.honeypot_id == honeypot_id
            ).first()
            if honeypot:
                session.delete(honeypot)
                session.commit()
                return True
            return False
        except SQLAlchemyError as e:
            session.rollback()
            logger.error(f"Error deleting honeypot: {e}")
            return False
        finally:
            session.close()

    def get_multi_honeypot_attacks(self, hours: int = 24) -> List[Dict]:
        """Get attacks from multiple honeypots for correlation"""
        session = self.get_session()
        try:
            start_time = datetime.utcnow() - timedelta(hours=hours)

            attacks = (
                session.query(Attack, LoginAttempt)
                .outerjoin(LoginAttempt, Attack.id == LoginAttempt.attack_id)
                .filter(Attack.timestamp >= start_time)
                .all()
            )

            result = []
            for attack, login in attacks:
                result.append({
                    'id': attack.id,
                    'timestamp': attack.timestamp,
                    'src_ip': attack.src_ip,
                    'honeypot_id': attack.honeypot_id,
                    'country': attack.country,
                    'session_id': attack.session_id,
                    'username': login.username if login else None,
                    'password': login.password if login else None
                })

            return result
        finally:
            session.close()

    def get_honeypot_stats(self) -> Dict:
        """Get statistics for all honeypots"""
        session = self.get_session()
        try:
            total = session.query(func.count(Honeypot.id)).scalar() or 0

            # Active in last 5 minutes
            active_cutoff = datetime.utcnow() - timedelta(minutes=5)
            active = session.query(func.count(Honeypot.id)).filter(
                Honeypot.last_seen >= active_cutoff
            ).scalar() or 0

            total_attacks = session.query(func.sum(Honeypot.attack_count)).scalar() or 0

            # Attacks by honeypot
            honeypots = session.query(Honeypot).all()
            by_honeypot = {h.name: h.attack_count or 0 for h in honeypots}

            return {
                'total_honeypots': total,
                'active_honeypots': active,
                'offline_honeypots': total - active,
                'total_attacks': total_attacks,
                'attacks_by_honeypot': by_honeypot
            }
        finally:
            session.close()
