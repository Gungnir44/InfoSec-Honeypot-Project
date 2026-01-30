#!/usr/bin/env python3
"""
Elasticsearch Sync Script

Syncs honeypot data from the database to Elasticsearch for advanced analysis.
"""
import sys
import os
import argparse
import logging
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.config import config
from backend.database.db_manager import DatabaseManager
from backend.integrations import HoneypotElasticsearch, ES_AVAILABLE

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ElasticsearchSync:
    """Sync honeypot data to Elasticsearch"""

    def __init__(self):
        if not ES_AVAILABLE:
            raise ImportError(
                "elasticsearch package not installed.\n"
                "Install it with: pip install elasticsearch"
            )

        self.db_manager = DatabaseManager()

        # Get ES configuration
        es_hosts = config.ELASTICSEARCH_HOSTS if hasattr(config, 'ELASTICSEARCH_HOSTS') else None
        es_cloud_id = config.ELASTICSEARCH_CLOUD_ID if hasattr(config, 'ELASTICSEARCH_CLOUD_ID') else None
        es_api_key = config.ELASTICSEARCH_API_KEY if hasattr(config, 'ELASTICSEARCH_API_KEY') else None
        es_username = config.ELASTICSEARCH_USERNAME if hasattr(config, 'ELASTICSEARCH_USERNAME') else None
        es_password = config.ELASTICSEARCH_PASSWORD if hasattr(config, 'ELASTICSEARCH_PASSWORD') else None

        if not es_hosts and not es_cloud_id:
            # Default to localhost
            es_hosts = ['http://localhost:9200']

        self.es = HoneypotElasticsearch(
            hosts=es_hosts,
            cloud_id=es_cloud_id,
            api_key=es_api_key,
            username=es_username,
            password=es_password
        )

        if not self.es.is_connected:
            raise ConnectionError("Failed to connect to Elasticsearch")

    def setup_indices(self):
        """Create all required indices"""
        logger.info("Setting up Elasticsearch indices...")
        self.es.create_indices()
        logger.info("Indices setup complete")

    def sync_attacks(self, limit: int = 1000) -> int:
        """Sync attack data to Elasticsearch"""
        logger.info(f"Syncing attacks (limit: {limit})...")

        session = self.db_manager.get_session()
        try:
            from backend.database.models import Attack, LoginAttempt, Command, Download

            attacks = session.query(Attack).limit(limit).all()

            documents = []
            for attack in attacks:
                # Get counts
                login_count = session.query(LoginAttempt).filter(
                    LoginAttempt.attack_id == attack.id
                ).count()

                success_count = session.query(LoginAttempt).filter(
                    LoginAttempt.attack_id == attack.id,
                    LoginAttempt.success == True
                ).count()

                cmd_count = session.query(Command).filter(
                    Command.attack_id == attack.id
                ).count()

                dl_count = session.query(Download).filter(
                    Download.attack_id == attack.id
                ).count()

                doc = {
                    "timestamp": attack.timestamp.isoformat() if attack.timestamp else None,
                    "session_id": attack.session_id,
                    "src_ip": attack.src_ip,
                    "src_port": attack.src_port,
                    "dst_port": attack.dst_port,
                    "country": attack.country,
                    "country_code": attack.country_code,
                    "city": attack.city,
                    "region": attack.region,
                    "isp": attack.isp,
                    "organization": attack.organization,
                    "asn": attack.asn,
                    "login_attempts": login_count,
                    "successful_logins": success_count,
                    "commands_count": cmd_count,
                    "downloads_count": dl_count
                }

                # Add geo_point
                if attack.latitude and attack.longitude:
                    doc["location"] = {
                        "lat": float(attack.latitude),
                        "lon": float(attack.longitude)
                    }

                documents.append(doc)

            count = self.es.bulk_index(self.es.INDEX_ATTACKS, documents)
            logger.info(f"Synced {count} attacks")
            return count

        finally:
            session.close()

    def sync_logins(self, limit: int = 5000) -> int:
        """Sync login attempts to Elasticsearch"""
        logger.info(f"Syncing login attempts (limit: {limit})...")

        session = self.db_manager.get_session()
        try:
            from backend.database.models import Attack, LoginAttempt

            logins = (
                session.query(LoginAttempt, Attack)
                .join(Attack, LoginAttempt.attack_id == Attack.id)
                .limit(limit)
                .all()
            )

            documents = []
            for login, attack in logins:
                doc = {
                    "timestamp": login.timestamp.isoformat() if login.timestamp else None,
                    "session_id": attack.session_id,
                    "src_ip": attack.src_ip,
                    "username": login.username,
                    "password": login.password,
                    "success": login.success,
                    "country": attack.country
                }
                documents.append(doc)

            count = self.es.bulk_index(self.es.INDEX_LOGINS, documents)
            logger.info(f"Synced {count} login attempts")
            return count

        finally:
            session.close()

    def sync_commands(self, limit: int = 5000) -> int:
        """Sync commands to Elasticsearch"""
        logger.info(f"Syncing commands (limit: {limit})...")

        session = self.db_manager.get_session()
        try:
            from backend.database.models import Attack, Command

            commands = (
                session.query(Command, Attack)
                .join(Attack, Command.attack_id == Attack.id)
                .limit(limit)
                .all()
            )

            documents = []
            for cmd, attack in commands:
                doc = {
                    "timestamp": cmd.timestamp.isoformat() if cmd.timestamp else None,
                    "session_id": attack.session_id,
                    "src_ip": attack.src_ip,
                    "command": cmd.command,
                    "category": cmd.category,
                    "success": cmd.success,
                    "country": attack.country
                }
                documents.append(doc)

            count = self.es.bulk_index(self.es.INDEX_COMMANDS, documents)
            logger.info(f"Synced {count} commands")
            return count

        finally:
            session.close()

    def sync_downloads(self, limit: int = 1000) -> int:
        """Sync downloads to Elasticsearch"""
        logger.info(f"Syncing downloads (limit: {limit})...")

        session = self.db_manager.get_session()
        try:
            from backend.database.models import Attack, Download

            downloads = (
                session.query(Download, Attack)
                .join(Attack, Download.attack_id == Attack.id)
                .limit(limit)
                .all()
            )

            documents = []
            for dl, attack in downloads:
                doc = {
                    "timestamp": dl.timestamp.isoformat() if dl.timestamp else None,
                    "session_id": attack.session_id,
                    "src_ip": attack.src_ip,
                    "url": dl.url,
                    "filename": dl.filename,
                    "file_hash": dl.file_hash,
                    "file_size": dl.file_size,
                    "malware_detected": dl.malware_detected,
                    "virustotal_score": dl.virustotal_score,
                    "country": attack.country
                }
                documents.append(doc)

            count = self.es.bulk_index(self.es.INDEX_DOWNLOADS, documents)
            logger.info(f"Synced {count} downloads")
            return count

        finally:
            session.close()

    def sync_profiles(self, limit: int = 1000) -> int:
        """Sync attacker profiles to Elasticsearch"""
        logger.info(f"Syncing attacker profiles (limit: {limit})...")

        session = self.db_manager.get_session()
        try:
            from backend.database.models import AttackerProfile
            import json

            profiles = session.query(AttackerProfile).limit(limit).all()

            documents = []
            for p in profiles:
                doc = {
                    "ip_address": p.ip_address,
                    "first_seen": p.first_seen.isoformat() if p.first_seen else None,
                    "last_seen": p.last_seen.isoformat() if p.last_seen else None,
                    "last_updated": p.last_updated.isoformat() if p.last_updated else None,
                    "total_sessions": p.total_sessions,
                    "total_login_attempts": p.total_login_attempts,
                    "total_commands": p.total_commands,
                    "total_downloads": p.total_downloads,
                    "risk_level": p.risk_level,
                    "risk_score": p.risk_score,
                    "sophistication_level": p.sophistication_level,
                    "sophistication_score": p.sophistication_score,
                    "primary_objective": p.primary_objective,
                    "behavioral_traits": json.loads(p.behavioral_traits) if p.behavioral_traits else [],
                    "detected_tools": [t.get('tool') for t in json.loads(p.detected_tools)] if p.detected_tools else [],
                    "has_malware": p.has_malware,
                    "appears_automated": p.appears_automated,
                    "is_persistent": p.is_persistent
                }
                documents.append(doc)

            count = self.es.bulk_index(self.es.INDEX_PROFILES, documents)
            logger.info(f"Synced {count} profiles")
            return count

        finally:
            session.close()

    def sync_threat_intel(self, limit: int = 1000) -> int:
        """Sync threat intelligence to Elasticsearch"""
        logger.info(f"Syncing threat intelligence (limit: {limit})...")

        session = self.db_manager.get_session()
        try:
            from backend.database.models import ThreatIntel
            import json

            intel_records = session.query(ThreatIntel).limit(limit).all()

            documents = []
            for intel in intel_records:
                doc = {
                    "ip_address": intel.ip_address,
                    "last_updated": intel.last_updated.isoformat() if intel.last_updated else None,
                    "abuse_confidence_score": intel.abuse_confidence_score,
                    "abuse_total_reports": intel.abuse_total_reports,
                    "is_tor_exit": intel.is_tor_exit,
                    "threat_level": intel.threat_level,
                    "threat_score": intel.threat_score,
                    "isp": intel.abuse_isp,
                    "domain": intel.abuse_domain,
                    "shodan_ports": json.loads(intel.shodan_ports) if intel.shodan_ports else [],
                    "shodan_vulns_count": intel.shodan_vulns_count,
                    "shodan_org": intel.shodan_org
                }
                documents.append(doc)

            count = self.es.bulk_index(self.es.INDEX_THREAT_INTEL, documents)
            logger.info(f"Synced {count} threat intel records")
            return count

        finally:
            session.close()

    def sync_all(self, limit: int = 1000) -> dict:
        """Sync all data to Elasticsearch"""
        results = {
            'attacks': self.sync_attacks(limit),
            'logins': self.sync_logins(limit * 5),
            'commands': self.sync_commands(limit * 5),
            'downloads': self.sync_downloads(limit),
            'profiles': self.sync_profiles(limit),
            'threat_intel': self.sync_threat_intel(limit)
        }
        return results

    def get_stats(self) -> dict:
        """Get Elasticsearch statistics"""
        return {
            'cluster_health': self.es.get_cluster_health(),
            'index_stats': self.es.get_index_stats()
        }


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='Sync honeypot data to Elasticsearch')

    parser.add_argument(
        '--setup',
        action='store_true',
        help='Create Elasticsearch indices'
    )

    parser.add_argument(
        '--sync-all',
        action='store_true',
        help='Sync all data types'
    )

    parser.add_argument(
        '--sync-attacks',
        action='store_true',
        help='Sync attacks only'
    )

    parser.add_argument(
        '--sync-logins',
        action='store_true',
        help='Sync login attempts only'
    )

    parser.add_argument(
        '--sync-commands',
        action='store_true',
        help='Sync commands only'
    )

    parser.add_argument(
        '--sync-profiles',
        action='store_true',
        help='Sync attacker profiles only'
    )

    parser.add_argument(
        '--stats',
        action='store_true',
        help='Show Elasticsearch statistics'
    )

    parser.add_argument(
        '--limit',
        type=int,
        default=1000,
        help='Maximum records to sync per type (default: 1000)'
    )

    args = parser.parse_args()

    print("=" * 60)
    print("Elasticsearch Sync")
    print("=" * 60)

    if not ES_AVAILABLE:
        print("\nError: elasticsearch package not installed")
        print("Install it with: pip install elasticsearch")
        sys.exit(1)

    try:
        sync = ElasticsearchSync()
        print(f"\nConnected to Elasticsearch")
    except ConnectionError as e:
        print(f"\nError: {e}")
        print("\nMake sure Elasticsearch is running and accessible.")
        print("Default: http://localhost:9200")
        print("\nTo configure, add to .env:")
        print("  ELASTICSEARCH_HOSTS=http://localhost:9200")
        print("  # Or for Elastic Cloud:")
        print("  ELASTICSEARCH_CLOUD_ID=your-cloud-id")
        print("  ELASTICSEARCH_API_KEY=your-api-key")
        sys.exit(1)
    except ImportError as e:
        print(f"\nError: {e}")
        sys.exit(1)

    if args.setup:
        sync.setup_indices()
        print("\nIndices created successfully")

    elif args.stats:
        stats = sync.get_stats()
        print("\nCluster Health:")
        health = stats['cluster_health']
        print(f"  Status: {health.get('status', 'unknown')}")
        print(f"  Nodes: {health.get('number_of_nodes', 0)}")

        print("\nIndex Statistics:")
        for index, info in stats['index_stats'].items():
            if info.get('exists'):
                print(f"  {index}: {info.get('doc_count', 0)} documents")
            else:
                print(f"  {index}: not created")

    elif args.sync_all:
        print(f"\nSyncing all data (limit: {args.limit} per type)...")
        results = sync.sync_all(args.limit)
        print("\nSync Results:")
        for data_type, count in results.items():
            print(f"  {data_type}: {count} documents")

    elif args.sync_attacks:
        count = sync.sync_attacks(args.limit)
        print(f"\nSynced {count} attacks")

    elif args.sync_logins:
        count = sync.sync_logins(args.limit)
        print(f"\nSynced {count} login attempts")

    elif args.sync_commands:
        count = sync.sync_commands(args.limit)
        print(f"\nSynced {count} commands")

    elif args.sync_profiles:
        count = sync.sync_profiles(args.limit)
        print(f"\nSynced {count} profiles")

    else:
        # Default: show stats
        print("\nNo action specified. Use --help for options.")
        print("\nQuick start:")
        print("  1. Start Elasticsearch: docker run -p 9200:9200 elasticsearch:8.11.0")
        print("  2. Create indices: python sync_elasticsearch.py --setup")
        print("  3. Sync data: python sync_elasticsearch.py --sync-all")
        print("  4. Open Kibana: http://localhost:5601")


if __name__ == '__main__':
    main()
