#!/usr/bin/env python3
"""
Threat Intelligence Enrichment Script

Enriches attacking IPs with data from AbuseIPDB and Shodan.
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
from backend.analyzers import ThreatIntelligenceManager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ThreatIntelEnricher:
    """Enrich IPs with threat intelligence"""

    def __init__(self):
        self.db_manager = DatabaseManager()

        # Check for API keys
        abuseipdb_key = config.ABUSEIPDB_API_KEY if config.ABUSEIPDB_ENABLED else None
        shodan_key = config.SHODAN_API_KEY if config.SHODAN_ENABLED else None

        if not abuseipdb_key and not shodan_key:
            raise ValueError(
                "No threat intelligence API keys configured.\n"
                "Set ABUSEIPDB_API_KEY and/or SHODAN_API_KEY in .env"
            )

        self.threat_intel = ThreatIntelligenceManager(
            abuseipdb_key=abuseipdb_key,
            shodan_key=shodan_key,
            rate_limit=config.THREAT_INTEL_RATE_LIMIT
        )

    def enrich_ip(self, ip_address: str) -> dict:
        """Enrich a single IP address"""
        logger.info(f"Enriching IP: {ip_address}")

        intel_data = self.threat_intel.enrich_ip(ip_address)

        if intel_data:
            # Prepare data for database
            db_data = self._prepare_db_data(intel_data)
            self.db_manager.save_threat_intel(db_data)

        return intel_data

    def enrich_unenriched(self, limit: int = 100) -> dict:
        """Enrich IPs that haven't been checked yet"""
        unenriched_ips = self.db_manager.get_unenriched_ips(
            limit=limit,
            cache_hours=config.THREAT_INTEL_CACHE_HOURS
        )

        if not unenriched_ips:
            logger.info("No IPs need enrichment")
            return {'enriched': 0, 'critical': 0, 'high': 0}

        logger.info(f"Found {len(unenriched_ips)} IPs to enrich")

        stats = {'enriched': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0}

        for ip in unenriched_ips:
            try:
                intel_data = self.threat_intel.enrich_ip(ip)

                if intel_data and intel_data.get('sources'):
                    db_data = self._prepare_db_data(intel_data)
                    self.db_manager.save_threat_intel(db_data)
                    stats['enriched'] += 1

                    threat_level = intel_data.get('threat_assessment', {}).get('threat_level', 'unknown')
                    if threat_level in stats:
                        stats[threat_level] += 1

                    self._log_enrichment_result(ip, intel_data)

            except Exception as e:
                logger.error(f"Error enriching {ip}: {e}")

        return stats

    def _prepare_db_data(self, intel_data: dict) -> dict:
        """Prepare intel data for database storage"""
        db_data = {
            'ip': intel_data.get('ip'),
            'enrichment_sources': ','.join(intel_data.get('sources', []))
        }

        # AbuseIPDB data
        if 'abuseipdb' in intel_data:
            abuse = intel_data['abuseipdb']
            db_data.update({
                'abuse_confidence_score': abuse.get('abuse_confidence_score'),
                'abuse_total_reports': abuse.get('total_reports'),
                'is_tor_exit': abuse.get('is_tor', False),
                'abuse_isp': abuse.get('isp'),
                'abuse_domain': abuse.get('domain'),
                'abuse_usage_type': abuse.get('usage_type')
            })

            if abuse.get('last_reported_at'):
                try:
                    db_data['abuse_last_reported'] = datetime.fromisoformat(
                        abuse['last_reported_at'].replace('Z', '+00:00')
                    )
                except (ValueError, AttributeError):
                    pass

        # Shodan data
        if 'shodan' in intel_data:
            shodan = intel_data['shodan']
            if shodan.get('found'):
                db_data.update({
                    'shodan_ports': shodan.get('ports', []),
                    'shodan_vulns_count': shodan.get('vuln_count', 0),
                    'shodan_os': shodan.get('os'),
                    'shodan_org': shodan.get('org'),
                    'shodan_hostnames': shodan.get('hostnames', [])
                })

        # Threat assessment
        assessment = intel_data.get('threat_assessment', {})
        db_data.update({
            'threat_level': assessment.get('threat_level'),
            'threat_score': assessment.get('overall_score'),
            'threat_indicators': assessment.get('indicators', [])
        })

        return db_data

    def _log_enrichment_result(self, ip: str, intel_data: dict):
        """Log the enrichment result"""
        assessment = intel_data.get('threat_assessment', {})
        threat_level = assessment.get('threat_level', 'unknown').upper()
        score = assessment.get('overall_score', 0)
        indicators = assessment.get('indicators', [])

        if threat_level in ['CRITICAL', 'HIGH']:
            logger.warning(f"  [{threat_level}] {ip} - Score: {score}")
            for indicator in indicators[:3]:
                logger.warning(f"    - {indicator}")
        else:
            logger.info(f"  [{threat_level}] {ip} - Score: {score}")

    def get_stats(self) -> dict:
        """Get current threat intel statistics"""
        return self.db_manager.get_threat_intel_stats()

    def get_high_threats(self, min_score: int = 50) -> list:
        """Get high-threat IPs"""
        return self.db_manager.get_high_threat_ips(min_score=min_score)


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='Enrich IPs with threat intelligence')

    parser.add_argument(
        '--enrich-all',
        action='store_true',
        help='Enrich all unenriched IPs'
    )

    parser.add_argument(
        '--ip',
        type=str,
        help='Enrich a specific IP address'
    )

    parser.add_argument(
        '--stats',
        action='store_true',
        help='Show threat intelligence statistics'
    )

    parser.add_argument(
        '--high-threats',
        action='store_true',
        help='List high-threat IPs'
    )

    parser.add_argument(
        '--limit',
        type=int,
        default=100,
        help='Maximum IPs to enrich (default: 100)'
    )

    parser.add_argument(
        '--min-score',
        type=int,
        default=50,
        help='Minimum threat score for --high-threats (default: 50)'
    )

    args = parser.parse_args()

    print("=" * 60)
    print("Threat Intelligence Enrichment")
    print("=" * 60)

    # Show configuration status
    print(f"\nAbuseIPDB: {'Configured' if config.ABUSEIPDB_API_KEY else 'Not configured'}")
    print(f"Shodan: {'Configured' if config.SHODAN_API_KEY else 'Not configured'}")

    try:
        enricher = ThreatIntelEnricher()
    except ValueError as e:
        print(f"\nError: {e}")
        print("\nTo configure threat intelligence:")
        print("1. Get AbuseIPDB key at https://www.abuseipdb.com/account/api")
        print("2. Get Shodan key at https://account.shodan.io/")
        print("3. Add keys to .env file")
        sys.exit(1)

    if args.stats:
        stats = enricher.get_stats()
        print("\nThreat Intelligence Statistics:")
        print(f"  Total attacking IPs: {stats['total_attacking_ips']}")
        print(f"  Enriched IPs: {stats['total_enriched']}")
        print(f"  Coverage: {stats['enrichment_coverage']}%")
        print(f"  Critical threats: {stats['critical_threats']}")
        print(f"  High threats: {stats['high_threats']}")
        print(f"  Tor exit nodes: {stats['tor_exit_nodes']}")
        print(f"  Average threat score: {stats['average_threat_score']}")

    elif args.high_threats:
        threats = enricher.get_high_threats(min_score=args.min_score)
        print(f"\nHigh-Threat IPs (score >= {args.min_score}):")
        if threats:
            for threat in threats:
                print(f"  {threat.ip_address}: Score {threat.threat_score} ({threat.threat_level})")
                if threat.is_tor_exit:
                    print(f"    [Tor Exit Node]")
        else:
            print("  No high-threat IPs found")

    elif args.ip:
        print(f"\nEnriching IP: {args.ip}")
        result = enricher.enrich_ip(args.ip)

        if result:
            print("\nResults:")
            print(f"  Sources: {', '.join(result.get('sources', []))}")

            assessment = result.get('threat_assessment', {})
            print(f"  Threat Level: {assessment.get('threat_level', 'unknown').upper()}")
            print(f"  Score: {assessment.get('overall_score', 0)}")

            if assessment.get('indicators'):
                print("  Indicators:")
                for indicator in assessment['indicators']:
                    print(f"    - {indicator}")

            print(f"  Recommendation: {assessment.get('recommendation', 'N/A')}")

            if 'abuseipdb' in result:
                abuse = result['abuseipdb']
                print(f"\n  AbuseIPDB:")
                print(f"    Abuse Score: {abuse.get('abuse_confidence_score', 0)}%")
                print(f"    Total Reports: {abuse.get('total_reports', 0)}")
                print(f"    Tor Exit: {abuse.get('is_tor', False)}")
                print(f"    Link: {abuse.get('abuseipdb_link', 'N/A')}")

            if 'shodan' in result and result['shodan'].get('found'):
                shodan = result['shodan']
                print(f"\n  Shodan:")
                print(f"    Organization: {shodan.get('org', 'N/A')}")
                print(f"    Open Ports: {shodan.get('ports', [])}")
                print(f"    Vulnerabilities: {shodan.get('vuln_count', 0)}")
                print(f"    Link: {shodan.get('shodan_link', 'N/A')}")
        else:
            print("\nEnrichment failed or no data available")

    else:
        # Default: enrich unenriched IPs
        print(f"\nEnriching up to {args.limit} IPs...")
        stats = enricher.enrich_unenriched(limit=args.limit)

        print(f"\nResults:")
        print(f"  Enriched: {stats['enriched']}")
        print(f"  Critical: {stats.get('critical', 0)}")
        print(f"  High: {stats.get('high', 0)}")
        print(f"  Medium: {stats.get('medium', 0)}")
        print(f"  Low: {stats.get('low', 0)}")


if __name__ == '__main__':
    main()
