#!/usr/bin/env python3
"""
Attacker Profile Generator

Builds behavioral profiles for attacking IPs based on their activity.
"""
import sys
import os
import argparse
import logging
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.database.db_manager import DatabaseManager
from backend.analyzers import AttackerProfiler

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ProfileGenerator:
    """Generate and manage attacker profiles"""

    def __init__(self):
        self.db_manager = DatabaseManager()
        self.profiler = AttackerProfiler(self.db_manager)

    def profile_ip(self, ip_address: str, save: bool = True) -> dict:
        """Generate profile for a single IP"""
        logger.info(f"Generating profile for {ip_address}")

        profile = self.profiler.build_profile(ip_address)

        if 'error' not in profile and save:
            self.db_manager.save_attacker_profile(profile)
            logger.info(f"Profile saved for {ip_address}")

        return profile

    def profile_all_unprofiled(self, limit: int = 100) -> dict:
        """Profile all IPs that haven't been profiled yet"""
        unprofiled_ips = self.db_manager.get_unprofiled_ips(limit=limit)

        if not unprofiled_ips:
            logger.info("No unprofiled IPs found")
            return {'profiled': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0}

        logger.info(f"Found {len(unprofiled_ips)} IPs to profile")

        stats = {'profiled': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'errors': 0}

        for ip in unprofiled_ips:
            try:
                profile = self.profiler.build_profile(ip)

                if 'error' not in profile:
                    self.db_manager.save_attacker_profile(profile)
                    stats['profiled'] += 1

                    risk_level = profile.get('risk_assessment', {}).get('level', 'low')
                    if risk_level in stats:
                        stats[risk_level] += 1

                    self._log_profile_summary(ip, profile)
                else:
                    stats['errors'] += 1

            except Exception as e:
                logger.error(f"Error profiling {ip}: {e}")
                stats['errors'] += 1

        return stats

    def refresh_all_profiles(self, limit: int = 100) -> dict:
        """Refresh all existing profiles"""
        session = self.db_manager.get_session()
        try:
            from backend.database.models import AttackerProfile
            profiles = session.query(AttackerProfile).limit(limit).all()
            ips = [p.ip_address for p in profiles]
        finally:
            session.close()

        if not ips:
            logger.info("No existing profiles to refresh")
            return {'refreshed': 0}

        logger.info(f"Refreshing {len(ips)} profiles")

        stats = {'refreshed': 0, 'errors': 0}

        for ip in ips:
            try:
                profile = self.profiler.build_profile(ip)
                if 'error' not in profile:
                    self.db_manager.save_attacker_profile(profile)
                    stats['refreshed'] += 1
            except Exception as e:
                logger.error(f"Error refreshing {ip}: {e}")
                stats['errors'] += 1

        return stats

    def _log_profile_summary(self, ip: str, profile: dict):
        """Log a summary of the generated profile"""
        risk = profile.get('risk_assessment', {})
        risk_level = risk.get('level', 'unknown').upper()
        risk_score = risk.get('score', 0)
        soph = profile.get('sophistication', {}).get('level', 'unknown')
        objective = profile.get('objectives', {}).get('primary_objective', 'unknown')

        if risk_level in ['CRITICAL', 'HIGH']:
            logger.warning(f"  [{risk_level}] {ip} - Score: {risk_score}, "
                          f"Sophistication: {soph}, Objective: {objective}")
        else:
            logger.info(f"  [{risk_level}] {ip} - Score: {risk_score}, "
                       f"Sophistication: {soph}, Objective: {objective}")

    def get_stats(self) -> dict:
        """Get profiling statistics"""
        return self.db_manager.get_attacker_profile_stats()

    def get_high_risk(self, min_score: int = 50) -> list:
        """Get high-risk profiles"""
        return self.db_manager.get_high_risk_profiles(min_score=min_score)


def print_profile(profile: dict):
    """Print a detailed profile"""
    if 'error' in profile:
        print(f"\nError: {profile['error']}")
        return

    print("\n" + "=" * 70)
    print(f"ATTACKER PROFILE: {profile['ip_address']}")
    print("=" * 70)

    # Risk Assessment
    risk = profile.get('risk_assessment', {})
    print(f"\nRISK ASSESSMENT")
    print(f"  Level: {risk.get('level', 'unknown').upper()}")
    print(f"  Score: {risk.get('score', 0)}/100")
    if risk.get('factors'):
        print(f"  Factors:")
        for factor in risk['factors']:
            print(f"    - {factor}")

    # Statistics
    stats = profile.get('statistics', {})
    print(f"\nSTATISTICS")
    print(f"  Sessions: {stats.get('total_sessions', 0)}")
    print(f"  Login attempts: {stats.get('total_login_attempts', 0)} "
          f"({stats.get('successful_logins', 0)} successful)")
    print(f"  Commands: {stats.get('total_commands', 0)}")
    print(f"  Downloads: {stats.get('total_downloads', 0)}")
    print(f"  Active period: {stats.get('active_days', 0)} days")
    print(f"  First seen: {stats.get('first_seen', 'N/A')}")
    print(f"  Last seen: {stats.get('last_seen', 'N/A')}")

    # Sophistication
    soph = profile.get('sophistication', {})
    print(f"\nSOPHISTICATION")
    print(f"  Level: {soph.get('level', 'unknown')}")
    print(f"  Score: {soph.get('score', 0)}/100")
    if soph.get('indicators'):
        print(f"  Indicators:")
        for ind in soph['indicators']:
            print(f"    - {ind}")

    # Objectives
    obj = profile.get('objectives', {})
    print(f"\nOBJECTIVES")
    print(f"  Primary: {obj.get('primary_objective', 'unknown')}")
    print(f"  Has malware: {obj.get('has_malware', False)}")
    if obj.get('all_objectives'):
        print(f"  All detected:")
        for name, data in obj['all_objectives'].items():
            print(f"    - {name}: {data.get('confidence', 0)}% confidence")

    # Behavioral Traits
    traits = profile.get('behavioral_traits', [])
    print(f"\nBEHAVIORAL TRAITS")
    if traits:
        print(f"  {', '.join(traits)}")
    else:
        print(f"  None identified")

    # Detected Tools
    tools = profile.get('detected_tools', [])
    print(f"\nDETECTED TOOLS")
    if tools:
        for tool in tools:
            print(f"  - {tool['tool']} ({tool['confidence']} confidence)")
    else:
        print(f"  None detected")

    # Temporal Patterns
    temporal = profile.get('temporal_patterns', {})
    print(f"\nTEMPORAL PATTERNS")
    print(f"  Peak hour: {temporal.get('peak_hour', 'N/A')}:00")
    print(f"  Peak day: {temporal.get('peak_day', 'N/A')}")
    print(f"  Appears automated: {temporal.get('appears_automated', False)}")
    print(f"  Timing consistency: {temporal.get('timing_consistency', 'N/A')}")

    # Credential Patterns
    creds = profile.get('credential_patterns', {})
    print(f"\nCREDENTIAL PATTERNS")
    print(f"  Unique usernames: {creds.get('unique_usernames', 0)}")
    print(f"  Unique passwords: {creds.get('unique_passwords', 0)}")
    if creds.get('detected_patterns'):
        print(f"  Patterns: {', '.join(creds['detected_patterns'])}")
    if creds.get('top_usernames'):
        top_users = list(creds['top_usernames'].items())[:5]
        print(f"  Top usernames: {', '.join(f'{u}({c})' for u, c in top_users)}")

    # Threat Intel
    if 'threat_intel' in profile:
        intel = profile['threat_intel']
        print(f"\nTHREAT INTELLIGENCE")
        print(f"  AbuseIPDB score: {intel.get('abuse_score', 'N/A')}%")
        print(f"  Total reports: {intel.get('total_reports', 'N/A')}")
        print(f"  Tor exit node: {intel.get('is_tor_exit', False)}")

    # Recommendations
    recs = profile.get('recommendations', [])
    print(f"\nRECOMMENDATIONS")
    for rec in recs:
        print(f"  - {rec}")

    print("\n" + "=" * 70)


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='Generate attacker profiles')

    parser.add_argument(
        '--ip',
        type=str,
        help='Profile a specific IP address'
    )

    parser.add_argument(
        '--profile-all',
        action='store_true',
        help='Profile all unprofiled IPs'
    )

    parser.add_argument(
        '--refresh',
        action='store_true',
        help='Refresh all existing profiles'
    )

    parser.add_argument(
        '--stats',
        action='store_true',
        help='Show profiling statistics'
    )

    parser.add_argument(
        '--high-risk',
        action='store_true',
        help='List high-risk attackers'
    )

    parser.add_argument(
        '--limit',
        type=int,
        default=100,
        help='Maximum IPs to profile (default: 100)'
    )

    parser.add_argument(
        '--min-score',
        type=int,
        default=50,
        help='Minimum risk score for --high-risk (default: 50)'
    )

    parser.add_argument(
        '--no-save',
        action='store_true',
        help='Do not save profile to database'
    )

    args = parser.parse_args()

    print("=" * 60)
    print("Attacker Profile Generator")
    print("=" * 60)

    generator = ProfileGenerator()

    if args.stats:
        stats = generator.get_stats()
        print("\nProfiling Statistics:")
        print(f"  Total attacking IPs: {stats['total_attacking_ips']}")
        print(f"  Profiled: {stats['total_profiles']}")
        print(f"  Coverage: {stats['coverage']}%")
        print(f"  Critical risk: {stats['critical_risk']}")
        print(f"  High risk: {stats['high_risk']}")
        print(f"  Advanced attackers: {stats['advanced_attackers']}")
        print(f"  Malware deployers: {stats['malware_deployers']}")
        print(f"  Automated attacks: {stats['automated_attacks']}")

        if stats.get('objective_distribution'):
            print("\n  Objective Distribution:")
            for obj, count in stats['objective_distribution'].items():
                print(f"    - {obj}: {count}")

    elif args.high_risk:
        profiles = generator.get_high_risk(min_score=args.min_score)
        print(f"\nHigh-Risk Attackers (score >= {args.min_score}):")
        if profiles:
            for p in profiles:
                print(f"  {p.ip_address}: Score {p.risk_score} ({p.risk_level}) - "
                      f"{p.sophistication_level}, {p.primary_objective}")
        else:
            print("  No high-risk attackers found")

    elif args.ip:
        profile = generator.profile_ip(args.ip, save=not args.no_save)
        print_profile(profile)

    elif args.refresh:
        print(f"\nRefreshing up to {args.limit} profiles...")
        stats = generator.refresh_all_profiles(limit=args.limit)
        print(f"\nResults:")
        print(f"  Refreshed: {stats['refreshed']}")
        print(f"  Errors: {stats['errors']}")

    else:
        # Default: profile all unprofiled
        print(f"\nProfiling up to {args.limit} IPs...")
        stats = generator.profile_all_unprofiled(limit=args.limit)
        print(f"\nResults:")
        print(f"  Profiled: {stats['profiled']}")
        print(f"  Critical: {stats['critical']}")
        print(f"  High: {stats['high']}")
        print(f"  Medium: {stats['medium']}")
        print(f"  Low: {stats['low']}")
        print(f"  Errors: {stats['errors']}")


if __name__ == '__main__':
    main()
