#!/usr/bin/env python3
"""
Honeypot Management Script

Manage multi-honeypot deployments from the command line.
"""
import sys
import os
import argparse
import logging

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.database.db_manager import DatabaseManager
from backend.coordination import HoneypotManager, AttackCorrelator

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def register_honeypot(args):
    """Register a new honeypot"""
    db_manager = DatabaseManager()
    manager = HoneypotManager(db_manager)

    result = manager.register_honeypot(
        name=args.name,
        location=args.location,
        ip_address=args.ip,
        honeypot_type=args.type,
        description=args.description
    )

    if 'error' in result:
        print(f"\nError: {result['error']}")
        return

    print("\n" + "=" * 60)
    print("HONEYPOT REGISTERED SUCCESSFULLY")
    print("=" * 60)
    print(f"\nHoneypot ID: {result['honeypot_id']}")
    print(f"Name: {args.name}")
    print(f"\nAPI Key: {result['api_key']}")
    print("\n" + "-" * 60)
    print("IMPORTANT: Save this API key securely!")
    print("It cannot be retrieved later.")
    print("-" * 60)
    print("\nTo deploy the agent on your honeypot:")
    print(f"  python honeypot_agent.py \\")
    print(f"    --server https://your-server.com \\")
    print(f"    --honeypot-id {result['honeypot_id']} \\")
    print(f"    --api-key {result['api_key']}")


def list_honeypots(args):
    """List all registered honeypots"""
    db_manager = DatabaseManager()
    manager = HoneypotManager(db_manager)

    status = manager.get_honeypot_status()

    print("\n" + "=" * 60)
    print("REGISTERED HONEYPOTS")
    print("=" * 60)
    print(f"\nTotal: {status['total']} | Active: {status['active']}")
    print("-" * 60)

    for hp in status['honeypots']:
        status_icon = "[ONLINE]" if hp['status'] == 'online' else "[OFFLINE]"
        print(f"\n{status_icon} {hp['name']}")
        print(f"  ID: {hp['honeypot_id']}")
        print(f"  Location: {hp['location'] or 'Not set'}")
        print(f"  IP: {hp['ip_address'] or 'Not set'}")
        print(f"  Type: {hp['honeypot_type']}")
        print(f"  Attacks: {hp['attack_count']}")
        print(f"  Last seen: {hp['last_seen'] or 'Never'}")


def show_stats(args):
    """Show honeypot statistics"""
    db_manager = DatabaseManager()
    stats = db_manager.get_honeypot_stats()

    print("\n" + "=" * 60)
    print("HONEYPOT STATISTICS")
    print("=" * 60)
    print(f"\nTotal honeypots: {stats['total_honeypots']}")
    print(f"Active (online): {stats['active_honeypots']}")
    print(f"Offline: {stats['offline_honeypots']}")
    print(f"Total attacks: {stats['total_attacks']}")

    if stats['attacks_by_honeypot']:
        print("\nAttacks by Honeypot:")
        for name, count in stats['attacks_by_honeypot'].items():
            print(f"  {name}: {count}")


def show_correlations(args):
    """Show attack correlations"""
    db_manager = DatabaseManager()
    correlator = AttackCorrelator(db_manager)

    print("\n" + "=" * 60)
    print(f"ATTACK CORRELATIONS (Last {args.hours} hours)")
    print("=" * 60)

    # Get coordinated attacks
    coordinated = correlator.find_coordinated_attacks(
        hours=args.hours,
        min_honeypots=args.min_honeypots
    )

    print(f"\nCoordinated Attacks (IPs hitting {args.min_honeypots}+ honeypots):")
    print("-" * 60)

    if coordinated:
        for attack in coordinated[:10]:
            print(f"\n  IP: {attack['src_ip']}")
            print(f"  Honeypots attacked: {attack['honeypot_count']}")
            print(f"  Total attacks: {attack['total_attacks']}")
            print(f"  Time span: {attack['time_span_minutes']} minutes")
            print(f"  Attack velocity: {attack['attack_velocity']}/hour")
    else:
        print("  No coordinated attacks detected")

    # Get campaigns
    campaigns = correlator.detect_distributed_campaigns(hours=args.hours)

    print(f"\n\nDistributed Campaigns (Multiple IPs, same credentials):")
    print("-" * 60)

    if campaigns:
        for campaign in campaigns[:5]:
            print(f"\n  Credential: {campaign['username']}:{campaign['password'][:8]}...")
            print(f"  Unique source IPs: {campaign['unique_source_ips']}")
            print(f"  Campaign type: {campaign['campaign_type']}")
            print(f"  Total attempts: {campaign['total_attempts']}")
    else:
        print("  No distributed campaigns detected")

    # Get overall stats
    stats = correlator.get_cross_honeypot_statistics(hours=args.hours)

    print(f"\n\nCross-Honeypot Statistics:")
    print("-" * 60)
    print(f"  Total attacks: {stats['total_attacks']}")
    print(f"  Unique IPs: {stats['unique_ips']}")
    print(f"  Active honeypots: {stats['honeypots_active']}")
    print(f"  Multi-honeypot attackers: {stats['multi_honeypot_attackers']}")
    print(f"  Coordinated attack %: {stats['coordinated_attack_percentage']}%")


def deactivate_honeypot(args):
    """Deactivate a honeypot"""
    db_manager = DatabaseManager()
    manager = HoneypotManager(db_manager)

    if manager.deactivate_honeypot(args.honeypot_id):
        print(f"\nHoneypot {args.honeypot_id} deactivated")
    else:
        print(f"\nFailed to deactivate honeypot {args.honeypot_id}")


def delete_honeypot(args):
    """Delete a honeypot"""
    db_manager = DatabaseManager()

    # Confirm deletion
    confirm = input(f"Delete honeypot {args.honeypot_id}? (yes/no): ")
    if confirm.lower() != 'yes':
        print("Cancelled")
        return

    if db_manager.delete_honeypot(args.honeypot_id):
        print(f"\nHoneypot {args.honeypot_id} deleted")
    else:
        print(f"\nFailed to delete honeypot {args.honeypot_id}")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Manage multi-honeypot deployments'
    )

    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # Register command
    reg_parser = subparsers.add_parser('register', help='Register a new honeypot')
    reg_parser.add_argument('--name', required=True, help='Unique name for the honeypot')
    reg_parser.add_argument('--location', help='Geographic location (e.g., US-East)')
    reg_parser.add_argument('--ip', help='Public IP address')
    reg_parser.add_argument('--type', default='cowrie', help='Honeypot type (default: cowrie)')
    reg_parser.add_argument('--description', help='Description')
    reg_parser.set_defaults(func=register_honeypot)

    # List command
    list_parser = subparsers.add_parser('list', help='List all honeypots')
    list_parser.set_defaults(func=list_honeypots)

    # Stats command
    stats_parser = subparsers.add_parser('stats', help='Show honeypot statistics')
    stats_parser.set_defaults(func=show_stats)

    # Correlations command
    corr_parser = subparsers.add_parser('correlations', help='Show attack correlations')
    corr_parser.add_argument('--hours', type=int, default=24, help='Hours to analyze (default: 24)')
    corr_parser.add_argument('--min-honeypots', type=int, default=2, help='Min honeypots for correlation (default: 2)')
    corr_parser.set_defaults(func=show_correlations)

    # Deactivate command
    deact_parser = subparsers.add_parser('deactivate', help='Deactivate a honeypot')
    deact_parser.add_argument('honeypot_id', help='Honeypot ID to deactivate')
    deact_parser.set_defaults(func=deactivate_honeypot)

    # Delete command
    del_parser = subparsers.add_parser('delete', help='Delete a honeypot')
    del_parser.add_argument('honeypot_id', help='Honeypot ID to delete')
    del_parser.set_defaults(func=delete_honeypot)

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    print("=" * 60)
    print("Honeypot Management")
    print("=" * 60)

    args.func(args)


if __name__ == '__main__':
    main()
