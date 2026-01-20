#!/usr/bin/env python3
"""
Database Setup Script

Initializes the PostgreSQL database and creates all required tables.
"""
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.database.db_manager import DatabaseManager
from backend.config import config


def main():
    """Initialize database"""
    print("=" * 60)
    print("Honeypot Database Setup")
    print("=" * 60)

    # Show configuration
    print(f"\nDatabase URI: {config.DATABASE_URI}")

    # Validate configuration
    errors = config.validate()
    if errors:
        print("\n⚠️  Configuration Issues:")
        for error in errors:
            print(f"  - {error}")
        print()

    # Confirm
    response = input("\nCreate/update database tables? [y/N]: ")
    if response.lower() != 'y':
        print("Aborted.")
        return

    # Initialize database manager
    db_manager = DatabaseManager()

    try:
        # Create tables
        print("\nCreating tables...")
        db_manager.create_tables()
        print("✓ Tables created successfully")

        # Test connection
        print("\nTesting database connection...")
        stats = db_manager.get_attack_stats()
        print(f"✓ Connection successful")
        print(f"  Current stats: {stats['total_attacks']} attacks recorded")

        print("\n" + "=" * 60)
        print("Database setup complete!")
        print("=" * 60)

    except Exception as e:
        print(f"\n✗ Error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
