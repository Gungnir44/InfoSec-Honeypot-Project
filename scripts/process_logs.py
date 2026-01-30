#!/usr/bin/env python3
"""
Log Processing Script

Processes Cowrie honeypot logs and imports them into the database.
Can run as a one-time import or continuous monitoring.
"""
import sys
import os
import time
import argparse
import logging
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.config import config
from backend.database.db_manager import DatabaseManager
from backend.analyzers import CowrieLogParser, GeoAnalyzer, PatternAnalyzer, CommandAnalyzer, VirusTotalAnalyzer

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class LogProcessor:
    """Process Cowrie logs and import to database"""

    def __init__(self, log_path: str, enable_virustotal: bool = True):
        self.log_path = log_path
        self.db_manager = DatabaseManager()
        self.log_parser = CowrieLogParser()
        self.geo_analyzer = GeoAnalyzer(use_api=True)
        self.pattern_analyzer = PatternAnalyzer()
        self.command_analyzer = CommandAnalyzer()
        self.file_position = 0

        # Initialize VirusTotal analyzer if enabled and configured
        self.vt_analyzer = None
        if enable_virustotal and config.VIRUSTOTAL_ENABLED and config.VIRUSTOTAL_API_KEY:
            self.vt_analyzer = VirusTotalAnalyzer(
                api_key=config.VIRUSTOTAL_API_KEY,
                rate_limit=config.VIRUSTOTAL_RATE_LIMIT
            )
            logger.info("VirusTotal integration enabled")
        else:
            logger.info("VirusTotal integration disabled (no API key or disabled in config)")

    def process_file(self, start_from_beginning: bool = False):
        """Process log file and import data"""
        if start_from_beginning:
            self.file_position = 0

        # Parse logs
        events, new_position = self.log_parser.parse_file(
            self.log_path,
            self.file_position
        )

        if not events:
            logger.info("No new events to process")
            return 0

        # Update file position
        self.file_position = new_position

        # Group by session
        sessions = self.log_parser.group_by_session(events)

        processed_count = 0

        for session_id, session_events in sessions.items():
            try:
                self.process_session(session_id, session_events)
                processed_count += 1
            except Exception as e:
                logger.error(f"Error processing session {session_id}: {e}")

        logger.info(f"Processed {processed_count} sessions ({len(events)} events)")
        return processed_count

    def process_session(self, session_id: str, events: list):
        """Process a single session"""
        # Check if session already exists
        existing_attack = self.db_manager.get_attack_by_session(session_id)
        if existing_attack:
            logger.debug(f"Session {session_id} already processed")
            return

        # Get session metadata
        metadata = self.log_parser.get_session_metadata(events)

        if not metadata.get('src_ip'):
            logger.warning(f"No source IP for session {session_id}")
            return

        # Geolocate IP
        geo_data = self.geo_analyzer.geolocate_ip(metadata['src_ip'])

        # Create attack record
        attack_data = {
            'timestamp': metadata.get('start_time'),
            'src_ip': metadata['src_ip'],
            'src_port': events[0].get('src_port'),
            'dst_port': events[0].get('dst_port'),
            'session_id': session_id,
            **geo_data
        }

        attack = self.db_manager.add_attack(attack_data)
        if not attack:
            logger.error(f"Failed to create attack record for {session_id}")
            return

        # Process login attempts
        login_attempts = self.log_parser.extract_login_attempts(events)
        for login in login_attempts:
            login_data = {
                'attack_id': attack.id,
                'username': login.get('username'),
                'password': login.get('password'),
                'success': login.get('success', False),
                'timestamp': login.get('timestamp')
            }
            self.db_manager.add_login_attempt(login_data)

        # Process commands
        command_events = self.log_parser.extract_commands(events)
        for cmd_event in command_events:
            cmd = cmd_event.get('command', '')
            category = self.command_analyzer.categorize_command(cmd)

            command_data = {
                'attack_id': attack.id,
                'command': cmd,
                'category': category,
                'timestamp': cmd_event.get('timestamp'),
                'success': True
            }
            self.db_manager.add_command(command_data)

        # Process downloads with VirusTotal integration
        download_events = self.log_parser.extract_downloads(events)
        for dl_event in download_events:
            self.process_download(attack.id, dl_event)

        logger.info(f"Processed session {session_id}: "
                   f"{len(login_attempts)} logins, {len(command_events)} commands, "
                   f"{len(download_events)} downloads")

    def process_download(self, attack_id: int, download_event: dict):
        """Process a download event with optional VirusTotal analysis"""
        file_hash = download_event.get('shasum')

        # Check if we've already processed this hash
        if file_hash:
            existing = self.db_manager.get_download_by_hash(file_hash)
            if existing:
                logger.debug(f"Download hash already exists: {file_hash[:16]}...")
                return

        download_data = {
            'attack_id': attack_id,
            'url': download_event.get('url'),
            'filename': download_event.get('outfile'),
            'file_hash': file_hash,
            'timestamp': download_event.get('timestamp'),
            'malware_detected': False,
            'virustotal_score': None
        }

        # Analyze with VirusTotal if available and we have a hash
        if self.vt_analyzer and self.vt_analyzer.is_enabled and file_hash:
            vt_result = self.vt_analyzer.analyze_hash(file_hash)

            if vt_result and vt_result.get('found'):
                download_data['malware_detected'] = vt_result.get('is_malware', False)
                download_data['virustotal_score'] = vt_result.get('detection_ratio', '')

                threat_summary = self.vt_analyzer.get_threat_summary(vt_result)
                logger.info(f"VirusTotal analysis for {file_hash[:16]}...: {threat_summary}")

                if vt_result.get('is_malware'):
                    logger.warning(f"MALWARE DETECTED: {file_hash} - {vt_result.get('popular_threat_names', 'Unknown')}")

        download = self.db_manager.add_download(download_data)
        if download:
            logger.debug(f"Added download: {download_data.get('url', 'unknown')}")

    def monitor_continuous(self, interval: int = 60):
        """Continuously monitor log file for new entries"""
        logger.info(f"Starting continuous monitoring of {self.log_path}")
        logger.info(f"Check interval: {interval} seconds")
        logger.info("Press Ctrl+C to stop")

        try:
            while True:
                self.process_file()
                time.sleep(interval)
        except KeyboardInterrupt:
            logger.info("\nMonitoring stopped")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='Process Cowrie honeypot logs')

    parser.add_argument(
        '--log-file',
        default=config.COWRIE_LOG_PATH,
        help='Path to Cowrie log file'
    )

    parser.add_argument(
        '--continuous',
        action='store_true',
        help='Continuously monitor log file'
    )

    parser.add_argument(
        '--interval',
        type=int,
        default=60,
        help='Monitoring interval in seconds (default: 60)'
    )

    parser.add_argument(
        '--from-beginning',
        action='store_true',
        help='Process entire log file from beginning'
    )

    args = parser.parse_args()

    # Initialize processor
    processor = LogProcessor(args.log_file)

    print("=" * 60)
    print("Cowrie Log Processor")
    print("=" * 60)
    print(f"Log file: {args.log_file}")
    print(f"Mode: {'Continuous' if args.continuous else 'One-time'}")
    print()

    # Process logs
    if args.continuous:
        processor.monitor_continuous(interval=args.interval)
    else:
        count = processor.process_file(start_from_beginning=args.from_beginning)
        print(f"\nProcessed {count} sessions")


if __name__ == '__main__':
    main()
