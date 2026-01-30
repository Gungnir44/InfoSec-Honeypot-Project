#!/usr/bin/env python3
"""
Honeypot Remote Agent

Deploy this agent on remote honeypots to send attack data to the central server.
Supports Cowrie and other JSON-based honeypot logs.

Usage:
    python honeypot_agent.py --server https://your-server.com --honeypot-id HP123 --api-key YOUR_KEY
"""
import sys
import os
import argparse
import logging
import json
import time
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

import requests

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('honeypot-agent')


class HoneypotAgent:
    """Agent for sending honeypot data to central server"""

    def __init__(
        self,
        server_url: str,
        honeypot_id: str,
        api_key: str,
        batch_size: int = 50,
        heartbeat_interval: int = 60
    ):
        """
        Initialize the honeypot agent.

        Args:
            server_url: URL of the central server
            honeypot_id: Unique ID of this honeypot
            api_key: API key for authentication
            batch_size: Number of events to send in each batch
            heartbeat_interval: Seconds between heartbeats
        """
        self.server_url = server_url.rstrip('/')
        self.honeypot_id = honeypot_id
        self.api_key = api_key
        self.batch_size = batch_size
        self.heartbeat_interval = heartbeat_interval

        # Track file positions
        self.file_positions = {}
        self.position_file = f".honeypot_agent_{honeypot_id}_positions.json"

        # Load saved positions
        self._load_positions()

    def _get_headers(self) -> Dict[str, str]:
        """Get request headers with authentication"""
        return {
            'Content-Type': 'application/json',
            'X-Honeypot-ID': self.honeypot_id,
            'X-API-Key': self.api_key
        }

    def _load_positions(self):
        """Load saved file positions"""
        if os.path.exists(self.position_file):
            try:
                with open(self.position_file, 'r') as f:
                    self.file_positions = json.load(f)
            except Exception as e:
                logger.error(f"Error loading positions: {e}")

    def _save_positions(self):
        """Save file positions for resume"""
        try:
            with open(self.position_file, 'w') as f:
                json.dump(self.file_positions, f)
        except Exception as e:
            logger.error(f"Error saving positions: {e}")

    def send_heartbeat(self) -> bool:
        """Send heartbeat to central server"""
        try:
            url = f"{self.server_url}/api/honeypots/heartbeat"
            response = requests.post(url, headers=self._get_headers(), timeout=10)

            if response.status_code == 200:
                logger.debug("Heartbeat sent successfully")
                return True
            else:
                logger.error(f"Heartbeat failed: {response.status_code}")
                return False

        except requests.RequestException as e:
            logger.error(f"Heartbeat error: {e}")
            return False

    def send_attack(self, attack_data: Dict) -> bool:
        """Send single attack to central server"""
        try:
            url = f"{self.server_url}/api/honeypots/receive"
            response = requests.post(
                url,
                headers=self._get_headers(),
                json=attack_data,
                timeout=30
            )

            if response.status_code == 200:
                return True
            else:
                logger.error(f"Failed to send attack: {response.status_code}")
                return False

        except requests.RequestException as e:
            logger.error(f"Error sending attack: {e}")
            return False

    def send_batch(self, attacks: List[Dict]) -> Dict:
        """Send batch of attacks to central server"""
        if not attacks:
            return {'success': True, 'received': 0}

        try:
            url = f"{self.server_url}/api/honeypots/receive"
            response = requests.post(
                url,
                headers=self._get_headers(),
                json=attacks,
                timeout=60
            )

            if response.status_code == 200:
                return response.json()
            else:
                logger.error(f"Batch send failed: {response.status_code}")
                return {'success': False, 'error': f"Status {response.status_code}"}

        except requests.RequestException as e:
            logger.error(f"Batch send error: {e}")
            return {'success': False, 'error': str(e)}

    def parse_cowrie_log(self, log_file: str, start_pos: int = 0) -> tuple:
        """
        Parse Cowrie JSON log file.

        Args:
            log_file: Path to Cowrie log file
            start_pos: Position to start reading from

        Returns:
            Tuple of (events list, new position)
        """
        events = []
        new_pos = start_pos

        try:
            with open(log_file, 'r', encoding='utf-8') as f:
                f.seek(start_pos)

                for line in f:
                    try:
                        event = json.loads(line.strip())
                        normalized = self._normalize_cowrie_event(event)
                        if normalized:
                            events.append(normalized)
                    except json.JSONDecodeError:
                        continue

                new_pos = f.tell()

        except Exception as e:
            logger.error(f"Error parsing log: {e}")

        return events, new_pos

    def _normalize_cowrie_event(self, event: Dict) -> Optional[Dict]:
        """Normalize Cowrie event to standard format"""
        event_id = event.get('eventid', '')

        # Only process relevant events
        if event_id not in [
            'cowrie.session.connect',
            'cowrie.login.success',
            'cowrie.login.failed',
            'cowrie.command.input',
            'cowrie.session.file_download'
        ]:
            return None

        normalized = {
            'timestamp': event.get('timestamp'),
            'src_ip': event.get('src_ip'),
            'src_port': event.get('src_port'),
            'dst_port': event.get('dst_port'),
            'session_id': event.get('session'),
            'event_type': event_id
        }

        if event_id in ['cowrie.login.success', 'cowrie.login.failed']:
            normalized['username'] = event.get('username')
            normalized['password'] = event.get('password')
            normalized['success'] = event_id == 'cowrie.login.success'

        elif event_id == 'cowrie.command.input':
            normalized['command'] = event.get('input')

        elif event_id == 'cowrie.session.file_download':
            normalized['url'] = event.get('url')
            normalized['filename'] = event.get('outfile')
            normalized['file_hash'] = event.get('shasum')

        return normalized

    def process_log_file(self, log_file: str) -> int:
        """
        Process a log file and send events to server.

        Args:
            log_file: Path to log file

        Returns:
            Number of events sent
        """
        # Get last position
        start_pos = self.file_positions.get(log_file, 0)

        # Parse new events
        events, new_pos = self.parse_cowrie_log(log_file, start_pos)

        if not events:
            return 0

        logger.info(f"Found {len(events)} new events in {log_file}")

        # Send in batches
        sent_count = 0
        for i in range(0, len(events), self.batch_size):
            batch = events[i:i + self.batch_size]
            result = self.send_batch(batch)

            if result.get('success'):
                sent_count += result.get('received', 0)
            else:
                logger.error(f"Batch send failed: {result.get('error')}")
                break

        # Update position if successful
        if sent_count > 0:
            self.file_positions[log_file] = new_pos
            self._save_positions()

        return sent_count

    def monitor_continuous(self, log_file: str, interval: int = 30):
        """
        Continuously monitor a log file for new events.

        Args:
            log_file: Path to log file
            interval: Seconds between checks
        """
        logger.info(f"Starting continuous monitoring of {log_file}")
        logger.info(f"Check interval: {interval}s, Heartbeat: {self.heartbeat_interval}s")
        logger.info("Press Ctrl+C to stop")

        last_heartbeat = 0

        try:
            while True:
                # Send heartbeat
                now = time.time()
                if now - last_heartbeat >= self.heartbeat_interval:
                    self.send_heartbeat()
                    last_heartbeat = now

                # Process log file
                sent = self.process_log_file(log_file)
                if sent > 0:
                    logger.info(f"Sent {sent} events to server")

                time.sleep(interval)

        except KeyboardInterrupt:
            logger.info("\nMonitoring stopped")

    def test_connection(self) -> bool:
        """Test connection to central server"""
        logger.info(f"Testing connection to {self.server_url}...")

        if self.send_heartbeat():
            logger.info("Connection successful!")
            return True
        else:
            logger.error("Connection failed!")
            return False


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Honeypot Remote Agent - Send attack data to central server'
    )

    parser.add_argument(
        '--server',
        required=True,
        help='Central server URL (e.g., https://honeypot.example.com)'
    )

    parser.add_argument(
        '--honeypot-id',
        required=True,
        help='Honeypot ID from registration'
    )

    parser.add_argument(
        '--api-key',
        required=True,
        help='API key from registration'
    )

    parser.add_argument(
        '--log-file',
        default='/home/cowrie/cowrie/var/log/cowrie/cowrie.json',
        help='Path to Cowrie JSON log file'
    )

    parser.add_argument(
        '--interval',
        type=int,
        default=30,
        help='Check interval in seconds (default: 30)'
    )

    parser.add_argument(
        '--batch-size',
        type=int,
        default=50,
        help='Events per batch (default: 50)'
    )

    parser.add_argument(
        '--test',
        action='store_true',
        help='Test connection and exit'
    )

    parser.add_argument(
        '--one-shot',
        action='store_true',
        help='Process log once and exit (no continuous monitoring)'
    )

    args = parser.parse_args()

    print("=" * 60)
    print("Honeypot Remote Agent")
    print("=" * 60)
    print(f"Server: {args.server}")
    print(f"Honeypot ID: {args.honeypot_id}")
    print(f"Log file: {args.log_file}")
    print()

    agent = HoneypotAgent(
        server_url=args.server,
        honeypot_id=args.honeypot_id,
        api_key=args.api_key,
        batch_size=args.batch_size
    )

    if args.test:
        success = agent.test_connection()
        sys.exit(0 if success else 1)

    # Check log file exists
    if not os.path.exists(args.log_file):
        print(f"Error: Log file not found: {args.log_file}")
        sys.exit(1)

    if args.one_shot:
        sent = agent.process_log_file(args.log_file)
        print(f"\nSent {sent} events to server")
    else:
        agent.monitor_continuous(args.log_file, interval=args.interval)


if __name__ == '__main__':
    main()
