"""
Cowrie log parser

Parses Cowrie JSON logs and extracts relevant data for analysis.
"""
import json
import logging
from datetime import datetime
from typing import Dict, Optional, List
from pathlib import Path

logger = logging.getLogger(__name__)


class CowrieLogParser:
    """Parse Cowrie JSON log files"""

    EVENT_TYPES = {
        'cowrie.login.success': 'login_success',
        'cowrie.login.failed': 'login_failed',
        'cowrie.command.input': 'command',
        'cowrie.session.connect': 'session_connect',
        'cowrie.session.closed': 'session_closed',
        'cowrie.session.file_download': 'file_download',
        'cowrie.session.file_upload': 'file_download',
        'cowrie.client.version': 'client_version',
    }

    def __init__(self):
        self.parsed_sessions = set()

    def parse_log_line(self, line: str) -> Optional[Dict]:
        """Parse a single line of Cowrie JSON log"""
        try:
            data = json.loads(line.strip())
            return self._normalize_event(data)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse log line: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error parsing log: {e}")
            return None

    def _normalize_event(self, data: Dict) -> Dict:
        """Normalize Cowrie event data to our format"""
        event_id = data.get('eventid', '')
        event_type = self.EVENT_TYPES.get(event_id, 'unknown')

        normalized = {
            'raw_event': event_id,
            'event_type': event_type,
            'timestamp': self._parse_timestamp(data.get('timestamp')),
            'session_id': data.get('session'),
            'src_ip': data.get('src_ip'),
            'src_port': data.get('src_port'),
            'dst_port': data.get('dst_port'),
            'sensor': data.get('sensor', 'unknown'),
            'message': data.get('message', ''),
        }

        # Add event-specific data
        if event_type in ['login_success', 'login_failed']:
            normalized['username'] = data.get('username')
            normalized['password'] = data.get('password')
            normalized['success'] = event_type == 'login_success'

        elif event_type == 'command':
            normalized['command'] = data.get('input', '')

        elif event_type == 'file_download':
            normalized['url'] = data.get('url')
            normalized['outfile'] = data.get('outfile')
            normalized['shasum'] = data.get('shasum')
            normalized['filename'] = data.get('filename')

        elif event_type == 'session_connect':
            normalized['protocol'] = data.get('protocol')

        return normalized

    def _parse_timestamp(self, timestamp_str: str) -> Optional[datetime]:
        """Parse Cowrie timestamp to datetime object"""
        if not timestamp_str:
            return None

        try:
            # Cowrie uses ISO 8601 format
            # Example: 2024-01-13T10:30:00.123456Z
            return datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        except (ValueError, AttributeError) as e:
            logger.error(f"Failed to parse timestamp '{timestamp_str}': {e}")
            return None

    def parse_file(self, file_path: str, start_pos: int = 0) -> tuple[List[Dict], int]:
        """
        Parse log file starting from a specific position

        Returns:
            tuple: (list of parsed events, new file position)
        """
        events = []
        path = Path(file_path)

        if not path.exists():
            logger.error(f"Log file not found: {file_path}")
            return events, start_pos

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                # Seek to start position
                f.seek(start_pos)

                for line in f:
                    event = self.parse_log_line(line)
                    if event:
                        events.append(event)

                # Get new file position
                new_pos = f.tell()

            logger.info(f"Parsed {len(events)} events from {file_path}")
            return events, new_pos

        except Exception as e:
            logger.error(f"Error reading log file: {e}")
            return events, start_pos

    def tail_file(self, file_path: str, lines: int = 100) -> List[Dict]:
        """
        Parse the last N lines of a log file

        Args:
            file_path: Path to log file
            lines: Number of lines to read from end

        Returns:
            List of parsed events
        """
        events = []
        path = Path(file_path)

        if not path.exists():
            logger.error(f"Log file not found: {file_path}")
            return events

        try:
            # Read last N lines
            with open(file_path, 'r', encoding='utf-8') as f:
                # Simple approach: read all lines and take last N
                # For very large files, consider a more efficient method
                all_lines = f.readlines()
                last_lines = all_lines[-lines:]

                for line in last_lines:
                    event = self.parse_log_line(line)
                    if event:
                        events.append(event)

            return events

        except Exception as e:
            logger.error(f"Error tailing log file: {e}")
            return events

    def group_by_session(self, events: List[Dict]) -> Dict[str, List[Dict]]:
        """Group events by session ID"""
        sessions = {}

        for event in events:
            session_id = event.get('session_id')
            if session_id:
                if session_id not in sessions:
                    sessions[session_id] = []
                sessions[session_id].append(event)

        return sessions

    def extract_login_attempts(self, events: List[Dict]) -> List[Dict]:
        """Extract login attempts from events"""
        return [
            event for event in events
            if event.get('event_type') in ['login_success', 'login_failed']
        ]

    def extract_commands(self, events: List[Dict]) -> List[Dict]:
        """Extract command executions from events"""
        return [
            event for event in events
            if event.get('event_type') == 'command'
        ]

    def extract_downloads(self, events: List[Dict]) -> List[Dict]:
        """Extract file downloads from events"""
        return [
            event for event in events
            if event.get('event_type') == 'file_download'
        ]

    def get_session_metadata(self, session_events: List[Dict]) -> Dict:
        """Extract metadata for a session"""
        if not session_events:
            return {}

        # Sort by timestamp
        sorted_events = sorted(
            session_events,
            key=lambda x: x.get('timestamp') or datetime.min
        )

        first_event = sorted_events[0]
        last_event = sorted_events[-1]

        # Count different event types
        login_attempts = len([e for e in session_events if e.get('event_type') in ['login_success', 'login_failed']])
        commands = len([e for e in session_events if e.get('event_type') == 'command'])
        downloads = len([e for e in session_events if e.get('event_type') == 'file_download'])

        start_time = first_event.get('timestamp')
        end_time = last_event.get('timestamp')

        duration = None
        if start_time and end_time:
            duration = int((end_time - start_time).total_seconds())

        return {
            'session_id': first_event.get('session_id'),
            'src_ip': first_event.get('src_ip'),
            'start_time': start_time,
            'end_time': end_time,
            'duration': duration,
            'login_attempts_count': login_attempts,
            'commands_count': commands,
            'downloads_count': downloads,
            'total_events': len(session_events),
        }
