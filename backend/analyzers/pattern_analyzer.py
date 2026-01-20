"""
Pattern analyzer

Detects attack patterns and classifies attacker behavior.
"""
import logging
from typing import List, Dict, Set
from datetime import datetime, timedelta
from collections import Counter

logger = logging.getLogger(__name__)


class PatternAnalyzer:
    """Analyze attack patterns and behaviors"""

    # Common bot usernames
    BOT_USERNAMES = {
        'admin', 'root', 'user', 'test', 'oracle', 'postgres',
        'mysql', 'administrator', 'support', 'guest', 'ubnt',
        'pi', 'default', 'master', 'jenkins', 'ftpuser'
    }

    # Common bot passwords
    BOT_PASSWORDS = {
        'admin', 'root', '123456', 'password', '12345', '12345678',
        '1234', 'qwerty', 'abc123', '111111', 'admin123', '1234567890'
    }

    # Reconnaissance commands
    RECON_COMMANDS = {
        'uname', 'whoami', 'id', 'pwd', 'ls', 'cat', 'ifconfig', 'ip',
        'netstat', 'ps', 'top', 'df', 'free', 'uptime', 'hostname'
    }

    # Download commands
    DOWNLOAD_COMMANDS = {
        'wget', 'curl', 'tftp', 'ftp', 'scp', 'rsync', 'git clone'
    }

    # Persistence commands
    PERSISTENCE_COMMANDS = {
        'crontab', 'systemctl', 'service', 'chkconfig', 'rc.local',
        'cron', 'at', 'nohup'
    }

    # Execution keywords
    EXECUTION_KEYWORDS = {
        'bash', 'sh', 'python', 'perl', 'ruby', 'php', 'node',
        'chmod +x', './run', './start', 'exec'
    }

    def __init__(self):
        pass

    def detect_brute_force(self, login_attempts: List[Dict], threshold: int = 10) -> Dict:
        """
        Detect brute force attacks

        Args:
            login_attempts: List of login attempt events
            threshold: Number of attempts per minute to be considered brute force

        Returns:
            Dict with brute force statistics
        """
        if not login_attempts:
            return {'is_brute_force': False, 'rate': 0}

        # Sort by timestamp
        sorted_attempts = sorted(
            login_attempts,
            key=lambda x: x.get('timestamp', datetime.min)
        )

        # Calculate attempts per minute
        if len(sorted_attempts) < 2:
            return {'is_brute_force': False, 'rate': 0}

        first_time = sorted_attempts[0].get('timestamp')
        last_time = sorted_attempts[-1].get('timestamp')

        if not first_time or not last_time:
            return {'is_brute_force': False, 'rate': 0}

        duration_seconds = (last_time - first_time).total_seconds()
        duration_minutes = max(duration_seconds / 60, 1)  # Avoid division by zero

        attempts_per_minute = len(sorted_attempts) / duration_minutes

        return {
            'is_brute_force': attempts_per_minute >= threshold,
            'rate': round(attempts_per_minute, 2),
            'total_attempts': len(sorted_attempts),
            'duration_minutes': round(duration_minutes, 2),
            'unique_passwords': len(set(a.get('password', '') for a in sorted_attempts)),
            'unique_usernames': len(set(a.get('username', '') for a in sorted_attempts)),
        }

    def detect_credential_stuffing(self, login_attempts: List[Dict]) -> bool:
        """
        Detect credential stuffing (many unique username/password pairs)
        """
        if len(login_attempts) < 5:
            return False

        credentials = set(
            (a.get('username', ''), a.get('password', ''))
            for a in login_attempts
        )

        # If more than 80% of attempts use unique credentials, likely credential stuffing
        unique_ratio = len(credentials) / len(login_attempts)
        return unique_ratio > 0.8

    def is_automated_bot(self, login_attempts: List[Dict], commands: List[Dict]) -> Dict:
        """
        Determine if attacker is an automated bot

        Indicators:
        - Uses common bot credentials
        - Rapid login attempts
        - Predictable command sequence
        - No interaction time between commands
        """
        bot_indicators = {
            'uses_common_credentials': False,
            'rapid_attempts': False,
            'predictable_commands': False,
            'no_think_time': False,
        }

        # Check for common bot credentials
        if login_attempts:
            usernames = [a.get('username', '').lower() for a in login_attempts]
            passwords = [a.get('password', '').lower() for a in login_attempts]

            bot_indicators['uses_common_credentials'] = (
                any(u in self.BOT_USERNAMES for u in usernames) or
                any(p in self.BOT_PASSWORDS for p in passwords)
            )

        # Check for rapid login attempts
        brute_force = self.detect_brute_force(login_attempts)
        bot_indicators['rapid_attempts'] = brute_force['is_brute_force']

        # Check command patterns
        if len(commands) >= 3:
            command_texts = [c.get('command', '').strip() for c in commands]

            # Bots often run the same reconnaissance sequence
            recon_count = sum(
                1 for cmd in command_texts
                if any(recon in cmd.lower() for recon in self.RECON_COMMANDS)
            )
            bot_indicators['predictable_commands'] = recon_count >= 2

            # Check time between commands
            sorted_commands = sorted(
                commands,
                key=lambda x: x.get('timestamp', datetime.min)
            )

            time_diffs = []
            for i in range(1, len(sorted_commands)):
                t1 = sorted_commands[i-1].get('timestamp')
                t2 = sorted_commands[i].get('timestamp')
                if t1 and t2:
                    time_diffs.append((t2 - t1).total_seconds())

            # Humans typically have variable think time, bots execute rapidly
            if time_diffs:
                avg_time = sum(time_diffs) / len(time_diffs)
                bot_indicators['no_think_time'] = avg_time < 1  # Less than 1 second average

        # Calculate bot confidence
        confidence = sum(bot_indicators.values()) / len(bot_indicators)

        return {
            'is_bot': confidence >= 0.5,
            'confidence': round(confidence, 2),
            'indicators': bot_indicators,
        }

    def categorize_commands(self, commands: List[Dict]) -> Dict[str, List[str]]:
        """
        Categorize commands by purpose

        Returns:
            Dict with categories: reconnaissance, download, persistence, execution, other
        """
        categories = {
            'reconnaissance': [],
            'download': [],
            'persistence': [],
            'execution': [],
            'other': [],
        }

        for cmd_event in commands:
            cmd = cmd_event.get('command', '').strip().lower()

            if not cmd:
                continue

            # Check each category
            categorized = False

            if any(recon in cmd for recon in self.RECON_COMMANDS):
                categories['reconnaissance'].append(cmd)
                categorized = True

            if any(dl in cmd for dl in self.DOWNLOAD_COMMANDS):
                categories['download'].append(cmd)
                categorized = True

            if any(persist in cmd for persist in self.PERSISTENCE_COMMANDS):
                categories['persistence'].append(cmd)
                categorized = True

            if any(exec_kw in cmd for exec_kw in self.EXECUTION_KEYWORDS):
                categories['execution'].append(cmd)
                categorized = True

            if not categorized:
                categories['other'].append(cmd)

        return categories

    def analyze_attack_intent(self, commands: List[Dict], downloads: List[Dict]) -> Dict:
        """
        Analyze the likely intent of the attacker

        Returns:
            Dict with likely intent and confidence
        """
        if not commands and not downloads:
            return {'intent': 'reconnaissance', 'confidence': 0.3}

        categorized = self.categorize_commands(commands)

        # Determine intent based on command categories
        if downloads or categorized['download']:
            if any('miner' in str(d).lower() or 'xmrig' in str(d).lower() for d in downloads):
                return {'intent': 'cryptomining', 'confidence': 0.9}
            else:
                return {'intent': 'malware_deployment', 'confidence': 0.8}

        if categorized['persistence']:
            return {'intent': 'persistence_establishment', 'confidence': 0.85}

        if len(categorized['reconnaissance']) > 3:
            return {'intent': 'reconnaissance', 'confidence': 0.7}

        if categorized['execution']:
            return {'intent': 'code_execution', 'confidence': 0.75}

        return {'intent': 'unknown', 'confidence': 0.4}

    def detect_attack_chain(self, session_events: List[Dict]) -> List[str]:
        """
        Detect the attack kill chain stages present

        Returns list of kill chain stages:
        - reconnaissance
        - weaponization
        - delivery
        - exploitation
        - installation
        - command_and_control
        - actions_on_objectives
        """
        stages = []

        logins = [e for e in session_events if e.get('event_type') in ['login_success', 'login_failed']]
        commands = [e for e in session_events if e.get('event_type') == 'command']
        downloads = [e for e in session_events if e.get('event_type') == 'file_download']

        # Reconnaissance - probing and login attempts
        if logins:
            stages.append('reconnaissance')

        # Exploitation - successful login
        if any(e.get('success') for e in logins):
            stages.append('exploitation')

        # Command execution - reconnaissance commands
        categorized = self.categorize_commands(commands)
        if categorized['reconnaissance']:
            if 'reconnaissance' not in stages:
                stages.append('reconnaissance')

        # Delivery - downloading files
        if downloads or categorized['download']:
            stages.append('delivery')

        # Installation - persistence mechanisms
        if categorized['persistence']:
            stages.append('installation')

        # Actions on objectives - code execution
        if categorized['execution']:
            stages.append('actions_on_objectives')

        return stages
