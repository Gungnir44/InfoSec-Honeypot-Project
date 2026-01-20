"""
Command analyzer

Analyzes commands executed by attackers for malicious patterns.
"""
import logging
import re
from typing import List, Dict, Optional
from collections import Counter

logger = logging.getLogger(__name__)


class CommandAnalyzer:
    """Analyze commands executed in the honeypot"""

    # Command categories with pattern matching
    CATEGORIES = {
        'reconnaissance': [
            r'\b(uname|whoami|id|pwd|hostname|uptime)\b',
            r'\b(ls|dir|cat|head|tail|find)\b',
            r'\b(ifconfig|ip\s+addr|netstat|ss)\b',
            r'\b(ps|top|pstree|lsof)\b',
            r'\b(df|du|free|mount)\b',
            r'/proc/(cpuinfo|meminfo|version)',
        ],
        'download': [
            r'\b(wget|curl|tftp|ftp|get|fetch)\s+',
            r'\bgit\s+clone\b',
            r'\bscp\s+',
            r'\brsync\s+',
        ],
        'persistence': [
            r'\bcrontab\b',
            r'/etc/rc\.local',
            r'\b(systemctl|service|chkconfig)\b',
            r'\.bash(rc|_profile)',
            r'/etc/cron',
            r'\bat\s+',
            r'\bnohup\b',
        ],
        'execution': [
            r'\b(bash|sh|zsh|ksh)\s+',
            r'\b(python|perl|ruby|php|node)\s+',
            r'chmod\s+(\+x|777|755)',
            r'\./[\w\-\.]+',
            r'\bexec\s+',
            r'\beval\s+',
        ],
        'privilege_escalation': [
            r'\bsu\s+',
            r'\bsudo\s+',
            r'/etc/(passwd|shadow|sudoers)',
            r'\buseradd\b',
            r'\bpasswd\s+',
        ],
        'network': [
            r'\b(nc|netcat|ncat)\s+',
            r'\b(ssh|telnet|rlogin)\s+',
            r'\b(nmap|masscan)\b',
            r'\biptables\b',
            r'/etc/hosts',
        ],
        'data_exfiltration': [
            r'\b(tar|zip|gzip|bzip2|7z)\s+',
            r'\b(nc|netcat).*\s+<',
            r'\bscp\s+.*@',
        ],
        'cleanup': [
            r'\b(rm|shred|wipe)\s+',
            r'history\s+-c',
            r'\bunset\s+HISTFILE',
            r'> /var/log/',
        ],
    }

    # Cryptocurrency mining indicators
    MINING_INDICATORS = [
        'xmrig', 'minerd', 'cpuminer', 'ccminer',
        'stratum+tcp', 'pool.', 'mining', 'miner',
        'hashrate', 'cryptonight', 'donate-level'
    ]

    # Malware/botnet indicators
    MALWARE_INDICATORS = [
        'mirai', 'gafgyt', 'qbot', 'emotet', 'trickbot',
        'cobalt', 'meterpreter', 'metasploit', 'empire',
        'powershell -enc', 'base64 -d', 'IEX'
    ]

    def __init__(self):
        # Compile regex patterns for performance
        self.compiled_patterns = {
            category: [re.compile(pattern, re.IGNORECASE) for pattern in patterns]
            for category, patterns in self.CATEGORIES.items()
        }

    def categorize_command(self, command: str) -> Optional[str]:
        """
        Categorize a single command

        Returns the first matching category, or 'unknown'
        """
        if not command:
            return 'unknown'

        for category, patterns in self.compiled_patterns.items():
            for pattern in patterns:
                if pattern.search(command):
                    return category

        return 'unknown'

    def analyze_commands(self, commands: List[str]) -> Dict:
        """
        Analyze a list of commands

        Returns statistics and insights
        """
        if not commands:
            return {
                'total': 0,
                'unique': 0,
                'categories': {},
                'top_commands': [],
                'malicious_indicators': [],
            }

        # Categorize all commands
        categories = Counter()
        for cmd in commands:
            category = self.categorize_command(cmd)
            categories[category] += 1

        # Count unique commands
        unique_commands = set(commands)
        command_counts = Counter(commands)

        # Check for malicious indicators
        malicious = self._detect_malicious_patterns(commands)

        return {
            'total': len(commands),
            'unique': len(unique_commands),
            'categories': dict(categories),
            'top_commands': command_counts.most_common(10),
            'malicious_indicators': malicious,
            'mining_detected': any('mining' in ind.lower() for ind in malicious),
            'malware_detected': any('malware' in ind.lower() for ind in malicious),
        }

    def _detect_malicious_patterns(self, commands: List[str]) -> List[str]:
        """Detect malicious patterns in commands"""
        indicators = []

        command_str = ' '.join(commands).lower()

        # Check for cryptocurrency mining
        for indicator in self.MINING_INDICATORS:
            if indicator.lower() in command_str:
                indicators.append(f"Cryptocurrency mining: {indicator}")

        # Check for malware/botnet
        for indicator in self.MALWARE_INDICATORS:
            if indicator.lower() in command_str:
                indicators.append(f"Malware/Botnet: {indicator}")

        # Check for suspicious patterns
        if re.search(r'rm\s+-rf\s+/', command_str):
            indicators.append("Destructive command: rm -rf /")

        if re.search(r'chmod\s+777', command_str):
            indicators.append("Insecure permissions: chmod 777")

        if re.search(r'(bash|sh).*-c.*base64', command_str):
            indicators.append("Obfuscated command: base64 encoded")

        if re.search(r'curl.*\|\s*(bash|sh)', command_str):
            indicators.append("Pipe to shell: curl | bash")

        return indicators

    def extract_urls(self, commands: List[str]) -> List[str]:
        """Extract URLs from commands"""
        url_pattern = re.compile(
            r'https?://[^\s<>"{}|\\^`\[\]]+'
        )

        urls = []
        for cmd in commands:
            matches = url_pattern.findall(cmd)
            urls.extend(matches)

        return urls

    def extract_ips(self, commands: List[str]) -> List[str]:
        """Extract IP addresses from commands"""
        ip_pattern = re.compile(
            r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        )

        ips = []
        for cmd in commands:
            matches = ip_pattern.findall(cmd)
            # Filter out invalid IPs
            valid_ips = [
                ip for ip in matches
                if all(0 <= int(octet) <= 255 for octet in ip.split('.'))
            ]
            ips.extend(valid_ips)

        return list(set(ips))

    def is_obfuscated(self, command: str) -> bool:
        """Check if command appears to be obfuscated"""
        obfuscation_patterns = [
            r'base64',
            r'\\x[0-9a-f]{2}',  # Hex encoding
            r'\$\{[^}]+\}',  # Variable substitution
            r'eval.*\(',
            r'chr\(\d+\)',  # Character encoding
        ]

        for pattern in obfuscation_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                return True

        return False

    def generate_command_report(self, commands: List[str]) -> str:
        """Generate a human-readable report of command analysis"""
        analysis = self.analyze_commands(commands)

        report = []
        report.append("=" * 60)
        report.append("COMMAND ANALYSIS REPORT")
        report.append("=" * 60)
        report.append(f"\nTotal commands executed: {analysis['total']}")
        report.append(f"Unique commands: {analysis['unique']}")

        report.append("\n\nCATEGORY BREAKDOWN:")
        for category, count in sorted(analysis['categories'].items(), key=lambda x: x[1], reverse=True):
            report.append(f"  {category.capitalize()}: {count}")

        if analysis['top_commands']:
            report.append("\n\nTOP 5 COMMANDS:")
            for i, (cmd, count) in enumerate(analysis['top_commands'][:5], 1):
                report.append(f"  {i}. [{count}x] {cmd[:60]}")

        if analysis['malicious_indicators']:
            report.append("\n\nMALICIOUS INDICATORS DETECTED:")
            for indicator in analysis['malicious_indicators']:
                report.append(f"  ⚠️  {indicator}")

        urls = self.extract_urls(commands)
        if urls:
            report.append("\n\nURLS FOUND:")
            for url in urls[:10]:
                report.append(f"  - {url}")

        ips = self.extract_ips(commands)
        if ips:
            report.append("\n\nIP ADDRESSES FOUND:")
            for ip in ips[:10]:
                report.append(f"  - {ip}")

        report.append("\n" + "=" * 60)

        return "\n".join(report)
