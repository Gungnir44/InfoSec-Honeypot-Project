"""
Automated Attacker Profiling

Builds behavioral profiles of attackers based on:
- Attack patterns and techniques
- Credential preferences
- Command sequences and tools
- Geographic and temporal patterns
- Sophistication assessment
- Attack objectives classification
"""
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from collections import Counter
import json
import re

logger = logging.getLogger(__name__)


class AttackerProfiler:
    """Build and analyze attacker profiles"""

    # Attack objective classifications
    OBJECTIVES = {
        'reconnaissance': ['uname', 'whoami', 'id', 'pwd', 'ls', 'cat /etc', 'ifconfig', 'ip addr', 'netstat'],
        'credential_theft': ['cat /etc/passwd', 'cat /etc/shadow', '.ssh', 'id_rsa', 'credentials', 'password'],
        'malware_deployment': ['wget', 'curl', 'tftp', 'chmod +x', './'],
        'cryptomining': ['xmrig', 'minerd', 'stratum', 'pool', 'hashrate', 'cpuminer'],
        'botnet_recruitment': ['mirai', 'gafgyt', 'tsunami', 'irc', 'ddos', 'flood'],
        'persistence': ['crontab', 'rc.local', 'systemctl', '.bashrc', 'authorized_keys'],
        'lateral_movement': ['ssh', 'scp', 'nc', 'nmap', 'ping'],
        'data_exfiltration': ['tar', 'zip', 'base64', 'curl -d', 'wget --post'],
        'privilege_escalation': ['sudo', 'su ', 'chmod 777', 'setuid'],
        'cleanup': ['rm -rf', 'history -c', 'unset HISTFILE', 'shred']
    }

    # Sophistication indicators
    SOPHISTICATION_MARKERS = {
        'low': ['admin', 'root', '123456', 'password', 'test'],
        'medium': ['encoded commands', 'multiple techniques', 'custom tools'],
        'high': ['obfuscation', 'anti-forensics', 'zero-day', 'custom malware'],
        'apt': ['long dwell time', 'targeted', 'stealth', 'data staging']
    }

    # Known tool signatures
    TOOL_SIGNATURES = {
        'hydra': r'hydra|^(root|admin|user)$.*\d{3,}',
        'medusa': r'medusa',
        'ncrack': r'ncrack',
        'metasploit': r'meterpreter|msfvenom|msf',
        'cobalt_strike': r'beacon|cobaltstrike',
        'mirai': r'mirai|dvrhelper|enable|system|shell|sh',
        'generic_scanner': r'scanner|scan|probe'
    }

    def __init__(self, db_manager):
        """
        Initialize the attacker profiler.

        Args:
            db_manager: DatabaseManager instance
        """
        self.db_manager = db_manager

    def build_profile(self, ip_address: str) -> Dict:
        """
        Build a comprehensive profile for an attacker IP.

        Args:
            ip_address: IP address to profile

        Returns:
            Attacker profile dictionary
        """
        logger.info(f"Building profile for {ip_address}")

        # Gather all attack data for this IP
        attacks = self._get_attacks_for_ip(ip_address)

        if not attacks:
            return {
                'ip_address': ip_address,
                'error': 'No attack data found for this IP'
            }

        # Build profile components
        profile = {
            'ip_address': ip_address,
            'profile_generated': datetime.utcnow().isoformat(),

            # Basic statistics
            'statistics': self._calculate_statistics(attacks),

            # Temporal analysis
            'temporal_patterns': self._analyze_temporal_patterns(attacks),

            # Credential analysis
            'credential_patterns': self._analyze_credentials(attacks),

            # Command analysis
            'command_patterns': self._analyze_commands(attacks),

            # Attack objectives
            'objectives': self._classify_objectives(attacks),

            # Sophistication assessment
            'sophistication': self._assess_sophistication(attacks),

            # Tool detection
            'detected_tools': self._detect_tools(attacks),

            # Behavioral traits
            'behavioral_traits': self._identify_behavioral_traits(attacks),

            # Risk assessment
            'risk_assessment': None,  # Filled in below

            # Recommendations
            'recommendations': []  # Filled in below
        }

        # Calculate overall risk and recommendations
        profile['risk_assessment'] = self._calculate_risk_assessment(profile)
        profile['recommendations'] = self._generate_recommendations(profile)

        # Add threat intel if available
        threat_intel = self.db_manager.get_threat_intel(ip_address)
        if threat_intel:
            profile['threat_intel'] = {
                'abuse_score': threat_intel.abuse_confidence_score,
                'total_reports': threat_intel.abuse_total_reports,
                'is_tor_exit': threat_intel.is_tor_exit,
                'threat_level': threat_intel.threat_level
            }

        return profile

    def _get_attacks_for_ip(self, ip_address: str) -> List[Dict]:
        """Get all attack data for an IP"""
        session = self.db_manager.get_session()
        try:
            from backend.database.models import Attack, LoginAttempt, Command, Download

            attacks = session.query(Attack).filter(
                Attack.src_ip == ip_address
            ).all()

            attack_data = []
            for attack in attacks:
                # Get associated data
                logins = session.query(LoginAttempt).filter(
                    LoginAttempt.attack_id == attack.id
                ).all()

                commands = session.query(Command).filter(
                    Command.attack_id == attack.id
                ).all()

                downloads = session.query(Download).filter(
                    Download.attack_id == attack.id
                ).all()

                attack_data.append({
                    'attack': attack,
                    'logins': logins,
                    'commands': commands,
                    'downloads': downloads
                })

            return attack_data
        finally:
            session.close()

    def _calculate_statistics(self, attacks: List[Dict]) -> Dict:
        """Calculate basic attack statistics"""
        total_sessions = len(attacks)
        total_logins = sum(len(a['logins']) for a in attacks)
        total_commands = sum(len(a['commands']) for a in attacks)
        total_downloads = sum(len(a['downloads']) for a in attacks)

        successful_logins = sum(
            1 for a in attacks
            for login in a['logins']
            if login.success
        )

        timestamps = [a['attack'].timestamp for a in attacks if a['attack'].timestamp]
        first_seen = min(timestamps) if timestamps else None
        last_seen = max(timestamps) if timestamps else None

        duration_days = (last_seen - first_seen).days if first_seen and last_seen else 0

        return {
            'total_sessions': total_sessions,
            'total_login_attempts': total_logins,
            'successful_logins': successful_logins,
            'login_success_rate': round(successful_logins / total_logins * 100, 1) if total_logins > 0 else 0,
            'total_commands': total_commands,
            'total_downloads': total_downloads,
            'first_seen': first_seen.isoformat() if first_seen else None,
            'last_seen': last_seen.isoformat() if last_seen else None,
            'active_days': duration_days,
            'avg_commands_per_session': round(total_commands / total_sessions, 1) if total_sessions > 0 else 0
        }

    def _analyze_temporal_patterns(self, attacks: List[Dict]) -> Dict:
        """Analyze when attacks occur"""
        hours = []
        days = []

        for attack in attacks:
            ts = attack['attack'].timestamp
            if ts:
                hours.append(ts.hour)
                days.append(ts.strftime('%A'))

        hour_distribution = Counter(hours)
        day_distribution = Counter(days)

        # Find peak activity times
        peak_hour = hour_distribution.most_common(1)[0] if hour_distribution else (0, 0)
        peak_day = day_distribution.most_common(1)[0] if day_distribution else ('Unknown', 0)

        # Determine if attacks are automated (consistent timing)
        hour_variance = self._calculate_variance(hours) if hours else 0
        is_automated = hour_variance < 5 and len(set(hours)) < 6

        return {
            'peak_hour': peak_hour[0],
            'peak_hour_count': peak_hour[1],
            'peak_day': peak_day[0],
            'peak_day_count': peak_day[1],
            'hour_distribution': dict(hour_distribution.most_common(5)),
            'day_distribution': dict(day_distribution),
            'appears_automated': is_automated,
            'timing_consistency': 'high' if hour_variance < 3 else 'medium' if hour_variance < 8 else 'low'
        }

    def _calculate_variance(self, values: List[int]) -> float:
        """Calculate variance of a list of values"""
        if not values:
            return 0
        mean = sum(values) / len(values)
        return sum((x - mean) ** 2 for x in values) / len(values)

    def _analyze_credentials(self, attacks: List[Dict]) -> Dict:
        """Analyze credential patterns"""
        usernames = []
        passwords = []
        combinations = []

        for attack in attacks:
            for login in attack['logins']:
                if login.username:
                    usernames.append(login.username)
                if login.password:
                    passwords.append(login.password)
                if login.username and login.password:
                    combinations.append(f"{login.username}:{login.password}")

        username_counts = Counter(usernames)
        password_counts = Counter(passwords)

        # Detect credential patterns
        patterns = []

        # Check for dictionary attack (many common passwords)
        common_passwords = {'123456', 'password', 'admin', 'root', '12345678', 'qwerty'}
        dict_attack_count = sum(1 for p in passwords if p in common_passwords)
        if dict_attack_count > 5:
            patterns.append('dictionary_attack')

        # Check for username enumeration (many usernames, few passwords)
        if len(set(usernames)) > len(set(passwords)) * 3:
            patterns.append('username_enumeration')

        # Check for password spraying (few passwords across many usernames)
        if len(set(passwords)) < 5 and len(set(usernames)) > 10:
            patterns.append('password_spraying')

        # Check for credential stuffing (many unique combinations)
        if len(set(combinations)) > 20:
            patterns.append('credential_stuffing')

        # Check for default credentials
        default_creds = {'admin:admin', 'root:root', 'user:user', 'admin:password', 'root:123456'}
        uses_defaults = any(c in default_creds for c in combinations)
        if uses_defaults:
            patterns.append('default_credentials')

        return {
            'unique_usernames': len(set(usernames)),
            'unique_passwords': len(set(passwords)),
            'top_usernames': dict(username_counts.most_common(10)),
            'top_passwords': dict(password_counts.most_common(10)),
            'detected_patterns': patterns,
            'uses_default_creds': uses_defaults,
            'credential_diversity': round(len(set(combinations)) / len(combinations) * 100, 1) if combinations else 0
        }

    def _analyze_commands(self, attacks: List[Dict]) -> Dict:
        """Analyze command execution patterns"""
        all_commands = []
        categories = []

        for attack in attacks:
            for cmd in attack['commands']:
                if cmd.command:
                    all_commands.append(cmd.command)
                if cmd.category:
                    categories.append(cmd.category)

        command_counts = Counter(all_commands)
        category_counts = Counter(categories)

        # Detect command sequences (kill chains)
        sequences = self._detect_command_sequences(attacks)

        return {
            'unique_commands': len(set(all_commands)),
            'top_commands': dict(command_counts.most_common(10)),
            'category_distribution': dict(category_counts),
            'detected_sequences': sequences,
            'uses_obfuscation': self._check_obfuscation(all_commands),
            'avg_command_length': round(sum(len(c) for c in all_commands) / len(all_commands), 1) if all_commands else 0
        }

    def _detect_command_sequences(self, attacks: List[Dict]) -> List[str]:
        """Detect common attack sequences (kill chains)"""
        sequences = []

        for attack in attacks:
            commands = [cmd.command.lower() for cmd in attack['commands'] if cmd.command]

            # Check for recon -> download -> execute sequence
            has_recon = any(c for c in commands if any(r in c for r in ['uname', 'whoami', 'id', 'cat /etc']))
            has_download = any(c for c in commands if any(d in c for d in ['wget', 'curl', 'tftp']))
            has_execute = any(c for c in commands if any(e in c for e in ['chmod +x', './', 'bash', 'sh ']))

            if has_recon and has_download and has_execute:
                sequences.append('recon_download_execute')

            # Check for persistence sequence
            has_persistence = any(c for c in commands if any(p in c for p in ['crontab', 'rc.local', '.bashrc']))
            if has_download and has_persistence:
                sequences.append('malware_persistence')

            # Check for lateral movement prep
            has_lateral = any(c for c in commands if any(l in c for l in ['ssh', 'scp', 'nmap']))
            if has_recon and has_lateral:
                sequences.append('lateral_movement_prep')

        return list(set(sequences))

    def _check_obfuscation(self, commands: List[str]) -> bool:
        """Check if commands use obfuscation techniques"""
        obfuscation_patterns = [
            r'base64',
            r'\$\(.+\)',  # Command substitution
            r'\\x[0-9a-f]{2}',  # Hex encoding
            r'eval\s+',
            r'`[^`]+`',  # Backtick execution
            r'\|\s*sh',
            r'\|\s*bash'
        ]

        for cmd in commands:
            for pattern in obfuscation_patterns:
                if re.search(pattern, cmd, re.IGNORECASE):
                    return True
        return False

    def _classify_objectives(self, attacks: List[Dict]) -> Dict:
        """Classify attack objectives based on behavior"""
        all_commands = []
        for attack in attacks:
            for cmd in attack['commands']:
                if cmd.command:
                    all_commands.append(cmd.command.lower())

        command_text = ' '.join(all_commands)

        detected_objectives = {}
        for objective, indicators in self.OBJECTIVES.items():
            matches = sum(1 for ind in indicators if ind.lower() in command_text)
            if matches > 0:
                detected_objectives[objective] = {
                    'confidence': min(100, matches * 20),
                    'indicator_count': matches
                }

        # Determine primary objective
        if detected_objectives:
            primary = max(detected_objectives.items(), key=lambda x: x[1]['confidence'])
            primary_objective = primary[0]
        else:
            primary_objective = 'unknown'

        # Check for downloads
        has_downloads = any(len(a['downloads']) > 0 for a in attacks)
        has_malware = any(
            d.malware_detected
            for a in attacks
            for d in a['downloads']
        )

        return {
            'primary_objective': primary_objective,
            'all_objectives': detected_objectives,
            'has_downloads': has_downloads,
            'has_malware': has_malware
        }

    def _assess_sophistication(self, attacks: List[Dict]) -> Dict:
        """Assess attacker sophistication level"""
        score = 0
        indicators = []

        # Check credential sophistication
        cred_analysis = self._analyze_credentials(attacks)
        if cred_analysis['credential_diversity'] > 80:
            score += 20
            indicators.append('High credential diversity')
        if 'credential_stuffing' in cred_analysis['detected_patterns']:
            score += 15
            indicators.append('Credential stuffing detected')

        # Check command sophistication
        cmd_analysis = self._analyze_commands(attacks)
        if cmd_analysis['uses_obfuscation']:
            score += 25
            indicators.append('Uses command obfuscation')
        if cmd_analysis['detected_sequences']:
            score += 20
            indicators.append(f"Kill chains: {', '.join(cmd_analysis['detected_sequences'])}")

        # Check for anti-forensics
        all_commands = [cmd.command.lower() for a in attacks for cmd in a['commands'] if cmd.command]
        anti_forensics = ['history -c', 'rm -rf /var/log', 'unset HISTFILE', 'shred']
        if any(af in ' '.join(all_commands) for af in anti_forensics):
            score += 20
            indicators.append('Anti-forensics techniques')

        # Check temporal patterns (automation vs manual)
        temporal = self._analyze_temporal_patterns(attacks)
        if not temporal['appears_automated']:
            score += 10
            indicators.append('Manual/targeted behavior')

        # Determine level
        if score >= 70:
            level = 'advanced'
        elif score >= 45:
            level = 'intermediate'
        elif score >= 20:
            level = 'basic'
        else:
            level = 'script_kiddie'

        return {
            'level': level,
            'score': score,
            'max_score': 100,
            'indicators': indicators
        }

    def _detect_tools(self, attacks: List[Dict]) -> List[Dict]:
        """Detect attack tools based on behavior patterns"""
        detected = []

        # Gather all text for analysis
        all_text = []
        for attack in attacks:
            for login in attack['logins']:
                if login.username:
                    all_text.append(login.username)
                if login.password:
                    all_text.append(login.password)
            for cmd in attack['commands']:
                if cmd.command:
                    all_text.append(cmd.command)

        combined_text = ' '.join(all_text).lower()

        for tool, pattern in self.TOOL_SIGNATURES.items():
            if re.search(pattern, combined_text, re.IGNORECASE):
                detected.append({
                    'tool': tool,
                    'confidence': 'high' if tool in combined_text else 'medium'
                })

        # Check for Mirai-style behavior
        mirai_commands = ['enable', 'system', 'shell', 'sh', '/bin/busybox']
        mirai_matches = sum(1 for m in mirai_commands if m in combined_text)
        if mirai_matches >= 3:
            detected.append({'tool': 'mirai_variant', 'confidence': 'high'})

        return detected

    def _identify_behavioral_traits(self, attacks: List[Dict]) -> List[str]:
        """Identify behavioral traits of the attacker"""
        traits = []

        stats = self._calculate_statistics(attacks)
        temporal = self._analyze_temporal_patterns(attacks)
        creds = self._analyze_credentials(attacks)

        # Persistence
        if stats['active_days'] > 7:
            traits.append('persistent')

        # Aggressive
        if stats['total_login_attempts'] > 100:
            traits.append('aggressive')

        # Methodical
        if temporal['timing_consistency'] == 'high':
            traits.append('methodical')

        # Opportunistic
        if creds['uses_default_creds']:
            traits.append('opportunistic')

        # Targeted
        if stats['active_days'] > 1 and stats['total_sessions'] < 5:
            traits.append('targeted')

        # Automated
        if temporal['appears_automated']:
            traits.append('automated')

        # Sophisticated
        if self._assess_sophistication(attacks)['level'] in ['advanced', 'intermediate']:
            traits.append('sophisticated')

        return traits

    def _calculate_risk_assessment(self, profile: Dict) -> Dict:
        """Calculate overall risk assessment"""
        risk_score = 0

        # Factor in sophistication
        soph_level = profile['sophistication']['level']
        if soph_level == 'advanced':
            risk_score += 40
        elif soph_level == 'intermediate':
            risk_score += 25
        elif soph_level == 'basic':
            risk_score += 15

        # Factor in objectives
        objectives = profile['objectives']
        high_risk_objectives = ['malware_deployment', 'cryptomining', 'botnet_recruitment', 'data_exfiltration']
        for obj in high_risk_objectives:
            if obj in objectives.get('all_objectives', {}):
                risk_score += 15

        if objectives.get('has_malware'):
            risk_score += 20

        # Factor in behavioral traits
        if 'persistent' in profile['behavioral_traits']:
            risk_score += 10
        if 'sophisticated' in profile['behavioral_traits']:
            risk_score += 10

        # Factor in threat intel
        if 'threat_intel' in profile:
            intel = profile['threat_intel']
            if intel.get('abuse_score', 0) > 50:
                risk_score += 20
            if intel.get('is_tor_exit'):
                risk_score += 10

        # Normalize score
        risk_score = min(100, risk_score)

        # Determine level
        if risk_score >= 75:
            level = 'critical'
        elif risk_score >= 50:
            level = 'high'
        elif risk_score >= 25:
            level = 'medium'
        else:
            level = 'low'

        return {
            'score': risk_score,
            'level': level,
            'factors': self._get_risk_factors(profile)
        }

    def _get_risk_factors(self, profile: Dict) -> List[str]:
        """Get list of risk factors"""
        factors = []

        if profile['objectives'].get('has_malware'):
            factors.append('Deployed malware')

        if profile['sophistication']['level'] in ['advanced', 'intermediate']:
            factors.append(f"Sophistication: {profile['sophistication']['level']}")

        if profile['detected_tools']:
            tools = [t['tool'] for t in profile['detected_tools']]
            factors.append(f"Tools detected: {', '.join(tools)}")

        if 'persistent' in profile['behavioral_traits']:
            factors.append('Persistent attacker')

        objectives = profile['objectives'].get('all_objectives', {})
        if objectives:
            top_objectives = sorted(objectives.items(), key=lambda x: x[1]['confidence'], reverse=True)[:2]
            factors.append(f"Objectives: {', '.join(o[0] for o in top_objectives)}")

        return factors

    def _generate_recommendations(self, profile: Dict) -> List[str]:
        """Generate security recommendations based on profile"""
        recommendations = []

        risk_level = profile['risk_assessment']['level']

        if risk_level in ['critical', 'high']:
            recommendations.append(f"BLOCK this IP ({profile['ip_address']}) immediately")
            recommendations.append("Review all systems that may have been accessed")

        if profile['objectives'].get('has_malware'):
            recommendations.append("Scan all systems for malware indicators")
            recommendations.append("Check for unauthorized processes and network connections")

        if 'persistence' in profile['objectives'].get('all_objectives', {}):
            recommendations.append("Audit cron jobs, startup scripts, and SSH authorized_keys")

        if 'credential_stuffing' in profile['credential_patterns'].get('detected_patterns', []):
            recommendations.append("Implement rate limiting on authentication endpoints")
            recommendations.append("Consider implementing MFA")

        if profile.get('threat_intel', {}).get('is_tor_exit'):
            recommendations.append("Consider blocking Tor exit nodes if not needed")

        if 'automated' in profile['behavioral_traits']:
            recommendations.append("Implement CAPTCHA or proof-of-work for authentication")

        if not recommendations:
            recommendations.append("Continue monitoring this IP")
            recommendations.append("No immediate action required")

        return recommendations

    def get_profile_summary(self, profile: Dict) -> str:
        """Generate a human-readable summary of the profile"""
        lines = [
            f"=== Attacker Profile: {profile['ip_address']} ===",
            "",
            f"Risk Level: {profile['risk_assessment']['level'].upper()} "
            f"(Score: {profile['risk_assessment']['score']}/100)",
            "",
            "Statistics:",
            f"  - Sessions: {profile['statistics']['total_sessions']}",
            f"  - Login attempts: {profile['statistics']['total_login_attempts']}",
            f"  - Commands executed: {profile['statistics']['total_commands']}",
            f"  - Active period: {profile['statistics']['active_days']} days",
            "",
            f"Sophistication: {profile['sophistication']['level']}",
            f"Primary Objective: {profile['objectives']['primary_objective']}",
            f"Behavioral Traits: {', '.join(profile['behavioral_traits']) or 'None identified'}",
            "",
            "Risk Factors:",
        ]

        for factor in profile['risk_assessment']['factors']:
            lines.append(f"  - {factor}")

        lines.extend([
            "",
            "Recommendations:",
        ])

        for rec in profile['recommendations']:
            lines.append(f"  - {rec}")

        return '\n'.join(lines)
