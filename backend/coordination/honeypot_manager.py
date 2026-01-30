"""
Multi-Honeypot Coordination System

Manages multiple honeypot deployments and correlates attacks across them:
- Honeypot registration and health monitoring
- Attack correlation across honeypots
- Distributed attack detection
- Centralized data aggregation
"""
import logging
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from collections import Counter, defaultdict
import json

logger = logging.getLogger(__name__)


class HoneypotManager:
    """Manage multiple honeypot deployments"""

    def __init__(self, db_manager):
        """
        Initialize honeypot manager.

        Args:
            db_manager: DatabaseManager instance
        """
        self.db_manager = db_manager

    def register_honeypot(
        self,
        name: str,
        location: str = None,
        ip_address: str = None,
        honeypot_type: str = "cowrie",
        description: str = None
    ) -> Dict:
        """
        Register a new honeypot in the system.

        Args:
            name: Unique name for the honeypot
            location: Geographic location (e.g., "US-East", "EU-West")
            ip_address: Public IP of the honeypot
            honeypot_type: Type of honeypot (cowrie, dionaea, etc.)
            description: Optional description

        Returns:
            Honeypot registration info including API key
        """
        # Generate unique ID and API key
        honeypot_id = self._generate_honeypot_id(name)
        api_key = secrets.token_urlsafe(32)

        honeypot_data = {
            'honeypot_id': honeypot_id,
            'name': name,
            'location': location,
            'ip_address': ip_address,
            'honeypot_type': honeypot_type,
            'description': description,
            'api_key_hash': hashlib.sha256(api_key.encode()).hexdigest(),
            'status': 'active',
            'registered_at': datetime.utcnow(),
            'last_seen': datetime.utcnow()
        }

        saved = self.db_manager.save_honeypot(honeypot_data)

        if saved:
            logger.info(f"Registered new honeypot: {name} ({honeypot_id})")
            return {
                'honeypot_id': honeypot_id,
                'name': name,
                'api_key': api_key,  # Only returned once at registration
                'message': 'Store this API key securely - it cannot be retrieved later'
            }
        else:
            return {'error': 'Failed to register honeypot'}

    def _generate_honeypot_id(self, name: str) -> str:
        """Generate unique honeypot ID"""
        timestamp = datetime.utcnow().isoformat()
        unique = f"{name}-{timestamp}-{secrets.token_hex(4)}"
        return hashlib.sha256(unique.encode()).hexdigest()[:16]

    def verify_api_key(self, honeypot_id: str, api_key: str) -> bool:
        """Verify honeypot API key"""
        honeypot = self.db_manager.get_honeypot(honeypot_id)
        if not honeypot:
            return False

        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        return key_hash == honeypot.api_key_hash

    def update_heartbeat(self, honeypot_id: str) -> bool:
        """Update honeypot last seen timestamp"""
        return self.db_manager.update_honeypot_heartbeat(honeypot_id)

    def get_honeypot_status(self, honeypot_id: str = None) -> Dict:
        """Get status of one or all honeypots"""
        if honeypot_id:
            honeypot = self.db_manager.get_honeypot(honeypot_id)
            if honeypot:
                return self._format_honeypot_status(honeypot)
            return {'error': 'Honeypot not found'}
        else:
            honeypots = self.db_manager.get_all_honeypots()
            return {
                'total': len(honeypots),
                'active': sum(1 for h in honeypots if self._is_active(h)),
                'honeypots': [self._format_honeypot_status(h) for h in honeypots]
            }

    def _format_honeypot_status(self, honeypot) -> Dict:
        """Format honeypot status for API response"""
        is_active = self._is_active(honeypot)
        return {
            'honeypot_id': honeypot.honeypot_id,
            'name': honeypot.name,
            'location': honeypot.location,
            'ip_address': honeypot.ip_address,
            'honeypot_type': honeypot.honeypot_type,
            'status': 'online' if is_active else 'offline',
            'last_seen': honeypot.last_seen.isoformat() if honeypot.last_seen else None,
            'registered_at': honeypot.registered_at.isoformat() if honeypot.registered_at else None,
            'attack_count': honeypot.attack_count or 0
        }

    def _is_active(self, honeypot) -> bool:
        """Check if honeypot is active (seen in last 5 minutes)"""
        if not honeypot.last_seen:
            return False
        return datetime.utcnow() - honeypot.last_seen < timedelta(minutes=5)

    def deactivate_honeypot(self, honeypot_id: str) -> bool:
        """Deactivate a honeypot"""
        return self.db_manager.update_honeypot_status(honeypot_id, 'inactive')

    def reactivate_honeypot(self, honeypot_id: str) -> bool:
        """Reactivate a honeypot"""
        return self.db_manager.update_honeypot_status(honeypot_id, 'active')


class AttackCorrelator:
    """Correlate attacks across multiple honeypots"""

    # Time window for considering attacks as coordinated (minutes)
    CORRELATION_WINDOW = 60

    # Minimum honeypots hit to consider distributed attack
    MIN_HONEYPOTS_FOR_DISTRIBUTED = 2

    def __init__(self, db_manager):
        """
        Initialize attack correlator.

        Args:
            db_manager: DatabaseManager instance
        """
        self.db_manager = db_manager

    def find_coordinated_attacks(
        self,
        hours: int = 24,
        min_honeypots: int = 2
    ) -> List[Dict]:
        """
        Find IPs that attacked multiple honeypots within a time window.

        Args:
            hours: Look back period in hours
            min_honeypots: Minimum number of honeypots attacked

        Returns:
            List of coordinated attack patterns
        """
        attacks = self.db_manager.get_multi_honeypot_attacks(hours=hours)

        # Group by source IP
        ip_attacks = defaultdict(list)
        for attack in attacks:
            ip_attacks[attack['src_ip']].append(attack)

        coordinated = []
        for src_ip, attack_list in ip_attacks.items():
            # Get unique honeypots attacked
            honeypots_hit = set(a['honeypot_id'] for a in attack_list if a.get('honeypot_id'))

            if len(honeypots_hit) >= min_honeypots:
                # Calculate time span
                timestamps = [a['timestamp'] for a in attack_list if a.get('timestamp')]
                if timestamps:
                    time_span = (max(timestamps) - min(timestamps)).total_seconds() / 60

                    coordinated.append({
                        'src_ip': src_ip,
                        'honeypots_attacked': list(honeypots_hit),
                        'honeypot_count': len(honeypots_hit),
                        'total_attacks': len(attack_list),
                        'first_seen': min(timestamps).isoformat(),
                        'last_seen': max(timestamps).isoformat(),
                        'time_span_minutes': round(time_span, 1),
                        'attack_velocity': round(len(attack_list) / max(time_span / 60, 1), 2),
                        'countries': list(set(a.get('country') for a in attack_list if a.get('country')))
                    })

        # Sort by number of honeypots attacked
        coordinated.sort(key=lambda x: x['honeypot_count'], reverse=True)

        return coordinated

    def detect_distributed_campaigns(self, hours: int = 24) -> List[Dict]:
        """
        Detect distributed attack campaigns (multiple IPs attacking same targets).

        Args:
            hours: Look back period in hours

        Returns:
            List of potential distributed campaigns
        """
        attacks = self.db_manager.get_multi_honeypot_attacks(hours=hours)

        # Group by credential combinations (potential botnet signature)
        credential_attacks = defaultdict(list)
        for attack in attacks:
            if attack.get('username') and attack.get('password'):
                cred_key = f"{attack['username']}:{attack['password']}"
                credential_attacks[cred_key].append(attack)

        campaigns = []
        for cred, attack_list in credential_attacks.items():
            unique_ips = set(a['src_ip'] for a in attack_list)
            unique_honeypots = set(a['honeypot_id'] for a in attack_list if a.get('honeypot_id'))

            # Multiple IPs using same credentials = potential botnet
            if len(unique_ips) >= 3:
                username, password = cred.split(':', 1)
                timestamps = [a['timestamp'] for a in attack_list if a.get('timestamp')]

                campaigns.append({
                    'credential': cred,
                    'username': username,
                    'password': password,
                    'unique_source_ips': len(unique_ips),
                    'source_ips': list(unique_ips)[:20],  # Limit to 20
                    'honeypots_targeted': list(unique_honeypots),
                    'total_attempts': len(attack_list),
                    'first_seen': min(timestamps).isoformat() if timestamps else None,
                    'last_seen': max(timestamps).isoformat() if timestamps else None,
                    'countries': list(set(a.get('country') for a in attack_list if a.get('country'))),
                    'campaign_type': self._classify_campaign(attack_list)
                })

        # Sort by number of unique IPs
        campaigns.sort(key=lambda x: x['unique_source_ips'], reverse=True)

        return campaigns

    def _classify_campaign(self, attacks: List[Dict]) -> str:
        """Classify the type of attack campaign"""
        unique_ips = len(set(a['src_ip'] for a in attacks))
        unique_creds = len(set(f"{a.get('username')}:{a.get('password')}" for a in attacks))

        if unique_ips > 10 and unique_creds == 1:
            return 'botnet_credential_spray'
        elif unique_ips > 5:
            return 'distributed_brute_force'
        elif unique_creds > 10:
            return 'credential_stuffing'
        else:
            return 'targeted_attack'

    def get_cross_honeypot_statistics(self, hours: int = 24) -> Dict:
        """
        Get statistics across all honeypots.

        Args:
            hours: Look back period in hours

        Returns:
            Cross-honeypot statistics
        """
        attacks = self.db_manager.get_multi_honeypot_attacks(hours=hours)

        if not attacks:
            return {
                'total_attacks': 0,
                'unique_ips': 0,
                'honeypots_active': 0,
                'multi_honeypot_attackers': 0,
                'multi_honeypot_attacker_ips': [],
                'top_countries': {},
                'hourly_distribution': {},
                'attacks_by_honeypot': {},
                'coordinated_attack_percentage': 0
            }

        unique_ips = set(a['src_ip'] for a in attacks)
        honeypots = set(a['honeypot_id'] for a in attacks if a.get('honeypot_id'))

        # IPs attacking multiple honeypots
        ip_honeypots = defaultdict(set)
        for attack in attacks:
            if attack.get('honeypot_id'):
                ip_honeypots[attack['src_ip']].add(attack['honeypot_id'])

        multi_honeypot_ips = [ip for ip, hps in ip_honeypots.items() if len(hps) > 1]

        # Country distribution
        country_counts = Counter(a.get('country') for a in attacks if a.get('country'))

        # Hourly distribution
        hour_counts = Counter(a['timestamp'].hour for a in attacks if a.get('timestamp'))

        # Attack distribution by honeypot
        honeypot_counts = Counter(a.get('honeypot_id') for a in attacks if a.get('honeypot_id'))

        return {
            'total_attacks': len(attacks),
            'unique_ips': len(unique_ips),
            'honeypots_active': len(honeypots),
            'multi_honeypot_attackers': len(multi_honeypot_ips),
            'multi_honeypot_attacker_ips': multi_honeypot_ips[:20],
            'top_countries': dict(country_counts.most_common(10)),
            'hourly_distribution': dict(sorted(hour_counts.items())),
            'attacks_by_honeypot': dict(honeypot_counts),
            'coordinated_attack_percentage': round(
                len(multi_honeypot_ips) / len(unique_ips) * 100, 1
            ) if unique_ips else 0
        }

    def get_attack_timeline_by_honeypot(self, hours: int = 24) -> Dict[str, List]:
        """
        Get attack timeline broken down by honeypot.

        Args:
            hours: Look back period in hours

        Returns:
            Timeline data by honeypot
        """
        attacks = self.db_manager.get_multi_honeypot_attacks(hours=hours)

        # Group by honeypot and hour
        honeypot_timeline = defaultdict(lambda: defaultdict(int))

        for attack in attacks:
            if attack.get('honeypot_id') and attack.get('timestamp'):
                hour_key = attack['timestamp'].strftime('%Y-%m-%d %H:00')
                honeypot_timeline[attack['honeypot_id']][hour_key] += 1

        # Convert to list format
        result = {}
        for honeypot_id, hours_data in honeypot_timeline.items():
            result[honeypot_id] = [
                {'timestamp': ts, 'count': count}
                for ts, count in sorted(hours_data.items())
            ]

        return result

    def find_attack_patterns(self, hours: int = 24) -> List[Dict]:
        """
        Identify common attack patterns across honeypots.

        Args:
            hours: Look back period in hours

        Returns:
            List of identified patterns
        """
        attacks = self.db_manager.get_multi_honeypot_attacks(hours=hours)

        patterns = []

        # Pattern 1: Rapid succession attacks (same IP, multiple honeypots, < 5 min)
        ip_attacks = defaultdict(list)
        for attack in attacks:
            ip_attacks[attack['src_ip']].append(attack)

        for src_ip, attack_list in ip_attacks.items():
            if len(attack_list) < 2:
                continue

            sorted_attacks = sorted(attack_list, key=lambda x: x.get('timestamp') or datetime.min)
            honeypots_hit = set()
            rapid_attacks = []

            for i in range(1, len(sorted_attacks)):
                if sorted_attacks[i].get('timestamp') and sorted_attacks[i-1].get('timestamp'):
                    time_diff = (sorted_attacks[i]['timestamp'] - sorted_attacks[i-1]['timestamp']).total_seconds()
                    if time_diff < 300:  # 5 minutes
                        rapid_attacks.append(sorted_attacks[i])
                        if sorted_attacks[i].get('honeypot_id'):
                            honeypots_hit.add(sorted_attacks[i]['honeypot_id'])
                        if sorted_attacks[i-1].get('honeypot_id'):
                            honeypots_hit.add(sorted_attacks[i-1]['honeypot_id'])

            if len(honeypots_hit) >= 2:
                patterns.append({
                    'pattern_type': 'rapid_multi_honeypot',
                    'src_ip': src_ip,
                    'honeypots': list(honeypots_hit),
                    'attack_count': len(rapid_attacks) + 1,
                    'description': f'Rapid attacks on {len(honeypots_hit)} honeypots'
                })

        # Pattern 2: Same commands across honeypots
        command_honeypots = defaultdict(set)
        command_ips = defaultdict(set)

        for attack in attacks:
            if attack.get('commands') and attack.get('honeypot_id'):
                for cmd in attack.get('commands', []):
                    command_honeypots[cmd].add(attack['honeypot_id'])
                    command_ips[cmd].add(attack['src_ip'])

        for cmd, honeypots in command_honeypots.items():
            if len(honeypots) >= 2 and len(cmd) > 5:  # Non-trivial commands
                patterns.append({
                    'pattern_type': 'shared_command',
                    'command': cmd[:100],
                    'honeypots': list(honeypots),
                    'unique_ips': len(command_ips[cmd]),
                    'description': f'Same command seen on {len(honeypots)} honeypots'
                })

        return patterns[:50]  # Limit results


class HoneypotDataReceiver:
    """Receive and process data from remote honeypots"""

    def __init__(self, db_manager, honeypot_manager: HoneypotManager):
        """
        Initialize data receiver.

        Args:
            db_manager: DatabaseManager instance
            honeypot_manager: HoneypotManager instance
        """
        self.db_manager = db_manager
        self.honeypot_manager = honeypot_manager

    def receive_attack_data(
        self,
        honeypot_id: str,
        api_key: str,
        attack_data: Dict
    ) -> Dict:
        """
        Receive attack data from a remote honeypot.

        Args:
            honeypot_id: ID of the reporting honeypot
            api_key: API key for authentication
            attack_data: Attack data to store

        Returns:
            Result of the operation
        """
        # Verify authentication
        if not self.honeypot_manager.verify_api_key(honeypot_id, api_key):
            logger.warning(f"Invalid API key for honeypot {honeypot_id}")
            return {'error': 'Authentication failed', 'status': 401}

        # Update heartbeat
        self.honeypot_manager.update_heartbeat(honeypot_id)

        # Add honeypot ID to attack data
        attack_data['honeypot_id'] = honeypot_id

        # Store the attack
        try:
            attack = self.db_manager.add_attack(attack_data)
            if attack:
                # Increment attack count for honeypot
                self.db_manager.increment_honeypot_attack_count(honeypot_id)

                return {
                    'success': True,
                    'attack_id': attack.id,
                    'message': 'Attack data received'
                }
            else:
                return {'error': 'Failed to store attack data', 'status': 500}

        except Exception as e:
            logger.error(f"Error receiving attack data: {e}")
            return {'error': str(e), 'status': 500}

    def receive_batch_data(
        self,
        honeypot_id: str,
        api_key: str,
        attacks: List[Dict]
    ) -> Dict:
        """
        Receive batch attack data from a remote honeypot.

        Args:
            honeypot_id: ID of the reporting honeypot
            api_key: API key for authentication
            attacks: List of attack data to store

        Returns:
            Result of the operation
        """
        # Verify authentication
        if not self.honeypot_manager.verify_api_key(honeypot_id, api_key):
            return {'error': 'Authentication failed', 'status': 401}

        # Update heartbeat
        self.honeypot_manager.update_heartbeat(honeypot_id)

        success_count = 0
        error_count = 0

        for attack_data in attacks:
            attack_data['honeypot_id'] = honeypot_id
            try:
                attack = self.db_manager.add_attack(attack_data)
                if attack:
                    success_count += 1
                else:
                    error_count += 1
            except Exception as e:
                logger.error(f"Error storing attack: {e}")
                error_count += 1

        # Update attack count
        if success_count > 0:
            self.db_manager.increment_honeypot_attack_count(honeypot_id, count=success_count)

        return {
            'success': True,
            'received': success_count,
            'errors': error_count,
            'total': len(attacks)
        }
