"""
Alert Manager

Coordinates alert generation and distribution.
"""
import logging
from typing import Dict, List, Any
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class AlertSeverity(Enum):
    """Alert severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertType(Enum):
    """Types of security alerts"""
    BRUTE_FORCE = "brute_force"
    MALWARE_DETECTED = "malware_detected"
    PERSISTENCE_ATTEMPT = "persistence_attempt"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    ANOMALOUS_BEHAVIOR = "anomalous_behavior"
    HIGH_VALUE_TARGET = "high_value_target"
    NEW_ATTACK_PATTERN = "new_attack_pattern"


class Alert:
    """Represents a security alert"""

    def __init__(
        self,
        alert_type: AlertType,
        severity: AlertSeverity,
        title: str,
        description: str,
        metadata: Dict[str, Any] = None
    ):
        self.alert_type = alert_type
        self.severity = severity
        self.title = title
        self.description = description
        self.metadata = metadata or {}
        self.timestamp = datetime.utcnow()

    def to_dict(self) -> Dict:
        """Convert alert to dictionary"""
        return {
            'type': self.alert_type.value,
            'severity': self.severity.value,
            'title': self.title,
            'description': self.description,
            'timestamp': self.timestamp.isoformat(),
            'metadata': self.metadata
        }

    def __str__(self) -> str:
        return f"[{self.severity.value.upper()}] {self.title}"


class AlertManager:
    """Manages alert generation and notification"""

    def __init__(self):
        self.notifiers = []
        self.alert_history = []

        # Alert thresholds
        self.thresholds = {
            'brute_force_attempts': 50,
            'sophistication_score': 7,
            'anomaly_score_threshold': -0.5,
            'commands_per_session': 20,
        }

    def add_notifier(self, notifier):
        """Add a notification channel"""
        self.notifiers.append(notifier)
        logger.info(f"Added notifier: {notifier.__class__.__name__}")

    def check_session(self, session_data: Dict, features: Dict, ml_predictions: Dict = None) -> List[Alert]:
        """
        Analyze session and generate alerts if needed

        Args:
            session_data: Raw session data
            features: Extracted features
            ml_predictions: ML model predictions (optional)

        Returns:
            List of generated alerts
        """
        alerts = []

        # Check for brute force
        if features.get('login_attempt_count', 0) >= self.thresholds['brute_force_attempts']:
            alert = Alert(
                alert_type=AlertType.BRUTE_FORCE,
                severity=AlertSeverity.MEDIUM,
                title=f"Brute Force Attack from {session_data.get('src_ip')}",
                description=f"{features['login_attempt_count']} login attempts detected",
                metadata={
                    'src_ip': session_data.get('src_ip'),
                    'country': session_data.get('country'),
                    'attempts': features['login_attempt_count']
                }
            )
            alerts.append(alert)

        # Check for malware
        if features.get('download_commands', 0) > 0 or features.get('has_downloads', 0) == 1:
            alert = Alert(
                alert_type=AlertType.MALWARE_DETECTED,
                severity=AlertSeverity.HIGH,
                title=f"Malware Download Attempt from {session_data.get('src_ip')}",
                description="Attacker attempted to download files",
                metadata={
                    'src_ip': session_data.get('src_ip'),
                    'country': session_data.get('country'),
                    'download_count': features.get('download_count', 0)
                }
            )
            alerts.append(alert)

        # Check for persistence attempts
        if features.get('persistence_commands', 0) > 0:
            alert = Alert(
                alert_type=AlertType.PERSISTENCE_ATTEMPT,
                severity=AlertSeverity.HIGH,
                title=f"Persistence Mechanism Detected from {session_data.get('src_ip')}",
                description="Attacker attempting to establish persistent access",
                metadata={
                    'src_ip': session_data.get('src_ip'),
                    'country': session_data.get('country'),
                    'persistence_commands': features['persistence_commands']
                }
            )
            alerts.append(alert)

        # Check for privilege escalation
        if features.get('privilege_escalation_commands', 0) > 0:
            alert = Alert(
                alert_type=AlertType.PRIVILEGE_ESCALATION,
                severity=AlertSeverity.CRITICAL,
                title=f"Privilege Escalation Attempt from {session_data.get('src_ip')}",
                description="Attacker attempting privilege escalation",
                metadata={
                    'src_ip': session_data.get('src_ip'),
                    'country': session_data.get('country')
                }
            )
            alerts.append(alert)

        # Check for sophisticated attacks
        if features.get('sophistication_score', 0) >= self.thresholds['sophistication_score']:
            alert = Alert(
                alert_type=AlertType.HIGH_VALUE_TARGET,
                severity=AlertSeverity.HIGH,
                title=f"Sophisticated Attack from {session_data.get('src_ip')}",
                description=f"High sophistication score: {features['sophistication_score']}",
                metadata={
                    'src_ip': session_data.get('src_ip'),
                    'country': session_data.get('country'),
                    'sophistication_score': features['sophistication_score']
                }
            )
            alerts.append(alert)

        # Check ML anomaly detection
        if ml_predictions and ml_predictions.get('is_anomalous'):
            alert = Alert(
                alert_type=AlertType.ANOMALOUS_BEHAVIOR,
                severity=AlertSeverity.MEDIUM,
                title=f"Anomalous Attack Pattern from {session_data.get('src_ip')}",
                description="ML model detected unusual attack behavior",
                metadata={
                    'src_ip': session_data.get('src_ip'),
                    'country': session_data.get('country'),
                    'anomaly_score': ml_predictions.get('anomaly_score')
                }
            )
            alerts.append(alert)

        # Send alerts
        for alert in alerts:
            self._send_alert(alert)
            self.alert_history.append(alert)

        return alerts

    def _send_alert(self, alert: Alert):
        """Send alert through all configured notifiers"""
        logger.warning(f"Alert generated: {alert}")

        for notifier in self.notifiers:
            try:
                notifier.send(alert)
            except Exception as e:
                logger.error(f"Failed to send alert via {notifier.__class__.__name__}: {e}")

    def get_recent_alerts(self, limit: int = 50) -> List[Alert]:
        """Get recent alerts"""
        return sorted(
            self.alert_history,
            key=lambda a: a.timestamp,
            reverse=True
        )[:limit]

    def get_alert_summary(self) -> Dict:
        """Get summary of alerts"""
        summary = {
            'total_alerts': len(self.alert_history),
            'by_severity': {},
            'by_type': {},
            'recent_count_24h': 0
        }

        # Count by severity
        for alert in self.alert_history:
            severity = alert.severity.value
            summary['by_severity'][severity] = summary['by_severity'].get(severity, 0) + 1

            alert_type = alert.alert_type.value
            summary['by_type'][alert_type] = summary['by_type'].get(alert_type, 0) + 1

            # Count recent alerts
            hours_old = (datetime.utcnow() - alert.timestamp).total_seconds() / 3600
            if hours_old < 24:
                summary['recent_count_24h'] += 1

        return summary
