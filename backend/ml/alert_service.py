"""
ML-Powered Alert Service
Sends notifications for anomalous attacks and high-threat events
"""
import os
import json
import smtplib
import requests
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from typing import Dict, List, Optional
from .predictor import get_predictor

logger = logging.getLogger(__name__)


class AlertService:
    """Handles ML-powered alerts and notifications"""

    def __init__(self):
        self.predictor = get_predictor()

        # Email config (from environment)
        self.smtp_host = os.getenv('SMTP_HOST', 'smtp.gmail.com')
        self.smtp_port = int(os.getenv('SMTP_PORT', 587))
        self.smtp_user = os.getenv('SMTP_USER', '')
        self.smtp_password = os.getenv('SMTP_PASSWORD', '')
        self.alert_email = os.getenv('ALERT_EMAIL', '')

        # Slack config
        self.slack_webhook = os.getenv('SLACK_WEBHOOK_URL', '')

        # Alert thresholds
        self.threat_score_threshold = int(os.getenv('THREAT_SCORE_THRESHOLD', 60))
        self.anomaly_alert_enabled = os.getenv('ANOMALY_ALERTS', 'true').lower() == 'true'

    def check_and_alert(self, attack: Dict) -> Optional[Dict]:
        """Check attack against ML models and send alerts if needed"""
        analysis = self.predictor.analyze_attack(attack)

        should_alert = False
        alert_reasons = []

        # Check threat score
        if analysis['threat_score'] >= self.threat_score_threshold:
            should_alert = True
            alert_reasons.append(f"High threat score: {analysis['threat_score']}")

        # Check for anomaly
        if self.anomaly_alert_enabled and analysis['anomaly'].get('is_anomaly'):
            severity = analysis['anomaly'].get('severity', 'unknown')
            if severity in ['critical', 'high']:
                should_alert = True
                alert_reasons.append(f"Anomaly detected: {severity} severity")

        if should_alert:
            alert_data = {
                'timestamp': datetime.utcnow().isoformat(),
                'attack': attack,
                'analysis': analysis,
                'reasons': alert_reasons
            }
            self._send_alerts(alert_data)
            return alert_data

        return None

    def _send_alerts(self, alert_data: Dict):
        """Send alerts through configured channels"""
        # Send email
        if self.smtp_user and self.alert_email:
            try:
                self._send_email_alert(alert_data)
            except Exception as e:
                logger.error(f"Email alert failed: {e}")

        # Send Slack
        if self.slack_webhook:
            try:
                self._send_slack_alert(alert_data)
            except Exception as e:
                logger.error(f"Slack alert failed: {e}")

        # Always log
        logger.warning(f"ALERT: {json.dumps(alert_data, default=str)}")

    def _send_email_alert(self, alert_data: Dict):
        """Send email alert"""
        attack = alert_data['attack']
        analysis = alert_data['analysis']

        subject = f"🚨 Honeypot Alert: {analysis['threat_level'].upper()} Threat Detected"

        body = f"""
        <html>
        <body style="font-family: Arial, sans-serif;">
        <h2 style="color: #e74c3c;">🚨 Honeypot Security Alert</h2>

        <h3>Threat Summary</h3>
        <table style="border-collapse: collapse; width: 100%;">
            <tr><td><strong>Threat Level:</strong></td><td style="color: #e74c3c;">{analysis['threat_level'].upper()}</td></tr>
            <tr><td><strong>Threat Score:</strong></td><td>{analysis['threat_score']}/100</td></tr>
            <tr><td><strong>Attack Type:</strong></td><td>{analysis['classification'].get('type', 'Unknown')}</td></tr>
            <tr><td><strong>Confidence:</strong></td><td>{analysis['classification'].get('confidence', 0)}%</td></tr>
        </table>

        <h3>Attack Details</h3>
        <table style="border-collapse: collapse; width: 100%;">
            <tr><td><strong>Source IP:</strong></td><td>{attack.get('src_ip', 'Unknown')}</td></tr>
            <tr><td><strong>Country:</strong></td><td>{attack.get('country', 'Unknown')}</td></tr>
            <tr><td><strong>Timestamp:</strong></td><td>{alert_data['timestamp']}</td></tr>
        </table>

        <h3>Alert Reasons</h3>
        <ul>
        {''.join(f'<li>{reason}</li>' for reason in alert_data['reasons'])}
        </ul>

        <h3>Anomaly Detection</h3>
        <table style="border-collapse: collapse; width: 100%;">
            <tr><td><strong>Is Anomaly:</strong></td><td>{'Yes ⚠️' if analysis['anomaly'].get('is_anomaly') else 'No'}</td></tr>
            <tr><td><strong>Severity:</strong></td><td>{analysis['anomaly'].get('severity', 'N/A')}</td></tr>
            <tr><td><strong>Anomaly Score:</strong></td><td>{analysis['anomaly'].get('score', 'N/A')}</td></tr>
        </table>

        <hr>
        <p style="color: #666; font-size: 12px;">
            This alert was generated by the ML-Powered Honeypot System.<br>
            Dashboard: <a href="http://35.184.174.192">View Dashboard</a>
        </p>
        </body>
        </html>
        """

        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = self.smtp_user
        msg['To'] = self.alert_email
        msg.attach(MIMEText(body, 'html'))

        with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
            server.starttls()
            server.login(self.smtp_user, self.smtp_password)
            server.send_message(msg)

        logger.info(f"Email alert sent to {self.alert_email}")

    def _send_slack_alert(self, alert_data: Dict):
        """Send Slack alert"""
        attack = alert_data['attack']
        analysis = alert_data['analysis']

        # Color based on threat level
        colors = {
            'critical': '#e74c3c',
            'high': '#e67e22',
            'medium': '#f39c12',
            'low': '#3498db',
            'minimal': '#2ecc71'
        }
        color = colors.get(analysis['threat_level'], '#95a5a6')

        payload = {
            "attachments": [{
                "color": color,
                "title": f"🚨 Honeypot Alert: {analysis['threat_level'].upper()} Threat",
                "fields": [
                    {"title": "Source IP", "value": attack.get('src_ip', 'Unknown'), "short": True},
                    {"title": "Country", "value": attack.get('country', 'Unknown'), "short": True},
                    {"title": "Threat Score", "value": f"{analysis['threat_score']}/100", "short": True},
                    {"title": "Attack Type", "value": analysis['classification'].get('type', 'Unknown'), "short": True},
                    {"title": "Is Anomaly", "value": "Yes ⚠️" if analysis['anomaly'].get('is_anomaly') else "No", "short": True},
                    {"title": "Anomaly Severity", "value": analysis['anomaly'].get('severity', 'N/A'), "short": True},
                ],
                "footer": "Honeypot ML Alert System",
                "ts": int(datetime.utcnow().timestamp())
            }]
        }

        response = requests.post(self.slack_webhook, json=payload, timeout=10)
        response.raise_for_status()
        logger.info("Slack alert sent successfully")

    def get_alert_stats(self) -> Dict:
        """Get alert statistics"""
        return {
            'email_configured': bool(self.smtp_user and self.alert_email),
            'slack_configured': bool(self.slack_webhook),
            'threat_threshold': self.threat_score_threshold,
            'anomaly_alerts_enabled': self.anomaly_alert_enabled
        }


# Global alert service instance
_alert_service = None

def get_alert_service() -> AlertService:
    """Get or create global alert service instance"""
    global _alert_service
    if _alert_service is None:
        _alert_service = AlertService()
    return _alert_service
