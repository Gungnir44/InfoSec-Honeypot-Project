"""
Notification Channels

Implementations for various alert notification methods.
"""
import logging
import smtplib
import requests
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)


class Notifier(ABC):
    """Base class for alert notifiers"""

    @abstractmethod
    def send(self, alert) -> bool:
        """Send alert notification"""
        pass


class EmailNotifier(Notifier):
    """Send alerts via email"""

    def __init__(
        self,
        smtp_host: str,
        smtp_port: int,
        username: str,
        password: str,
        from_email: str,
        to_emails: list
    ):
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.username = username
        self.password = password
        self.from_email = from_email
        self.to_emails = to_emails

    def send(self, alert) -> bool:
        """Send email alert"""
        try:
            msg = MIMEMultipart()
            msg['From'] = self.from_email
            msg['To'] = ', '.join(self.to_emails)
            msg['Subject'] = f"[HONEYPOT ALERT] {alert.title}"

            body = f"""
Honeypot Security Alert
{'=' * 60}

Type: {alert.alert_type.value}
Severity: {alert.severity.value}
Timestamp: {alert.timestamp}

Description:
{alert.description}

Metadata:
{self._format_metadata(alert.metadata)}
            """

            msg.attach(MIMEText(body, 'plain'))

            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                server.starttls()
                server.login(self.username, self.password)
                server.send_message(msg)

            logger.info(f"Email alert sent to {self.to_emails}")
            return True

        except Exception as e:
            logger.error(f"Failed to send email alert: {e}")
            return False

    def _format_metadata(self, metadata: dict) -> str:
        """Format metadata for email"""
        return '\n'.join(f"  {k}: {v}" for k, v in metadata.items())


class SlackNotifier(Notifier):
    """Send alerts to Slack via webhook"""

    def __init__(self, webhook_url: str, channel: Optional[str] = None):
        self.webhook_url = webhook_url
        self.channel = channel

    def send(self, alert) -> bool:
        """Send Slack alert"""
        try:
            # Map severity to color
            colors = {
                'low': '#36a64f',       # Green
                'medium': '#ff9900',    # Orange
                'high': '#ff0000',      # Red
                'critical': '#8b0000'   # Dark Red
            }

            payload = {
                'attachments': [{
                    'fallback': alert.title,
                    'color': colors.get(alert.severity.value, '#808080'),
                    'title': f":warning: {alert.title}",
                    'text': alert.description,
                    'fields': [
                        {
                            'title': 'Severity',
                            'value': alert.severity.value.upper(),
                            'short': True
                        },
                        {
                            'title': 'Type',
                            'value': alert.alert_type.value,
                            'short': True
                        }
                    ] + [
                        {
                            'title': k.replace('_', ' ').title(),
                            'value': str(v),
                            'short': True
                        }
                        for k, v in alert.metadata.items()
                    ],
                    'ts': int(alert.timestamp.timestamp())
                }]
            }

            if self.channel:
                payload['channel'] = self.channel

            response = requests.post(
                self.webhook_url,
                json=payload,
                timeout=10
            )

            response.raise_for_status()

            logger.info("Slack alert sent successfully")
            return True

        except Exception as e:
            logger.error(f"Failed to send Slack alert: {e}")
            return False


class WebhookNotifier(Notifier):
    """Send alerts to generic webhook"""

    def __init__(self, webhook_url: str, headers: dict = None):
        self.webhook_url = webhook_url
        self.headers = headers or {'Content-Type': 'application/json'}

    def send(self, alert) -> bool:
        """Send webhook alert"""
        try:
            payload = alert.to_dict()

            response = requests.post(
                self.webhook_url,
                json=payload,
                headers=self.headers,
                timeout=10
            )

            response.raise_for_status()

            logger.info(f"Webhook alert sent to {self.webhook_url}")
            return True

        except Exception as e:
            logger.error(f"Failed to send webhook alert: {e}")
            return False


class ConsoleNotifier(Notifier):
    """Print alerts to console (for testing)"""

    def send(self, alert) -> bool:
        """Print alert to console"""
        print("\n" + "=" * 60)
        print(f"SECURITY ALERT: {alert.title}")
        print("=" * 60)
        print(f"Severity: {alert.severity.value.upper()}")
        print(f"Type: {alert.alert_type.value}")
        print(f"Time: {alert.timestamp}")
        print(f"\nDescription:\n{alert.description}")

        if alert.metadata:
            print("\nDetails:")
            for k, v in alert.metadata.items():
                print(f"  {k}: {v}")

        print("=" * 60 + "\n")
        return True
