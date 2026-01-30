"""
Threat Intelligence Integration

Enriches attack data with external threat intelligence from:
- AbuseIPDB: IP reputation and abuse reports
- Shodan: Host information, open ports, vulnerabilities
"""
import logging
import time
from datetime import datetime, timedelta
from typing import Dict, Optional, List
from functools import lru_cache

import requests

logger = logging.getLogger(__name__)


class AbuseIPDBAnalyzer:
    """Query AbuseIPDB for IP reputation data"""

    API_BASE = "https://api.abuseipdb.com/api/v2"

    # Rate limits: Free tier allows 1000 requests/day
    RATE_LIMIT_REQUESTS = 60  # Per minute to be safe
    RATE_LIMIT_WINDOW = 60

    def __init__(self, api_key: str, rate_limit: bool = True):
        """
        Initialize AbuseIPDB analyzer.

        Args:
            api_key: AbuseIPDB API key
            rate_limit: Enable rate limiting
        """
        self.api_key = api_key
        self.rate_limit = rate_limit
        self.request_times: List[datetime] = []
        self._enabled = bool(api_key)

        if not self._enabled:
            logger.warning("AbuseIPDB API key not configured. IP reputation checks disabled.")

    @property
    def is_enabled(self) -> bool:
        return self._enabled

    def _get_headers(self) -> Dict[str, str]:
        return {
            "Key": self.api_key,
            "Accept": "application/json"
        }

    def _wait_for_rate_limit(self):
        """Respect rate limits"""
        if not self.rate_limit:
            return

        now = datetime.now()
        self.request_times = [
            t for t in self.request_times
            if now - t < timedelta(seconds=self.RATE_LIMIT_WINDOW)
        ]

        if len(self.request_times) >= self.RATE_LIMIT_REQUESTS:
            oldest = min(self.request_times)
            wait_time = (oldest + timedelta(seconds=self.RATE_LIMIT_WINDOW) - now).total_seconds()
            if wait_time > 0:
                logger.info(f"AbuseIPDB rate limit. Waiting {wait_time:.1f}s...")
                time.sleep(wait_time + 0.5)

        self.request_times.append(datetime.now())

    def check_ip(self, ip_address: str, max_age_days: int = 90) -> Optional[Dict]:
        """
        Check an IP address against AbuseIPDB.

        Args:
            ip_address: IP to check
            max_age_days: How far back to check reports (1-365)

        Returns:
            IP reputation data or None if error
        """
        if not self._enabled:
            return None

        # Skip private/local IPs
        if self._is_private_ip(ip_address):
            return {'is_private': True, 'ip': ip_address}

        self._wait_for_rate_limit()

        try:
            url = f"{self.API_BASE}/check"
            params = {
                "ipAddress": ip_address,
                "maxAgeInDays": str(max_age_days),
                "verbose": ""
            }

            response = requests.get(
                url,
                headers=self._get_headers(),
                params=params,
                timeout=30
            )

            if response.status_code == 200:
                data = response.json().get('data', {})
                return self._parse_check_response(data)

            elif response.status_code == 429:
                logger.warning("AbuseIPDB rate limit exceeded")
                return None

            else:
                logger.error(f"AbuseIPDB API error: {response.status_code}")
                return None

        except requests.RequestException as e:
            logger.error(f"AbuseIPDB request failed: {e}")
            return None

    def _parse_check_response(self, data: Dict) -> Dict:
        """Parse AbuseIPDB check response"""
        abuse_score = data.get('abuseConfidenceScore', 0)

        # Determine threat level based on abuse score
        if abuse_score >= 80:
            threat_level = 'critical'
        elif abuse_score >= 50:
            threat_level = 'high'
        elif abuse_score >= 25:
            threat_level = 'medium'
        elif abuse_score > 0:
            threat_level = 'low'
        else:
            threat_level = 'clean'

        return {
            'ip': data.get('ipAddress'),
            'is_public': data.get('isPublic', True),
            'abuse_confidence_score': abuse_score,
            'threat_level': threat_level,
            'is_whitelisted': data.get('isWhitelisted', False),
            'country_code': data.get('countryCode'),
            'isp': data.get('isp'),
            'domain': data.get('domain'),
            'usage_type': data.get('usageType'),
            'total_reports': data.get('totalReports', 0),
            'num_distinct_users': data.get('numDistinctUsers', 0),
            'last_reported_at': data.get('lastReportedAt'),
            'is_tor': data.get('isTor', False),
            'reports': data.get('reports', [])[:5],  # Last 5 reports
            'abuseipdb_link': f"https://www.abuseipdb.com/check/{data.get('ipAddress')}"
        }

    def report_ip(self, ip_address: str, categories: List[int], comment: str = "") -> bool:
        """
        Report an IP to AbuseIPDB.

        Args:
            ip_address: IP to report
            categories: List of abuse category IDs
            comment: Optional description

        Returns:
            True if reported successfully

        Category IDs:
            3: Fraud Orders, 4: DDoS Attack, 5: FTP Brute-Force,
            6: Ping of Death, 7: Phishing, 8: Fraud VoIP,
            9: Open Proxy, 10: Web Spam, 11: Email Spam,
            14: Port Scan, 15: Hacking, 18: Brute-Force,
            19: Bad Web Bot, 20: Exploited Host, 21: Web App Attack,
            22: SSH, 23: IoT Targeted
        """
        if not self._enabled:
            return False

        self._wait_for_rate_limit()

        try:
            url = f"{self.API_BASE}/report"
            data = {
                "ip": ip_address,
                "categories": ",".join(str(c) for c in categories),
                "comment": comment[:1024] if comment else ""
            }

            response = requests.post(
                url,
                headers=self._get_headers(),
                data=data,
                timeout=30
            )

            if response.status_code == 200:
                logger.info(f"Reported IP to AbuseIPDB: {ip_address}")
                return True
            else:
                logger.error(f"Failed to report IP: {response.status_code}")
                return False

        except requests.RequestException as e:
            logger.error(f"AbuseIPDB report failed: {e}")
            return False

    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private/local"""
        import ipaddress
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved
        except ValueError:
            return False


class ShodanAnalyzer:
    """Query Shodan for host information"""

    API_BASE = "https://api.shodan.io"

    # Rate limits vary by plan, free tier is limited
    RATE_LIMIT_REQUESTS = 1  # 1 per second for free tier
    RATE_LIMIT_WINDOW = 1

    def __init__(self, api_key: str, rate_limit: bool = True):
        """
        Initialize Shodan analyzer.

        Args:
            api_key: Shodan API key
            rate_limit: Enable rate limiting
        """
        self.api_key = api_key
        self.rate_limit = rate_limit
        self.last_request_time = None
        self._enabled = bool(api_key)

        if not self._enabled:
            logger.warning("Shodan API key not configured. Host intel disabled.")

    @property
    def is_enabled(self) -> bool:
        return self._enabled

    def _wait_for_rate_limit(self):
        """Respect rate limits"""
        if not self.rate_limit or not self.last_request_time:
            self.last_request_time = datetime.now()
            return

        elapsed = (datetime.now() - self.last_request_time).total_seconds()
        if elapsed < self.RATE_LIMIT_WINDOW:
            time.sleep(self.RATE_LIMIT_WINDOW - elapsed + 0.1)

        self.last_request_time = datetime.now()

    def get_host_info(self, ip_address: str) -> Optional[Dict]:
        """
        Get host information from Shodan.

        Args:
            ip_address: IP to look up

        Returns:
            Host information or None if error/not found
        """
        if not self._enabled:
            return None

        # Skip private IPs
        if self._is_private_ip(ip_address):
            return {'is_private': True, 'ip': ip_address}

        self._wait_for_rate_limit()

        try:
            url = f"{self.API_BASE}/shodan/host/{ip_address}"
            params = {"key": self.api_key}

            response = requests.get(url, params=params, timeout=30)

            if response.status_code == 200:
                data = response.json()
                return self._parse_host_response(data)

            elif response.status_code == 404:
                logger.info(f"IP not found in Shodan: {ip_address}")
                return {'found': False, 'ip': ip_address}

            elif response.status_code == 401:
                logger.error("Shodan API key invalid")
                return None

            else:
                logger.error(f"Shodan API error: {response.status_code}")
                return None

        except requests.RequestException as e:
            logger.error(f"Shodan request failed: {e}")
            return None

    def _parse_host_response(self, data: Dict) -> Dict:
        """Parse Shodan host response"""
        # Extract open ports and services
        ports = data.get('ports', [])
        services = []

        for item in data.get('data', []):
            service = {
                'port': item.get('port'),
                'protocol': item.get('transport', 'tcp'),
                'product': item.get('product'),
                'version': item.get('version'),
                'banner': item.get('data', '')[:200] if item.get('data') else None
            }
            services.append(service)

        # Extract vulnerabilities
        vulns = []
        for item in data.get('data', []):
            if 'vulns' in item:
                for vuln_id, vuln_data in item['vulns'].items():
                    vulns.append({
                        'id': vuln_id,
                        'cvss': vuln_data.get('cvss'),
                        'verified': vuln_data.get('verified', False)
                    })

        # Determine risk level
        if vulns:
            high_cvss = any(v.get('cvss', 0) >= 7.0 for v in vulns)
            risk_level = 'critical' if high_cvss else 'high'
        elif len(ports) > 10:
            risk_level = 'medium'
        elif len(ports) > 5:
            risk_level = 'low'
        else:
            risk_level = 'minimal'

        return {
            'found': True,
            'ip': data.get('ip_str'),
            'hostnames': data.get('hostnames', []),
            'country': data.get('country_name'),
            'country_code': data.get('country_code'),
            'city': data.get('city'),
            'org': data.get('org'),
            'isp': data.get('isp'),
            'asn': data.get('asn'),
            'os': data.get('os'),
            'ports': ports,
            'services': services[:10],  # Top 10 services
            'vulns': vulns[:10],  # Top 10 vulns
            'vuln_count': len(vulns),
            'tags': data.get('tags', []),
            'last_update': data.get('last_update'),
            'risk_level': risk_level,
            'shodan_link': f"https://www.shodan.io/host/{data.get('ip_str')}"
        }

    def search_exploits(self, query: str, limit: int = 10) -> Optional[List[Dict]]:
        """
        Search Shodan Exploits database.

        Args:
            query: Search query (e.g., "apache 2.4")
            limit: Max results to return

        Returns:
            List of exploit information
        """
        if not self._enabled:
            return None

        self._wait_for_rate_limit()

        try:
            url = f"{self.API_BASE}/api-info"
            params = {
                "key": self.api_key,
                "query": query
            }

            # Note: Exploit search requires paid API
            # This is a simplified version
            return []

        except requests.RequestException as e:
            logger.error(f"Shodan exploit search failed: {e}")
            return None

    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private/local"""
        import ipaddress
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved
        except ValueError:
            return False


class ThreatIntelligenceManager:
    """Unified threat intelligence manager"""

    def __init__(
        self,
        abuseipdb_key: str = None,
        shodan_key: str = None,
        rate_limit: bool = True
    ):
        """
        Initialize threat intelligence manager.

        Args:
            abuseipdb_key: AbuseIPDB API key
            shodan_key: Shodan API key
            rate_limit: Enable rate limiting
        """
        self.abuseipdb = AbuseIPDBAnalyzer(abuseipdb_key, rate_limit) if abuseipdb_key else None
        self.shodan = ShodanAnalyzer(shodan_key, rate_limit) if shodan_key else None

        enabled_sources = []
        if self.abuseipdb and self.abuseipdb.is_enabled:
            enabled_sources.append("AbuseIPDB")
        if self.shodan and self.shodan.is_enabled:
            enabled_sources.append("Shodan")

        if enabled_sources:
            logger.info(f"Threat intelligence enabled: {', '.join(enabled_sources)}")
        else:
            logger.warning("No threat intelligence sources configured")

    def enrich_ip(self, ip_address: str) -> Dict:
        """
        Enrich an IP with all available threat intelligence.

        Args:
            ip_address: IP to enrich

        Returns:
            Combined threat intelligence data
        """
        result = {
            'ip': ip_address,
            'enriched_at': datetime.utcnow().isoformat(),
            'sources': []
        }

        # AbuseIPDB check
        if self.abuseipdb and self.abuseipdb.is_enabled:
            abuseipdb_data = self.abuseipdb.check_ip(ip_address)
            if abuseipdb_data:
                result['abuseipdb'] = abuseipdb_data
                result['sources'].append('abuseipdb')

        # Shodan check
        if self.shodan and self.shodan.is_enabled:
            shodan_data = self.shodan.get_host_info(ip_address)
            if shodan_data:
                result['shodan'] = shodan_data
                result['sources'].append('shodan')

        # Calculate overall threat score
        result['threat_assessment'] = self._calculate_threat_assessment(result)

        return result

    def _calculate_threat_assessment(self, intel_data: Dict) -> Dict:
        """Calculate overall threat assessment from all sources"""
        scores = []
        indicators = []

        # AbuseIPDB score
        if 'abuseipdb' in intel_data:
            abuse_data = intel_data['abuseipdb']
            if not abuse_data.get('is_private'):
                abuse_score = abuse_data.get('abuse_confidence_score', 0)
                scores.append(abuse_score)

                if abuse_score > 0:
                    indicators.append(f"AbuseIPDB score: {abuse_score}%")
                if abuse_data.get('is_tor'):
                    indicators.append("Tor exit node")
                if abuse_data.get('total_reports', 0) > 10:
                    indicators.append(f"{abuse_data['total_reports']} abuse reports")

        # Shodan risk indicators
        if 'shodan' in intel_data:
            shodan_data = intel_data['shodan']
            if shodan_data.get('found'):
                vuln_count = shodan_data.get('vuln_count', 0)
                if vuln_count > 0:
                    indicators.append(f"{vuln_count} known vulnerabilities")
                    scores.append(min(100, vuln_count * 10))

                port_count = len(shodan_data.get('ports', []))
                if port_count > 10:
                    indicators.append(f"{port_count} open ports")

        # Calculate overall score (0-100)
        overall_score = max(scores) if scores else 0

        # Determine threat level
        if overall_score >= 80:
            threat_level = 'critical'
        elif overall_score >= 50:
            threat_level = 'high'
        elif overall_score >= 25:
            threat_level = 'medium'
        elif overall_score > 0:
            threat_level = 'low'
        else:
            threat_level = 'unknown'

        return {
            'overall_score': overall_score,
            'threat_level': threat_level,
            'indicators': indicators,
            'recommendation': self._get_recommendation(threat_level, indicators)
        }

    def _get_recommendation(self, threat_level: str, indicators: List[str]) -> str:
        """Generate recommendation based on threat assessment"""
        if threat_level == 'critical':
            return "HIGH PRIORITY: Block this IP immediately. Known malicious actor."
        elif threat_level == 'high':
            return "Consider blocking this IP. Multiple threat indicators detected."
        elif threat_level == 'medium':
            return "Monitor activity from this IP closely."
        elif threat_level == 'low':
            return "Low risk, but continue monitoring."
        else:
            return "Insufficient data for assessment."

    def batch_enrich(self, ip_addresses: List[str]) -> Dict[str, Dict]:
        """
        Enrich multiple IPs.

        Args:
            ip_addresses: List of IPs to enrich

        Returns:
            Dict mapping IP to enrichment data
        """
        results = {}
        for ip in ip_addresses:
            results[ip] = self.enrich_ip(ip)
        return results

    def get_status(self) -> Dict:
        """Get status of threat intelligence sources"""
        return {
            'abuseipdb': {
                'enabled': self.abuseipdb.is_enabled if self.abuseipdb else False,
                'configured': bool(self.abuseipdb)
            },
            'shodan': {
                'enabled': self.shodan.is_enabled if self.shodan else False,
                'configured': bool(self.shodan)
            }
        }
