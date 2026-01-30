"""
VirusTotal Integration for Malware Analysis

Provides automated malware scanning for files downloaded by attackers.
Uses VirusTotal API v3 for hash lookups and file analysis.
"""
import hashlib
import logging
import time
from datetime import datetime, timedelta
from typing import Dict, Optional, List
from pathlib import Path

import requests

logger = logging.getLogger(__name__)


class VirusTotalAnalyzer:
    """Analyze files and hashes using VirusTotal API"""

    API_BASE = "https://www.virustotal.com/api/v3"

    # Rate limiting: Free API allows 4 requests/minute, 500/day
    RATE_LIMIT_REQUESTS = 4
    RATE_LIMIT_WINDOW = 60  # seconds

    def __init__(self, api_key: str, rate_limit: bool = True):
        """
        Initialize VirusTotal analyzer.

        Args:
            api_key: VirusTotal API key
            rate_limit: Enable rate limiting for free API tier
        """
        self.api_key = api_key
        self.rate_limit = rate_limit
        self.request_times: List[datetime] = []
        self._enabled = bool(api_key)

        if not self._enabled:
            logger.warning("VirusTotal API key not configured. Malware analysis disabled.")

    @property
    def is_enabled(self) -> bool:
        """Check if VirusTotal analysis is enabled"""
        return self._enabled

    def _get_headers(self) -> Dict[str, str]:
        """Get API request headers"""
        return {
            "x-apikey": self.api_key,
            "Accept": "application/json"
        }

    def _wait_for_rate_limit(self):
        """Wait if necessary to respect rate limits"""
        if not self.rate_limit:
            return

        now = datetime.now()
        # Remove requests older than the window
        self.request_times = [
            t for t in self.request_times
            if now - t < timedelta(seconds=self.RATE_LIMIT_WINDOW)
        ]

        # If at limit, wait
        if len(self.request_times) >= self.RATE_LIMIT_REQUESTS:
            oldest = min(self.request_times)
            wait_time = (oldest + timedelta(seconds=self.RATE_LIMIT_WINDOW) - now).total_seconds()
            if wait_time > 0:
                logger.info(f"Rate limit reached. Waiting {wait_time:.1f}s...")
                time.sleep(wait_time + 0.5)

        self.request_times.append(datetime.now())

    def analyze_hash(self, file_hash: str) -> Optional[Dict]:
        """
        Look up a file hash in VirusTotal.

        Args:
            file_hash: SHA256, SHA1, or MD5 hash of the file

        Returns:
            Analysis results dict or None if not found/error
        """
        if not self._enabled:
            return None

        if not file_hash:
            return None

        # Normalize hash
        file_hash = file_hash.lower().strip()

        self._wait_for_rate_limit()

        try:
            url = f"{self.API_BASE}/files/{file_hash}"
            response = requests.get(url, headers=self._get_headers(), timeout=30)

            if response.status_code == 200:
                data = response.json()
                return self._parse_file_report(data)

            elif response.status_code == 404:
                logger.info(f"Hash not found in VirusTotal: {file_hash[:16]}...")
                return {
                    'found': False,
                    'hash': file_hash,
                    'message': 'File not found in VirusTotal database'
                }

            elif response.status_code == 429:
                logger.warning("VirusTotal rate limit exceeded")
                return {
                    'found': False,
                    'hash': file_hash,
                    'error': 'Rate limit exceeded'
                }

            else:
                logger.error(f"VirusTotal API error: {response.status_code}")
                return None

        except requests.RequestException as e:
            logger.error(f"VirusTotal request failed: {e}")
            return None

    def analyze_file(self, file_path: str) -> Optional[Dict]:
        """
        Calculate hash and analyze a local file.

        Args:
            file_path: Path to the file to analyze

        Returns:
            Analysis results dict or None if error
        """
        path = Path(file_path)
        if not path.exists():
            logger.error(f"File not found: {file_path}")
            return None

        # Calculate SHA256
        sha256_hash = self._calculate_sha256(file_path)
        if not sha256_hash:
            return None

        result = self.analyze_hash(sha256_hash)
        if result:
            result['file_path'] = str(file_path)
            result['file_size'] = path.stat().st_size

        return result

    def submit_file(self, file_path: str) -> Optional[Dict]:
        """
        Submit a file to VirusTotal for analysis.

        Note: This uses more API quota than hash lookup.
        Use only for files not already in VT database.

        Args:
            file_path: Path to file to submit

        Returns:
            Submission result dict or None if error
        """
        if not self._enabled:
            return None

        path = Path(file_path)
        if not path.exists():
            logger.error(f"File not found: {file_path}")
            return None

        # Check file size (VT limit is 32MB for direct upload)
        file_size = path.stat().st_size
        if file_size > 32 * 1024 * 1024:
            logger.warning(f"File too large for direct upload: {file_size} bytes")
            return None

        self._wait_for_rate_limit()

        try:
            url = f"{self.API_BASE}/files"

            with open(file_path, 'rb') as f:
                files = {'file': (path.name, f)}
                response = requests.post(
                    url,
                    headers=self._get_headers(),
                    files=files,
                    timeout=120
                )

            if response.status_code == 200:
                data = response.json()
                analysis_id = data.get('data', {}).get('id')
                logger.info(f"File submitted to VirusTotal. Analysis ID: {analysis_id}")
                return {
                    'submitted': True,
                    'analysis_id': analysis_id,
                    'file_path': str(file_path)
                }
            else:
                logger.error(f"File submission failed: {response.status_code}")
                return None

        except requests.RequestException as e:
            logger.error(f"File submission request failed: {e}")
            return None

    def get_analysis_status(self, analysis_id: str) -> Optional[Dict]:
        """
        Check the status of a submitted file analysis.

        Args:
            analysis_id: Analysis ID from submit_file()

        Returns:
            Analysis status dict or None if error
        """
        if not self._enabled:
            return None

        self._wait_for_rate_limit()

        try:
            url = f"{self.API_BASE}/analyses/{analysis_id}"
            response = requests.get(url, headers=self._get_headers(), timeout=30)

            if response.status_code == 200:
                data = response.json()
                attributes = data.get('data', {}).get('attributes', {})
                status = attributes.get('status')

                result = {
                    'analysis_id': analysis_id,
                    'status': status
                }

                if status == 'completed':
                    stats = attributes.get('stats', {})
                    result['stats'] = stats
                    result['malicious'] = stats.get('malicious', 0)
                    result['suspicious'] = stats.get('suspicious', 0)
                    result['undetected'] = stats.get('undetected', 0)

                return result
            else:
                logger.error(f"Analysis status check failed: {response.status_code}")
                return None

        except requests.RequestException as e:
            logger.error(f"Analysis status request failed: {e}")
            return None

    def analyze_url(self, url: str) -> Optional[Dict]:
        """
        Analyze a URL (e.g., malware download URL).

        Args:
            url: URL to analyze

        Returns:
            Analysis results dict or None if error
        """
        if not self._enabled:
            return None

        import base64

        self._wait_for_rate_limit()

        try:
            # URL must be base64 encoded (without padding)
            url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip('=')
            api_url = f"{self.API_BASE}/urls/{url_id}"

            response = requests.get(api_url, headers=self._get_headers(), timeout=30)

            if response.status_code == 200:
                data = response.json()
                return self._parse_url_report(data)

            elif response.status_code == 404:
                logger.info(f"URL not found in VirusTotal: {url[:50]}...")
                return {
                    'found': False,
                    'url': url,
                    'message': 'URL not found in VirusTotal database'
                }

            else:
                logger.error(f"URL analysis failed: {response.status_code}")
                return None

        except requests.RequestException as e:
            logger.error(f"URL analysis request failed: {e}")
            return None

    def _parse_file_report(self, data: Dict) -> Dict:
        """Parse VirusTotal file report response"""
        attributes = data.get('data', {}).get('attributes', {})
        stats = attributes.get('last_analysis_stats', {})

        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        undetected = stats.get('undetected', 0)
        total = malicious + suspicious + undetected + stats.get('harmless', 0)

        # Get detection names
        results = attributes.get('last_analysis_results', {})
        detections = []
        for engine, result in results.items():
            if result.get('category') in ['malicious', 'suspicious']:
                detections.append({
                    'engine': engine,
                    'result': result.get('result'),
                    'category': result.get('category')
                })

        # Determine threat level
        detection_ratio = (malicious + suspicious) / total if total > 0 else 0
        if detection_ratio >= 0.5:
            threat_level = 'critical'
        elif detection_ratio >= 0.25:
            threat_level = 'high'
        elif detection_ratio >= 0.1:
            threat_level = 'medium'
        elif malicious + suspicious > 0:
            threat_level = 'low'
        else:
            threat_level = 'clean'

        return {
            'found': True,
            'hash': attributes.get('sha256'),
            'md5': attributes.get('md5'),
            'sha1': attributes.get('sha1'),
            'sha256': attributes.get('sha256'),
            'file_size': attributes.get('size'),
            'file_type': attributes.get('type_description'),
            'file_names': attributes.get('names', [])[:5],  # First 5 names
            'malicious': malicious,
            'suspicious': suspicious,
            'undetected': undetected,
            'total_engines': total,
            'detection_ratio': f"{malicious + suspicious}/{total}",
            'threat_level': threat_level,
            'is_malware': malicious > 0 or suspicious > 0,
            'popular_threat_names': attributes.get('popular_threat_classification', {}).get('suggested_threat_label'),
            'detections': detections[:10],  # Top 10 detections
            'first_seen': attributes.get('first_submission_date'),
            'last_seen': attributes.get('last_analysis_date'),
            'tags': attributes.get('tags', []),
            'vt_link': f"https://www.virustotal.com/gui/file/{attributes.get('sha256')}"
        }

    def _parse_url_report(self, data: Dict) -> Dict:
        """Parse VirusTotal URL report response"""
        attributes = data.get('data', {}).get('attributes', {})
        stats = attributes.get('last_analysis_stats', {})

        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        total = sum(stats.values())

        return {
            'found': True,
            'url': attributes.get('url'),
            'final_url': attributes.get('last_final_url'),
            'malicious': malicious,
            'suspicious': suspicious,
            'total_engines': total,
            'detection_ratio': f"{malicious + suspicious}/{total}",
            'is_malicious': malicious > 0 or suspicious > 0,
            'categories': attributes.get('categories', {}),
            'last_analysis_date': attributes.get('last_analysis_date')
        }

    def _calculate_sha256(self, file_path: str) -> Optional[str]:
        """Calculate SHA256 hash of a file"""
        try:
            sha256 = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except Exception as e:
            logger.error(f"Failed to calculate hash: {e}")
            return None

    def batch_analyze_hashes(self, hashes: List[str]) -> Dict[str, Dict]:
        """
        Analyze multiple hashes with rate limiting.

        Args:
            hashes: List of file hashes to analyze

        Returns:
            Dict mapping hash to analysis result
        """
        results = {}

        for file_hash in hashes:
            result = self.analyze_hash(file_hash)
            if result:
                results[file_hash] = result

        return results

    def get_threat_summary(self, analysis_result: Dict) -> str:
        """
        Generate a human-readable threat summary.

        Args:
            analysis_result: Result from analyze_hash() or analyze_file()

        Returns:
            Summary string
        """
        if not analysis_result or not analysis_result.get('found'):
            return "File not found in VirusTotal database"

        threat_level = analysis_result.get('threat_level', 'unknown')
        detection_ratio = analysis_result.get('detection_ratio', '0/0')
        threat_name = analysis_result.get('popular_threat_names') or 'Unknown'

        if threat_level == 'clean':
            return f"Clean - No threats detected ({detection_ratio} engines)"
        else:
            return f"{threat_level.upper()} - {threat_name} ({detection_ratio} engines detected)"
