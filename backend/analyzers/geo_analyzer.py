"""
Geolocation analyzer

Resolves IP addresses to geographic locations using GeoIP2.
"""
import logging
from typing import Optional, Dict
import requests
from functools import lru_cache

logger = logging.getLogger(__name__)


class GeoAnalyzer:
    """Analyze IP addresses for geolocation data"""

    def __init__(self, geoip_db_path: Optional[str] = None, use_api: bool = True):
        """
        Initialize GeoAnalyzer

        Args:
            geoip_db_path: Path to MaxMind GeoIP2 database (optional)
            use_api: Whether to use online API as fallback
        """
        self.geoip_db_path = geoip_db_path
        self.use_api = use_api
        self.reader = None

        # Try to initialize MaxMind reader
        if geoip_db_path:
            try:
                import geoip2.database
                self.reader = geoip2.database.Reader(geoip_db_path)
                logger.info(f"GeoIP2 database loaded: {geoip_db_path}")
            except ImportError:
                logger.warning("geoip2 library not installed. Install with: pip install geoip2")
            except Exception as e:
                logger.warning(f"Could not load GeoIP2 database: {e}")

    @lru_cache(maxsize=1000)
    def geolocate_ip(self, ip_address: str) -> Dict:
        """
        Get geolocation data for an IP address

        Returns dict with: country, country_code, city, region,
                          latitude, longitude, isp, organization, asn
        """
        # Try MaxMind database first
        if self.reader:
            try:
                return self._geolocate_maxmind(ip_address)
            except Exception as e:
                logger.debug(f"MaxMind lookup failed for {ip_address}: {e}")

        # Fall back to API
        if self.use_api:
            return self._geolocate_api(ip_address)

        return self._empty_result()

    def _geolocate_maxmind(self, ip_address: str) -> Dict:
        """Geolocate using MaxMind GeoIP2 database"""
        try:
            response = self.reader.city(ip_address)

            return {
                'country': response.country.name,
                'country_code': response.country.iso_code,
                'city': response.city.name,
                'region': response.subdivisions.most_specific.name if response.subdivisions else None,
                'latitude': response.location.latitude,
                'longitude': response.location.longitude,
                'isp': None,  # Requires ISP database
                'organization': None,
                'asn': None,
            }
        except Exception as e:
            logger.error(f"MaxMind error for {ip_address}: {e}")
            raise

    def _geolocate_api(self, ip_address: str) -> Dict:
        """
        Geolocate using free API (ip-api.com)

        Note: Free tier has rate limits (45 requests/minute)
        For production, consider:
        - MaxMind GeoIP2 database (download locally)
        - Paid API services
        - Caching results
        """
        try:
            # Using ip-api.com (free, no API key required)
            # Limit: 45 requests per minute
            url = f"http://ip-api.com/json/{ip_address}"
            params = {
                'fields': 'status,message,country,countryCode,region,city,lat,lon,isp,org,as'
            }

            response = requests.get(url, params=params, timeout=5)
            response.raise_for_status()
            data = response.json()

            if data.get('status') == 'success':
                return {
                    'country': data.get('country'),
                    'country_code': data.get('countryCode'),
                    'city': data.get('city'),
                    'region': data.get('region'),
                    'latitude': data.get('lat'),
                    'longitude': data.get('lon'),
                    'isp': data.get('isp'),
                    'organization': data.get('org'),
                    'asn': data.get('as'),
                }
            else:
                logger.warning(f"API lookup failed for {ip_address}: {data.get('message')}")
                return self._empty_result()

        except requests.RequestException as e:
            logger.error(f"API request failed for {ip_address}: {e}")
            return self._empty_result()
        except Exception as e:
            logger.error(f"Unexpected error during API lookup: {e}")
            return self._empty_result()

    def _empty_result(self) -> Dict:
        """Return empty geolocation result"""
        return {
            'country': None,
            'country_code': None,
            'city': None,
            'region': None,
            'latitude': None,
            'longitude': None,
            'isp': None,
            'organization': None,
            'asn': None,
        }

    def is_private_ip(self, ip_address: str) -> bool:
        """Check if IP is private/internal"""
        import ipaddress
        try:
            ip = ipaddress.ip_address(ip_address)
            return ip.is_private
        except ValueError:
            return False

    def __del__(self):
        """Clean up GeoIP2 reader"""
        if self.reader:
            self.reader.close()
