"""
Configuration management for honeypot backend
"""
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()


class Config:
    """Base configuration"""

    # Database configuration
    DB_HOST = os.getenv('DB_HOST', 'localhost')
    DB_PORT = os.getenv('DB_PORT', '5432')
    DB_NAME = os.getenv('DB_NAME', 'honeypot_db')
    DB_USER = os.getenv('DB_USER', 'honeypot_user')
    DB_PASSWORD = os.getenv('DB_PASSWORD', 'change_this_password')

    DATABASE_URI = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

    # Alternative: SQLite for development
    # DATABASE_URI = "sqlite:///honeypot.db"

    # Cowrie log path
    COWRIE_LOG_PATH = os.getenv('COWRIE_LOG_PATH', '/home/honeypot/cowrie/var/log/cowrie/cowrie.json')

    # GeoIP database path (download from MaxMind)
    GEOIP_DB_PATH = os.getenv('GEOIP_DB_PATH', './data/GeoLite2-City.mmdb')

    # Analysis settings
    BRUTE_FORCE_THRESHOLD = int(os.getenv('BRUTE_FORCE_THRESHOLD', '10'))  # Login attempts per minute
    LOG_PROCESSING_INTERVAL = int(os.getenv('LOG_PROCESSING_INTERVAL', '60'))  # seconds

    # Dashboard settings
    DASHBOARD_SECRET_KEY = os.getenv('DASHBOARD_SECRET_KEY', 'dev-secret-key-change-in-production')
    DASHBOARD_HOST = os.getenv('DASHBOARD_HOST', '0.0.0.0')
    DASHBOARD_PORT = int(os.getenv('DASHBOARD_PORT', '5000'))

    # Security
    ENABLE_AUTHENTICATION = os.getenv('ENABLE_AUTHENTICATION', 'False').lower() == 'true'
    ADMIN_USERNAME = os.getenv('ADMIN_USERNAME', 'admin')
    ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', 'admin')  # Change in production!

    # VirusTotal Integration
    VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY', '')
    VIRUSTOTAL_ENABLED = os.getenv('VIRUSTOTAL_ENABLED', 'True').lower() == 'true'
    VIRUSTOTAL_RATE_LIMIT = os.getenv('VIRUSTOTAL_RATE_LIMIT', 'True').lower() == 'true'

    # Cowrie download directory (where captured malware is stored)
    COWRIE_DOWNLOAD_PATH = os.getenv('COWRIE_DOWNLOAD_PATH', '/home/honeypot/cowrie/var/lib/cowrie/downloads')

    # Threat Intelligence Integration
    # AbuseIPDB - IP reputation database (https://www.abuseipdb.com/)
    ABUSEIPDB_API_KEY = os.getenv('ABUSEIPDB_API_KEY', '')
    ABUSEIPDB_ENABLED = os.getenv('ABUSEIPDB_ENABLED', 'True').lower() == 'true'

    # Shodan - Internet device search engine (https://www.shodan.io/)
    SHODAN_API_KEY = os.getenv('SHODAN_API_KEY', '')
    SHODAN_ENABLED = os.getenv('SHODAN_ENABLED', 'True').lower() == 'true'

    # Threat Intel settings
    THREAT_INTEL_RATE_LIMIT = os.getenv('THREAT_INTEL_RATE_LIMIT', 'True').lower() == 'true'
    THREAT_INTEL_CACHE_HOURS = int(os.getenv('THREAT_INTEL_CACHE_HOURS', '24'))

    # Elasticsearch Configuration
    ELASTICSEARCH_ENABLED = os.getenv('ELASTICSEARCH_ENABLED', 'False').lower() == 'true'
    ELASTICSEARCH_HOSTS = os.getenv('ELASTICSEARCH_HOSTS', 'http://localhost:9200').split(',')
    ELASTICSEARCH_CLOUD_ID = os.getenv('ELASTICSEARCH_CLOUD_ID', '')
    ELASTICSEARCH_API_KEY = os.getenv('ELASTICSEARCH_API_KEY', '')
    ELASTICSEARCH_USERNAME = os.getenv('ELASTICSEARCH_USERNAME', '')
    ELASTICSEARCH_PASSWORD = os.getenv('ELASTICSEARCH_PASSWORD', '')

    @classmethod
    def validate(cls):
        """Validate configuration"""
        errors = []

        if cls.DB_PASSWORD == 'change_this_password':
            errors.append("Database password not set. Update DB_PASSWORD in .env")

        if cls.DASHBOARD_SECRET_KEY == 'dev-secret-key-change-in-production':
            errors.append("Dashboard secret key not set. Update DASHBOARD_SECRET_KEY in .env")

        if not os.path.exists(os.path.dirname(cls.COWRIE_LOG_PATH) or '.'):
            errors.append(f"Cowrie log directory does not exist: {cls.COWRIE_LOG_PATH}")

        return errors


class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    DATABASE_URI = "sqlite:///honeypot_dev.db"


class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False


# Select configuration based on environment
ENV = os.getenv('FLASK_ENV', 'development')
if ENV == 'production':
    config = ProductionConfig()
else:
    config = DevelopmentConfig()
