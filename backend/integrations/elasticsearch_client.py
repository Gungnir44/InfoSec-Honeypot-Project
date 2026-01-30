"""
Elasticsearch Integration for Advanced Log Analysis

Provides:
- Centralized log storage and indexing
- Full-text search across attack data
- Real-time aggregations and analytics
- Integration with Kibana dashboards
"""
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import json

logger = logging.getLogger(__name__)

# Try to import elasticsearch, handle if not installed
try:
    from elasticsearch import Elasticsearch, helpers
    ES_AVAILABLE = True
except ImportError:
    ES_AVAILABLE = False
    logger.warning("elasticsearch package not installed. Run: pip install elasticsearch")


class HoneypotElasticsearch:
    """Elasticsearch client for honeypot data"""

    # Index names
    INDEX_ATTACKS = "honeypot-attacks"
    INDEX_LOGINS = "honeypot-logins"
    INDEX_COMMANDS = "honeypot-commands"
    INDEX_DOWNLOADS = "honeypot-downloads"
    INDEX_PROFILES = "honeypot-profiles"
    INDEX_THREAT_INTEL = "honeypot-threat-intel"

    def __init__(
        self,
        hosts: List[str] = None,
        cloud_id: str = None,
        api_key: str = None,
        username: str = None,
        password: str = None,
        verify_certs: bool = True
    ):
        """
        Initialize Elasticsearch client.

        Args:
            hosts: List of ES hosts (e.g., ['http://localhost:9200'])
            cloud_id: Elastic Cloud ID (for cloud deployments)
            api_key: API key for authentication
            username: Basic auth username
            password: Basic auth password
            verify_certs: Verify SSL certificates
        """
        if not ES_AVAILABLE:
            raise ImportError("elasticsearch package not installed")

        self.es = None
        self._connected = False

        try:
            if cloud_id:
                # Elastic Cloud connection
                if api_key:
                    self.es = Elasticsearch(cloud_id=cloud_id, api_key=api_key)
                else:
                    self.es = Elasticsearch(
                        cloud_id=cloud_id,
                        basic_auth=(username, password)
                    )
            elif hosts:
                # Self-hosted connection
                if api_key:
                    self.es = Elasticsearch(hosts=hosts, api_key=api_key, verify_certs=verify_certs)
                elif username and password:
                    self.es = Elasticsearch(
                        hosts=hosts,
                        basic_auth=(username, password),
                        verify_certs=verify_certs
                    )
                else:
                    self.es = Elasticsearch(hosts=hosts, verify_certs=verify_certs)

            # Test connection
            if self.es and self.es.ping():
                self._connected = True
                logger.info("Connected to Elasticsearch")
            else:
                logger.error("Failed to connect to Elasticsearch")

        except Exception as e:
            logger.error(f"Elasticsearch connection error: {e}")

    @property
    def is_connected(self) -> bool:
        return self._connected

    def create_indices(self):
        """Create all honeypot indices with mappings"""
        if not self._connected:
            return False

        indices = {
            self.INDEX_ATTACKS: self._get_attacks_mapping(),
            self.INDEX_LOGINS: self._get_logins_mapping(),
            self.INDEX_COMMANDS: self._get_commands_mapping(),
            self.INDEX_DOWNLOADS: self._get_downloads_mapping(),
            self.INDEX_PROFILES: self._get_profiles_mapping(),
            self.INDEX_THREAT_INTEL: self._get_threat_intel_mapping()
        }

        for index_name, mapping in indices.items():
            try:
                if not self.es.indices.exists(index=index_name):
                    self.es.indices.create(index=index_name, body=mapping)
                    logger.info(f"Created index: {index_name}")
                else:
                    logger.info(f"Index already exists: {index_name}")
            except Exception as e:
                logger.error(f"Error creating index {index_name}: {e}")

        return True

    def _get_attacks_mapping(self) -> Dict:
        """Get mapping for attacks index"""
        return {
            "mappings": {
                "properties": {
                    "timestamp": {"type": "date"},
                    "session_id": {"type": "keyword"},
                    "src_ip": {"type": "ip"},
                    "src_port": {"type": "integer"},
                    "dst_port": {"type": "integer"},
                    "country": {"type": "keyword"},
                    "country_code": {"type": "keyword"},
                    "city": {"type": "keyword"},
                    "region": {"type": "keyword"},
                    "location": {"type": "geo_point"},
                    "isp": {"type": "keyword"},
                    "organization": {"type": "keyword"},
                    "asn": {"type": "keyword"},
                    "login_attempts": {"type": "integer"},
                    "successful_logins": {"type": "integer"},
                    "commands_count": {"type": "integer"},
                    "downloads_count": {"type": "integer"},
                    "duration_seconds": {"type": "integer"},
                    "threat_level": {"type": "keyword"},
                    "threat_score": {"type": "integer"},
                    "tags": {"type": "keyword"}
                }
            }
        }

    def _get_logins_mapping(self) -> Dict:
        """Get mapping for login attempts index"""
        return {
            "mappings": {
                "properties": {
                    "timestamp": {"type": "date"},
                    "session_id": {"type": "keyword"},
                    "src_ip": {"type": "ip"},
                    "username": {"type": "keyword"},
                    "password": {"type": "keyword"},
                    "success": {"type": "boolean"},
                    "country": {"type": "keyword"}
                }
            }
        }

    def _get_commands_mapping(self) -> Dict:
        """Get mapping for commands index"""
        return {
            "mappings": {
                "properties": {
                    "timestamp": {"type": "date"},
                    "session_id": {"type": "keyword"},
                    "src_ip": {"type": "ip"},
                    "command": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                    "category": {"type": "keyword"},
                    "success": {"type": "boolean"},
                    "country": {"type": "keyword"}
                }
            }
        }

    def _get_downloads_mapping(self) -> Dict:
        """Get mapping for downloads index"""
        return {
            "mappings": {
                "properties": {
                    "timestamp": {"type": "date"},
                    "session_id": {"type": "keyword"},
                    "src_ip": {"type": "ip"},
                    "url": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                    "filename": {"type": "keyword"},
                    "file_hash": {"type": "keyword"},
                    "file_size": {"type": "long"},
                    "malware_detected": {"type": "boolean"},
                    "virustotal_score": {"type": "keyword"},
                    "threat_name": {"type": "keyword"},
                    "country": {"type": "keyword"}
                }
            }
        }

    def _get_profiles_mapping(self) -> Dict:
        """Get mapping for attacker profiles index"""
        return {
            "mappings": {
                "properties": {
                    "ip_address": {"type": "ip"},
                    "first_seen": {"type": "date"},
                    "last_seen": {"type": "date"},
                    "last_updated": {"type": "date"},
                    "total_sessions": {"type": "integer"},
                    "total_login_attempts": {"type": "integer"},
                    "total_commands": {"type": "integer"},
                    "total_downloads": {"type": "integer"},
                    "risk_level": {"type": "keyword"},
                    "risk_score": {"type": "integer"},
                    "sophistication_level": {"type": "keyword"},
                    "sophistication_score": {"type": "integer"},
                    "primary_objective": {"type": "keyword"},
                    "behavioral_traits": {"type": "keyword"},
                    "detected_tools": {"type": "keyword"},
                    "has_malware": {"type": "boolean"},
                    "appears_automated": {"type": "boolean"},
                    "is_persistent": {"type": "boolean"}
                }
            }
        }

    def _get_threat_intel_mapping(self) -> Dict:
        """Get mapping for threat intelligence index"""
        return {
            "mappings": {
                "properties": {
                    "ip_address": {"type": "ip"},
                    "last_updated": {"type": "date"},
                    "abuse_confidence_score": {"type": "integer"},
                    "abuse_total_reports": {"type": "integer"},
                    "is_tor_exit": {"type": "boolean"},
                    "threat_level": {"type": "keyword"},
                    "threat_score": {"type": "integer"},
                    "isp": {"type": "keyword"},
                    "domain": {"type": "keyword"},
                    "shodan_ports": {"type": "integer"},
                    "shodan_vulns_count": {"type": "integer"},
                    "shodan_org": {"type": "keyword"}
                }
            }
        }

    # ===== Indexing Methods =====

    def index_attack(self, attack_data: Dict) -> bool:
        """Index a single attack"""
        if not self._connected:
            return False

        try:
            # Prepare document
            doc = self._prepare_attack_doc(attack_data)

            self.es.index(
                index=self.INDEX_ATTACKS,
                id=attack_data.get('session_id'),
                document=doc
            )
            return True
        except Exception as e:
            logger.error(f"Error indexing attack: {e}")
            return False

    def index_login(self, login_data: Dict) -> bool:
        """Index a login attempt"""
        if not self._connected:
            return False

        try:
            self.es.index(index=self.INDEX_LOGINS, document=login_data)
            return True
        except Exception as e:
            logger.error(f"Error indexing login: {e}")
            return False

    def index_command(self, command_data: Dict) -> bool:
        """Index a command"""
        if not self._connected:
            return False

        try:
            self.es.index(index=self.INDEX_COMMANDS, document=command_data)
            return True
        except Exception as e:
            logger.error(f"Error indexing command: {e}")
            return False

    def bulk_index(self, index_name: str, documents: List[Dict]) -> int:
        """Bulk index documents"""
        if not self._connected:
            return 0

        try:
            actions = [
                {
                    "_index": index_name,
                    "_source": doc
                }
                for doc in documents
            ]

            success, _ = helpers.bulk(self.es, actions, raise_on_error=False)
            logger.info(f"Bulk indexed {success} documents to {index_name}")
            return success
        except Exception as e:
            logger.error(f"Bulk indexing error: {e}")
            return 0

    def _prepare_attack_doc(self, attack_data: Dict) -> Dict:
        """Prepare attack document for indexing"""
        doc = {
            "timestamp": attack_data.get('timestamp'),
            "session_id": attack_data.get('session_id'),
            "src_ip": attack_data.get('src_ip'),
            "src_port": attack_data.get('src_port'),
            "dst_port": attack_data.get('dst_port'),
            "country": attack_data.get('country'),
            "country_code": attack_data.get('country_code'),
            "city": attack_data.get('city'),
            "isp": attack_data.get('isp'),
            "organization": attack_data.get('organization'),
            "asn": attack_data.get('asn')
        }

        # Add geo_point if coordinates available
        lat = attack_data.get('latitude')
        lon = attack_data.get('longitude')
        if lat and lon:
            doc['location'] = {"lat": lat, "lon": lon}

        return doc

    # ===== Search Methods =====

    def search_attacks(
        self,
        query: str = None,
        src_ip: str = None,
        country: str = None,
        start_date: datetime = None,
        end_date: datetime = None,
        threat_level: str = None,
        size: int = 100
    ) -> List[Dict]:
        """Search attacks with filters"""
        if not self._connected:
            return []

        must_clauses = []

        if query:
            must_clauses.append({"query_string": {"query": query}})

        if src_ip:
            must_clauses.append({"term": {"src_ip": src_ip}})

        if country:
            must_clauses.append({"term": {"country": country}})

        if threat_level:
            must_clauses.append({"term": {"threat_level": threat_level}})

        if start_date or end_date:
            range_query = {"range": {"timestamp": {}}}
            if start_date:
                range_query["range"]["timestamp"]["gte"] = start_date.isoformat()
            if end_date:
                range_query["range"]["timestamp"]["lte"] = end_date.isoformat()
            must_clauses.append(range_query)

        body = {
            "query": {"bool": {"must": must_clauses}} if must_clauses else {"match_all": {}},
            "sort": [{"timestamp": "desc"}],
            "size": size
        }

        try:
            response = self.es.search(index=self.INDEX_ATTACKS, body=body)
            return [hit["_source"] for hit in response["hits"]["hits"]]
        except Exception as e:
            logger.error(f"Search error: {e}")
            return []

    def search_commands(self, command_pattern: str, size: int = 100) -> List[Dict]:
        """Search for specific command patterns"""
        if not self._connected:
            return []

        body = {
            "query": {
                "match": {"command": command_pattern}
            },
            "sort": [{"timestamp": "desc"}],
            "size": size
        }

        try:
            response = self.es.search(index=self.INDEX_COMMANDS, body=body)
            return [hit["_source"] for hit in response["hits"]["hits"]]
        except Exception as e:
            logger.error(f"Command search error: {e}")
            return []

    # ===== Aggregation Methods =====

    def get_attacks_by_country(self, days: int = 30) -> Dict[str, int]:
        """Get attack count by country"""
        if not self._connected:
            return {}

        body = {
            "query": {
                "range": {
                    "timestamp": {
                        "gte": f"now-{days}d"
                    }
                }
            },
            "aggs": {
                "by_country": {
                    "terms": {"field": "country", "size": 50}
                }
            },
            "size": 0
        }

        try:
            response = self.es.search(index=self.INDEX_ATTACKS, body=body)
            buckets = response["aggregations"]["by_country"]["buckets"]
            return {b["key"]: b["doc_count"] for b in buckets}
        except Exception as e:
            logger.error(f"Aggregation error: {e}")
            return {}

    def get_top_attackers(self, days: int = 30, limit: int = 20) -> List[Dict]:
        """Get top attacking IPs"""
        if not self._connected:
            return []

        body = {
            "query": {
                "range": {
                    "timestamp": {
                        "gte": f"now-{days}d"
                    }
                }
            },
            "aggs": {
                "by_ip": {
                    "terms": {"field": "src_ip", "size": limit},
                    "aggs": {
                        "country": {"terms": {"field": "country", "size": 1}}
                    }
                }
            },
            "size": 0
        }

        try:
            response = self.es.search(index=self.INDEX_ATTACKS, body=body)
            buckets = response["aggregations"]["by_ip"]["buckets"]
            return [
                {
                    "ip": b["key"],
                    "count": b["doc_count"],
                    "country": b["country"]["buckets"][0]["key"] if b["country"]["buckets"] else "Unknown"
                }
                for b in buckets
            ]
        except Exception as e:
            logger.error(f"Aggregation error: {e}")
            return []

    def get_attack_timeline(self, days: int = 30, interval: str = "1d") -> List[Dict]:
        """Get attack timeline histogram"""
        if not self._connected:
            return []

        body = {
            "query": {
                "range": {
                    "timestamp": {
                        "gte": f"now-{days}d"
                    }
                }
            },
            "aggs": {
                "timeline": {
                    "date_histogram": {
                        "field": "timestamp",
                        "fixed_interval": interval
                    }
                }
            },
            "size": 0
        }

        try:
            response = self.es.search(index=self.INDEX_ATTACKS, body=body)
            buckets = response["aggregations"]["timeline"]["buckets"]
            return [
                {"timestamp": b["key_as_string"], "count": b["doc_count"]}
                for b in buckets
            ]
        except Exception as e:
            logger.error(f"Timeline error: {e}")
            return []

    def get_top_credentials(self, days: int = 30, limit: int = 20) -> Dict:
        """Get most common usernames and passwords"""
        if not self._connected:
            return {"usernames": [], "passwords": []}

        body = {
            "query": {
                "range": {
                    "timestamp": {
                        "gte": f"now-{days}d"
                    }
                }
            },
            "aggs": {
                "top_usernames": {
                    "terms": {"field": "username", "size": limit}
                },
                "top_passwords": {
                    "terms": {"field": "password", "size": limit}
                }
            },
            "size": 0
        }

        try:
            response = self.es.search(index=self.INDEX_LOGINS, body=body)
            return {
                "usernames": [
                    {"username": b["key"], "count": b["doc_count"]}
                    for b in response["aggregations"]["top_usernames"]["buckets"]
                ],
                "passwords": [
                    {"password": b["key"], "count": b["doc_count"]}
                    for b in response["aggregations"]["top_passwords"]["buckets"]
                ]
            }
        except Exception as e:
            logger.error(f"Credentials aggregation error: {e}")
            return {"usernames": [], "passwords": []}

    def get_command_categories(self, days: int = 30) -> Dict[str, int]:
        """Get command distribution by category"""
        if not self._connected:
            return {}

        body = {
            "query": {
                "range": {
                    "timestamp": {
                        "gte": f"now-{days}d"
                    }
                }
            },
            "aggs": {
                "by_category": {
                    "terms": {"field": "category", "size": 20}
                }
            },
            "size": 0
        }

        try:
            response = self.es.search(index=self.INDEX_COMMANDS, body=body)
            buckets = response["aggregations"]["by_category"]["buckets"]
            return {b["key"]: b["doc_count"] for b in buckets}
        except Exception as e:
            logger.error(f"Category aggregation error: {e}")
            return {}

    def get_threat_level_distribution(self, days: int = 30) -> Dict[str, int]:
        """Get distribution of threat levels"""
        if not self._connected:
            return {}

        body = {
            "query": {
                "range": {
                    "timestamp": {
                        "gte": f"now-{days}d"
                    }
                }
            },
            "aggs": {
                "by_threat_level": {
                    "terms": {"field": "threat_level", "size": 10}
                }
            },
            "size": 0
        }

        try:
            response = self.es.search(index=self.INDEX_ATTACKS, body=body)
            buckets = response["aggregations"]["by_threat_level"]["buckets"]
            return {b["key"]: b["doc_count"] for b in buckets}
        except Exception as e:
            logger.error(f"Threat level aggregation error: {e}")
            return {}

    # ===== Statistics =====

    def get_index_stats(self) -> Dict:
        """Get statistics for all indices"""
        if not self._connected:
            return {}

        stats = {}
        indices = [
            self.INDEX_ATTACKS,
            self.INDEX_LOGINS,
            self.INDEX_COMMANDS,
            self.INDEX_DOWNLOADS,
            self.INDEX_PROFILES,
            self.INDEX_THREAT_INTEL
        ]

        for index in indices:
            try:
                if self.es.indices.exists(index=index):
                    count = self.es.count(index=index)["count"]
                    stats[index] = {"doc_count": count, "exists": True}
                else:
                    stats[index] = {"doc_count": 0, "exists": False}
            except Exception as e:
                stats[index] = {"error": str(e)}

        return stats

    def get_cluster_health(self) -> Dict:
        """Get Elasticsearch cluster health"""
        if not self._connected:
            return {"status": "disconnected"}

        try:
            return dict(self.es.cluster.health())
        except Exception as e:
            return {"status": "error", "message": str(e)}
