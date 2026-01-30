"""
API endpoints for honeypot dashboard

Provides JSON data for frontend visualizations
"""
import sys
import os
from flask import Blueprint, jsonify, request
from datetime import datetime, timedelta

# Add parent directories to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from backend.database.db_manager import DatabaseManager

api_bp = Blueprint('api', __name__)
db_manager = DatabaseManager()


@api_bp.route('/stats/summary', methods=['GET'])
def get_summary_stats():
    """Get overall attack statistics"""
    try:
        stats = db_manager.get_attack_stats()
        return jsonify({
            'success': True,
            'data': stats
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@api_bp.route('/attacks/recent', methods=['GET'])
def get_recent_attacks():
    """Get recent attacks"""
    try:
        limit = request.args.get('limit', 100, type=int)
        attacks = db_manager.get_recent_attacks(limit=limit)

        # Convert to dict for JSON serialization
        attacks_data = [
            {
                'id': attack.id,
                'timestamp': attack.timestamp.isoformat() if attack.timestamp else None,
                'src_ip': attack.src_ip,
                'src_port': attack.src_port,
                'country': attack.country,
                'city': attack.city,
                'session_id': attack.session_id,
            }
            for attack in attacks
        ]

        return jsonify({
            'success': True,
            'data': attacks_data,
            'count': len(attacks_data)
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@api_bp.route('/attacks/by-country', methods=['GET'])
def get_attacks_by_country():
    """Get attack distribution by country"""
    try:
        attacks = db_manager.get_attacks_by_country()

        data = [
            {
                'country': country,
                'country_code': country_code,
                'count': count
            }
            for country, country_code, count in attacks
        ]

        return jsonify({
            'success': True,
            'data': data
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@api_bp.route('/attacks/timeline', methods=['GET'])
def get_attack_timeline():
    """Get attacks over time"""
    try:
        days = request.args.get('days', 30, type=int)
        interval = request.args.get('interval', 'day', type=str)

        timeline = db_manager.get_attacks_over_time(days=days, interval=interval)

        data = [
            {
                'timestamp': timestamp.isoformat() if timestamp else None,
                'count': count
            }
            for timestamp, count in timeline
        ]

        return jsonify({
            'success': True,
            'data': data
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@api_bp.route('/attacks/top-ips', methods=['GET'])
def get_top_ips():
    """Get top attacking IPs"""
    try:
        limit = request.args.get('limit', 20, type=int)
        top_ips = db_manager.get_top_attacking_ips(limit=limit)

        data = [
            {
                'ip': ip,
                'country': country,
                'count': count
            }
            for ip, country, count in top_ips
        ]

        return jsonify({
            'success': True,
            'data': data
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@api_bp.route('/attacks/map', methods=['GET'])
def get_attack_map_data():
    """Get geographic data for attack map"""
    try:
        map_data = db_manager.get_map_data()

        return jsonify({
            'success': True,
            'data': map_data
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@api_bp.route('/credentials/top', methods=['GET'])
def get_top_credentials():
    """Get most common username/password combinations"""
    try:
        limit = request.args.get('limit', 20, type=int)
        credentials = db_manager.get_top_credentials(limit=limit)

        data = [
            {
                'username': username,
                'password': password,
                'count': count
            }
            for username, password, count in credentials
        ]

        return jsonify({
            'success': True,
            'data': data
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@api_bp.route('/credentials/usernames', methods=['GET'])
def get_top_usernames():
    """Get most common usernames"""
    try:
        limit = request.args.get('limit', 20, type=int)
        usernames = db_manager.get_top_usernames(limit=limit)

        data = [
            {
                'username': username,
                'count': count
            }
            for username, count in usernames
        ]

        return jsonify({
            'success': True,
            'data': data
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@api_bp.route('/commands/top', methods=['GET'])
def get_top_commands():
    """Get most executed commands"""
    try:
        limit = request.args.get('limit', 20, type=int)
        commands = db_manager.get_top_commands(limit=limit)

        data = [
            {
                'command': command,
                'count': count
            }
            for command, count in commands
        ]

        return jsonify({
            'success': True,
            'data': data
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@api_bp.route('/commands/categories', methods=['GET'])
def get_command_categories():
    """Get command distribution by category"""
    try:
        categories = db_manager.get_commands_by_category()

        data = [
            {
                'category': category or 'unknown',
                'count': count
            }
            for category, count in categories
        ]

        return jsonify({
            'success': True,
            'data': data
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


# ===== Malware/Download Endpoints =====

@api_bp.route('/downloads/recent', methods=['GET'])
def get_recent_downloads():
    """Get recent file downloads"""
    try:
        limit = request.args.get('limit', 50, type=int)
        downloads = db_manager.get_downloads_with_attack_info(limit=limit)

        data = [
            {
                'id': dl['id'],
                'url': dl['url'],
                'filename': dl['filename'],
                'file_hash': dl['file_hash'],
                'file_size': dl['file_size'],
                'timestamp': dl['timestamp'].isoformat() if dl['timestamp'] else None,
                'malware_detected': dl['malware_detected'],
                'virustotal_score': dl['virustotal_score'],
                'src_ip': dl['src_ip'],
                'country': dl['country'],
                'session_id': dl['session_id']
            }
            for dl in downloads
        ]

        return jsonify({
            'success': True,
            'data': data,
            'count': len(data)
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@api_bp.route('/downloads/malware', methods=['GET'])
def get_malware_downloads():
    """Get downloads detected as malware"""
    try:
        limit = request.args.get('limit', 50, type=int)
        downloads = db_manager.get_malware_downloads(limit=limit)

        data = [
            {
                'id': dl.id,
                'url': dl.url,
                'filename': dl.filename,
                'file_hash': dl.file_hash,
                'file_size': dl.file_size,
                'timestamp': dl.timestamp.isoformat() if dl.timestamp else None,
                'malware_detected': dl.malware_detected,
                'virustotal_score': dl.virustotal_score
            }
            for dl in downloads
        ]

        return jsonify({
            'success': True,
            'data': data,
            'count': len(data)
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@api_bp.route('/downloads/stats', methods=['GET'])
def get_download_stats():
    """Get download/malware statistics"""
    try:
        stats = db_manager.get_download_stats()

        return jsonify({
            'success': True,
            'data': stats
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@api_bp.route('/downloads/scan/<file_hash>', methods=['POST'])
def scan_file_hash(file_hash):
    """Manually trigger VirusTotal scan for a file hash"""
    try:
        # Import here to avoid circular imports
        import sys
        import os
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
        from backend.config import config
        from backend.analyzers import VirusTotalAnalyzer

        if not config.VIRUSTOTAL_API_KEY:
            return jsonify({
                'success': False,
                'error': 'VirusTotal API key not configured'
            }), 400

        vt_analyzer = VirusTotalAnalyzer(
            api_key=config.VIRUSTOTAL_API_KEY,
            rate_limit=config.VIRUSTOTAL_RATE_LIMIT
        )

        result = vt_analyzer.analyze_hash(file_hash)

        if result:
            # Update database if we have this hash
            download = db_manager.get_download_by_hash(file_hash)
            if download and result.get('found'):
                db_manager.update_download_virustotal(
                    download.id,
                    result.get('is_malware', False),
                    result.get('detection_ratio', '')
                )

            return jsonify({
                'success': True,
                'data': result
            })
        else:
            return jsonify({
                'success': False,
                'error': 'VirusTotal analysis failed'
            }), 500

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@api_bp.route('/virustotal/status', methods=['GET'])
def get_virustotal_status():
    """Check VirusTotal integration status"""
    try:
        import sys
        import os
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
        from backend.config import config

        return jsonify({
            'success': True,
            'data': {
                'enabled': config.VIRUSTOTAL_ENABLED,
                'configured': bool(config.VIRUSTOTAL_API_KEY),
                'rate_limit': config.VIRUSTOTAL_RATE_LIMIT
            }
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


# ===== Threat Intelligence Endpoints =====

@api_bp.route('/threat-intel/status', methods=['GET'])
def get_threat_intel_status():
    """Check threat intelligence integration status"""
    try:
        import sys
        import os
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
        from backend.config import config

        return jsonify({
            'success': True,
            'data': {
                'abuseipdb': {
                    'enabled': config.ABUSEIPDB_ENABLED,
                    'configured': bool(config.ABUSEIPDB_API_KEY)
                },
                'shodan': {
                    'enabled': config.SHODAN_ENABLED,
                    'configured': bool(config.SHODAN_API_KEY)
                },
                'rate_limit': config.THREAT_INTEL_RATE_LIMIT,
                'cache_hours': config.THREAT_INTEL_CACHE_HOURS
            }
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@api_bp.route('/threat-intel/stats', methods=['GET'])
def get_threat_intel_stats():
    """Get threat intelligence statistics"""
    try:
        stats = db_manager.get_threat_intel_stats()

        return jsonify({
            'success': True,
            'data': stats
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@api_bp.route('/threat-intel/ip/<ip_address>', methods=['GET'])
def get_ip_threat_intel(ip_address):
    """Get threat intelligence for a specific IP"""
    try:
        intel = db_manager.get_threat_intel(ip_address)

        if intel:
            import json
            data = {
                'ip_address': intel.ip_address,
                'threat_level': intel.threat_level,
                'threat_score': intel.threat_score,
                'abuse_confidence_score': intel.abuse_confidence_score,
                'abuse_total_reports': intel.abuse_total_reports,
                'is_tor_exit': intel.is_tor_exit,
                'abuse_isp': intel.abuse_isp,
                'shodan_vulns_count': intel.shodan_vulns_count,
                'shodan_org': intel.shodan_org,
                'shodan_os': intel.shodan_os,
                'shodan_ports': json.loads(intel.shodan_ports) if intel.shodan_ports else [],
                'threat_indicators': json.loads(intel.threat_indicators) if intel.threat_indicators else [],
                'enrichment_sources': intel.enrichment_sources,
                'last_updated': intel.last_updated.isoformat() if intel.last_updated else None
            }

            return jsonify({
                'success': True,
                'data': data
            })
        else:
            return jsonify({
                'success': True,
                'data': None,
                'message': 'No threat intel data for this IP'
            })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@api_bp.route('/threat-intel/ip/<ip_address>/enrich', methods=['POST'])
def enrich_ip_threat_intel(ip_address):
    """Enrich an IP with threat intelligence (on-demand)"""
    try:
        import sys
        import os
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
        from backend.config import config
        from backend.analyzers import ThreatIntelligenceManager

        abuseipdb_key = config.ABUSEIPDB_API_KEY if config.ABUSEIPDB_ENABLED else None
        shodan_key = config.SHODAN_API_KEY if config.SHODAN_ENABLED else None

        if not abuseipdb_key and not shodan_key:
            return jsonify({
                'success': False,
                'error': 'No threat intelligence API keys configured'
            }), 400

        threat_intel = ThreatIntelligenceManager(
            abuseipdb_key=abuseipdb_key,
            shodan_key=shodan_key,
            rate_limit=config.THREAT_INTEL_RATE_LIMIT
        )

        result = threat_intel.enrich_ip(ip_address)

        if result:
            # Save to database
            import json
            db_data = {
                'ip': ip_address,
                'enrichment_sources': ','.join(result.get('sources', []))
            }

            if 'abuseipdb' in result:
                abuse = result['abuseipdb']
                db_data.update({
                    'abuse_confidence_score': abuse.get('abuse_confidence_score'),
                    'abuse_total_reports': abuse.get('total_reports'),
                    'is_tor_exit': abuse.get('is_tor', False),
                    'abuse_isp': abuse.get('isp'),
                    'abuse_domain': abuse.get('domain'),
                    'abuse_usage_type': abuse.get('usage_type')
                })

            if 'shodan' in result and result['shodan'].get('found'):
                shodan = result['shodan']
                db_data.update({
                    'shodan_ports': shodan.get('ports', []),
                    'shodan_vulns_count': shodan.get('vuln_count', 0),
                    'shodan_os': shodan.get('os'),
                    'shodan_org': shodan.get('org'),
                    'shodan_hostnames': shodan.get('hostnames', [])
                })

            assessment = result.get('threat_assessment', {})
            db_data.update({
                'threat_level': assessment.get('threat_level'),
                'threat_score': assessment.get('overall_score'),
                'threat_indicators': assessment.get('indicators', [])
            })

            db_manager.save_threat_intel(db_data)

            return jsonify({
                'success': True,
                'data': result
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Enrichment failed'
            }), 500

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@api_bp.route('/threat-intel/high-threats', methods=['GET'])
def get_high_threat_ips():
    """Get IPs with high threat scores"""
    try:
        min_score = request.args.get('min_score', 50, type=int)
        limit = request.args.get('limit', 50, type=int)

        threats = db_manager.get_high_threat_ips(min_score=min_score, limit=limit)

        import json
        data = [
            {
                'ip_address': t.ip_address,
                'threat_level': t.threat_level,
                'threat_score': t.threat_score,
                'abuse_confidence_score': t.abuse_confidence_score,
                'is_tor_exit': t.is_tor_exit,
                'shodan_vulns_count': t.shodan_vulns_count,
                'threat_indicators': json.loads(t.threat_indicators) if t.threat_indicators else []
            }
            for t in threats
        ]

        return jsonify({
            'success': True,
            'data': data,
            'count': len(data)
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@api_bp.route('/threat-intel/tor-nodes', methods=['GET'])
def get_tor_exit_nodes():
    """Get IPs identified as Tor exit nodes"""
    try:
        tor_nodes = db_manager.get_tor_exit_nodes()

        data = [
            {
                'ip_address': t.ip_address,
                'threat_score': t.threat_score,
                'abuse_confidence_score': t.abuse_confidence_score
            }
            for t in tor_nodes
        ]

        return jsonify({
            'success': True,
            'data': data,
            'count': len(data)
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@api_bp.route('/attacks/with-threat-intel', methods=['GET'])
def get_attacks_with_intel():
    """Get recent attacks with threat intelligence data"""
    try:
        limit = request.args.get('limit', 50, type=int)
        attacks = db_manager.get_attacks_with_threat_intel(limit=limit)

        return jsonify({
            'success': True,
            'data': attacks,
            'count': len(attacks)
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


# ===== Attacker Profile Endpoints =====

@api_bp.route('/profiles/stats', methods=['GET'])
def get_profile_stats():
    """Get attacker profiling statistics"""
    try:
        stats = db_manager.get_attacker_profile_stats()

        return jsonify({
            'success': True,
            'data': stats
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@api_bp.route('/profiles/top', methods=['GET'])
def get_top_profiles():
    """Get top attacker profiles sorted by risk score"""
    try:
        limit = request.args.get('limit', 10, type=int)

        session = db_manager.get_session()
        try:
            from backend.database.models import AttackerProfile
            profiles = (
                session.query(AttackerProfile)
                .order_by(AttackerProfile.risk_score.desc())
                .limit(limit)
                .all()
            )

            data = [
                {
                    'ip_address': p.ip_address,
                    'risk_level': p.risk_level,
                    'risk_score': p.risk_score,
                    'sophistication_level': p.sophistication_level,
                    'primary_objective': p.primary_objective,
                    'total_sessions': p.total_sessions,
                    'total_commands': p.total_commands
                }
                for p in profiles
            ]
        finally:
            session.close()

        return jsonify({
            'success': True,
            'data': data,
            'count': len(data)
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@api_bp.route('/profiles/ip/<ip_address>', methods=['GET'])
def get_attacker_profile(ip_address):
    """Get attacker profile for a specific IP"""
    try:
        profile = db_manager.get_attacker_profile(ip_address)

        if profile:
            import json
            data = {
                'ip_address': profile.ip_address,
                'total_sessions': profile.total_sessions,
                'total_login_attempts': profile.total_login_attempts,
                'successful_logins': profile.successful_logins,
                'total_commands': profile.total_commands,
                'total_downloads': profile.total_downloads,
                'first_seen': profile.first_seen.isoformat() if profile.first_seen else None,
                'last_seen': profile.last_seen.isoformat() if profile.last_seen else None,
                'active_days': profile.active_days,
                'sophistication_level': profile.sophistication_level,
                'sophistication_score': profile.sophistication_score,
                'primary_objective': profile.primary_objective,
                'all_objectives': json.loads(profile.all_objectives) if profile.all_objectives else {},
                'risk_level': profile.risk_level,
                'risk_score': profile.risk_score,
                'risk_factors': json.loads(profile.risk_factors) if profile.risk_factors else [],
                'behavioral_traits': json.loads(profile.behavioral_traits) if profile.behavioral_traits else [],
                'detected_tools': json.loads(profile.detected_tools) if profile.detected_tools else [],
                'credential_patterns': json.loads(profile.credential_patterns) if profile.credential_patterns else [],
                'appears_automated': profile.appears_automated,
                'peak_hour': profile.peak_hour,
                'peak_day': profile.peak_day,
                'has_malware': profile.has_malware,
                'uses_obfuscation': profile.uses_obfuscation,
                'is_persistent': profile.is_persistent,
                'recommendations': json.loads(profile.recommendations) if profile.recommendations else [],
                'profile_generated': profile.profile_generated.isoformat() if profile.profile_generated else None,
                'last_updated': profile.last_updated.isoformat() if profile.last_updated else None
            }

            return jsonify({
                'success': True,
                'data': data
            })
        else:
            return jsonify({
                'success': True,
                'data': None,
                'message': 'No profile found for this IP'
            })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@api_bp.route('/profiles/ip/<ip_address>/generate', methods=['POST'])
def generate_attacker_profile(ip_address):
    """Generate profile for a specific IP (on-demand)"""
    try:
        import sys
        import os
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
        from backend.analyzers import AttackerProfiler

        profiler = AttackerProfiler(db_manager)
        profile = profiler.build_profile(ip_address)

        if 'error' not in profile:
            db_manager.save_attacker_profile(profile)

            return jsonify({
                'success': True,
                'data': profile
            })
        else:
            return jsonify({
                'success': False,
                'error': profile.get('error')
            }), 404

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@api_bp.route('/profiles/high-risk', methods=['GET'])
def get_high_risk_profiles():
    """Get high-risk attacker profiles"""
    try:
        min_score = request.args.get('min_score', 50, type=int)
        limit = request.args.get('limit', 50, type=int)

        profiles = db_manager.get_high_risk_profiles(min_score=min_score, limit=limit)

        import json
        data = [
            {
                'ip_address': p.ip_address,
                'risk_level': p.risk_level,
                'risk_score': p.risk_score,
                'sophistication_level': p.sophistication_level,
                'primary_objective': p.primary_objective,
                'has_malware': p.has_malware,
                'appears_automated': p.appears_automated,
                'behavioral_traits': json.loads(p.behavioral_traits) if p.behavioral_traits else [],
                'total_sessions': p.total_sessions
            }
            for p in profiles
        ]

        return jsonify({
            'success': True,
            'data': data,
            'count': len(data)
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@api_bp.route('/profiles/by-objective/<objective>', methods=['GET'])
def get_profiles_by_objective(objective):
    """Get profiles with a specific primary objective"""
    try:
        limit = request.args.get('limit', 50, type=int)
        profiles = db_manager.get_profiles_by_objective(objective, limit=limit)

        import json
        data = [
            {
                'ip_address': p.ip_address,
                'risk_level': p.risk_level,
                'risk_score': p.risk_score,
                'sophistication_level': p.sophistication_level,
                'total_sessions': p.total_sessions,
                'has_malware': p.has_malware
            }
            for p in profiles
        ]

        return jsonify({
            'success': True,
            'data': data,
            'count': len(data)
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@api_bp.route('/profiles/by-sophistication/<level>', methods=['GET'])
def get_profiles_by_sophistication(level):
    """Get profiles with a specific sophistication level"""
    try:
        limit = request.args.get('limit', 50, type=int)
        profiles = db_manager.get_profiles_by_sophistication(level, limit=limit)

        import json
        data = [
            {
                'ip_address': p.ip_address,
                'risk_level': p.risk_level,
                'risk_score': p.risk_score,
                'primary_objective': p.primary_objective,
                'total_sessions': p.total_sessions,
                'detected_tools': json.loads(p.detected_tools) if p.detected_tools else []
            }
            for p in profiles
        ]

        return jsonify({
            'success': True,
            'data': data,
            'count': len(data)
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@api_bp.route('/profiles/malware-deployers', methods=['GET'])
def get_malware_deployers():
    """Get profiles of attackers who deployed malware"""
    try:
        limit = request.args.get('limit', 50, type=int)

        session = db_manager.get_session()
        try:
            from backend.database.models import AttackerProfile
            profiles = (
                session.query(AttackerProfile)
                .filter(AttackerProfile.has_malware == True)
                .order_by(AttackerProfile.risk_score.desc())
                .limit(limit)
                .all()
            )

            import json
            data = [
                {
                    'ip_address': p.ip_address,
                    'risk_level': p.risk_level,
                    'risk_score': p.risk_score,
                    'sophistication_level': p.sophistication_level,
                    'primary_objective': p.primary_objective,
                    'detected_tools': json.loads(p.detected_tools) if p.detected_tools else [],
                    'total_downloads': p.total_downloads
                }
                for p in profiles
            ]
        finally:
            session.close()

        return jsonify({
            'success': True,
            'data': data,
            'count': len(data)
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


# ===== Elasticsearch Endpoints =====

@api_bp.route('/elasticsearch/status', methods=['GET'])
def get_elasticsearch_status():
    """Check Elasticsearch connection status"""
    try:
        import sys
        import os
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
        from backend.config import config
        from backend.integrations import ES_AVAILABLE

        if not ES_AVAILABLE:
            return jsonify({
                'success': True,
                'data': {
                    'available': False,
                    'message': 'elasticsearch package not installed'
                }
            })

        if not config.ELASTICSEARCH_ENABLED:
            return jsonify({
                'success': True,
                'data': {
                    'available': True,
                    'enabled': False,
                    'message': 'Elasticsearch integration disabled in config'
                }
            })

        from backend.integrations import HoneypotElasticsearch

        es = HoneypotElasticsearch(
            hosts=config.ELASTICSEARCH_HOSTS,
            cloud_id=config.ELASTICSEARCH_CLOUD_ID or None,
            api_key=config.ELASTICSEARCH_API_KEY or None,
            username=config.ELASTICSEARCH_USERNAME or None,
            password=config.ELASTICSEARCH_PASSWORD or None
        )

        if es.is_connected:
            health = es.get_cluster_health()
            stats = es.get_index_stats()

            return jsonify({
                'success': True,
                'data': {
                    'available': True,
                    'enabled': True,
                    'connected': True,
                    'cluster_health': health,
                    'index_stats': stats
                }
            })
        else:
            return jsonify({
                'success': True,
                'data': {
                    'available': True,
                    'enabled': True,
                    'connected': False,
                    'message': 'Failed to connect to Elasticsearch'
                }
            })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@api_bp.route('/elasticsearch/search', methods=['POST'])
def elasticsearch_search():
    """Search Elasticsearch indices"""
    try:
        import sys
        import os
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
        from backend.config import config
        from backend.integrations import HoneypotElasticsearch, ES_AVAILABLE

        if not ES_AVAILABLE or not config.ELASTICSEARCH_ENABLED:
            return jsonify({
                'success': False,
                'error': 'Elasticsearch not available'
            }), 400

        es = HoneypotElasticsearch(
            hosts=config.ELASTICSEARCH_HOSTS,
            cloud_id=config.ELASTICSEARCH_CLOUD_ID or None,
            api_key=config.ELASTICSEARCH_API_KEY or None
        )

        if not es.is_connected:
            return jsonify({
                'success': False,
                'error': 'Failed to connect to Elasticsearch'
            }), 500

        data = request.get_json()
        query = data.get('query')
        src_ip = data.get('src_ip')
        country = data.get('country')
        threat_level = data.get('threat_level')
        size = data.get('size', 100)

        results = es.search_attacks(
            query=query,
            src_ip=src_ip,
            country=country,
            threat_level=threat_level,
            size=size
        )

        return jsonify({
            'success': True,
            'data': results,
            'count': len(results)
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


# ===== Multi-Honeypot Coordination Endpoints =====

@api_bp.route('/honeypots', methods=['GET'])
def get_honeypots():
    """Get all registered honeypots"""
    try:
        import sys
        import os
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
        from backend.coordination import HoneypotManager

        manager = HoneypotManager(db_manager)
        status = manager.get_honeypot_status()

        return jsonify({
            'success': True,
            'data': status
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@api_bp.route('/honeypots/register', methods=['POST'])
def register_honeypot():
    """Register a new honeypot"""
    try:
        import sys
        import os
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
        from backend.coordination import HoneypotManager

        data = request.get_json()
        if not data or not data.get('name'):
            return jsonify({
                'success': False,
                'error': 'Name is required'
            }), 400

        manager = HoneypotManager(db_manager)
        result = manager.register_honeypot(
            name=data['name'],
            location=data.get('location'),
            ip_address=data.get('ip_address'),
            honeypot_type=data.get('honeypot_type', 'cowrie'),
            description=data.get('description')
        )

        if 'error' in result:
            return jsonify({
                'success': False,
                'error': result['error']
            }), 400

        return jsonify({
            'success': True,
            'data': result
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@api_bp.route('/honeypots/<honeypot_id>', methods=['GET'])
def get_honeypot(honeypot_id):
    """Get specific honeypot status"""
    try:
        import sys
        import os
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
        from backend.coordination import HoneypotManager

        manager = HoneypotManager(db_manager)
        status = manager.get_honeypot_status(honeypot_id)

        if 'error' in status:
            return jsonify({
                'success': False,
                'error': status['error']
            }), 404

        return jsonify({
            'success': True,
            'data': status
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@api_bp.route('/honeypots/<honeypot_id>/deactivate', methods=['POST'])
def deactivate_honeypot(honeypot_id):
    """Deactivate a honeypot"""
    try:
        import sys
        import os
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
        from backend.coordination import HoneypotManager

        manager = HoneypotManager(db_manager)
        success = manager.deactivate_honeypot(honeypot_id)

        return jsonify({
            'success': success,
            'message': 'Honeypot deactivated' if success else 'Failed to deactivate'
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@api_bp.route('/honeypots/stats', methods=['GET'])
def get_honeypot_stats():
    """Get honeypot statistics"""
    try:
        stats = db_manager.get_honeypot_stats()

        return jsonify({
            'success': True,
            'data': stats
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@api_bp.route('/honeypots/receive', methods=['POST'])
def receive_honeypot_data():
    """Receive attack data from remote honeypot"""
    try:
        import sys
        import os
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
        from backend.coordination import HoneypotManager, HoneypotDataReceiver

        # Get auth from headers
        honeypot_id = request.headers.get('X-Honeypot-ID')
        api_key = request.headers.get('X-API-Key')

        if not honeypot_id or not api_key:
            return jsonify({
                'success': False,
                'error': 'Missing authentication headers'
            }), 401

        data = request.get_json()
        if not data:
            return jsonify({
                'success': False,
                'error': 'No data provided'
            }), 400

        manager = HoneypotManager(db_manager)
        receiver = HoneypotDataReceiver(db_manager, manager)

        # Check if batch or single
        if isinstance(data, list):
            result = receiver.receive_batch_data(honeypot_id, api_key, data)
        else:
            result = receiver.receive_attack_data(honeypot_id, api_key, data)

        status_code = result.get('status', 200)
        if 'status' in result:
            del result['status']

        return jsonify(result), status_code

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@api_bp.route('/honeypots/heartbeat', methods=['POST'])
def honeypot_heartbeat():
    """Receive heartbeat from remote honeypot"""
    try:
        import sys
        import os
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
        from backend.coordination import HoneypotManager

        honeypot_id = request.headers.get('X-Honeypot-ID')
        api_key = request.headers.get('X-API-Key')

        if not honeypot_id or not api_key:
            return jsonify({
                'success': False,
                'error': 'Missing authentication headers'
            }), 401

        manager = HoneypotManager(db_manager)

        if not manager.verify_api_key(honeypot_id, api_key):
            return jsonify({
                'success': False,
                'error': 'Authentication failed'
            }), 401

        manager.update_heartbeat(honeypot_id)

        return jsonify({
            'success': True,
            'message': 'Heartbeat received'
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@api_bp.route('/correlation/coordinated-attacks', methods=['GET'])
def get_coordinated_attacks():
    """Find coordinated attacks across honeypots"""
    try:
        import sys
        import os
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
        from backend.coordination import AttackCorrelator

        hours = request.args.get('hours', 24, type=int)
        min_honeypots = request.args.get('min_honeypots', 2, type=int)

        correlator = AttackCorrelator(db_manager)
        coordinated = correlator.find_coordinated_attacks(
            hours=hours,
            min_honeypots=min_honeypots
        )

        return jsonify({
            'success': True,
            'data': coordinated,
            'count': len(coordinated)
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@api_bp.route('/correlation/campaigns', methods=['GET'])
def get_attack_campaigns():
    """Detect distributed attack campaigns"""
    try:
        import sys
        import os
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
        from backend.coordination import AttackCorrelator

        hours = request.args.get('hours', 24, type=int)

        correlator = AttackCorrelator(db_manager)
        campaigns = correlator.detect_distributed_campaigns(hours=hours)

        return jsonify({
            'success': True,
            'data': campaigns,
            'count': len(campaigns)
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@api_bp.route('/correlation/statistics', methods=['GET'])
def get_correlation_statistics():
    """Get cross-honeypot statistics"""
    try:
        import sys
        import os
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
        from backend.coordination import AttackCorrelator

        hours = request.args.get('hours', 24, type=int)

        correlator = AttackCorrelator(db_manager)
        stats = correlator.get_cross_honeypot_statistics(hours=hours)

        return jsonify({
            'success': True,
            'data': stats
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@api_bp.route('/correlation/patterns', methods=['GET'])
def get_attack_patterns():
    """Find attack patterns across honeypots"""
    try:
        import sys
        import os
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
        from backend.coordination import AttackCorrelator

        hours = request.args.get('hours', 24, type=int)

        correlator = AttackCorrelator(db_manager)
        patterns = correlator.find_attack_patterns(hours=hours)

        return jsonify({
            'success': True,
            'data': patterns,
            'count': len(patterns)
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@api_bp.route('/correlation/timeline', methods=['GET'])
def get_correlation_timeline():
    """Get attack timeline by honeypot"""
    try:
        import sys
        import os
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
        from backend.coordination import AttackCorrelator

        hours = request.args.get('hours', 24, type=int)

        correlator = AttackCorrelator(db_manager)
        timeline = correlator.get_attack_timeline_by_honeypot(hours=hours)

        return jsonify({
            'success': True,
            'data': timeline
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@api_bp.route('/elasticsearch/aggregations/<agg_type>', methods=['GET'])
def elasticsearch_aggregations(agg_type):
    """Get Elasticsearch aggregations"""
    try:
        import sys
        import os
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
        from backend.config import config
        from backend.integrations import HoneypotElasticsearch, ES_AVAILABLE

        if not ES_AVAILABLE or not config.ELASTICSEARCH_ENABLED:
            return jsonify({
                'success': False,
                'error': 'Elasticsearch not available'
            }), 400

        es = HoneypotElasticsearch(
            hosts=config.ELASTICSEARCH_HOSTS,
            cloud_id=config.ELASTICSEARCH_CLOUD_ID or None,
            api_key=config.ELASTICSEARCH_API_KEY or None
        )

        if not es.is_connected:
            return jsonify({
                'success': False,
                'error': 'Failed to connect to Elasticsearch'
            }), 500

        days = request.args.get('days', 30, type=int)

        if agg_type == 'countries':
            data = es.get_attacks_by_country(days=days)
        elif agg_type == 'top-attackers':
            data = es.get_top_attackers(days=days)
        elif agg_type == 'timeline':
            interval = request.args.get('interval', '1d')
            data = es.get_attack_timeline(days=days, interval=interval)
        elif agg_type == 'credentials':
            data = es.get_top_credentials(days=days)
        elif agg_type == 'command-categories':
            data = es.get_command_categories(days=days)
        elif agg_type == 'threat-levels':
            data = es.get_threat_level_distribution(days=days)
        else:
            return jsonify({
                'success': False,
                'error': f'Unknown aggregation type: {agg_type}'
            }), 400

        return jsonify({
            'success': True,
            'data': data
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
