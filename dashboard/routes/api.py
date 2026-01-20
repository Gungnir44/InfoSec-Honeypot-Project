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
