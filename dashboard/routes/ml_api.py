"""
ML-Powered Threat Intelligence API
Provides endpoints for attack analysis, predictions, and threat intelligence
"""
from flask import Blueprint, jsonify, request
from datetime import datetime, timedelta
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from backend.ml.predictor import get_predictor
from backend.ml.alert_service import get_alert_service
from backend.database.db_manager import DatabaseManager

ml_api = Blueprint('ml_api', __name__)
db = DatabaseManager()


@ml_api.route('/api/ml/analyze/<int:attack_id>', methods=['GET'])
def analyze_attack(attack_id):
    """Analyze a specific attack with ML models"""
    try:
        session = db.get_session()
        from backend.database.models import Attack
        attack = session.query(Attack).filter(Attack.id == attack_id).first()
        session.close()

        if not attack:
            return jsonify({'error': 'Attack not found'}), 404

        attack_dict = {
            'id': attack.id,
            'src_ip': attack.src_ip,
            'src_port': attack.src_port,
            'dst_port': attack.dst_port,
            'country': attack.country,
            'latitude': attack.latitude,
            'longitude': attack.longitude,
            'timestamp': attack.timestamp.isoformat() if attack.timestamp else None
        }

        predictor = get_predictor()
        analysis = predictor.analyze_attack(attack_dict)

        return jsonify(analysis)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@ml_api.route('/api/ml/analyze/batch', methods=['POST'])
def analyze_batch():
    """Analyze multiple attacks"""
    try:
        data = request.get_json()
        attack_ids = data.get('attack_ids', [])

        if not attack_ids:
            return jsonify({'error': 'No attack IDs provided'}), 400

        session = db.get_session()
        from backend.database.models import Attack
        attacks = session.query(Attack).filter(Attack.id.in_(attack_ids)).all()
        session.close()

        predictor = get_predictor()
        results = []

        for attack in attacks:
            attack_dict = {
                'id': attack.id,
                'src_ip': attack.src_ip,
                'src_port': attack.src_port,
                'dst_port': attack.dst_port,
                'country': attack.country,
                'latitude': attack.latitude,
                'longitude': attack.longitude,
            }
            results.append(predictor.analyze_attack(attack_dict))

        return jsonify({'analyses': results, 'count': len(results)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@ml_api.route('/api/ml/threat-intel', methods=['GET'])
def get_threat_intelligence():
    """Get comprehensive threat intelligence summary"""
    try:
        days = request.args.get('days', 7, type=int)
        predictor = get_predictor()

        # Get recent attacks
        attacks = db.get_recent_attacks(limit=1000)

        # Analyze all attacks
        threat_levels = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'minimal': 0}
        attack_types = {}
        anomalies = []
        high_threat_ips = []

        for attack in attacks:
            attack_dict = {
                'id': attack.id,
                'src_ip': attack.src_ip,
                'src_port': attack.src_port,
                'dst_port': attack.dst_port,
                'country': attack.country,
                'latitude': attack.latitude,
                'longitude': attack.longitude,
            }

            analysis = predictor.analyze_attack(attack_dict)

            # Count threat levels
            level = analysis.get('threat_level', 'minimal')
            threat_levels[level] = threat_levels.get(level, 0) + 1

            # Count attack types
            attack_type = analysis['classification'].get('type', 'unknown')
            attack_types[attack_type] = attack_types.get(attack_type, 0) + 1

            # Track anomalies
            if analysis['anomaly'].get('is_anomaly'):
                anomalies.append({
                    'attack_id': attack.id,
                    'src_ip': attack.src_ip,
                    'country': attack.country,
                    'severity': analysis['anomaly'].get('severity'),
                    'score': analysis['anomaly'].get('score')
                })

            # Track high threat IPs
            if analysis['threat_score'] >= 60:
                high_threat_ips.append({
                    'ip': attack.src_ip,
                    'country': attack.country,
                    'threat_score': analysis['threat_score'],
                    'attack_type': attack_type
                })

        # Get top attacking countries
        country_stats = db.get_attacks_by_country()

        return jsonify({
            'summary': {
                'total_attacks_analyzed': len(attacks),
                'period_days': days,
                'generated_at': datetime.utcnow().isoformat()
            },
            'threat_distribution': threat_levels,
            'attack_types': attack_types,
            'anomalies': {
                'total': len(anomalies),
                'recent': anomalies[:10]  # Top 10 most recent
            },
            'high_threat_actors': high_threat_ips[:20],  # Top 20
            'top_countries': [
                {'country': c[0], 'code': c[1], 'attacks': c[2]}
                for c in country_stats[:10]
            ]
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@ml_api.route('/api/ml/predict', methods=['POST'])
def predict_attack():
    """Predict attack type for new/incoming attack data"""
    try:
        data = request.get_json()

        if not data:
            return jsonify({'error': 'No data provided'}), 400

        predictor = get_predictor()
        analysis = predictor.analyze_attack(data)

        return jsonify(analysis)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@ml_api.route('/api/ml/anomalies', methods=['GET'])
def get_anomalies():
    """Get all detected anomalies"""
    try:
        limit = request.args.get('limit', 50, type=int)
        min_severity = request.args.get('min_severity', 'low')

        severity_order = ['minimal', 'low', 'medium', 'high', 'critical']
        min_index = severity_order.index(min_severity) if min_severity in severity_order else 0

        predictor = get_predictor()
        attacks = db.get_recent_attacks(limit=500)

        anomalies = []
        for attack in attacks:
            attack_dict = {
                'id': attack.id,
                'src_ip': attack.src_ip,
                'src_port': attack.src_port,
                'dst_port': attack.dst_port,
                'country': attack.country,
                'latitude': attack.latitude,
                'longitude': attack.longitude,
                'timestamp': attack.timestamp.isoformat() if attack.timestamp else None
            }

            analysis = predictor.analyze_attack(attack_dict)

            if analysis['anomaly'].get('is_anomaly'):
                severity = analysis['anomaly'].get('severity', 'low')
                if severity_order.index(severity) >= min_index:
                    anomalies.append({
                        'attack': attack_dict,
                        'analysis': analysis
                    })

            if len(anomalies) >= limit:
                break

        return jsonify({
            'anomalies': anomalies,
            'count': len(anomalies),
            'min_severity_filter': min_severity
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@ml_api.route('/api/ml/ip/<ip_address>', methods=['GET'])
def get_ip_threat_profile(ip_address):
    """Get threat profile for a specific IP address"""
    try:
        session = db.get_session()
        from backend.database.models import Attack, LoginAttempt, Command

        # Get all attacks from this IP
        attacks = session.query(Attack).filter(Attack.src_ip == ip_address).all()

        if not attacks:
            session.close()
            return jsonify({'error': 'No attacks found from this IP'}), 404

        predictor = get_predictor()

        # Analyze all attacks from this IP
        analyses = []
        total_threat_score = 0
        attack_types = {}

        for attack in attacks:
            attack_dict = {
                'id': attack.id,
                'src_ip': attack.src_ip,
                'src_port': attack.src_port,
                'dst_port': attack.dst_port,
                'country': attack.country,
                'latitude': attack.latitude,
                'longitude': attack.longitude,
            }
            analysis = predictor.analyze_attack(attack_dict)
            analyses.append(analysis)
            total_threat_score += analysis['threat_score']

            attack_type = analysis['classification'].get('type', 'unknown')
            attack_types[attack_type] = attack_types.get(attack_type, 0) + 1

        # Get login attempts
        login_count = session.query(LoginAttempt).join(Attack).filter(
            Attack.src_ip == ip_address
        ).count()

        # Get commands
        command_count = session.query(Command).join(Attack).filter(
            Attack.src_ip == ip_address
        ).count()

        session.close()

        avg_threat_score = total_threat_score / len(attacks) if attacks else 0

        return jsonify({
            'ip': ip_address,
            'country': attacks[0].country if attacks else 'Unknown',
            'first_seen': min(a.timestamp for a in attacks if a.timestamp).isoformat() if attacks else None,
            'last_seen': max(a.timestamp for a in attacks if a.timestamp).isoformat() if attacks else None,
            'total_attacks': len(attacks),
            'login_attempts': login_count,
            'commands_executed': command_count,
            'average_threat_score': round(avg_threat_score, 2),
            'threat_level': predictor._get_threat_level(int(avg_threat_score)),
            'attack_types': attack_types,
            'is_persistent_threat': len(attacks) > 5,
            'anomaly_count': sum(1 for a in analyses if a['anomaly'].get('is_anomaly'))
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@ml_api.route('/api/ml/status', methods=['GET'])
def get_ml_status():
    """Get ML system status"""
    try:
        predictor = get_predictor()
        alert_service = get_alert_service()

        return jsonify({
            'status': 'operational',
            'models': {
                'classifier_loaded': predictor.classifier is not None,
                'anomaly_detector_loaded': predictor.anomaly_detector is not None
            },
            'alerts': alert_service.get_alert_stats(),
            'timestamp': datetime.utcnow().isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e), 'status': 'error'}), 500
