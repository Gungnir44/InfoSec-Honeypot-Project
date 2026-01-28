#!/usr/bin/env python3
"""
Automated Weekly Threat Intelligence Report Generator
Generates comprehensive PDF/HTML reports of honeypot activity
"""
import sys
import os
from datetime import datetime, timedelta
import json
import logging

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.chdir(os.path.dirname(os.path.abspath(__file__)))

from backend.database.db_manager import DatabaseManager
from backend.ml.predictor import get_predictor

# Setup logging
os.makedirs('logs', exist_ok=True)
os.makedirs('reports', exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/reports.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


def generate_weekly_report():
    """Generate comprehensive weekly threat intelligence report"""
    logger.info("=" * 60)
    logger.info(f"Starting weekly report generation at {datetime.now()}")

    db = DatabaseManager()
    predictor = get_predictor()

    # Get date range
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=7)

    # Gather statistics
    stats = db.get_attack_stats()
    attacks = db.get_recent_attacks(limit=10000)
    country_data = db.get_attacks_by_country()
    top_ips = db.get_top_attacking_ips(limit=20)
    top_credentials = db.get_top_credentials(limit=20)
    top_commands = db.get_top_commands(limit=20)

    # ML Analysis
    threat_levels = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'minimal': 0}
    attack_types = {}
    anomalies = []

    logger.info(f"Analyzing {len(attacks)} attacks with ML models...")

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
                'ip': attack.src_ip,
                'country': attack.country,
                'severity': analysis['anomaly'].get('severity')
            })

    # Generate HTML report
    report_html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Honeypot Threat Intelligence Report</title>
        <style>
            body {{
                font-family: 'Segoe UI', Arial, sans-serif;
                background: #1a1a2e;
                color: #eee;
                padding: 40px;
                max-width: 1200px;
                margin: 0 auto;
            }}
            h1 {{ color: #4cc9f0; border-bottom: 2px solid #4cc9f0; padding-bottom: 10px; }}
            h2 {{ color: #f72585; margin-top: 40px; }}
            h3 {{ color: #7209b7; }}
            .card {{
                background: #16213e;
                border-radius: 10px;
                padding: 20px;
                margin: 20px 0;
                box-shadow: 0 4px 6px rgba(0,0,0,0.3);
            }}
            .stat-grid {{
                display: grid;
                grid-template-columns: repeat(4, 1fr);
                gap: 20px;
            }}
            .stat-box {{
                background: #0f3460;
                border-radius: 8px;
                padding: 20px;
                text-align: center;
            }}
            .stat-value {{
                font-size: 36px;
                font-weight: bold;
                color: #4cc9f0;
            }}
            .stat-label {{
                color: #aaa;
                margin-top: 5px;
            }}
            table {{
                width: 100%;
                border-collapse: collapse;
                margin: 20px 0;
            }}
            th, td {{
                padding: 12px;
                text-align: left;
                border-bottom: 1px solid #333;
            }}
            th {{
                background: #0f3460;
                color: #4cc9f0;
            }}
            tr:hover {{
                background: #1f4068;
            }}
            .threat-critical {{ color: #e74c3c; font-weight: bold; }}
            .threat-high {{ color: #e67e22; }}
            .threat-medium {{ color: #f39c12; }}
            .threat-low {{ color: #3498db; }}
            .progress-bar {{
                background: #333;
                border-radius: 10px;
                overflow: hidden;
                height: 20px;
            }}
            .progress-fill {{
                height: 100%;
                border-radius: 10px;
            }}
            .footer {{
                margin-top: 40px;
                padding-top: 20px;
                border-top: 1px solid #333;
                color: #666;
                text-align: center;
            }}
        </style>
    </head>
    <body>
        <h1>🛡️ Honeypot Threat Intelligence Report</h1>
        <p><strong>Report Period:</strong> {start_date.strftime('%Y-%m-%d')} to {end_date.strftime('%Y-%m-%d')}</p>
        <p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>

        <h2>📊 Executive Summary</h2>
        <div class="stat-grid">
            <div class="stat-box">
                <div class="stat-value">{stats['total_attacks']:,}</div>
                <div class="stat-label">Total Attacks</div>
            </div>
            <div class="stat-box">
                <div class="stat-value">{stats['unique_ips']:,}</div>
                <div class="stat-label">Unique IPs</div>
            </div>
            <div class="stat-box">
                <div class="stat-value">{stats['unique_countries']}</div>
                <div class="stat-label">Countries</div>
            </div>
            <div class="stat-box">
                <div class="stat-value">{len(anomalies)}</div>
                <div class="stat-label">Anomalies Detected</div>
            </div>
        </div>

        <h2>🎯 Threat Level Distribution</h2>
        <div class="card">
            <table>
                <tr>
                    <th>Threat Level</th>
                    <th>Count</th>
                    <th>Percentage</th>
                    <th>Visual</th>
                </tr>
                {''.join(f'''
                <tr>
                    <td class="threat-{level}">{level.upper()}</td>
                    <td>{count}</td>
                    <td>{(count/len(attacks)*100):.1f}%</td>
                    <td>
                        <div class="progress-bar">
                            <div class="progress-fill" style="width: {count/len(attacks)*100}%; background: {'#e74c3c' if level=='critical' else '#e67e22' if level=='high' else '#f39c12' if level=='medium' else '#3498db' if level=='low' else '#2ecc71'};"></div>
                        </div>
                    </td>
                </tr>
                ''' for level, count in sorted(threat_levels.items(), key=lambda x: ['critical','high','medium','low','minimal'].index(x[0])))}
            </table>
        </div>

        <h2>🔍 Attack Type Classification (ML)</h2>
        <div class="card">
            <table>
                <tr>
                    <th>Attack Type</th>
                    <th>Count</th>
                    <th>Percentage</th>
                </tr>
                {''.join(f'''
                <tr>
                    <td>{attack_type}</td>
                    <td>{count}</td>
                    <td>{(count/len(attacks)*100):.1f}%</td>
                </tr>
                ''' for attack_type, count in sorted(attack_types.items(), key=lambda x: -x[1]))}
            </table>
        </div>

        <h2>🌍 Top Attacking Countries</h2>
        <div class="card">
            <table>
                <tr>
                    <th>Rank</th>
                    <th>Country</th>
                    <th>Attacks</th>
                </tr>
                {''.join(f'''
                <tr>
                    <td>{i+1}</td>
                    <td>{country[0] or 'Unknown'}</td>
                    <td>{country[2]}</td>
                </tr>
                ''' for i, country in enumerate(country_data[:10]))}
            </table>
        </div>

        <h2>🔥 Top Attacking IPs</h2>
        <div class="card">
            <table>
                <tr>
                    <th>IP Address</th>
                    <th>Country</th>
                    <th>Attacks</th>
                </tr>
                {''.join(f'''
                <tr>
                    <td><code>{ip[0]}</code></td>
                    <td>{ip[1] or 'Unknown'}</td>
                    <td>{ip[2]}</td>
                </tr>
                ''' for ip in top_ips[:10])}
            </table>
        </div>

        <h2>🔑 Top Credentials Attempted</h2>
        <div class="card">
            <table>
                <tr>
                    <th>Username</th>
                    <th>Password</th>
                    <th>Attempts</th>
                </tr>
                {''.join(f'''
                <tr>
                    <td><code>{cred[0]}</code></td>
                    <td><code>{cred[1][:20]}{'...' if len(cred[1]) > 20 else ''}</code></td>
                    <td>{cred[2]}</td>
                </tr>
                ''' for cred in top_credentials[:10])}
            </table>
        </div>

        <h2>⚠️ Anomalies Detected</h2>
        <div class="card">
            <p>ML-based anomaly detection identified <strong>{len(anomalies)}</strong> unusual attack patterns.</p>
            {'<table><tr><th>IP</th><th>Country</th><th>Severity</th></tr>' + ''.join(f'''
            <tr>
                <td><code>{a['ip']}</code></td>
                <td>{a['country'] or 'Unknown'}</td>
                <td class="threat-{a['severity']}">{a['severity'].upper()}</td>
            </tr>
            ''' for a in anomalies[:10]) + '</table>' if anomalies else '<p>No significant anomalies detected this period.</p>'}
        </div>

        <h2>📈 Key Insights</h2>
        <div class="card">
            <ul>
                <li>Primary attack source: <strong>{stats['top_country']}</strong> ({stats['top_country_count']} attacks)</li>
                <li>Most common attack type: <strong>{max(attack_types, key=attack_types.get) if attack_types else 'N/A'}</strong></li>
                <li>High/Critical threats: <strong>{threat_levels['high'] + threat_levels['critical']}</strong> ({((threat_levels['high'] + threat_levels['critical'])/len(attacks)*100):.1f}% of total)</li>
                <li>Anomaly rate: <strong>{(len(anomalies)/len(attacks)*100):.2f}%</strong></li>
            </ul>
        </div>

        <div class="footer">
            <p>Generated by ML-Powered Honeypot System</p>
            <p>Dashboard: <a href="http://35.184.174.192" style="color: #4cc9f0;">http://35.184.174.192</a></p>
        </div>
    </body>
    </html>
    """

    # Save report
    report_filename = f"reports/threat_report_{end_date.strftime('%Y%m%d')}.html"
    with open(report_filename, 'w', encoding='utf-8') as f:
        f.write(report_html)

    logger.info(f"Report saved to {report_filename}")

    # Also save JSON version
    json_report = {
        'period': {
            'start': start_date.isoformat(),
            'end': end_date.isoformat()
        },
        'summary': stats,
        'threat_levels': threat_levels,
        'attack_types': attack_types,
        'anomalies_count': len(anomalies),
        'top_countries': [{'country': c[0], 'attacks': c[2]} for c in country_data[:10]],
        'top_ips': [{'ip': ip[0], 'country': ip[1], 'attacks': ip[2]} for ip in top_ips[:10]],
        'generated_at': datetime.utcnow().isoformat()
    }

    json_filename = f"reports/threat_report_{end_date.strftime('%Y%m%d')}.json"
    with open(json_filename, 'w') as f:
        json.dump(json_report, f, indent=2, default=str)

    logger.info(f"JSON report saved to {json_filename}")
    logger.info("Report generation complete!")

    return report_filename


if __name__ == "__main__":
    generate_weekly_report()
