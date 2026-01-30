"""
Main Flask application for honeypot dashboard
"""
import os
import sys
from flask import Flask, render_template
from flask_cors import CORS
from werkzeug.middleware.proxy_fix import ProxyFix

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.config import config
from backend.database.db_manager import DatabaseManager

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = config.DASHBOARD_SECRET_KEY
app.config['JSON_SORT_KEYS'] = False

# Support for HTTPS behind reverse proxy (Nginx)
# This ensures request.scheme returns 'https' and url_for generates https:// URLs
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

# Enable CORS for API endpoints
CORS(app, resources={r"/api/*": {"origins": "*"}})

# Initialize database manager
db_manager = DatabaseManager()

# Import routes after app initialization to avoid circular imports
from dashboard.routes import api, views
from dashboard.routes.ml_api import ml_api

# Register blueprints
app.register_blueprint(api.api_bp, url_prefix='/api')
app.register_blueprint(views.views_bp)
app.register_blueprint(ml_api)  # ML API routes


@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('dashboard.html')


@app.route('/health')
def health():
    """Health check endpoint"""
    return {'status': 'healthy', 'version': '1.0.0'}


@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    return render_template('500.html'), 500


def init_db():
    """Initialize database tables"""
    try:
        db_manager.create_tables()
        print("[OK] Database tables created successfully")
    except Exception as e:
        print(f"[ERROR] Error creating database tables: {e}")
        sys.exit(1)


if __name__ == '__main__':
    # Create tables if they don't exist
    init_db()

    # Validate configuration
    errors = config.validate()
    if errors:
        print("Configuration warnings:")
        for error in errors:
            print(f"  - {error}")
        print()

    print("=" * 60)
    print("   Honeypot Dashboard Server Starting")
    print("=" * 60)
    print(f"\nServer: http://{config.DASHBOARD_HOST}:{config.DASHBOARD_PORT}")
    print(f"Environment: {'Production' if not config.DEBUG else 'Development'}")
    print(f"Database: {config.DATABASE_URI.split('@')[-1] if '@' in config.DATABASE_URI else 'SQLite'}")
    print("\nPress Ctrl+C to stop\n")

    # Run Flask app
    app.run(
        host=config.DASHBOARD_HOST,
        port=config.DASHBOARD_PORT,
        debug=config.DEBUG
    )
