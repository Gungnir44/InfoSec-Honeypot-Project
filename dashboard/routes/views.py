"""
View routes for dashboard pages
"""
from flask import Blueprint, render_template

views_bp = Blueprint('views', __name__)


@views_bp.route('/dashboard')
def dashboard():
    """Main dashboard page"""
    return render_template('dashboard.html')


@views_bp.route('/attacks')
def attacks():
    """Attack details page"""
    return render_template('attacks.html')


@views_bp.route('/analytics')
def analytics():
    """Advanced analytics page"""
    return render_template('analytics.html')


@views_bp.route('/about')
def about():
    """About page"""
    return render_template('about.html')
