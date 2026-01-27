#!/usr/bin/env python3
"""
Automatic ML Model Retraining Script
Runs weekly via systemd timer to update models with new attack data
"""
import sys
import os
import logging
from datetime import datetime

# Setup path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.chdir(os.path.dirname(os.path.abspath(__file__)))

from backend.database.db_manager import DatabaseManager
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
import pandas as pd

# Ensure logs directory exists
os.makedirs('logs', exist_ok=True)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/retrain.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


def retrain_models():
    """Retrain ML models with latest attack data"""
    logger.info("=" * 50)
    logger.info(f"Starting ML model retraining at {datetime.now()}")

    try:
        db = DatabaseManager()
        attacks = db.get_recent_attacks(limit=50000)
        logger.info(f"Loaded {len(attacks)} attacks from database")

        if len(attacks) < 100:
            logger.warning("Not enough data for training (need 100+)")
            return False

        # Extract features
        data = []
        for attack in attacks:
            data.append({
                'src_port': attack.src_port or 0,
                'dst_port': attack.dst_port or 2222,
                'has_geo': 1 if attack.country else 0,
                'latitude': attack.latitude or 0,
                'longitude': attack.longitude or 0,
            })

        features_df = pd.DataFrame(data)
        logger.info(f"Extracted features from {len(features_df)} attacks")

        # Labels (simplified classification)
        labels = ['brute_force'] * len(features_df)

        # Ensure models directory exists
        os.makedirs('models', exist_ok=True)

        # Scale features
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(features_df)

        # Train classifier
        logger.info("Training Attack Classifier...")
        classifier = RandomForestClassifier(n_estimators=100, random_state=42)
        classifier.fit(X_scaled, labels)
        joblib.dump({'model': classifier, 'scaler': scaler}, 'models/attack_classifier.joblib')
        logger.info("Attack Classifier saved!")

        # Train anomaly detector
        logger.info("Training Anomaly Detector...")
        detector = IsolationForest(contamination=0.1, random_state=42)
        detector.fit(X_scaled)
        joblib.dump({'model': detector, 'scaler': scaler}, 'models/anomaly_detector.joblib')
        logger.info("Anomaly Detector saved!")

        logger.info(f"Retraining complete! Models updated with {len(attacks)} attacks")
        return True

    except Exception as e:
        logger.error(f"Retraining failed: {e}")
        return False


if __name__ == "__main__":
    success = retrain_models()
    sys.exit(0 if success else 1)
