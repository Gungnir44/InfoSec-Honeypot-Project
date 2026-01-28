"""
ML Predictor Service
Real-time attack classification and anomaly detection
"""
import os
import joblib
import numpy as np
import pandas as pd
from typing import Dict, List, Optional, Tuple
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class MLPredictor:
    """Handles ML predictions for attack classification and anomaly detection"""

    def __init__(self, models_dir: str = 'models'):
        self.models_dir = models_dir
        self.classifier = None
        self.classifier_scaler = None
        self.anomaly_detector = None
        self.anomaly_scaler = None
        self._load_models()

    def _load_models(self):
        """Load trained ML models"""
        try:
            classifier_path = os.path.join(self.models_dir, 'attack_classifier.joblib')
            if os.path.exists(classifier_path):
                data = joblib.load(classifier_path)
                self.classifier = data['model']
                self.classifier_scaler = data['scaler']
                logger.info("Attack classifier loaded successfully")

            detector_path = os.path.join(self.models_dir, 'anomaly_detector.joblib')
            if os.path.exists(detector_path):
                data = joblib.load(detector_path)
                self.anomaly_detector = data['model']
                self.anomaly_scaler = data['scaler']
                logger.info("Anomaly detector loaded successfully")

        except Exception as e:
            logger.error(f"Error loading models: {e}")

    def extract_features(self, attack: Dict) -> pd.DataFrame:
        """Extract features from an attack record"""
        features = {
            'src_port': attack.get('src_port', 0) or 0,
            'dst_port': attack.get('dst_port', 2222) or 2222,
            'has_geo': 1 if attack.get('country') else 0,
            'latitude': attack.get('latitude', 0) or 0,
            'longitude': attack.get('longitude', 0) or 0,
        }
        return pd.DataFrame([features])

    def classify_attack(self, attack: Dict) -> Dict:
        """Classify an attack and return prediction with confidence"""
        if not self.classifier:
            return {'error': 'Classifier not loaded', 'type': 'unknown', 'confidence': 0}

        try:
            features = self.extract_features(attack)
            X_scaled = self.classifier_scaler.transform(features)

            prediction = self.classifier.predict(X_scaled)[0]
            probabilities = self.classifier.predict_proba(X_scaled)[0]
            confidence = float(max(probabilities))

            return {
                'type': prediction,
                'confidence': round(confidence * 100, 2),
                'probabilities': {
                    cls: round(prob * 100, 2)
                    for cls, prob in zip(self.classifier.classes_, probabilities)
                }
            }
        except Exception as e:
            logger.error(f"Classification error: {e}")
            return {'error': str(e), 'type': 'unknown', 'confidence': 0}

    def detect_anomaly(self, attack: Dict) -> Dict:
        """Detect if an attack is anomalous"""
        if not self.anomaly_detector:
            return {'error': 'Anomaly detector not loaded', 'is_anomaly': False, 'score': 0}

        try:
            features = self.extract_features(attack)
            X_scaled = self.anomaly_scaler.transform(features)

            # Isolation Forest: -1 = anomaly, 1 = normal
            prediction = self.anomaly_detector.predict(X_scaled)[0]
            score = self.anomaly_detector.decision_function(X_scaled)[0]

            return {
                'is_anomaly': prediction == -1,
                'score': round(float(score), 4),
                'severity': self._get_anomaly_severity(score)
            }
        except Exception as e:
            logger.error(f"Anomaly detection error: {e}")
            return {'error': str(e), 'is_anomaly': False, 'score': 0}

    def _get_anomaly_severity(self, score: float) -> str:
        """Convert anomaly score to severity level"""
        if score < -0.5:
            return 'critical'
        elif score < -0.3:
            return 'high'
        elif score < -0.1:
            return 'medium'
        elif score < 0:
            return 'low'
        else:
            return 'normal'

    def analyze_attack(self, attack: Dict) -> Dict:
        """Full analysis of an attack including classification and anomaly detection"""
        classification = self.classify_attack(attack)
        anomaly = self.detect_anomaly(attack)

        # Calculate threat score (0-100)
        threat_score = self._calculate_threat_score(classification, anomaly, attack)

        return {
            'attack_id': attack.get('id'),
            'timestamp': datetime.utcnow().isoformat(),
            'classification': classification,
            'anomaly': anomaly,
            'threat_score': threat_score,
            'threat_level': self._get_threat_level(threat_score)
        }

    def _calculate_threat_score(self, classification: Dict, anomaly: Dict, attack: Dict) -> int:
        """Calculate overall threat score (0-100)"""
        score = 20  # Base score

        # Add points based on attack type
        attack_type_scores = {
            'brute_force': 20,
            'reconnaissance': 30,
            'malware_deployment': 50,
            'persistence': 40,
            'advanced': 60,
            'bot': 15
        }
        score += attack_type_scores.get(classification.get('type', ''), 10)

        # Add points for anomalies
        if anomaly.get('is_anomaly'):
            severity_scores = {'critical': 30, 'high': 20, 'medium': 10, 'low': 5}
            score += severity_scores.get(anomaly.get('severity', ''), 0)

        # Cap at 100
        return min(score, 100)

    def _get_threat_level(self, score: int) -> str:
        """Convert threat score to level"""
        if score >= 80:
            return 'critical'
        elif score >= 60:
            return 'high'
        elif score >= 40:
            return 'medium'
        elif score >= 20:
            return 'low'
        else:
            return 'minimal'

    def batch_analyze(self, attacks: List[Dict]) -> List[Dict]:
        """Analyze multiple attacks"""
        return [self.analyze_attack(attack) for attack in attacks]


# Global predictor instance
_predictor = None

def get_predictor() -> MLPredictor:
    """Get or create global predictor instance"""
    global _predictor
    if _predictor is None:
        _predictor = MLPredictor()
    return _predictor
