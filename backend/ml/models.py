"""
Machine Learning Models for Attack Analysis

Provides classification and anomaly detection models.
"""
import numpy as np
import pickle
import logging
from typing import Optional, Tuple, Dict, List
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix

logger = logging.getLogger(__name__)


class AttackClassifier:
    """
    Classify attacks into categories:
    - brute_force: Simple credential guessing
    - reconnaissance: Information gathering
    - malware_deployment: Downloading and executing malware
    - persistence: Establishing continued access
    - bot: Automated bot activity
    - advanced: Sophisticated human-driven attacks
    """

    def __init__(self, model_path: Optional[str] = None):
        """
        Initialize classifier

        Args:
            model_path: Path to saved model file
        """
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            n_jobs=-1
        )
        self.scaler = StandardScaler()
        self.feature_names = []
        self.label_map = {
            0: 'brute_force',
            1: 'reconnaissance',
            2: 'malware_deployment',
            3: 'persistence',
            4: 'bot',
            5: 'advanced'
        }

        if model_path and Path(model_path).exists():
            self.load(model_path)

    def train(self, X: np.ndarray, y: np.ndarray,
             feature_names: List[str]) -> Dict[str, float]:
        """
        Train the classification model

        Args:
            X: Feature matrix
            y: Labels
            feature_names: List of feature names

        Returns:
            Dictionary with training metrics
        """
        self.feature_names = feature_names

        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )

        # Scale features
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)

        # Train model
        logger.info("Training Random Forest classifier...")
        self.model.fit(X_train_scaled, y_train)

        # Evaluate
        train_score = self.model.score(X_train_scaled, y_train)
        test_score = self.model.score(X_test_scaled, y_test)

        logger.info(f"Training accuracy: {train_score:.3f}")
        logger.info(f"Test accuracy: {test_score:.3f}")

        # Get predictions for detailed metrics
        y_pred = self.model.predict(X_test_scaled)

        # Classification report
        report = classification_report(
            y_test, y_pred,
            target_names=[self.label_map[i] for i in sorted(self.label_map.keys())],
            output_dict=True
        )

        metrics = {
            'train_accuracy': float(train_score),
            'test_accuracy': float(test_score),
            'classification_report': report
        }

        return metrics

    def predict(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """
        Predict attack types

        Args:
            X: Feature matrix

        Returns:
            Tuple of (predicted labels, prediction probabilities)
        """
        X_scaled = self.scaler.transform(X)
        predictions = self.model.predict(X_scaled)
        probabilities = self.model.predict_proba(X_scaled)

        return predictions, probabilities

    def predict_label(self, X: np.ndarray) -> List[str]:
        """
        Predict attack type labels (human-readable)

        Args:
            X: Feature matrix

        Returns:
            List of attack type labels
        """
        predictions, _ = self.predict(X)
        return [self.label_map[pred] for pred in predictions]

    def get_feature_importance(self) -> np.ndarray:
        """Get feature importance scores"""
        return self.model.feature_importances_

    def save(self, path: str):
        """Save model to disk"""
        model_data = {
            'model': self.model,
            'scaler': self.scaler,
            'feature_names': self.feature_names,
            'label_map': self.label_map
        }

        with open(path, 'wb') as f:
            pickle.dump(model_data, f)

        logger.info(f"Model saved to {path}")

    def load(self, path: str):
        """Load model from disk"""
        with open(path, 'rb') as f:
            model_data = pickle.load(f)

        self.model = model_data['model']
        self.scaler = model_data['scaler']
        self.feature_names = model_data['feature_names']
        self.label_map = model_data['label_map']

        logger.info(f"Model loaded from {path}")


class AnomalyDetector:
    """
    Detect anomalous attack patterns using unsupervised learning

    Uses Isolation Forest to identify unusual attack behavior that
    doesn't match typical patterns.
    """

    def __init__(self, contamination: float = 0.1, model_path: Optional[str] = None):
        """
        Initialize anomaly detector

        Args:
            contamination: Expected proportion of outliers (0.0 to 0.5)
            model_path: Path to saved model file
        """
        self.model = IsolationForest(
            contamination=contamination,
            random_state=42,
            n_jobs=-1
        )
        self.scaler = StandardScaler()
        self.feature_names = []
        self.threshold = None

        if model_path and Path(model_path).exists():
            self.load(model_path)

    def fit(self, X: np.ndarray, feature_names: List[str]):
        """
        Fit anomaly detector on normal attack patterns

        Args:
            X: Feature matrix
            feature_names: List of feature names
        """
        self.feature_names = feature_names

        # Scale features
        X_scaled = self.scaler.fit_transform(X)

        # Fit model
        logger.info("Training Isolation Forest anomaly detector...")
        self.model.fit(X_scaled)

        # Calculate anomaly scores
        scores = self.model.score_samples(X_scaled)
        self.threshold = np.percentile(scores, 10)  # Bottom 10% are anomalies

        logger.info(f"Anomaly detector trained. Threshold: {self.threshold:.3f}")

    def predict(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """
        Detect anomalies

        Args:
            X: Feature matrix

        Returns:
            Tuple of (anomaly labels [-1=anomaly, 1=normal], anomaly scores)
        """
        X_scaled = self.scaler.transform(X)
        predictions = self.model.predict(X_scaled)
        scores = self.model.score_samples(X_scaled)

        return predictions, scores

    def is_anomalous(self, X: np.ndarray, score_threshold: Optional[float] = None) -> np.ndarray:
        """
        Check if samples are anomalous

        Args:
            X: Feature matrix
            score_threshold: Custom threshold for anomaly scores

        Returns:
            Boolean array indicating anomalies
        """
        predictions, scores = self.predict(X)

        if score_threshold is not None:
            return scores < score_threshold
        else:
            return predictions == -1

    def get_anomaly_report(self, X: np.ndarray, session_ids: List[str]) -> str:
        """
        Generate human-readable anomaly report

        Args:
            X: Feature matrix
            session_ids: List of session IDs

        Returns:
            Formatted report string
        """
        predictions, scores = self.predict(X)
        anomalies = predictions == -1

        report = []
        report.append("=" * 60)
        report.append("ANOMALY DETECTION REPORT")
        report.append("=" * 60)
        report.append(f"Total sessions analyzed: {len(X)}")
        report.append(f"Anomalies detected: {anomalies.sum()}")
        report.append(f"Anomaly rate: {anomalies.sum() / len(X) * 100:.2f}%")
        report.append("")

        if anomalies.sum() > 0:
            report.append("ANOMALOUS SESSIONS:")
            report.append("-" * 60)

            # Get top anomalies
            anomaly_indices = np.where(anomalies)[0]
            anomaly_scores = scores[anomaly_indices]

            # Sort by score (most anomalous first)
            sorted_indices = anomaly_indices[np.argsort(anomaly_scores)]

            for idx in sorted_indices[:20]:  # Top 20
                report.append(f"Session: {session_ids[idx]}")
                report.append(f"  Anomaly score: {scores[idx]:.3f}")
                report.append("")

        report.append("=" * 60)

        return "\n".join(report)

    def save(self, path: str):
        """Save model to disk"""
        model_data = {
            'model': self.model,
            'scaler': self.scaler,
            'feature_names': self.feature_names,
            'threshold': self.threshold
        }

        with open(path, 'wb') as f:
            pickle.dump(model_data, f)

        logger.info(f"Anomaly detector saved to {path}")

    def load(self, path: str):
        """Load model from disk"""
        with open(path, 'rb') as f:
            model_data = pickle.load(f)

        self.model = model_data['model']
        self.scaler = model_data['scaler']
        self.feature_names = model_data['feature_names']
        self.threshold = model_data.get('threshold')

        logger.info(f"Anomaly detector loaded from {path}")
