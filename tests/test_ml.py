"""
Tests for ML module
"""
import pytest
import numpy as np
import pandas as pd
from datetime import datetime, timedelta

from backend.ml.feature_engineering import FeatureEngineer
from backend.ml.models import AttackClassifier, AnomalyDetector


class TestFeatureEngineer:
    def test_extract_session_features(self):
        engineer = FeatureEngineer()

        session_data = {
            'timestamp': datetime.utcnow(),
            'src_ip': '1.2.3.4',
            'src_port': 45000,
            'dst_port': 2222,
            'country': 'China',
            'duration': 120,
            'login_attempts': [
                {'username': 'root', 'password': 'admin', 'success': False},
                {'username': 'root', 'password': 'password', 'success': True},
            ],
            'commands': [
                {'command': 'whoami', 'category': 'reconnaissance', 'timestamp': datetime.utcnow()},
                {'command': 'uname -a', 'category': 'reconnaissance', 'timestamp': datetime.utcnow() + timedelta(seconds=5)},
            ],
            'downloads': []
        }

        features = engineer.extract_session_features(session_data)

        assert 'login_attempt_count' in features
        assert features['login_attempt_count'] == 2
        assert features['successful_login'] == 1
        assert features['command_count'] == 2
        assert features['recon_commands'] == 2

    def test_create_dataset(self):
        engineer = FeatureEngineer()

        sessions = [
            {
                'session_id': 'session1',
                'src_ip': '1.2.3.4',
                'timestamp': datetime.utcnow(),
                'duration': 60,
                'login_attempts': [],
                'commands': [],
                'downloads': []
            },
            {
                'session_id': 'session2',
                'src_ip': '5.6.7.8',
                'timestamp': datetime.utcnow(),
                'duration': 120,
                'login_attempts': [],
                'commands': [],
                'downloads': []
            }
        ]

        df = engineer.create_dataset(sessions)

        assert len(df) == 2
        assert 'session_id' in df.columns
        assert 'login_attempt_count' in df.columns


class TestAttackClassifier:
    def test_train_and_predict(self):
        # Create synthetic training data
        np.random.seed(42)

        X_train = np.random.randn(100, 10)
        y_train = np.random.randint(0, 3, 100)  # 3 classes

        feature_names = [f'feature_{i}' for i in range(10)]

        classifier = AttackClassifier()
        metrics = classifier.train(X_train, y_train, feature_names)

        assert 'train_accuracy' in metrics
        assert 'test_accuracy' in metrics
        assert metrics['train_accuracy'] > 0

        # Test prediction
        X_test = np.random.randn(5, 10)
        predictions, probabilities = classifier.predict(X_test)

        assert len(predictions) == 5
        assert probabilities.shape == (5, 3)


class TestAnomalyDetector:
    def test_fit_and_predict(self):
        # Create synthetic data with outliers
        np.random.seed(42)

        X_normal = np.random.randn(100, 10)
        X_test = np.vstack([
            np.random.randn(10, 10),  # Normal
            np.random.randn(5, 10) * 5  # Outliers
        ])

        feature_names = [f'feature_{i}' for i in range(10)]

        detector = AnomalyDetector(contamination=0.1)
        detector.fit(X_normal, feature_names)

        predictions, scores = detector.predict(X_test)

        assert len(predictions) == 15
        assert len(scores) == 15
        assert -1 in predictions  # At least some anomalies detected
