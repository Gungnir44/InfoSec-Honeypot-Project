"""
ML Model Training Pipeline

Coordinates the entire training process from data loading to model evaluation.
"""
import sys
import os
from pathlib import Path
from datetime import datetime
from typing import Dict
import logging

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from backend.database.db_manager import DatabaseManager
from backend.ml.feature_engineering import FeatureEngineer
from backend.ml.models import AttackClassifier, AnomalyDetector

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ModelTrainer:
    """Orchestrates ML model training pipeline"""

    def __init__(self, db_manager: DatabaseManager = None):
        """
        Initialize trainer

        Args:
            db_manager: DatabaseManager instance (creates new if None)
        """
        self.db_manager = db_manager or DatabaseManager()
        self.feature_engineer = FeatureEngineer()
        self.classifier = None
        self.anomaly_detector = None

    def load_training_data(self, min_commands: int = 1) -> pd.DataFrame:
        """
        Load attack data from database for training

        Args:
            min_commands: Minimum number of commands for a session to be included

        Returns:
            DataFrame with attack sessions
        """
        logger.info("Loading training data from database...")

        # Get all attacks
        session = self.db_manager.get_session()

        try:
            from backend.database.models import Attack, LoginAttempt, Command

            attacks = session.query(Attack).all()

            session_data = []

            for attack in attacks:
                # Get related data
                login_attempts = [
                    {
                        'username': la.username,
                        'password': la.password,
                        'success': la.success,
                        'timestamp': la.timestamp
                    }
                    for la in attack.login_attempts
                ]

                commands = [
                    {
                        'command': cmd.command,
                        'category': cmd.category,
                        'timestamp': cmd.timestamp
                    }
                    for cmd in attack.commands
                ]

                # Filter sessions with too few commands
                if len(commands) < min_commands:
                    continue

                session_dict = {
                    'session_id': attack.session_id,
                    'src_ip': attack.src_ip,
                    'src_port': attack.src_port,
                    'dst_port': attack.dst_port,
                    'timestamp': attack.timestamp,
                    'country': attack.country,
                    'city': attack.city,
                    'latitude': attack.latitude,
                    'longitude': attack.longitude,
                    'login_attempts': login_attempts,
                    'commands': commands,
                    'downloads': [],  # Add download data if available
                    'duration': 0  # Calculate from session data
                }

                # Calculate duration
                if commands:
                    timestamps = [c['timestamp'] for c in commands]
                    duration = (max(timestamps) - min(timestamps)).total_seconds()
                    session_dict['duration'] = duration

                session_data.append(session_dict)

            logger.info(f"Loaded {len(session_data)} sessions for training")

            return session_data

        finally:
            session.close()

    def create_labels(self, df: pd.DataFrame) -> np.ndarray:
        """
        Create labels for supervised learning

        Uses heuristics to label attack types based on behavior patterns.
        In production, you'd want manual labeling or semi-supervised learning.

        Args:
            df: DataFrame with extracted features

        Returns:
            Array of labels
        """
        logger.info("Generating labels from attack patterns...")

        labels = []

        for _, row in df.iterrows():
            # Brute force: many login attempts, few/no commands
            if row['login_attempt_count'] > 10 and row['command_count'] < 3:
                label = 0  # brute_force

            # Reconnaissance: many recon commands, no execution
            elif row['recon_commands'] > 3 and row['execution_commands'] == 0:
                label = 1  # reconnaissance

            # Malware deployment: downloads and execution
            elif row['download_commands'] > 0 or row['has_downloads'] == 1:
                label = 2  # malware_deployment

            # Persistence: persistence commands present
            elif row['persistence_commands'] > 0:
                label = 3  # persistence

            # Bot: very fast, predictable behavior
            elif row['is_likely_bot'] == 1 and row['command_count'] < 5:
                label = 4  # bot

            # Advanced: sophisticated patterns
            elif row['sophistication_score'] >= 5:
                label = 5  # advanced

            # Default: brute force
            else:
                label = 0

            labels.append(label)

        label_counts = pd.Series(labels).value_counts()
        logger.info(f"Label distribution:\n{label_counts}")

        return np.array(labels)

    def train_classifier(self, save_path: str = 'models/attack_classifier.pkl') -> Dict:
        """
        Train attack classification model

        Args:
            save_path: Path to save trained model

        Returns:
            Dictionary with training metrics
        """
        logger.info("=" * 60)
        logger.info("TRAINING ATTACK CLASSIFIER")
        logger.info("=" * 60)

        # Load data
        sessions = self.load_training_data()

        if len(sessions) < 10:
            logger.warning("Not enough training data. Need at least 10 sessions.")
            return {'error': 'Insufficient training data'}

        # Extract features
        df = self.feature_engineer.create_dataset(sessions)

        # Create labels
        y = self.create_labels(df)

        # Prepare features
        X, feature_names = self.feature_engineer.prepare_for_classification(df)

        # Train model
        self.classifier = AttackClassifier()
        metrics = self.classifier.train(X, y, feature_names)

        # Feature importance
        importance = self.classifier.get_feature_importance()
        importance_report = self.feature_engineer.get_feature_importance_report(
            feature_names, importance
        )
        logger.info(f"\n{importance_report}")

        # Save model
        os.makedirs(os.path.dirname(save_path), exist_ok=True)
        self.classifier.save(save_path)

        logger.info(f"\n✓ Classifier training complete!")

        return metrics

    def train_anomaly_detector(self, save_path: str = 'models/anomaly_detector.pkl') -> Dict:
        """
        Train anomaly detection model

        Args:
            save_path: Path to save trained model

        Returns:
            Dictionary with training info
        """
        logger.info("=" * 60)
        logger.info("TRAINING ANOMALY DETECTOR")
        logger.info("=" * 60)

        # Load data
        sessions = self.load_training_data()

        if len(sessions) < 20:
            logger.warning("Not enough training data for anomaly detection.")
            return {'error': 'Insufficient training data'}

        # Extract features
        df = self.feature_engineer.create_dataset(sessions)

        # Prepare features
        X, feature_names = self.feature_engineer.prepare_for_classification(df)

        # Train model
        self.anomaly_detector = AnomalyDetector(contamination=0.1)
        self.anomaly_detector.fit(X, feature_names)

        # Generate report
        session_ids = df['session_id'].tolist()
        report = self.anomaly_detector.get_anomaly_report(X, session_ids)
        logger.info(f"\n{report}")

        # Save model
        os.makedirs(os.path.dirname(save_path), exist_ok=True)
        self.anomaly_detector.save(save_path)

        logger.info(f"\n✓ Anomaly detector training complete!")

        return {
            'samples_trained': len(X),
            'threshold': self.anomaly_detector.threshold
        }

    def export_dataset(self, output_dir: str = 'data/ml_training'):
        """
        Export dataset for external ML tools

        Args:
            output_dir: Directory to save dataset files
        """
        logger.info("Exporting dataset for ML training...")

        os.makedirs(output_dir, exist_ok=True)

        # Load data
        sessions = self.load_training_data(min_commands=0)
        df = self.feature_engineer.create_dataset(sessions)

        # Create labels
        labels = self.create_labels(df)
        df['label'] = labels

        # Map labels to names
        label_map = {
            0: 'brute_force',
            1: 'reconnaissance',
            2: 'malware_deployment',
            3: 'persistence',
            4: 'bot',
            5: 'advanced'
        }
        df['label_name'] = df['label'].map(label_map)

        # Export in multiple formats
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

        # CSV
        csv_path = f"{output_dir}/honeypot_dataset_{timestamp}.csv"
        self.feature_engineer.export_for_training(df, csv_path, format='csv')

        # JSON Lines
        json_path = f"{output_dir}/honeypot_dataset_{timestamp}.jsonl"
        self.feature_engineer.export_for_training(df, json_path, format='json')

        # Summary statistics
        summary_path = f"{output_dir}/dataset_summary_{timestamp}.txt"
        with open(summary_path, 'w') as f:
            f.write("=" * 60 + "\n")
            f.write("HONEYPOT ML DATASET SUMMARY\n")
            f.write("=" * 60 + "\n\n")
            f.write(f"Total samples: {len(df)}\n\n")
            f.write("Label distribution:\n")
            f.write(str(df['label_name'].value_counts()) + "\n\n")
            f.write("Feature statistics:\n")
            f.write(str(df.describe()) + "\n")

        logger.info(f"Dataset exported to {output_dir}")
        logger.info(f"  CSV: {csv_path}")
        logger.info(f"  JSON: {json_path}")
        logger.info(f"  Summary: {summary_path}")

        return {
            'csv_path': csv_path,
            'json_path': json_path,
            'summary_path': summary_path,
            'sample_count': len(df)
        }


def main():
    """Command-line interface for model training"""
    import argparse

    parser = argparse.ArgumentParser(description='Train ML models for attack analysis')

    parser.add_argument(
        '--mode',
        choices=['classifier', 'anomaly', 'both', 'export'],
        default='both',
        help='Training mode'
    )

    parser.add_argument(
        '--classifier-path',
        default='models/attack_classifier.pkl',
        help='Path to save classifier model'
    )

    parser.add_argument(
        '--anomaly-path',
        default='models/anomaly_detector.pkl',
        help='Path to save anomaly detector'
    )

    parser.add_argument(
        '--export-dir',
        default='data/ml_training',
        help='Directory for dataset export'
    )

    args = parser.parse_args()

    trainer = ModelTrainer()

    if args.mode in ['classifier', 'both']:
        trainer.train_classifier(save_path=args.classifier_path)

    if args.mode in ['anomaly', 'both']:
        trainer.train_anomaly_detector(save_path=args.anomaly_path)

    if args.mode == 'export':
        trainer.export_dataset(output_dir=args.export_dir)


if __name__ == '__main__':
    main()
