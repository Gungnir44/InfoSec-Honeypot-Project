"""
Feature Engineering for ML Models

Extracts meaningful features from attack data for machine learning.
"""
import numpy as np
import pandas as pd
from typing import Dict, List, Any
from datetime import datetime, timedelta
from collections import Counter
import logging

logger = logging.getLogger(__name__)


class FeatureEngineer:
    """Extract features from attack sessions for ML models"""

    def __init__(self):
        pass

    def extract_session_features(self, session_data: Dict) -> Dict[str, Any]:
        """
        Extract features from a single attack session

        Returns dict with numerical and categorical features ready for ML
        """
        features = {}

        # === Temporal Features ===
        features['hour_of_day'] = session_data.get('timestamp', datetime.utcnow()).hour
        features['day_of_week'] = session_data.get('timestamp', datetime.utcnow()).weekday()
        features['is_weekend'] = 1 if features['day_of_week'] >= 5 else 0
        features['duration_seconds'] = session_data.get('duration', 0)

        # === Network Features ===
        features['src_port'] = session_data.get('src_port', 0)
        features['dst_port'] = session_data.get('dst_port', 2222)

        # === Geographic Features ===
        features['has_geolocation'] = 1 if session_data.get('country') else 0
        features['country'] = session_data.get('country', 'Unknown')
        features['latitude'] = session_data.get('latitude', 0.0)
        features['longitude'] = session_data.get('longitude', 0.0)

        # === Login Attempt Features ===
        login_attempts = session_data.get('login_attempts', [])
        features['login_attempt_count'] = len(login_attempts)
        features['successful_login'] = 1 if any(l.get('success') for l in login_attempts) else 0
        features['failed_login_count'] = sum(1 for l in login_attempts if not l.get('success'))

        # Login velocity (attempts per minute)
        if features['duration_seconds'] > 0:
            features['login_velocity'] = (features['login_attempt_count'] / features['duration_seconds']) * 60
        else:
            features['login_velocity'] = 0

        # Username/password diversity
        usernames = [l.get('username', '') for l in login_attempts]
        passwords = [l.get('password', '') for l in login_attempts]
        features['unique_usernames'] = len(set(usernames))
        features['unique_passwords'] = len(set(passwords))
        features['credential_diversity'] = features['unique_usernames'] + features['unique_passwords']

        # === Command Features ===
        commands = session_data.get('commands', [])
        features['command_count'] = len(commands)

        # Command velocity (commands per minute)
        if features['duration_seconds'] > 0:
            features['command_velocity'] = (features['command_count'] / features['duration_seconds']) * 60
        else:
            features['command_velocity'] = 0

        # Command categories
        categories = [c.get('category', 'unknown') for c in commands]
        category_counts = Counter(categories)

        features['recon_commands'] = category_counts.get('reconnaissance', 0)
        features['download_commands'] = category_counts.get('download', 0)
        features['persistence_commands'] = category_counts.get('persistence', 0)
        features['execution_commands'] = category_counts.get('execution', 0)
        features['privilege_escalation_commands'] = category_counts.get('privilege_escalation', 0)

        # Unique commands
        unique_commands = len(set(c.get('command', '') for c in commands))
        features['unique_commands'] = unique_commands
        features['command_repetition_rate'] = 1 - (unique_commands / max(features['command_count'], 1))

        # === Download Features ===
        downloads = session_data.get('downloads', [])
        features['download_count'] = len(downloads)
        features['has_downloads'] = 1 if downloads else 0

        # === Behavioral Features ===
        # Time between actions
        if commands:
            timestamps = [c.get('timestamp') for c in commands if c.get('timestamp')]
            if len(timestamps) > 1:
                time_diffs = [(timestamps[i] - timestamps[i-1]).total_seconds()
                             for i in range(1, len(timestamps))]
                features['avg_time_between_commands'] = np.mean(time_diffs)
                features['std_time_between_commands'] = np.std(time_diffs)
                features['min_time_between_commands'] = np.min(time_diffs)
                features['max_time_between_commands'] = np.max(time_diffs)
            else:
                features['avg_time_between_commands'] = 0
                features['std_time_between_commands'] = 0
                features['min_time_between_commands'] = 0
                features['max_time_between_commands'] = 0
        else:
            features['avg_time_between_commands'] = 0
            features['std_time_between_commands'] = 0
            features['min_time_between_commands'] = 0
            features['max_time_between_commands'] = 0

        # === Bot/Human Indicators ===
        # Very fast actions suggest automation
        features['is_likely_bot'] = 1 if features['avg_time_between_commands'] < 1 else 0

        # Predictable patterns suggest bot
        features['is_predictable'] = 1 if features['std_time_between_commands'] < 0.5 else 0

        # === Attack Sophistication Score ===
        sophistication_score = 0

        # Points for various sophistication indicators
        if features['persistence_commands'] > 0:
            sophistication_score += 2
        if features['download_commands'] > 0:
            sophistication_score += 2
        if features['execution_commands'] > 0:
            sophistication_score += 1
        if features['unique_commands'] > 5:
            sophistication_score += 1
        if features['credential_diversity'] > 10:
            sophistication_score += 1
        if not features['is_likely_bot']:
            sophistication_score += 2  # Human operators are more sophisticated

        features['sophistication_score'] = sophistication_score

        return features

    def create_dataset(self, sessions: List[Dict]) -> pd.DataFrame:
        """
        Create ML-ready dataset from multiple sessions

        Args:
            sessions: List of session dictionaries with attack data

        Returns:
            pandas DataFrame with extracted features
        """
        features_list = []

        for session in sessions:
            try:
                features = self.extract_session_features(session)
                features['session_id'] = session.get('session_id', '')
                features['src_ip'] = session.get('src_ip', '')
                features_list.append(features)
            except Exception as e:
                logger.error(f"Error extracting features from session: {e}")
                continue

        df = pd.DataFrame(features_list)

        # Handle any missing values
        df = df.fillna(0)

        return df

    def prepare_for_classification(self, df: pd.DataFrame) -> tuple:
        """
        Prepare dataset for classification

        Returns:
            tuple: (X, feature_names) where X is feature matrix
        """
        # Select numerical features only for modeling
        numerical_features = [
            'hour_of_day', 'day_of_week', 'is_weekend', 'duration_seconds',
            'src_port', 'login_attempt_count', 'successful_login',
            'failed_login_count', 'login_velocity', 'unique_usernames',
            'unique_passwords', 'credential_diversity', 'command_count',
            'command_velocity', 'recon_commands', 'download_commands',
            'persistence_commands', 'execution_commands',
            'privilege_escalation_commands', 'unique_commands',
            'command_repetition_rate', 'download_count', 'has_downloads',
            'avg_time_between_commands', 'std_time_between_commands',
            'min_time_between_commands', 'max_time_between_commands',
            'is_likely_bot', 'is_predictable', 'sophistication_score'
        ]

        # Filter to available features
        available_features = [f for f in numerical_features if f in df.columns]

        X = df[available_features].values

        return X, available_features

    def export_for_training(self, df: pd.DataFrame, output_path: str, format: str = 'csv'):
        """
        Export dataset for ML training

        Args:
            df: DataFrame with features
            output_path: Path to save file
            format: 'csv', 'json', or 'parquet'
        """
        if format == 'csv':
            df.to_csv(output_path, index=False)
        elif format == 'json':
            df.to_json(output_path, orient='records', lines=True)
        elif format == 'parquet':
            df.to_parquet(output_path, index=False)
        else:
            raise ValueError(f"Unsupported format: {format}")

        logger.info(f"Exported {len(df)} samples to {output_path}")

    def get_feature_importance_report(self, feature_names: List[str],
                                     importance_scores: np.ndarray) -> str:
        """
        Generate a human-readable feature importance report

        Args:
            feature_names: List of feature names
            importance_scores: Array of importance scores

        Returns:
            Formatted string report
        """
        # Sort by importance
        indices = np.argsort(importance_scores)[::-1]

        report = []
        report.append("=" * 60)
        report.append("FEATURE IMPORTANCE REPORT")
        report.append("=" * 60)
        report.append("")

        for i, idx in enumerate(indices[:20], 1):  # Top 20
            report.append(f"{i:2d}. {feature_names[idx]:35s} {importance_scores[idx]:.4f}")

        report.append("")
        report.append("=" * 60)

        return "\n".join(report)
