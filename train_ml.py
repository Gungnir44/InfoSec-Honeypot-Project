#!/usr/bin/env python3
"""
ML Model Training Script
Trains attack classifier and anomaly detector on honeypot data
"""
import sys
sys.path.insert(0, '.')
from backend.database.db_manager import DatabaseManager
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
import os
import pandas as pd

print('Loading data from database...')
db = DatabaseManager()
attacks = db.get_recent_attacks(limit=10000)
print(f'Loaded {len(attacks)} attacks')

if len(attacks) >= 100:
    print('Extracting features...')
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
    print(f'Built {len(features_df)} feature vectors')

    labels = ['brute_force'] * len(features_df)
    os.makedirs('models', exist_ok=True)

    print('Training Attack Classifier...')
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(features_df)
    classifier = RandomForestClassifier(n_estimators=100, random_state=42)
    classifier.fit(X_scaled, labels)
    joblib.dump({'model': classifier, 'scaler': scaler}, 'models/attack_classifier.joblib')
    print('Attack Classifier saved!')

    print('Training Anomaly Detector...')
    detector = IsolationForest(contamination=0.1, random_state=42)
    detector.fit(X_scaled)
    joblib.dump({'model': detector, 'scaler': scaler}, 'models/anomaly_detector.joblib')
    print('Anomaly Detector saved!')

    print('ML Training Complete!')
else:
    print('Not enough data yet. Need at least 100 attacks.')
