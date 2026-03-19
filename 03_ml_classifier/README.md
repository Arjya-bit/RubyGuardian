# RubyGuardian Phase 3 - ML Malware Classifier

Machine learning pipeline for classifying Ruby scripts as benign or malicious,
with multi-label threat categorization.

## Architecture

```
03_ml_classifier/
├── config/                  # Model, training, and feature configuration
├── data/                    # Raw, processed, and augmented datasets
├── feature_extraction/      # Static and behavioral feature extractors
├── models/                  # Classifier implementations and training
│   ├── training/            # Training pipeline and hyperparameter tuning
│   ├── evaluation/          # Metrics, plots, and adversarial testing
│   └── saved_models/        # Serialized model artifacts
├── api/                     # FastAPI serving layer
├── notebooks/               # Exploration and analysis notebooks
└── tests/                   # Unit and integration tests
```

## Features Extracted

- **Static Analysis**: AST structure, method complexity, control flow depth
- **String Patterns**: Suspicious string literals, encoded payloads, URLs/IPs
- **API Calls**: Dangerous system calls, network operations, file operations
- **Import Analysis**: Gem usage patterns, require chains, dynamic loading
- **Obfuscation Score**: Entropy analysis, encoding detection, naming patterns
- **Behavioral Features**: Syscall sequences, resource access patterns
- **Network Features**: Connection patterns, DNS queries, data transfer volumes

## Models

1. **Random Forest** - Baseline classifier with interpretable feature importance
2. **Gradient Boosting (XGBoost)** - High-performance gradient boosted trees
3. **Neural Network (PyTorch)** - Deep learning classifier for complex patterns
4. **Ensemble** - Weighted voting ensemble of all three models

## Quick Start

```bash
# Install dependencies
pip install -e .

# Extract features from raw scripts
python -m feature_extraction.feature_pipeline --input data/raw --output data/processed

# Train models
python -m models.training.train_pipeline --config config/training_config.yml

# Evaluate
python -m models.evaluation.evaluator --model models/saved_models/ensemble_latest.pkl

# Start API server
uvicorn api.app:app --host 0.0.0.0 --port 8000
```

## API Endpoints

| Method | Path                | Description                     |
|--------|---------------------|---------------------------------|
| POST   | `/classify`         | Classify a single Ruby script   |
| POST   | `/batch_classify`   | Classify multiple scripts       |
| GET    | `/model_info`       | Model metadata and version info |
| GET    | `/health`           | Health check                    |

## Training Data

The classifier is trained on curated datasets of:
- **Benign**: DevOps scripts, web applications, CLI tools, automation scripts
- **Malicious**: Reverse shells, process injection, data exfiltration,
  persistence mechanisms, obfuscated payloads

## Evaluation Metrics

- Accuracy, Precision, Recall, F1-Score (per-class and macro)
- ROC-AUC curves with confidence intervals
- Confusion matrices with normalized counts
- Feature importance rankings
- Adversarial robustness testing results
