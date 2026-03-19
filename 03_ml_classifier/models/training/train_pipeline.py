"""
Full training pipeline for RubyGuardian malware classifiers.

Orchestrates data loading, feature extraction, train/val/test splitting,
class balancing, model training, ensemble creation, evaluation, and
model export in a single configurable pipeline.
"""

import json
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

import numpy as np
import pandas as pd
import yaml
from loguru import logger
from sklearn.model_selection import StratifiedKFold, train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder

from models.random_forest_classifier import RandomForestMalwareClassifier
from models.xgboost_classifier import XGBoostMalwareClassifier
from models.neural_net_classifier import NeuralNetMalwareClassifier
from models.ensemble_classifier import EnsembleMalwareClassifier


class TrainPipeline:
    """End-to-end training pipeline for malware classifiers.

    Coordinates the full lifecycle from raw data through trained and
    evaluated models, with support for cross-validation, class balancing,
    and experiment tracking.
    """

    def __init__(
        self,
        config_path: Optional[str | Path] = None,
        model_config_path: Optional[str | Path] = None,
    ) -> None:
        """Initialize the training pipeline.

        Args:
            config_path: Path to training_config.yml.
            model_config_path: Path to model_config.yml.
        """
        self.config = self._load_config(config_path)
        self.model_config_path = model_config_path

        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        self.feature_names: list[str] = []

        self.models: dict[str, Any] = {}
        self.ensemble: Optional[EnsembleMalwareClassifier] = None
        self.evaluation_results: dict[str, Any] = {}
        self.run_metadata: dict[str, Any] = {}

        logger.info("TrainPipeline initialized")

    @staticmethod
    def _load_config(config_path: Optional[str | Path]) -> dict[str, Any]:
        """Load training configuration from YAML.

        Args:
            config_path: Path to the config file.

        Returns:
            Configuration dictionary with defaults.
        """
        defaults: dict[str, Any] = {
            "data": {
                "raw_dir": "data/raw",
                "processed_dir": "data/processed",
                "test_size": 0.2,
                "validation_size": 0.15,
                "random_state": 42,
                "stratify": True,
            },
            "cross_validation": {
                "strategy": "stratified_kfold",
                "n_splits": 5,
                "shuffle": True,
                "random_state": 42,
            },
            "pipeline": {
                "steps": [],
            },
            "output": {
                "model_dir": "models/saved_models",
                "report_dir": "models/evaluation/reports",
            },
        }

        if config_path is None:
            return defaults

        path = Path(config_path)
        if not path.exists():
            logger.warning("Config not found: {}, using defaults", path)
            return defaults

        with open(path) as f:
            config = yaml.safe_load(f)

        # Merge with defaults
        for key in defaults:
            if key not in config:
                config[key] = defaults[key]

        return config

    def load_data(
        self,
        features_path: Optional[str | Path] = None,
        labels_path: Optional[str | Path] = None,
    ) -> tuple[np.ndarray, np.ndarray]:
        """Load preprocessed feature and label data.

        Args:
            features_path: Path to the features CSV or NPY file.
            labels_path: Path to the labels CSV or NPY file.

        Returns:
            Tuple of (feature_matrix, label_array).

        Raises:
            FileNotFoundError: If data files are not found.
        """
        data_config = self.config["data"]

        if features_path is None:
            features_path = Path(data_config["processed_dir"]) / "features" / "features.csv"
        if labels_path is None:
            labels_path = Path(data_config["processed_dir"]) / "labels" / "labels.csv"

        features_path = Path(features_path)
        labels_path = Path(labels_path)

        if not features_path.exists():
            raise FileNotFoundError(f"Features file not found: {features_path}")
        if not labels_path.exists():
            raise FileNotFoundError(f"Labels file not found: {labels_path}")

        # Load based on file extension
        if features_path.suffix == ".npy":
            X = np.load(features_path)
        else:
            df = pd.read_csv(features_path)
            self.feature_names = list(df.columns)
            X = df.values

        if labels_path.suffix == ".npy":
            y = np.load(labels_path)
        else:
            y_df = pd.read_csv(labels_path)
            if y_df.shape[1] == 1:
                y = y_df.iloc[:, 0].values
            else:
                y = y_df["label"].values if "label" in y_df.columns else y_df.iloc[:, 0].values

        logger.info("Loaded data: {} samples, {} features", X.shape[0], X.shape[1])
        return X, y

    def split_data(
        self,
        X: np.ndarray,
        y: np.ndarray,
    ) -> dict[str, np.ndarray]:
        """Split data into train, validation, and test sets.

        Args:
            X: Feature matrix.
            y: Label array.

        Returns:
            Dictionary with keys 'X_train', 'X_val', 'X_test',
            'y_train', 'y_val', 'y_test'.
        """
        data_config = self.config["data"]
        test_size = data_config["test_size"]
        val_size = data_config["validation_size"]
        random_state = data_config["random_state"]
        stratify = data_config.get("stratify", True)

        stratify_col = y if stratify else None

        X_temp, X_test, y_temp, y_test = train_test_split(
            X, y,
            test_size=test_size,
            random_state=random_state,
            stratify=stratify_col,
        )

        # Compute validation fraction relative to the remaining data
        val_fraction = val_size / (1.0 - test_size)
        stratify_temp = y_temp if stratify else None

        X_train, X_val, y_train, y_val = train_test_split(
            X_temp, y_temp,
            test_size=val_fraction,
            random_state=random_state,
            stratify=stratify_temp,
        )

        logger.info(
            "Data split: train={}, val={}, test={}",
            X_train.shape[0], X_val.shape[0], X_test.shape[0],
        )

        return {
            "X_train": X_train,
            "X_val": X_val,
            "X_test": X_test,
            "y_train": y_train,
            "y_val": y_val,
            "y_test": y_test,
        }

    def normalize_features(
        self,
        splits: dict[str, np.ndarray],
    ) -> dict[str, np.ndarray]:
        """Apply standard scaling to feature splits.

        Fits the scaler on training data and transforms all splits.

        Args:
            splits: Dictionary of data splits from split_data().

        Returns:
            Updated splits dictionary with scaled features.
        """
        self.scaler.fit(splits["X_train"])
        splits["X_train"] = self.scaler.transform(splits["X_train"])
        splits["X_val"] = self.scaler.transform(splits["X_val"])
        splits["X_test"] = self.scaler.transform(splits["X_test"])

        logger.info("Features normalized with StandardScaler")
        return splits

    def train_random_forest(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
    ) -> RandomForestMalwareClassifier:
        """Train the Random Forest classifier.

        Args:
            X_train: Training features.
            y_train: Training labels.

        Returns:
            Trained RandomForestMalwareClassifier.
        """
        logger.info("Training Random Forest classifier...")
        clf = RandomForestMalwareClassifier(
            config_path=self.model_config_path,
            feature_names=self.feature_names,
        )
        clf.fit(X_train, y_train, feature_names=self.feature_names)
        self.models["random_forest"] = clf
        return clf

    def train_xgboost(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        X_val: Optional[np.ndarray] = None,
        y_val: Optional[np.ndarray] = None,
    ) -> XGBoostMalwareClassifier:
        """Train the XGBoost classifier.

        Args:
            X_train: Training features.
            y_train: Training labels.
            X_val: Optional validation features.
            y_val: Optional validation labels.

        Returns:
            Trained XGBoostMalwareClassifier.
        """
        logger.info("Training XGBoost classifier...")
        clf = XGBoostMalwareClassifier(
            config_path=self.model_config_path,
            feature_names=self.feature_names,
        )
        clf.fit(X_train, y_train, X_val=X_val, y_val=y_val,
                feature_names=self.feature_names)
        self.models["gradient_boost"] = clf
        return clf

    def train_neural_network(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        X_val: Optional[np.ndarray] = None,
        y_val: Optional[np.ndarray] = None,
    ) -> NeuralNetMalwareClassifier:
        """Train the Neural Network classifier.

        Args:
            X_train: Training features.
            y_train: Training labels.
            X_val: Optional validation features.
            y_val: Optional validation labels.

        Returns:
            Trained NeuralNetMalwareClassifier.
        """
        logger.info("Training Neural Network classifier...")
        clf = NeuralNetMalwareClassifier(
            config_path=self.model_config_path,
            feature_names=self.feature_names,
        )
        clf.fit(X_train, y_train, X_val=X_val, y_val=y_val,
                feature_names=self.feature_names)
        self.models["neural_network"] = clf
        return clf

    def create_ensemble(
        self,
        X_val: Optional[np.ndarray] = None,
        y_val: Optional[np.ndarray] = None,
        optimize_weights: bool = True,
    ) -> EnsembleMalwareClassifier:
        """Create a weighted ensemble from trained models.

        Args:
            X_val: Validation features for weight optimization.
            y_val: Validation labels for weight optimization.
            optimize_weights: Whether to optimize ensemble weights.

        Returns:
            Configured EnsembleMalwareClassifier.
        """
        logger.info("Creating ensemble classifier...")
        self.ensemble = EnsembleMalwareClassifier(config_path=self.model_config_path)

        for name, model in self.models.items():
            self.ensemble.add_model(name, model)

        self.ensemble.classes_ = np.unique(
            np.concatenate([m.classes_ for m in self.models.values()])
        )
        self.ensemble.is_fitted = True

        if optimize_weights and X_val is not None and y_val is not None:
            self.ensemble.optimize_weights(X_val, y_val)

        return self.ensemble

    def cross_validate(
        self,
        X: np.ndarray,
        y: np.ndarray,
        model_name: str = "random_forest",
    ) -> dict[str, list[float]]:
        """Run stratified k-fold cross-validation.

        Args:
            X: Full feature matrix.
            y: Full label array.
            model_name: Which model to cross-validate.

        Returns:
            Dictionary of metric lists across folds.
        """
        cv_config = self.config["cross_validation"]
        n_splits = cv_config["n_splits"]
        random_state = cv_config["random_state"]

        skf = StratifiedKFold(
            n_splits=n_splits,
            shuffle=cv_config.get("shuffle", True),
            random_state=random_state,
        )

        fold_metrics: dict[str, list[float]] = {
            "accuracy": [],
            "f1_weighted": [],
            "precision_weighted": [],
            "recall_weighted": [],
        }

        for fold, (train_idx, val_idx) in enumerate(skf.split(X, y)):
            logger.info("Cross-validation fold {}/{}", fold + 1, n_splits)

            X_fold_train, X_fold_val = X[train_idx], X[val_idx]
            y_fold_train, y_fold_val = y[train_idx], y[val_idx]

            if model_name == "random_forest":
                clf = RandomForestMalwareClassifier(config_path=self.model_config_path)
            elif model_name == "gradient_boost":
                clf = XGBoostMalwareClassifier(config_path=self.model_config_path)
            elif model_name == "neural_network":
                clf = NeuralNetMalwareClassifier(config_path=self.model_config_path)
            else:
                raise ValueError(f"Unknown model: {model_name}")

            clf.fit(X_fold_train, y_fold_train)
            metrics = clf.evaluate(X_fold_val, y_fold_val)

            for key in fold_metrics:
                fold_metrics[key].append(metrics.get(key, 0.0))

        for key, values in fold_metrics.items():
            mean_val = np.mean(values)
            std_val = np.std(values)
            logger.info(
                "CV {} - {}: {:.4f} (+/- {:.4f})",
                model_name, key, mean_val, std_val,
            )

        return fold_metrics

    def run(
        self,
        features_path: Optional[str | Path] = None,
        labels_path: Optional[str | Path] = None,
    ) -> dict[str, Any]:
        """Execute the full training pipeline.

        Args:
            features_path: Path to features file.
            labels_path: Path to labels file.

        Returns:
            Dictionary with all training results and metrics.
        """
        start_time = time.time()
        self.run_metadata = {
            "start_time": datetime.utcnow().isoformat(),
            "config": self.config,
        }

        logger.info("Starting full training pipeline")

        # Step 1: Load data
        X, y = self.load_data(features_path, labels_path)

        # Step 2: Split data
        splits = self.split_data(X, y)

        # Step 3: Normalize
        splits = self.normalize_features(splits)

        # Step 4: Train models
        self.train_random_forest(splits["X_train"], splits["y_train"])

        self.train_xgboost(
            splits["X_train"], splits["y_train"],
            splits["X_val"], splits["y_val"],
        )

        self.train_neural_network(
            splits["X_train"], splits["y_train"],
            splits["X_val"], splits["y_val"],
        )

        # Step 5: Create ensemble
        self.create_ensemble(splits["X_val"], splits["y_val"])

        # Step 6: Evaluate all models on test set
        self.evaluation_results = {}
        for name, model in self.models.items():
            self.evaluation_results[name] = model.evaluate(
                splits["X_test"], splits["y_test"]
            )

        if self.ensemble is not None:
            self.evaluation_results["ensemble"] = self.ensemble.evaluate(
                splits["X_test"], splits["y_test"]
            )

        # Step 7: Save models
        self._save_models()

        elapsed = time.time() - start_time
        self.run_metadata["elapsed_seconds"] = elapsed
        self.run_metadata["end_time"] = datetime.utcnow().isoformat()

        logger.info("Training pipeline complete in {:.1f}s", elapsed)

        return {
            "metadata": self.run_metadata,
            "evaluation": self.evaluation_results,
            "models": list(self.models.keys()),
        }

    def _save_models(self) -> None:
        """Save all trained models to the configured output directory."""
        output_dir = Path(self.config["output"]["model_dir"])
        output_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

        for name, model in self.models.items():
            model_path = output_dir / f"{name}_{timestamp}.pkl"
            model.save(model_path)

        if self.ensemble is not None:
            ensemble_path = output_dir / f"ensemble_{timestamp}.pkl"
            self.ensemble.save(ensemble_path)

            # Also save as "latest" for quick access
            latest_path = output_dir / "ensemble_latest.pkl"
            self.ensemble.save(latest_path)

        # Save run report
        report_dir = Path(self.config["output"].get("report_dir", "models/evaluation/reports"))
        report_dir.mkdir(parents=True, exist_ok=True)
        report_path = report_dir / f"training_report_{timestamp}.json"

        report = {
            "metadata": self.run_metadata,
            "evaluation": {
                name: {
                    k: v for k, v in metrics.items()
                    if k != "classification_report"
                }
                for name, metrics in self.evaluation_results.items()
            },
        }

        with open(report_path, "w") as f:
            json.dump(report, f, indent=2, default=str)

        logger.info("Models and report saved to {}", output_dir)

    def get_best_model(self) -> tuple[str, Any]:
        """Return the model with the highest F1-weighted score.

        Returns:
            Tuple of (model_name, model_instance).
        """
        best_name = None
        best_f1 = 0.0

        for name, metrics in self.evaluation_results.items():
            f1 = metrics.get("f1_weighted", 0.0)
            if isinstance(metrics, dict) and "ensemble" in metrics:
                f1 = metrics["ensemble"].get("f1_weighted", 0.0)
            if f1 > best_f1:
                best_f1 = f1
                best_name = name

        if best_name == "ensemble":
            return best_name, self.ensemble
        return best_name, self.models.get(best_name)


def main() -> None:
    """CLI entry point for running the training pipeline."""
    import click

    @click.command()
    @click.option("--config", default="config/training_config.yml", help="Training config path")
    @click.option("--model-config", default="config/model_config.yml", help="Model config path")
    @click.option("--features", default=None, help="Path to features file")
    @click.option("--labels", default=None, help="Path to labels file")
    def train(config: str, model_config: str, features: Optional[str], labels: Optional[str]) -> None:
        """Run the full training pipeline."""
        pipeline = TrainPipeline(config_path=config, model_config_path=model_config)
        results = pipeline.run(features_path=features, labels_path=labels)
        logger.info("Pipeline results: {}", json.dumps(
            {k: v for k, v in results.items() if k != "evaluation"},
            indent=2, default=str,
        ))

    train()
