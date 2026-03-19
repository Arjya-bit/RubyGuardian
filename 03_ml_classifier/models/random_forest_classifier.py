"""
Random Forest classifier for Ruby malware detection.

Implements a Random Forest model with feature importance analysis,
out-of-bag scoring, and configurable hyperparameters loaded from
the project model configuration.
"""

import pickle
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import numpy as np
import yaml
from loguru import logger
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    f1_score,
    precision_score,
    recall_score,
)


@dataclass
class RFPredictionResult:
    """Container for a single Random Forest prediction."""

    label: str
    confidence: float
    probabilities: dict[str, float] = field(default_factory=dict)
    feature_importances: Optional[dict[str, float]] = None


class RandomForestMalwareClassifier:
    """Random Forest classifier with feature importance tracking.

    Wraps scikit-learn's RandomForestClassifier with project-specific
    configuration loading, training, prediction, persistence, and
    feature importance analysis for Ruby malware classification.
    """

    DEFAULT_PARAMS = {
        "n_estimators": 500,
        "max_depth": 30,
        "min_samples_split": 5,
        "min_samples_leaf": 2,
        "max_features": "sqrt",
        "class_weight": "balanced",
        "n_jobs": -1,
        "random_state": 42,
        "bootstrap": True,
        "oob_score": True,
    }

    LABEL_MAP = {
        0: "benign",
        1: "malicious",
    }

    THREAT_CATEGORIES = [
        "reverse_shell",
        "process_injection",
        "exfiltration",
        "persistence",
        "obfuscated",
        "clean",
    ]

    def __init__(
        self,
        config_path: Optional[str | Path] = None,
        params: Optional[dict[str, Any]] = None,
        feature_names: Optional[list[str]] = None,
    ) -> None:
        """Initialize the Random Forest malware classifier.

        Args:
            config_path: Path to model_config.yml for loading RF parameters.
            params: Optional dict of RF hyperparameters to override config.
            feature_names: Optional list of feature names for importance tracking.
        """
        self.params = dict(self.DEFAULT_PARAMS)

        if config_path:
            self._load_config(config_path)

        if params:
            self.params.update(params)

        self.feature_names = feature_names or []
        self.model: Optional[RandomForestClassifier] = None
        self.is_fitted = False
        self.oob_score_: Optional[float] = None
        self.classes_: Optional[np.ndarray] = None
        self._feature_importances: Optional[np.ndarray] = None

        logger.info(
            "RandomForestMalwareClassifier initialized with {} estimators",
            self.params["n_estimators"],
        )

    def _load_config(self, config_path: str | Path) -> None:
        """Load model parameters from YAML configuration.

        Args:
            config_path: Path to the model config YAML file.
        """
        path = Path(config_path)
        if not path.exists():
            logger.warning("Config file not found: {}, using defaults", path)
            return

        with open(path) as f:
            config = yaml.safe_load(f)

        rf_config = config.get("random_forest", {})
        for key, value in rf_config.items():
            if key in self.DEFAULT_PARAMS:
                self.params[key] = value

        logger.debug("Loaded RF config from {}", path)

    def fit(
        self,
        X: np.ndarray,
        y: np.ndarray,
        feature_names: Optional[list[str]] = None,
    ) -> "RandomForestMalwareClassifier":
        """Train the Random Forest model.

        Args:
            X: Training feature matrix of shape (n_samples, n_features).
            y: Target labels of shape (n_samples,).
            feature_names: Optional feature names to associate with columns.

        Returns:
            Self for method chaining.
        """
        if feature_names:
            self.feature_names = feature_names

        logger.info(
            "Training Random Forest on {} samples with {} features",
            X.shape[0],
            X.shape[1],
        )

        self.model = RandomForestClassifier(**self.params)
        self.model.fit(X, y)

        self.is_fitted = True
        self.classes_ = self.model.classes_
        self._feature_importances = self.model.feature_importances_

        if self.params.get("oob_score"):
            self.oob_score_ = self.model.oob_score_
            logger.info("OOB Score: {:.4f}", self.oob_score_)

        logger.info("Random Forest training complete")
        return self

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Predict class labels for the given feature matrix.

        Args:
            X: Feature matrix of shape (n_samples, n_features).

        Returns:
            Predicted class labels of shape (n_samples,).

        Raises:
            RuntimeError: If the model has not been fitted.
        """
        self._check_is_fitted()
        return self.model.predict(X)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Predict class probabilities for the given feature matrix.

        Args:
            X: Feature matrix of shape (n_samples, n_features).

        Returns:
            Class probabilities of shape (n_samples, n_classes).

        Raises:
            RuntimeError: If the model has not been fitted.
        """
        self._check_is_fitted()
        return self.model.predict_proba(X)

    def predict_single(
        self,
        features: np.ndarray,
        include_importances: bool = False,
    ) -> RFPredictionResult:
        """Predict a single sample and return a detailed result.

        Args:
            features: Feature vector of shape (n_features,).
            include_importances: If True, include top feature importances.

        Returns:
            RFPredictionResult with label, confidence, and probabilities.
        """
        self._check_is_fitted()

        X = features.reshape(1, -1)
        proba = self.model.predict_proba(X)[0]
        predicted_class = self.classes_[np.argmax(proba)]
        confidence = float(np.max(proba))

        probabilities = {
            str(cls): float(p)
            for cls, p in zip(self.classes_, proba)
        }

        importances = None
        if include_importances:
            importances = self.get_top_feature_importances(n_top=10)

        label = self.LABEL_MAP.get(int(predicted_class), str(predicted_class))

        return RFPredictionResult(
            label=label,
            confidence=confidence,
            probabilities=probabilities,
            feature_importances=importances,
        )

    def evaluate(
        self,
        X: np.ndarray,
        y: np.ndarray,
    ) -> dict[str, Any]:
        """Evaluate the model on test data and return metrics.

        Args:
            X: Test feature matrix of shape (n_samples, n_features).
            y: True labels of shape (n_samples,).

        Returns:
            Dictionary of evaluation metrics.
        """
        self._check_is_fitted()

        y_pred = self.predict(X)
        y_proba = self.predict_proba(X)

        metrics = {
            "accuracy": float(accuracy_score(y, y_pred)),
            "precision_weighted": float(precision_score(y, y_pred, average="weighted", zero_division=0)),
            "recall_weighted": float(recall_score(y, y_pred, average="weighted", zero_division=0)),
            "f1_weighted": float(f1_score(y, y_pred, average="weighted", zero_division=0)),
            "f1_macro": float(f1_score(y, y_pred, average="macro", zero_division=0)),
            "classification_report": classification_report(y, y_pred, output_dict=True, zero_division=0),
            "oob_score": self.oob_score_,
        }

        logger.info(
            "RF Evaluation - Accuracy: {:.4f}, F1-weighted: {:.4f}",
            metrics["accuracy"],
            metrics["f1_weighted"],
        )
        return metrics

    def get_feature_importances(self) -> dict[str, float]:
        """Get feature importances as a name-value mapping.

        Returns:
            Dictionary mapping feature names to importance scores.
            If feature_names was not provided, uses generic names.
        """
        self._check_is_fitted()

        names = self.feature_names or [
            f"feature_{i}" for i in range(len(self._feature_importances))
        ]

        importances = {
            name: float(imp)
            for name, imp in zip(names, self._feature_importances)
        }

        return dict(sorted(importances.items(), key=lambda x: x[1], reverse=True))

    def get_top_feature_importances(self, n_top: int = 20) -> dict[str, float]:
        """Get the top N most important features.

        Args:
            n_top: Number of top features to return.

        Returns:
            Dictionary of top feature names and importance scores.
        """
        all_importances = self.get_feature_importances()
        return dict(list(all_importances.items())[:n_top])

    def save(self, path: str | Path) -> None:
        """Serialize the model to disk.

        Args:
            path: File path for the saved model.
        """
        self._check_is_fitted()

        save_path = Path(path)
        save_path.parent.mkdir(parents=True, exist_ok=True)

        model_data = {
            "model": self.model,
            "params": self.params,
            "feature_names": self.feature_names,
            "classes": self.classes_,
            "oob_score": self.oob_score_,
            "feature_importances": self._feature_importances,
        }

        with open(save_path, "wb") as f:
            pickle.dump(model_data, f, protocol=pickle.HIGHEST_PROTOCOL)

        logger.info("Random Forest model saved to {}", save_path)

    @classmethod
    def load(cls, path: str | Path) -> "RandomForestMalwareClassifier":
        """Load a serialized model from disk.

        Args:
            path: File path to the saved model.

        Returns:
            Loaded RandomForestMalwareClassifier instance.

        Raises:
            FileNotFoundError: If the model file does not exist.
        """
        load_path = Path(path)
        if not load_path.exists():
            raise FileNotFoundError(f"Model file not found: {load_path}")

        with open(load_path, "rb") as f:
            model_data = pickle.load(f)

        instance = cls()
        instance.model = model_data["model"]
        instance.params = model_data["params"]
        instance.feature_names = model_data["feature_names"]
        instance.classes_ = model_data["classes"]
        instance.oob_score_ = model_data["oob_score"]
        instance._feature_importances = model_data["feature_importances"]
        instance.is_fitted = True

        logger.info("Random Forest model loaded from {}", load_path)
        return instance

    def get_params(self) -> dict[str, Any]:
        """Get the current model parameters.

        Returns:
            Dictionary of model parameters.
        """
        return dict(self.params)

    def set_params(self, **params: Any) -> "RandomForestMalwareClassifier":
        """Update model parameters.

        Args:
            **params: Keyword arguments of parameters to update.

        Returns:
            Self for method chaining.
        """
        self.params.update(params)
        self.is_fitted = False
        self.model = None
        logger.debug("RF parameters updated, model needs retraining")
        return self

    def _check_is_fitted(self) -> None:
        """Verify the model has been trained.

        Raises:
            RuntimeError: If the model has not been fitted.
        """
        if not self.is_fitted or self.model is None:
            raise RuntimeError(
                "Model has not been fitted. Call fit() before prediction."
            )
