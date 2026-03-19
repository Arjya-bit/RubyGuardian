"""
XGBoost gradient boosted trees classifier for Ruby malware detection.

Implements an XGBoost model with early stopping, feature importance
analysis, and configurable hyperparameters for multi-class threat
categorization of Ruby scripts.
"""

import pickle
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import numpy as np
import yaml
from loguru import logger

try:
    import xgboost as xgb
except ImportError:
    xgb = None
    logger.warning("xgboost not installed; XGBoostMalwareClassifier unavailable")

from sklearn.metrics import (
    accuracy_score,
    classification_report,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.preprocessing import LabelEncoder


@dataclass
class XGBPredictionResult:
    """Container for an XGBoost prediction result."""

    label: str
    confidence: float
    probabilities: dict[str, float] = field(default_factory=dict)
    feature_importances: Optional[dict[str, float]] = None


class XGBoostMalwareClassifier:
    """XGBoost gradient boosted trees classifier for malware detection.

    Wraps the XGBoost library with project-specific configuration,
    early stopping, multiple importance types (gain, weight, cover),
    and model serialization for Ruby malware classification.
    """

    DEFAULT_PARAMS = {
        "n_estimators": 300,
        "max_depth": 8,
        "learning_rate": 0.05,
        "subsample": 0.8,
        "colsample_bytree": 0.8,
        "min_child_weight": 3,
        "gamma": 0.1,
        "reg_alpha": 0.1,
        "reg_lambda": 1.0,
        "scale_pos_weight": 1.0,
        "objective": "multi:softprob",
        "eval_metric": "mlogloss",
        "tree_method": "hist",
        "random_state": 42,
        "early_stopping_rounds": 20,
    }

    LABEL_MAP = {
        0: "benign",
        1: "malicious",
    }

    def __init__(
        self,
        config_path: Optional[str | Path] = None,
        params: Optional[dict[str, Any]] = None,
        feature_names: Optional[list[str]] = None,
    ) -> None:
        """Initialize the XGBoost malware classifier.

        Args:
            config_path: Path to model_config.yml for loading parameters.
            params: Optional override parameters.
            feature_names: Optional feature name list for importance tracking.

        Raises:
            ImportError: If xgboost is not installed.
        """
        if xgb is None:
            raise ImportError(
                "xgboost is required. Install with: pip install xgboost>=2.0.0"
            )

        self.params = dict(self.DEFAULT_PARAMS)

        if config_path:
            self._load_config(config_path)

        if params:
            self.params.update(params)

        self.feature_names = feature_names or []
        self.model: Optional[xgb.XGBClassifier] = None
        self.label_encoder = LabelEncoder()
        self.is_fitted = False
        self.classes_: Optional[np.ndarray] = None
        self.best_iteration_: Optional[int] = None
        self.evals_result_: Optional[dict] = None

        logger.info(
            "XGBoostMalwareClassifier initialized with lr={}, n_estimators={}",
            self.params["learning_rate"],
            self.params["n_estimators"],
        )

    def _load_config(self, config_path: str | Path) -> None:
        """Load parameters from YAML configuration.

        Args:
            config_path: Path to the model configuration file.
        """
        path = Path(config_path)
        if not path.exists():
            logger.warning("Config not found: {}, using defaults", path)
            return

        with open(path) as f:
            config = yaml.safe_load(f)

        gb_config = config.get("gradient_boost", {})
        for key, value in gb_config.items():
            if key in self.DEFAULT_PARAMS:
                self.params[key] = value

        logger.debug("Loaded XGBoost config from {}", path)

    def _build_xgb_params(self) -> dict[str, Any]:
        """Build parameter dict compatible with XGBClassifier constructor.

        Returns:
            Filtered parameter dictionary.
        """
        xgb_params = dict(self.params)
        early_stopping = xgb_params.pop("early_stopping_rounds", None)
        return xgb_params, early_stopping

    def fit(
        self,
        X: np.ndarray,
        y: np.ndarray,
        X_val: Optional[np.ndarray] = None,
        y_val: Optional[np.ndarray] = None,
        feature_names: Optional[list[str]] = None,
    ) -> "XGBoostMalwareClassifier":
        """Train the XGBoost model with optional early stopping.

        Args:
            X: Training feature matrix of shape (n_samples, n_features).
            y: Training labels of shape (n_samples,).
            X_val: Optional validation feature matrix for early stopping.
            y_val: Optional validation labels for early stopping.
            feature_names: Optional feature names for the columns.

        Returns:
            Self for method chaining.
        """
        if feature_names:
            self.feature_names = feature_names

        logger.info(
            "Training XGBoost on {} samples with {} features",
            X.shape[0],
            X.shape[1],
        )

        xgb_params, early_stopping = self._build_xgb_params()

        self.model = xgb.XGBClassifier(**xgb_params)

        fit_kwargs: dict[str, Any] = {}

        if X_val is not None and y_val is not None:
            fit_kwargs["eval_set"] = [(X, y), (X_val, y_val)]
            if early_stopping:
                self.model.set_params(early_stopping_rounds=early_stopping)
            fit_kwargs["verbose"] = False
        else:
            fit_kwargs["eval_set"] = [(X, y)]
            fit_kwargs["verbose"] = False

        self.model.fit(X, y, **fit_kwargs)

        self.is_fitted = True
        self.classes_ = self.model.classes_
        self.best_iteration_ = getattr(self.model, "best_iteration", None)
        self.evals_result_ = getattr(self.model, "evals_result_", None)

        if self.best_iteration_ is not None:
            logger.info("Best iteration: {}", self.best_iteration_)

        logger.info("XGBoost training complete")
        return self

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Predict class labels.

        Args:
            X: Feature matrix of shape (n_samples, n_features).

        Returns:
            Predicted labels of shape (n_samples,).
        """
        self._check_is_fitted()
        return self.model.predict(X)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Predict class probabilities.

        Args:
            X: Feature matrix of shape (n_samples, n_features).

        Returns:
            Probability matrix of shape (n_samples, n_classes).
        """
        self._check_is_fitted()
        return self.model.predict_proba(X)

    def predict_single(
        self,
        features: np.ndarray,
        include_importances: bool = False,
    ) -> XGBPredictionResult:
        """Predict a single sample with detailed output.

        Args:
            features: Feature vector of shape (n_features,).
            include_importances: Whether to include feature importances.

        Returns:
            XGBPredictionResult with label, confidence, and probabilities.
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

        return XGBPredictionResult(
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
        """Evaluate model performance on test data.

        Args:
            X: Test features of shape (n_samples, n_features).
            y: True labels of shape (n_samples,).

        Returns:
            Dictionary of evaluation metrics.
        """
        self._check_is_fitted()

        y_pred = self.predict(X)

        metrics = {
            "accuracy": float(accuracy_score(y, y_pred)),
            "precision_weighted": float(precision_score(y, y_pred, average="weighted", zero_division=0)),
            "recall_weighted": float(recall_score(y, y_pred, average="weighted", zero_division=0)),
            "f1_weighted": float(f1_score(y, y_pred, average="weighted", zero_division=0)),
            "f1_macro": float(f1_score(y, y_pred, average="macro", zero_division=0)),
            "classification_report": classification_report(y, y_pred, output_dict=True, zero_division=0),
            "best_iteration": self.best_iteration_,
        }

        logger.info(
            "XGBoost Evaluation - Accuracy: {:.4f}, F1-weighted: {:.4f}",
            metrics["accuracy"],
            metrics["f1_weighted"],
        )
        return metrics

    def get_feature_importances(
        self,
        importance_type: str = "gain",
    ) -> dict[str, float]:
        """Get feature importances by the specified type.

        Args:
            importance_type: One of 'gain', 'weight', 'cover', 'total_gain',
                or 'total_cover'.

        Returns:
            Dictionary mapping feature names to importance values,
            sorted in descending order.
        """
        self._check_is_fitted()

        booster = self.model.get_booster()
        raw_importances = booster.get_score(importance_type=importance_type)

        names = self.feature_names or [
            f"feature_{i}" for i in range(self.model.n_features_in_)
        ]

        importances = {}
        for i, name in enumerate(names):
            key = f"f{i}"
            importances[name] = raw_importances.get(key, 0.0)

        total = sum(importances.values()) or 1.0
        importances = {k: v / total for k, v in importances.items()}

        return dict(sorted(importances.items(), key=lambda x: x[1], reverse=True))

    def get_top_feature_importances(
        self,
        n_top: int = 20,
        importance_type: str = "gain",
    ) -> dict[str, float]:
        """Get the top N most important features.

        Args:
            n_top: Number of top features to return.
            importance_type: Type of importance metric.

        Returns:
            Ordered dictionary of top features and their importances.
        """
        all_importances = self.get_feature_importances(importance_type)
        return dict(list(all_importances.items())[:n_top])

    def get_learning_curves(self) -> Optional[dict[str, list[float]]]:
        """Get training and validation learning curves.

        Returns:
            Dictionary with eval set names as keys and metric lists as values,
            or None if no eval results are available.
        """
        if self.evals_result_ is None:
            return None
        return dict(self.evals_result_)

    def save(self, path: str | Path) -> None:
        """Save the model to disk.

        Args:
            path: Destination file path.
        """
        self._check_is_fitted()

        save_path = Path(path)
        save_path.parent.mkdir(parents=True, exist_ok=True)

        model_data = {
            "model": self.model,
            "params": self.params,
            "feature_names": self.feature_names,
            "classes": self.classes_,
            "best_iteration": self.best_iteration_,
        }

        with open(save_path, "wb") as f:
            pickle.dump(model_data, f, protocol=pickle.HIGHEST_PROTOCOL)

        logger.info("XGBoost model saved to {}", save_path)

    @classmethod
    def load(cls, path: str | Path) -> "XGBoostMalwareClassifier":
        """Load a serialized model from disk.

        Args:
            path: Path to the saved model file.

        Returns:
            Loaded XGBoostMalwareClassifier instance.

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
        instance.best_iteration_ = model_data["best_iteration"]
        instance.is_fitted = True

        logger.info("XGBoost model loaded from {}", load_path)
        return instance

    def get_params(self) -> dict[str, Any]:
        """Return current model parameters."""
        return dict(self.params)

    def set_params(self, **params: Any) -> "XGBoostMalwareClassifier":
        """Update model parameters and invalidate the fitted model.

        Args:
            **params: Parameters to update.

        Returns:
            Self for method chaining.
        """
        self.params.update(params)
        self.is_fitted = False
        self.model = None
        logger.debug("XGBoost parameters updated, model needs retraining")
        return self

    def _check_is_fitted(self) -> None:
        """Verify the model is trained.

        Raises:
            RuntimeError: If the model has not been fitted.
        """
        if not self.is_fitted or self.model is None:
            raise RuntimeError(
                "Model has not been fitted. Call fit() before prediction."
            )
