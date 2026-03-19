"""
Weighted voting ensemble classifier for Ruby malware detection.

Combines predictions from Random Forest, XGBoost, and Neural Network
classifiers using configurable soft or hard voting with per-model
weights and confidence thresholds.
"""

import pickle
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional, Protocol

import numpy as np
import yaml
from loguru import logger
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    f1_score,
    precision_score,
    recall_score,
)


class ClassifierProtocol(Protocol):
    """Protocol for classifiers compatible with the ensemble."""

    def predict(self, X: np.ndarray) -> np.ndarray: ...
    def predict_proba(self, X: np.ndarray) -> np.ndarray: ...
    def evaluate(self, X: np.ndarray, y: np.ndarray) -> dict[str, Any]: ...


@dataclass
class EnsemblePredictionResult:
    """Container for an ensemble prediction result."""

    label: str
    confidence: float
    probabilities: dict[str, float] = field(default_factory=dict)
    per_model_predictions: dict[str, dict[str, Any]] = field(default_factory=dict)
    agreement_score: float = 0.0
    fallback_used: bool = False


class EnsembleMalwareClassifier:
    """Weighted voting ensemble of multiple malware classifiers.

    Supports soft voting (probability averaging) and hard voting
    (majority vote) with configurable per-model weights. Includes
    a confidence threshold below which a fallback (most conservative)
    strategy is applied.
    """

    DEFAULT_WEIGHTS = {
        "random_forest": 0.3,
        "gradient_boost": 0.4,
        "neural_network": 0.3,
    }

    LABEL_MAP = {
        0: "benign",
        1: "malicious",
    }

    def __init__(
        self,
        config_path: Optional[str | Path] = None,
        voting: str = "soft",
        weights: Optional[dict[str, float]] = None,
        confidence_threshold: float = 0.7,
        fallback_strategy: str = "most_conservative",
    ) -> None:
        """Initialize the ensemble classifier.

        Args:
            config_path: Path to model_config.yml.
            voting: Voting strategy ('soft' or 'hard').
            weights: Per-model weight dictionary.
            confidence_threshold: Minimum confidence for direct prediction.
            fallback_strategy: Strategy when confidence is below threshold.
        """
        self.voting = voting
        self.weights = weights or dict(self.DEFAULT_WEIGHTS)
        self.confidence_threshold = confidence_threshold
        self.fallback_strategy = fallback_strategy

        if config_path:
            self._load_config(config_path)

        self.models: dict[str, Any] = {}
        self.is_fitted = False
        self.classes_: Optional[np.ndarray] = None
        self.model_metrics: dict[str, dict[str, float]] = {}

        logger.info(
            "EnsembleMalwareClassifier initialized: voting={}, threshold={}",
            self.voting,
            self.confidence_threshold,
        )

    def _load_config(self, config_path: str | Path) -> None:
        """Load ensemble configuration from YAML.

        Args:
            config_path: Path to the model config file.
        """
        path = Path(config_path)
        if not path.exists():
            logger.warning("Config not found: {}, using defaults", path)
            return

        with open(path) as f:
            config = yaml.safe_load(f)

        ens_config = config.get("ensemble", {})
        self.voting = ens_config.get("voting", self.voting)
        self.confidence_threshold = ens_config.get(
            "confidence_threshold", self.confidence_threshold
        )
        self.fallback_strategy = ens_config.get(
            "fallback_strategy", self.fallback_strategy
        )

        raw_weights = ens_config.get("weights", {})
        if raw_weights:
            self.weights = dict(raw_weights)

        logger.debug("Loaded ensemble config from {}", path)

    def add_model(self, name: str, model: Any, weight: Optional[float] = None) -> None:
        """Add a classifier to the ensemble.

        Args:
            name: Identifier for the model.
            model: Classifier instance implementing predict and predict_proba.
            weight: Optional weight override for this model.
        """
        self.models[name] = model
        if weight is not None:
            self.weights[name] = weight

        if name not in self.weights:
            self.weights[name] = 1.0 / max(len(self.models), 1)

        logger.info("Added model '{}' to ensemble (weight={})", name, self.weights.get(name))

    def remove_model(self, name: str) -> None:
        """Remove a classifier from the ensemble.

        Args:
            name: Identifier of the model to remove.
        """
        if name in self.models:
            del self.models[name]
            self.weights.pop(name, None)
            logger.info("Removed model '{}' from ensemble", name)

    def fit(
        self,
        X: np.ndarray,
        y: np.ndarray,
        X_val: Optional[np.ndarray] = None,
        y_val: Optional[np.ndarray] = None,
    ) -> "EnsembleMalwareClassifier":
        """Train all constituent models.

        Args:
            X: Training features.
            y: Training labels.
            X_val: Optional validation features.
            y_val: Optional validation labels.

        Returns:
            Self for method chaining.

        Raises:
            ValueError: If no models have been added to the ensemble.
        """
        if not self.models:
            raise ValueError("No models added to ensemble. Use add_model() first.")

        self.classes_ = np.unique(y)

        logger.info(
            "Training ensemble with {} models on {} samples",
            len(self.models),
            X.shape[0],
        )

        for name, model in self.models.items():
            logger.info("Training model: {}", name)
            try:
                if hasattr(model, "fit"):
                    fit_kwargs: dict[str, Any] = {"X": X, "y": y}
                    # Pass validation data if the model supports it
                    if X_val is not None and y_val is not None:
                        import inspect
                        sig = inspect.signature(model.fit)
                        if "X_val" in sig.parameters:
                            fit_kwargs["X_val"] = X_val
                            fit_kwargs["y_val"] = y_val
                    model.fit(**fit_kwargs)
            except Exception as e:
                logger.error("Failed to train model '{}': {}", name, e)
                raise

        self.is_fitted = True
        logger.info("Ensemble training complete")
        return self

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Predict class labels using the ensemble.

        Args:
            X: Feature matrix of shape (n_samples, n_features).

        Returns:
            Predicted labels of shape (n_samples,).
        """
        self._check_is_fitted()

        if self.voting == "soft":
            proba = self.predict_proba(X)
            return self.classes_[np.argmax(proba, axis=1)]
        else:
            return self._hard_vote_predict(X)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Predict class probabilities using weighted averaging.

        Args:
            X: Feature matrix of shape (n_samples, n_features).

        Returns:
            Weighted average probability matrix.
        """
        self._check_is_fitted()

        total_weight = sum(self.weights.get(name, 1.0) for name in self.models)
        weighted_proba = None

        for name, model in self.models.items():
            weight = self.weights.get(name, 1.0) / total_weight
            proba = model.predict_proba(X)

            if weighted_proba is None:
                weighted_proba = weight * proba
            else:
                weighted_proba += weight * proba

        return weighted_proba

    def _hard_vote_predict(self, X: np.ndarray) -> np.ndarray:
        """Predict using weighted hard voting.

        Each model casts a vote for its predicted class, weighted
        by the model's configured weight. Ties broken by highest weight.

        Args:
            X: Feature matrix.

        Returns:
            Predicted labels.
        """
        n_samples = X.shape[0]
        n_classes = len(self.classes_)
        vote_matrix = np.zeros((n_samples, n_classes))

        for name, model in self.models.items():
            weight = self.weights.get(name, 1.0)
            predictions = model.predict(X)
            for i, pred in enumerate(predictions):
                class_idx = np.where(self.classes_ == pred)[0]
                if len(class_idx) > 0:
                    vote_matrix[i, class_idx[0]] += weight

        return self.classes_[np.argmax(vote_matrix, axis=1)]

    def predict_single(
        self,
        features: np.ndarray,
    ) -> EnsemblePredictionResult:
        """Predict a single sample with detailed ensemble output.

        Args:
            features: Feature vector of shape (n_features,).

        Returns:
            EnsemblePredictionResult with per-model details.
        """
        self._check_is_fitted()

        X = features.reshape(1, -1)
        per_model: dict[str, dict[str, Any]] = {}
        predictions_list: list[int] = []

        for name, model in self.models.items():
            proba = model.predict_proba(X)[0]
            pred_class = self.classes_[np.argmax(proba)]
            per_model[name] = {
                "prediction": int(pred_class),
                "confidence": float(np.max(proba)),
                "probabilities": {
                    str(cls): float(p) for cls, p in zip(self.classes_, proba)
                },
            }
            predictions_list.append(int(pred_class))

        # Ensemble probability
        ensemble_proba = self.predict_proba(X)[0]
        predicted_class = self.classes_[np.argmax(ensemble_proba)]
        confidence = float(np.max(ensemble_proba))

        probabilities = {
            str(cls): float(p)
            for cls, p in zip(self.classes_, ensemble_proba)
        }

        # Agreement score: fraction of models agreeing with ensemble prediction
        n_agree = sum(1 for p in predictions_list if p == predicted_class)
        agreement = n_agree / len(predictions_list) if predictions_list else 0.0

        # Fallback if confidence is below threshold
        fallback_used = False
        if confidence < self.confidence_threshold:
            if self.fallback_strategy == "most_conservative":
                # Default to "malicious" for safety
                predicted_class = self._get_conservative_class()
                fallback_used = True
                logger.warning(
                    "Low confidence ({:.3f}), using fallback strategy",
                    confidence,
                )

        label = self.LABEL_MAP.get(int(predicted_class), str(predicted_class))

        return EnsemblePredictionResult(
            label=label,
            confidence=confidence,
            probabilities=probabilities,
            per_model_predictions=per_model,
            agreement_score=agreement,
            fallback_used=fallback_used,
        )

    def _get_conservative_class(self) -> int:
        """Return the most conservative (malicious) class label.

        Returns:
            Class label corresponding to 'malicious'.
        """
        if self.classes_ is not None and len(self.classes_) > 1:
            return int(self.classes_[1])  # malicious = 1
        return 1

    def evaluate(self, X: np.ndarray, y: np.ndarray) -> dict[str, Any]:
        """Evaluate ensemble and individual model performance.

        Args:
            X: Test features.
            y: True labels.

        Returns:
            Dictionary with ensemble metrics and per-model metrics.
        """
        self._check_is_fitted()

        y_pred = self.predict(X)

        ensemble_metrics = {
            "accuracy": float(accuracy_score(y, y_pred)),
            "precision_weighted": float(precision_score(y, y_pred, average="weighted", zero_division=0)),
            "recall_weighted": float(recall_score(y, y_pred, average="weighted", zero_division=0)),
            "f1_weighted": float(f1_score(y, y_pred, average="weighted", zero_division=0)),
            "f1_macro": float(f1_score(y, y_pred, average="macro", zero_division=0)),
            "classification_report": classification_report(y, y_pred, output_dict=True, zero_division=0),
        }

        # Evaluate individual models
        per_model_metrics = {}
        for name, model in self.models.items():
            try:
                per_model_metrics[name] = model.evaluate(X, y)
            except Exception as e:
                logger.warning("Failed to evaluate model '{}': {}", name, e)
                per_model_metrics[name] = {"error": str(e)}

        self.model_metrics = per_model_metrics

        results = {
            "ensemble": ensemble_metrics,
            "per_model": per_model_metrics,
            "voting": self.voting,
            "weights": dict(self.weights),
        }

        logger.info(
            "Ensemble Evaluation - Accuracy: {:.4f}, F1-weighted: {:.4f}",
            ensemble_metrics["accuracy"],
            ensemble_metrics["f1_weighted"],
        )
        return results

    def get_model_comparison(self) -> dict[str, dict[str, float]]:
        """Compare performance metrics across all models.

        Returns:
            Dictionary mapping model names to their key metrics.
        """
        comparison = {}
        for name, metrics in self.model_metrics.items():
            if "error" not in metrics:
                comparison[name] = {
                    "accuracy": metrics.get("accuracy", 0.0),
                    "f1_weighted": metrics.get("f1_weighted", 0.0),
                    "precision_weighted": metrics.get("precision_weighted", 0.0),
                    "recall_weighted": metrics.get("recall_weighted", 0.0),
                }
        return comparison

    def optimize_weights(
        self,
        X_val: np.ndarray,
        y_val: np.ndarray,
        n_trials: int = 100,
    ) -> dict[str, float]:
        """Optimize ensemble weights using random search on validation data.

        Args:
            X_val: Validation features.
            y_val: Validation labels.
            n_trials: Number of random weight combinations to try.

        Returns:
            Optimized weight dictionary.
        """
        self._check_is_fitted()

        model_names = list(self.models.keys())
        n_models = len(model_names)
        best_f1 = 0.0
        best_weights = dict(self.weights)

        # Cache individual model probabilities
        cached_probas = {}
        for name, model in self.models.items():
            cached_probas[name] = model.predict_proba(X_val)

        rng = np.random.RandomState(42)

        for trial in range(n_trials):
            # Generate random weights that sum to 1
            raw_weights = rng.dirichlet(np.ones(n_models))
            trial_weights = {
                name: float(w) for name, w in zip(model_names, raw_weights)
            }

            # Compute weighted ensemble prediction
            total_weight = sum(trial_weights.values())
            weighted_proba = None
            for name in model_names:
                w = trial_weights[name] / total_weight
                if weighted_proba is None:
                    weighted_proba = w * cached_probas[name]
                else:
                    weighted_proba += w * cached_probas[name]

            y_pred = self.classes_[np.argmax(weighted_proba, axis=1)]
            f1 = float(f1_score(y_val, y_pred, average="weighted", zero_division=0))

            if f1 > best_f1:
                best_f1 = f1
                best_weights = trial_weights

        self.weights = best_weights
        logger.info(
            "Optimized weights: {} (F1={:.4f})",
            {k: f"{v:.3f}" for k, v in best_weights.items()},
            best_f1,
        )
        return best_weights

    def save(self, path: str | Path) -> None:
        """Save the ensemble to disk.

        Args:
            path: Destination file path.
        """
        self._check_is_fitted()

        save_path = Path(path)
        save_path.parent.mkdir(parents=True, exist_ok=True)

        model_data = {
            "models": self.models,
            "weights": self.weights,
            "voting": self.voting,
            "confidence_threshold": self.confidence_threshold,
            "fallback_strategy": self.fallback_strategy,
            "classes": self.classes_,
            "model_metrics": self.model_metrics,
        }

        with open(save_path, "wb") as f:
            pickle.dump(model_data, f, protocol=pickle.HIGHEST_PROTOCOL)

        logger.info("Ensemble model saved to {}", save_path)

    @classmethod
    def load(cls, path: str | Path) -> "EnsembleMalwareClassifier":
        """Load an ensemble from disk.

        Args:
            path: Path to the saved ensemble file.

        Returns:
            Loaded EnsembleMalwareClassifier instance.
        """
        load_path = Path(path)
        if not load_path.exists():
            raise FileNotFoundError(f"Model file not found: {load_path}")

        with open(load_path, "rb") as f:
            model_data = pickle.load(f)

        instance = cls(
            voting=model_data["voting"],
            weights=model_data["weights"],
            confidence_threshold=model_data["confidence_threshold"],
            fallback_strategy=model_data["fallback_strategy"],
        )
        instance.models = model_data["models"]
        instance.classes_ = model_data["classes"]
        instance.model_metrics = model_data["model_metrics"]
        instance.is_fitted = True

        logger.info("Ensemble model loaded from {}", load_path)
        return instance

    def _check_is_fitted(self) -> None:
        """Verify the ensemble has been trained.

        Raises:
            RuntimeError: If the ensemble is not fitted.
        """
        if not self.is_fitted or not self.models:
            raise RuntimeError(
                "Ensemble has not been fitted. Call fit() or add trained models."
            )
