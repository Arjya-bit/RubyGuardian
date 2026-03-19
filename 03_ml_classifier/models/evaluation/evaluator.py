"""
Comprehensive model evaluation for RubyGuardian malware classifiers.

Computes classification metrics, generates confusion matrices,
ROC curves, precision-recall curves, and comparative analysis
reports across multiple models and thresholds.
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
from sklearn.metrics import (
    accuracy_score,
    auc,
    classification_report,
    confusion_matrix,
    f1_score,
    log_loss,
    matthews_corrcoef,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)


class ModelEvaluator:
    """Comprehensive evaluator for malware classification models.

    Supports single-model evaluation, model comparison, threshold
    analysis, and detailed reporting with persistence to JSON and CSV.
    """

    LABEL_MAP = {
        0: "benign",
        1: "malicious",
    }

    def __init__(
        self,
        config_path: Optional[str | Path] = None,
        output_dir: Optional[str | Path] = None,
    ) -> None:
        """Initialize the model evaluator.

        Args:
            config_path: Path to training_config.yml for output settings.
            output_dir: Override directory for evaluation reports.
        """
        self.config = self._load_config(config_path)
        self.output_dir = Path(
            output_dir
            or self.config.get("output", {}).get(
                "report_dir", "models/evaluation/reports"
            )
        )
        self.evaluation_history: list[dict[str, Any]] = []

        logger.info("ModelEvaluator initialized (output_dir={})", self.output_dir)

    @staticmethod
    def _load_config(config_path: Optional[str | Path]) -> dict[str, Any]:
        """Load evaluation configuration from YAML.

        Args:
            config_path: Path to the config file.

        Returns:
            Configuration dictionary.
        """
        if config_path is None:
            return {}

        path = Path(config_path)
        if not path.exists():
            logger.warning("Config not found: {}, using defaults", path)
            return {}

        with open(path) as f:
            return yaml.safe_load(f) or {}

    def evaluate_model(
        self,
        model: Any,
        X_test: np.ndarray,
        y_test: np.ndarray,
        model_name: str = "model",
        threshold: Optional[float] = None,
    ) -> dict[str, Any]:
        """Run a full evaluation on a single model.

        Computes accuracy, precision, recall, F1, MCC, ROC-AUC,
        log loss, confusion matrix, and per-class metrics.

        Args:
            model: Trained classifier with predict and predict_proba methods.
            X_test: Test feature matrix.
            y_test: True labels.
            model_name: Identifier for the model.
            threshold: Optional custom decision threshold for binary classification.

        Returns:
            Dictionary with all computed metrics.
        """
        start_time = time.time()
        logger.info("Evaluating model: {} on {} samples", model_name, X_test.shape[0])

        # Get predictions
        y_proba = None
        if hasattr(model, "predict_proba"):
            y_proba = model.predict_proba(X_test)

        if threshold is not None and y_proba is not None and y_proba.shape[1] == 2:
            y_pred = (y_proba[:, 1] >= threshold).astype(int)
        else:
            y_pred = model.predict(X_test)

        # Core metrics
        metrics: dict[str, Any] = {
            "model_name": model_name,
            "n_samples": int(X_test.shape[0]),
            "n_features": int(X_test.shape[1]),
            "accuracy": float(accuracy_score(y_test, y_pred)),
            "precision_weighted": float(
                precision_score(y_test, y_pred, average="weighted", zero_division=0)
            ),
            "recall_weighted": float(
                recall_score(y_test, y_pred, average="weighted", zero_division=0)
            ),
            "f1_weighted": float(
                f1_score(y_test, y_pred, average="weighted", zero_division=0)
            ),
            "f1_macro": float(
                f1_score(y_test, y_pred, average="macro", zero_division=0)
            ),
            "f1_micro": float(
                f1_score(y_test, y_pred, average="micro", zero_division=0)
            ),
            "mcc": float(matthews_corrcoef(y_test, y_pred)),
        }

        # Probabilistic metrics
        if y_proba is not None:
            try:
                metrics["log_loss"] = float(log_loss(y_test, y_proba))
            except ValueError:
                metrics["log_loss"] = None

            try:
                if y_proba.shape[1] == 2:
                    metrics["roc_auc"] = float(
                        roc_auc_score(y_test, y_proba[:, 1])
                    )
                else:
                    metrics["roc_auc"] = float(
                        roc_auc_score(
                            y_test, y_proba, multi_class="ovr", average="weighted"
                        )
                    )
            except ValueError:
                metrics["roc_auc"] = None

        # Confusion matrix
        cm = confusion_matrix(y_test, y_pred)
        metrics["confusion_matrix"] = cm.tolist()

        # Per-class classification report
        class_report = classification_report(
            y_test, y_pred, output_dict=True, zero_division=0
        )
        metrics["classification_report"] = class_report

        # Binary-specific metrics
        unique_classes = np.unique(y_test)
        if len(unique_classes) == 2:
            tn, fp, fn, tp = cm.ravel()
            metrics["true_positives"] = int(tp)
            metrics["true_negatives"] = int(tn)
            metrics["false_positives"] = int(fp)
            metrics["false_negatives"] = int(fn)
            metrics["specificity"] = float(tn / (tn + fp)) if (tn + fp) > 0 else 0.0
            metrics["false_positive_rate"] = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
            metrics["false_negative_rate"] = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0

        # ROC curve data (for plotting)
        if y_proba is not None and len(unique_classes) == 2:
            fpr, tpr, roc_thresholds = roc_curve(y_test, y_proba[:, 1])
            metrics["roc_curve"] = {
                "fpr": fpr.tolist(),
                "tpr": tpr.tolist(),
                "thresholds": roc_thresholds.tolist(),
                "auc": float(auc(fpr, tpr)),
            }

            # Precision-recall curve data
            pr_precision, pr_recall, pr_thresholds = precision_recall_curve(
                y_test, y_proba[:, 1]
            )
            metrics["pr_curve"] = {
                "precision": pr_precision.tolist(),
                "recall": pr_recall.tolist(),
                "thresholds": pr_thresholds.tolist(),
                "auc": float(auc(pr_recall, pr_precision)),
            }

        elapsed = time.time() - start_time
        metrics["evaluation_time_seconds"] = elapsed
        metrics["timestamp"] = datetime.utcnow().isoformat()

        if threshold is not None:
            metrics["decision_threshold"] = threshold

        self.evaluation_history.append(metrics)

        logger.info(
            "Model '{}' - Accuracy: {:.4f}, F1: {:.4f}, MCC: {:.4f}",
            model_name,
            metrics["accuracy"],
            metrics["f1_weighted"],
            metrics["mcc"],
        )

        return metrics

    def compare_models(
        self,
        models: dict[str, Any],
        X_test: np.ndarray,
        y_test: np.ndarray,
    ) -> dict[str, Any]:
        """Evaluate and compare multiple models.

        Args:
            models: Dictionary mapping model names to model instances.
            X_test: Test feature matrix.
            y_test: True labels.

        Returns:
            Dictionary with per-model metrics and a comparison summary.
        """
        logger.info("Comparing {} models", len(models))

        results: dict[str, Any] = {}
        for name, model in models.items():
            results[name] = self.evaluate_model(model, X_test, y_test, model_name=name)

        # Build comparison summary
        comparison_keys = [
            "accuracy", "f1_weighted", "f1_macro", "precision_weighted",
            "recall_weighted", "mcc", "roc_auc",
        ]

        summary: dict[str, dict[str, float | None]] = {}
        for name, metrics in results.items():
            summary[name] = {
                key: metrics.get(key) for key in comparison_keys
            }

        # Determine best model per metric
        best_per_metric: dict[str, str] = {}
        for key in comparison_keys:
            best_name = None
            best_val = -float("inf")
            for name, vals in summary.items():
                val = vals.get(key)
                if val is not None and val > best_val:
                    best_val = val
                    best_name = name
            if best_name:
                best_per_metric[key] = best_name

        return {
            "per_model": results,
            "summary": summary,
            "best_per_metric": best_per_metric,
            "n_models": len(models),
            "n_samples": int(X_test.shape[0]),
        }

    def threshold_analysis(
        self,
        model: Any,
        X_test: np.ndarray,
        y_test: np.ndarray,
        thresholds: Optional[list[float]] = None,
        model_name: str = "model",
    ) -> list[dict[str, Any]]:
        """Evaluate a binary classifier across multiple decision thresholds.

        Useful for finding the optimal operating point based on
        precision/recall trade-offs for the security domain.

        Args:
            model: Trained classifier with predict_proba.
            X_test: Test feature matrix.
            y_test: True labels.
            thresholds: List of thresholds to evaluate (default: 0.1 to 0.9).
            model_name: Identifier for the model.

        Returns:
            List of metric dictionaries, one per threshold.
        """
        if thresholds is None:
            thresholds = [round(t * 0.05, 2) for t in range(1, 20)]

        y_proba = model.predict_proba(X_test)
        if y_proba.shape[1] != 2:
            raise ValueError("Threshold analysis requires binary classification")

        results: list[dict[str, Any]] = []

        for thresh in thresholds:
            y_pred = (y_proba[:, 1] >= thresh).astype(int)

            cm = confusion_matrix(y_test, y_pred)
            tn, fp, fn, tp = cm.ravel()

            result = {
                "model_name": model_name,
                "threshold": thresh,
                "accuracy": float(accuracy_score(y_test, y_pred)),
                "precision": float(
                    precision_score(y_test, y_pred, zero_division=0)
                ),
                "recall": float(recall_score(y_test, y_pred, zero_division=0)),
                "f1": float(f1_score(y_test, y_pred, zero_division=0)),
                "specificity": float(tn / (tn + fp)) if (tn + fp) > 0 else 0.0,
                "false_positive_rate": float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0,
                "true_positives": int(tp),
                "true_negatives": int(tn),
                "false_positives": int(fp),
                "false_negatives": int(fn),
            }
            results.append(result)

        logger.info(
            "Threshold analysis for '{}': {} thresholds evaluated",
            model_name,
            len(results),
        )
        return results

    def find_optimal_threshold(
        self,
        model: Any,
        X_test: np.ndarray,
        y_test: np.ndarray,
        optimize_for: str = "f1",
        model_name: str = "model",
    ) -> dict[str, Any]:
        """Find the optimal decision threshold for a specific metric.

        Args:
            model: Trained binary classifier.
            X_test: Test feature matrix.
            y_test: True labels.
            optimize_for: Metric to optimize ('f1', 'precision', 'recall').
            model_name: Identifier for the model.

        Returns:
            Dictionary with optimal threshold and corresponding metrics.
        """
        results = self.threshold_analysis(model, X_test, y_test, model_name=model_name)

        best_result = max(results, key=lambda r: r.get(optimize_for, 0.0))

        logger.info(
            "Optimal threshold for '{}' ({}): {:.2f} -> {:.4f}",
            model_name,
            optimize_for,
            best_result["threshold"],
            best_result[optimize_for],
        )
        return best_result

    def save_report(
        self,
        metrics: dict[str, Any],
        filename: Optional[str] = None,
    ) -> Path:
        """Save an evaluation report to disk as JSON.

        Args:
            metrics: Evaluation metrics dictionary.
            filename: Optional filename override.

        Returns:
            Path to the saved report.
        """
        self.output_dir.mkdir(parents=True, exist_ok=True)

        if filename is None:
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            model_name = metrics.get("model_name", "evaluation")
            filename = f"{model_name}_report_{timestamp}.json"

        report_path = self.output_dir / filename

        # Make a serializable copy
        serializable = self._make_serializable(metrics)

        with open(report_path, "w") as f:
            json.dump(serializable, f, indent=2, default=str)

        logger.info("Evaluation report saved to {}", report_path)
        return report_path

    def save_comparison_report(
        self,
        comparison: dict[str, Any],
        filename: Optional[str] = None,
    ) -> Path:
        """Save a model comparison report to disk.

        Saves both a JSON report and a CSV summary table.

        Args:
            comparison: Output from compare_models().
            filename: Optional filename prefix.

        Returns:
            Path to the saved JSON report.
        """
        self.output_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        prefix = filename or f"comparison_{timestamp}"

        # Save JSON report
        json_path = self.output_dir / f"{prefix}.json"
        serializable = self._make_serializable(comparison)
        with open(json_path, "w") as f:
            json.dump(serializable, f, indent=2, default=str)

        # Save CSV summary
        if "summary" in comparison:
            csv_path = self.output_dir / f"{prefix}_summary.csv"
            df = pd.DataFrame(comparison["summary"]).T
            df.index.name = "model"
            df.to_csv(csv_path)
            logger.info("Comparison CSV saved to {}", csv_path)

        logger.info("Comparison report saved to {}", json_path)
        return json_path

    def get_evaluation_history(self) -> list[dict[str, Any]]:
        """Return the history of all evaluations performed.

        Returns:
            List of evaluation metrics dictionaries.
        """
        return list(self.evaluation_history)

    def clear_history(self) -> None:
        """Clear the evaluation history."""
        self.evaluation_history.clear()
        logger.debug("Evaluation history cleared")

    @staticmethod
    def _make_serializable(obj: Any) -> Any:
        """Recursively convert numpy types to Python-native types.

        Args:
            obj: Object to make JSON-serializable.

        Returns:
            JSON-serializable object.
        """
        if isinstance(obj, dict):
            return {k: ModelEvaluator._make_serializable(v) for k, v in obj.items()}
        elif isinstance(obj, (list, tuple)):
            return [ModelEvaluator._make_serializable(item) for item in obj]
        elif isinstance(obj, np.integer):
            return int(obj)
        elif isinstance(obj, np.floating):
            return float(obj)
        elif isinstance(obj, np.ndarray):
            return obj.tolist()
        return obj


def main() -> None:
    """CLI entry point for model evaluation."""
    import click

    @click.command()
    @click.option("--model-path", required=True, help="Path to saved model file")
    @click.option("--features", required=True, help="Path to test features file")
    @click.option("--labels", required=True, help="Path to test labels file")
    @click.option("--config", default="config/training_config.yml", help="Config path")
    @click.option("--output", default=None, help="Output directory for reports")
    @click.option("--threshold", default=None, type=float, help="Decision threshold")
    def evaluate(
        model_path: str,
        features: str,
        labels: str,
        config: str,
        output: Optional[str],
        threshold: Optional[float],
    ) -> None:
        """Evaluate a trained malware classifier."""
        import pickle

        # Load model
        with open(model_path, "rb") as f:
            model = pickle.load(f)

        # Load test data
        features_path = Path(features)
        if features_path.suffix == ".npy":
            X_test = np.load(features_path)
        else:
            X_test = pd.read_csv(features_path).values

        labels_path = Path(labels)
        if labels_path.suffix == ".npy":
            y_test = np.load(labels_path)
        else:
            y_df = pd.read_csv(labels_path)
            y_test = y_df.iloc[:, 0].values

        # Run evaluation
        evaluator = ModelEvaluator(config_path=config, output_dir=output)
        model_name = Path(model_path).stem

        metrics = evaluator.evaluate_model(
            model, X_test, y_test,
            model_name=model_name,
            threshold=threshold,
        )

        report_path = evaluator.save_report(metrics)
        logger.info("Evaluation complete. Report: {}", report_path)

    evaluate()
