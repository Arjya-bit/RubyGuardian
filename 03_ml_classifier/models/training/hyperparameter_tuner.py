"""
Hyperparameter tuning for RubyGuardian malware classifiers.

Supports grid search, random search, and Optuna-based Bayesian
optimization for finding optimal model hyperparameters with
cross-validation scoring.
"""

import time
from itertools import product
from pathlib import Path
from typing import Any, Callable, Optional

import numpy as np
import yaml
from loguru import logger
from sklearn.model_selection import StratifiedKFold, cross_val_score

from models.random_forest_classifier import RandomForestMalwareClassifier
from models.xgboost_classifier import XGBoostMalwareClassifier
from models.neural_net_classifier import NeuralNetMalwareClassifier


class HyperparameterTuner:
    """Hyperparameter tuning engine for malware classifiers.

    Provides grid search, random search, and Optuna-based optimization
    with stratified cross-validation scoring and result tracking.
    """

    # Default search spaces for each model type
    RF_SEARCH_SPACE = {
        "n_estimators": [100, 300, 500, 800],
        "max_depth": [10, 20, 30, None],
        "min_samples_split": [2, 5, 10],
        "min_samples_leaf": [1, 2, 4],
        "max_features": ["sqrt", "log2"],
    }

    XGB_SEARCH_SPACE = {
        "n_estimators": [100, 200, 300, 500],
        "max_depth": [4, 6, 8, 10],
        "learning_rate": [0.01, 0.05, 0.1, 0.2],
        "subsample": [0.6, 0.8, 1.0],
        "colsample_bytree": [0.6, 0.8, 1.0],
        "min_child_weight": [1, 3, 5],
        "gamma": [0.0, 0.1, 0.3],
    }

    NN_SEARCH_SPACE = {
        "hidden_layers": [[128, 64], [256, 128, 64], [512, 256, 128, 64]],
        "dropout_rates": [[0.2, 0.2], [0.3, 0.3, 0.2], [0.4, 0.3, 0.2, 0.1]],
        "learning_rate": [0.0001, 0.0005, 0.001, 0.005],
        "batch_size": [32, 64, 128],
        "weight_decay": [0.00001, 0.0001, 0.001],
    }

    def __init__(
        self,
        config_path: Optional[str | Path] = None,
        n_splits: int = 5,
        scoring: str = "f1_weighted",
        random_state: int = 42,
    ) -> None:
        """Initialize the hyperparameter tuner.

        Args:
            config_path: Path to training_config.yml.
            n_splits: Number of cross-validation folds.
            scoring: Scoring metric for evaluation.
            random_state: Random seed for reproducibility.
        """
        self.n_splits = n_splits
        self.scoring = scoring
        self.random_state = random_state

        self.results_history: list[dict[str, Any]] = []
        self.best_params: Optional[dict[str, Any]] = None
        self.best_score: float = 0.0

        if config_path:
            self._load_config(config_path)

        logger.info(
            "HyperparameterTuner initialized: scoring={}, n_splits={}",
            self.scoring, self.n_splits,
        )

    def _load_config(self, config_path: str | Path) -> None:
        """Load tuning configuration from YAML.

        Args:
            config_path: Path to the training config file.
        """
        path = Path(config_path)
        if not path.exists():
            return

        with open(path) as f:
            config = yaml.safe_load(f)

        tuning_config = config.get("hyperparameter_tuning", {})
        self.scoring = tuning_config.get("metric", self.scoring)

        cv_config = config.get("cross_validation", {})
        self.n_splits = cv_config.get("n_splits", self.n_splits)
        self.random_state = cv_config.get("random_state", self.random_state)

    def grid_search(
        self,
        model_type: str,
        X: np.ndarray,
        y: np.ndarray,
        param_grid: Optional[dict[str, list]] = None,
    ) -> dict[str, Any]:
        """Perform exhaustive grid search over parameter combinations.

        Args:
            model_type: Model type ('random_forest', 'gradient_boost', 'neural_network').
            X: Feature matrix.
            y: Label array.
            param_grid: Custom parameter grid. Defaults to built-in spaces.

        Returns:
            Dictionary with best parameters, score, and all results.
        """
        if param_grid is None:
            param_grid = self._get_default_search_space(model_type)

        param_names = list(param_grid.keys())
        param_values = list(param_grid.values())
        all_combinations = list(product(*param_values))

        logger.info(
            "Grid search for {}: {} parameter combinations",
            model_type, len(all_combinations),
        )

        self.results_history = []
        self.best_score = 0.0
        self.best_params = None

        for i, values in enumerate(all_combinations):
            params = dict(zip(param_names, values))
            score = self._evaluate_params(model_type, X, y, params)

            result = {
                "params": params,
                "mean_score": score,
                "iteration": i + 1,
            }
            self.results_history.append(result)

            if score > self.best_score:
                self.best_score = score
                self.best_params = dict(params)

            if (i + 1) % 10 == 0:
                logger.info(
                    "Grid search progress: {}/{}, best_score={:.4f}",
                    i + 1, len(all_combinations), self.best_score,
                )

        logger.info(
            "Grid search complete. Best score: {:.4f}",
            self.best_score,
        )

        return {
            "best_params": self.best_params,
            "best_score": self.best_score,
            "all_results": self.results_history,
            "method": "grid_search",
            "model_type": model_type,
        }

    def random_search(
        self,
        model_type: str,
        X: np.ndarray,
        y: np.ndarray,
        param_distributions: Optional[dict[str, Any]] = None,
        n_trials: int = 50,
    ) -> dict[str, Any]:
        """Perform random search over parameter distributions.

        Args:
            model_type: Model type string.
            X: Feature matrix.
            y: Label array.
            param_distributions: Parameter distributions (lists to sample from).
            n_trials: Number of random trials.

        Returns:
            Dictionary with best parameters and search results.
        """
        if param_distributions is None:
            param_distributions = self._get_default_search_space(model_type)

        rng = np.random.RandomState(self.random_state)

        logger.info(
            "Random search for {}: {} trials",
            model_type, n_trials,
        )

        self.results_history = []
        self.best_score = 0.0
        self.best_params = None

        for trial in range(n_trials):
            # Sample random parameters
            params = {}
            for param_name, param_values in param_distributions.items():
                if isinstance(param_values, list):
                    idx = rng.randint(0, len(param_values))
                    params[param_name] = param_values[idx]
                elif isinstance(param_values, tuple) and len(param_values) == 2:
                    # Continuous range
                    low, high = param_values
                    if isinstance(low, int) and isinstance(high, int):
                        params[param_name] = int(rng.randint(low, high + 1))
                    else:
                        params[param_name] = float(rng.uniform(low, high))
                else:
                    params[param_name] = param_values

            score = self._evaluate_params(model_type, X, y, params)

            result = {
                "params": params,
                "mean_score": score,
                "trial": trial + 1,
            }
            self.results_history.append(result)

            if score > self.best_score:
                self.best_score = score
                self.best_params = dict(params)

            if (trial + 1) % 10 == 0:
                logger.info(
                    "Random search trial {}/{}, best_score={:.4f}",
                    trial + 1, n_trials, self.best_score,
                )

        logger.info(
            "Random search complete. Best score: {:.4f}",
            self.best_score,
        )

        return {
            "best_params": self.best_params,
            "best_score": self.best_score,
            "all_results": self.results_history,
            "method": "random_search",
            "model_type": model_type,
            "n_trials": n_trials,
        }

    def optuna_search(
        self,
        model_type: str,
        X: np.ndarray,
        y: np.ndarray,
        n_trials: int = 100,
        timeout: Optional[int] = None,
    ) -> dict[str, Any]:
        """Perform Bayesian optimization using Optuna.

        Args:
            model_type: Model type string.
            X: Feature matrix.
            y: Label array.
            n_trials: Maximum number of trials.
            timeout: Maximum time in seconds.

        Returns:
            Dictionary with best parameters and study results.

        Raises:
            ImportError: If optuna is not installed.
        """
        try:
            import optuna
        except ImportError:
            raise ImportError(
                "optuna is required for Bayesian optimization. "
                "Install with: pip install optuna"
            )

        logger.info(
            "Optuna search for {}: max {} trials",
            model_type, n_trials,
        )

        def objective(trial: optuna.Trial) -> float:
            params = self._sample_optuna_params(trial, model_type)
            return self._evaluate_params(model_type, X, y, params)

        sampler = optuna.samplers.TPESampler(seed=self.random_state)
        pruner = optuna.pruners.MedianPruner(
            n_startup_trials=10,
            n_warmup_steps=5,
        )

        study = optuna.create_study(
            direction="maximize",
            sampler=sampler,
            pruner=pruner,
        )

        study.optimize(
            objective,
            n_trials=n_trials,
            timeout=timeout,
            show_progress_bar=False,
        )

        self.best_params = dict(study.best_params)
        self.best_score = study.best_value

        self.results_history = [
            {
                "params": dict(trial.params),
                "mean_score": trial.value,
                "trial": trial.number,
                "state": str(trial.state),
            }
            for trial in study.trials
            if trial.value is not None
        ]

        logger.info(
            "Optuna search complete. Best score: {:.4f}",
            self.best_score,
        )

        return {
            "best_params": self.best_params,
            "best_score": self.best_score,
            "all_results": self.results_history,
            "method": "optuna",
            "model_type": model_type,
            "n_trials_completed": len(study.trials),
        }

    def _sample_optuna_params(
        self,
        trial: Any,
        model_type: str,
    ) -> dict[str, Any]:
        """Sample parameters using Optuna trial suggestions.

        Args:
            trial: Optuna trial object.
            model_type: Model type string.

        Returns:
            Dictionary of sampled hyperparameters.
        """
        if model_type == "random_forest":
            return {
                "n_estimators": trial.suggest_int("n_estimators", 100, 1000, step=100),
                "max_depth": trial.suggest_int("max_depth", 5, 50),
                "min_samples_split": trial.suggest_int("min_samples_split", 2, 20),
                "min_samples_leaf": trial.suggest_int("min_samples_leaf", 1, 10),
                "max_features": trial.suggest_categorical("max_features", ["sqrt", "log2"]),
            }
        elif model_type == "gradient_boost":
            return {
                "n_estimators": trial.suggest_int("n_estimators", 100, 800, step=50),
                "max_depth": trial.suggest_int("max_depth", 3, 12),
                "learning_rate": trial.suggest_float("learning_rate", 0.005, 0.3, log=True),
                "subsample": trial.suggest_float("subsample", 0.5, 1.0),
                "colsample_bytree": trial.suggest_float("colsample_bytree", 0.5, 1.0),
                "min_child_weight": trial.suggest_int("min_child_weight", 1, 10),
                "gamma": trial.suggest_float("gamma", 0.0, 1.0),
                "reg_alpha": trial.suggest_float("reg_alpha", 0.001, 10.0, log=True),
                "reg_lambda": trial.suggest_float("reg_lambda", 0.001, 10.0, log=True),
            }
        elif model_type == "neural_network":
            n_layers = trial.suggest_int("n_layers", 2, 4)
            hidden_layers = [
                trial.suggest_int(f"hidden_{i}", 32, 512, step=32)
                for i in range(n_layers)
            ]
            dropout_rates = [
                trial.suggest_float(f"dropout_{i}", 0.1, 0.5)
                for i in range(n_layers)
            ]
            return {
                "hidden_layers": hidden_layers,
                "dropout_rates": dropout_rates,
                "learning_rate": trial.suggest_float("learning_rate", 0.0001, 0.01, log=True),
                "batch_size": trial.suggest_categorical("batch_size", [32, 64, 128, 256]),
                "weight_decay": trial.suggest_float("weight_decay", 1e-6, 1e-2, log=True),
            }
        else:
            raise ValueError(f"Unknown model type: {model_type}")

    def _evaluate_params(
        self,
        model_type: str,
        X: np.ndarray,
        y: np.ndarray,
        params: dict[str, Any],
    ) -> float:
        """Evaluate a parameter set using cross-validation.

        Args:
            model_type: Model type string.
            X: Feature matrix.
            y: Labels.
            params: Parameter dictionary to evaluate.

        Returns:
            Mean cross-validation score.
        """
        skf = StratifiedKFold(
            n_splits=self.n_splits,
            shuffle=True,
            random_state=self.random_state,
        )

        scores = []

        for train_idx, val_idx in skf.split(X, y):
            X_train, X_val = X[train_idx], X[val_idx]
            y_train, y_val = y[train_idx], y[val_idx]

            try:
                model = self._create_model(model_type, params)
                model.fit(X_train, y_train)
                metrics = model.evaluate(X_val, y_val)
                scores.append(metrics.get(self.scoring, 0.0))
            except Exception as e:
                logger.warning("Evaluation failed for params {}: {}", params, e)
                scores.append(0.0)

        return float(np.mean(scores)) if scores else 0.0

    def _create_model(
        self,
        model_type: str,
        params: dict[str, Any],
    ) -> Any:
        """Instantiate a model with the given parameters.

        Args:
            model_type: Model type string.
            params: Hyperparameters for the model.

        Returns:
            Model instance.
        """
        if model_type == "random_forest":
            return RandomForestMalwareClassifier(params=params)
        elif model_type == "gradient_boost":
            return XGBoostMalwareClassifier(params=params)
        elif model_type == "neural_network":
            arch_keys = {"hidden_layers", "dropout_rates", "activation", "batch_norm"}
            train_keys = {"learning_rate", "batch_size", "weight_decay", "epochs"}
            architecture = {k: v for k, v in params.items() if k in arch_keys}
            training = {k: v for k, v in params.items() if k in train_keys}
            return NeuralNetMalwareClassifier(
                architecture=architecture or None,
                training_params=training or None,
            )
        else:
            raise ValueError(f"Unknown model type: {model_type}")

    def _get_default_search_space(self, model_type: str) -> dict[str, list]:
        """Get the default search space for a model type.

        Args:
            model_type: Model type string.

        Returns:
            Parameter grid dictionary.
        """
        spaces = {
            "random_forest": self.RF_SEARCH_SPACE,
            "gradient_boost": self.XGB_SEARCH_SPACE,
            "neural_network": self.NN_SEARCH_SPACE,
        }
        if model_type not in spaces:
            raise ValueError(f"No search space defined for: {model_type}")
        return spaces[model_type]

    def get_results_dataframe(self) -> Any:
        """Convert results history to a pandas DataFrame.

        Returns:
            DataFrame with one row per trial.
        """
        import pandas as pd

        rows = []
        for result in self.results_history:
            row = {"mean_score": result["mean_score"]}
            row.update(result["params"])
            rows.append(row)

        return pd.DataFrame(rows).sort_values("mean_score", ascending=False)

    def get_best_result(self) -> dict[str, Any]:
        """Return the best result found during tuning.

        Returns:
            Dictionary with best params and score.
        """
        return {
            "best_params": self.best_params,
            "best_score": self.best_score,
        }
