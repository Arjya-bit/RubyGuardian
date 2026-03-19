"""
Tests for ML classifier robustness to random noise injection.

Verifies that the classifier maintains stable predictions when features
are perturbed with Gaussian noise at various magnitudes, simulating
measurement uncertainty and environmental variability.
"""

from typing import Any

import numpy as np
import pytest
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, f1_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler


def generate_dataset(n_samples: int = 1000, n_features: int = 47,
                     malicious_ratio: float = 0.3,
                     seed: int = 42) -> tuple[np.ndarray, np.ndarray]:
    """Generate synthetic security event features with labels.

    Args:
        n_samples: Total number of samples.
        n_features: Number of features per sample.
        malicious_ratio: Fraction of malicious samples.
        seed: Random seed.

    Returns:
        Tuple of (features, labels).
    """
    rng = np.random.RandomState(seed)
    n_malicious = int(n_samples * malicious_ratio)
    n_benign = n_samples - n_malicious

    benign = np.abs(rng.randn(n_benign, n_features) * 1.5 + 1.0)
    malicious = np.abs(rng.randn(n_malicious, n_features) * 1.5 + 1.0)

    # Inject malicious behavioral signals
    malicious[:, 0] += rng.uniform(3.0, 8.0, n_malicious)   # ptrace_count
    malicious[:, 1] += rng.uniform(2.0, 5.0, n_malicious)   # dns_entropy
    malicious[:, 3] += rng.uniform(2.0, 6.0, n_malicious)   # mmap_exec
    malicious[:, 20] += rng.uniform(1.0, 4.0, n_malicious)  # outbound_ips

    X = np.vstack([benign, malicious])
    y = np.concatenate([np.zeros(n_benign), np.ones(n_malicious)])
    return X, y


def add_gaussian_noise(X: np.ndarray, sigma: float,
                       seed: int = 42) -> np.ndarray:
    """Add Gaussian noise to feature matrix.

    Args:
        X: Feature matrix (n_samples, n_features).
        sigma: Standard deviation of noise.
        seed: Random seed.

    Returns:
        Noisy feature matrix with non-negative values.
    """
    rng = np.random.RandomState(seed)
    noise = rng.randn(*X.shape) * sigma
    return np.maximum(X + noise, 0)


def add_salt_pepper_noise(X: np.ndarray, fraction: float,
                           seed: int = 42) -> np.ndarray:
    """Add salt-and-pepper noise (random zero/max values).

    Args:
        X: Feature matrix.
        fraction: Fraction of values to corrupt.
        seed: Random seed.

    Returns:
        Corrupted feature matrix.
    """
    rng = np.random.RandomState(seed)
    noisy = X.copy()
    mask = rng.random(X.shape) < fraction
    noisy[mask] = rng.choice([0, X.max()], size=mask.sum())
    return noisy


def add_uniform_noise(X: np.ndarray, magnitude: float,
                       seed: int = 42) -> np.ndarray:
    """Add uniform noise within [-magnitude, +magnitude].

    Args:
        X: Feature matrix.
        magnitude: Maximum noise magnitude.
        seed: Random seed.
    """
    rng = np.random.RandomState(seed)
    noise = rng.uniform(-magnitude, magnitude, size=X.shape)
    return np.maximum(X + noise, 0)


class TestNoiseInjection:
    """Test classifier robustness under various noise conditions."""

    @pytest.fixture(scope="class")
    def trained_pipeline(self) -> dict[str, Any]:
        """Train a classifier and return all components."""
        X, y = generate_dataset(n_samples=1000)
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.3, stratify=y, random_state=42
        )
        scaler = StandardScaler()
        X_train_s = scaler.fit_transform(X_train)
        X_test_s = scaler.transform(X_test)

        model = RandomForestClassifier(
            n_estimators=100, max_depth=15, random_state=42
        )
        model.fit(X_train_s, y_train)

        baseline_acc = accuracy_score(y_test, model.predict(X_test_s))
        baseline_f1 = f1_score(y_test, model.predict(X_test_s))

        return {
            "model": model,
            "scaler": scaler,
            "X_test": X_test,
            "y_test": y_test,
            "baseline_acc": baseline_acc,
            "baseline_f1": baseline_f1,
        }

    def test_baseline_performance(self, trained_pipeline: dict) -> None:
        """Verify baseline model performance is sufficient."""
        assert trained_pipeline["baseline_acc"] > 0.90
        assert trained_pipeline["baseline_f1"] > 0.85

    @pytest.mark.parametrize("sigma", [0.1, 0.3, 0.5, 1.0])
    def test_gaussian_noise_robustness(self, trained_pipeline: dict,
                                        sigma: float) -> None:
        """Classifier should tolerate Gaussian noise at various levels."""
        model = trained_pipeline["model"]
        scaler = trained_pipeline["scaler"]
        X_test = trained_pipeline["X_test"]
        y_test = trained_pipeline["y_test"]
        baseline_acc = trained_pipeline["baseline_acc"]

        noisy_X = add_gaussian_noise(X_test, sigma=sigma)
        noisy_X_s = scaler.transform(noisy_X)
        noisy_acc = accuracy_score(y_test, model.predict(noisy_X_s))

        max_degradation = min(0.15, sigma * 0.2)
        assert noisy_acc >= baseline_acc - max_degradation, (
            f"Gaussian noise (sigma={sigma}) degraded accuracy from "
            f"{baseline_acc:.3f} to {noisy_acc:.3f} "
            f"(max allowed: {baseline_acc - max_degradation:.3f})"
        )

    @pytest.mark.parametrize("fraction", [0.01, 0.05, 0.1])
    def test_salt_pepper_noise_robustness(self, trained_pipeline: dict,
                                           fraction: float) -> None:
        """Classifier should tolerate sparse value corruption."""
        model = trained_pipeline["model"]
        scaler = trained_pipeline["scaler"]
        X_test = trained_pipeline["X_test"]
        y_test = trained_pipeline["y_test"]
        baseline_acc = trained_pipeline["baseline_acc"]

        noisy_X = add_salt_pepper_noise(X_test, fraction=fraction)
        noisy_X_s = scaler.transform(noisy_X)
        noisy_acc = accuracy_score(y_test, model.predict(noisy_X_s))

        max_degradation = fraction * 1.5
        assert noisy_acc >= baseline_acc - max_degradation, (
            f"Salt-pepper noise (frac={fraction}) degraded accuracy from "
            f"{baseline_acc:.3f} to {noisy_acc:.3f}"
        )

    @pytest.mark.parametrize("magnitude", [0.5, 1.0, 2.0])
    def test_uniform_noise_robustness(self, trained_pipeline: dict,
                                       magnitude: float) -> None:
        """Classifier should tolerate uniform noise."""
        model = trained_pipeline["model"]
        scaler = trained_pipeline["scaler"]
        X_test = trained_pipeline["X_test"]
        y_test = trained_pipeline["y_test"]
        baseline_acc = trained_pipeline["baseline_acc"]

        noisy_X = add_uniform_noise(X_test, magnitude=magnitude)
        noisy_X_s = scaler.transform(noisy_X)
        noisy_acc = accuracy_score(y_test, model.predict(noisy_X_s))

        max_degradation = min(0.20, magnitude * 0.1)
        assert noisy_acc >= baseline_acc - max_degradation

    def test_prediction_stability_under_small_noise(
        self, trained_pipeline: dict
    ) -> None:
        """Small noise should not flip predictions for confident samples."""
        model = trained_pipeline["model"]
        scaler = trained_pipeline["scaler"]
        X_test = trained_pipeline["X_test"]

        X_test_s = scaler.transform(X_test)
        base_probs = model.predict_proba(X_test_s)[:, 1]

        # Select highly confident predictions (>0.8 or <0.2)
        confident_mask = (base_probs > 0.8) | (base_probs < 0.2)
        confident_X = X_test[confident_mask]

        noisy_X = add_gaussian_noise(confident_X, sigma=0.1)
        noisy_X_s = scaler.transform(noisy_X)
        noisy_probs = model.predict_proba(noisy_X_s)[:, 1]

        base_preds = (base_probs[confident_mask] > 0.5).astype(int)
        noisy_preds = (noisy_probs > 0.5).astype(int)

        flip_rate = np.mean(base_preds != noisy_preds)
        assert flip_rate < 0.05, (
            f"Prediction flip rate {flip_rate:.3f} exceeds 5% threshold "
            f"for confident predictions under small noise"
        )

    def test_noise_does_not_create_false_positives(
        self, trained_pipeline: dict
    ) -> None:
        """Noise on benign samples should not create excessive false positives."""
        model = trained_pipeline["model"]
        scaler = trained_pipeline["scaler"]
        X_test = trained_pipeline["X_test"]
        y_test = trained_pipeline["y_test"]

        benign_X = X_test[y_test == 0]
        noisy_benign = add_gaussian_noise(benign_X, sigma=0.5)
        noisy_benign_s = scaler.transform(noisy_benign)

        preds = model.predict(noisy_benign_s)
        false_positive_rate = np.mean(preds == 1)
        assert false_positive_rate < 0.10, (
            f"Noise-induced FPR {false_positive_rate:.3f} exceeds 10% threshold"
        )

    def test_repeated_noise_produces_consistent_results(
        self, trained_pipeline: dict
    ) -> None:
        """Multiple noise realizations should produce similar accuracy."""
        model = trained_pipeline["model"]
        scaler = trained_pipeline["scaler"]
        X_test = trained_pipeline["X_test"]
        y_test = trained_pipeline["y_test"]

        accuracies: list[float] = []
        for seed in range(10):
            noisy_X = add_gaussian_noise(X_test, sigma=0.3, seed=seed)
            noisy_X_s = scaler.transform(noisy_X)
            acc = accuracy_score(y_test, model.predict(noisy_X_s))
            accuracies.append(acc)

        std_dev = np.std(accuracies)
        assert std_dev < 0.03, (
            f"Accuracy variance across noise seeds too high: std={std_dev:.4f}"
        )
