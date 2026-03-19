"""
Tests for ML classifier resilience against adversarial feature manipulation.

Verifies that the classifier maintains detection capability when attackers
deliberately manipulate observable features to mimic benign behavior
while preserving malicious functionality.
"""

from typing import Optional

import numpy as np
import pytest
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler


class FeatureManipulator:
    """Implements adversarial feature manipulation strategies."""

    def __init__(self, benign_profile: np.ndarray, seed: int = 42) -> None:
        """Initialize with a benign feature profile to mimic.

        Args:
            benign_profile: Mean feature values of benign samples.
            seed: Random seed for reproducibility.
        """
        self.benign_profile = benign_profile
        self.rng = np.random.RandomState(seed)

    def mimicry_attack(self, features: np.ndarray,
                       strength: float = 0.5) -> np.ndarray:
        """Shift features toward benign profile while keeping malicious core.

        Attackers inject benign-looking operations (file reads, normal HTTP)
        to dilute malicious signal in aggregated features.

        Args:
            features: Original malicious feature vector.
            strength: How aggressively to mimic (0=none, 1=full mimicry).
        """
        manipulated = features.copy()
        # Blend toward benign profile
        manipulated = (1 - strength) * features + strength * self.benign_profile
        # Preserve critical features that cannot be hidden (ptrace, mmap)
        # Attacker must still perform these operations
        preserve_indices = [0, 3]  # ptrace_count, mmap_exec
        for idx in preserve_indices:
            manipulated[idx] = max(features[idx] * 0.7, manipulated[idx])
        return manipulated

    def feature_padding_attack(self, features: np.ndarray,
                                padding_factor: float = 2.0) -> np.ndarray:
        """Pad non-critical features with benign noise.

        Inject unnecessary benign operations to overwhelm malicious signals
        in ratio-based features.

        Args:
            features: Original malicious feature vector.
            padding_factor: Multiplier for benign noise injection.
        """
        manipulated = features.copy()
        benign_noise = self.benign_profile * padding_factor
        # Add benign activity to dilute ratios
        non_critical = list(range(5, len(features)))
        for idx in non_critical:
            manipulated[idx] += benign_noise[idx] * self.rng.uniform(0.5, 1.5)
        return manipulated

    def gradient_based_attack(self, features: np.ndarray,
                               model: RandomForestClassifier,
                               scaler: StandardScaler,
                               epsilon: float = 0.3,
                               n_steps: int = 10) -> np.ndarray:
        """Estimate gradient direction and perturb features to reduce score.

        Uses finite-difference gradient estimation since Random Forest
        is not directly differentiable.

        Args:
            features: Original feature vector.
            model: Trained classifier.
            scaler: Feature scaler.
            epsilon: Maximum perturbation per step.
            n_steps: Number of optimization steps.
        """
        perturbed = features.copy()
        delta = 0.01

        for _ in range(n_steps):
            scaled = scaler.transform(perturbed.reshape(1, -1))
            current_score = model.predict_proba(scaled)[0, 1]

            if current_score < 0.5:
                break

            # Estimate gradient via finite differences
            gradient = np.zeros_like(perturbed)
            for i in range(len(perturbed)):
                perturbed_plus = perturbed.copy()
                perturbed_plus[i] += delta
                scaled_plus = scaler.transform(perturbed_plus.reshape(1, -1))
                score_plus = model.predict_proba(scaled_plus)[0, 1]
                gradient[i] = (score_plus - current_score) / delta

            # Step in negative gradient direction (reduce malicious score)
            step = -epsilon * gradient / (np.linalg.norm(gradient) + 1e-8)
            perturbed += step
            perturbed = np.maximum(perturbed, 0)  # Features must be non-negative

        return perturbed

    def timing_manipulation(self, features: np.ndarray,
                             slowdown: float = 3.0) -> np.ndarray:
        """Slow down attack to spread features over longer time window.

        Reducing attack speed dilutes per-window feature counts.

        Args:
            features: Original feature vector.
            slowdown: Factor by which attack is slowed.
        """
        manipulated = features.copy()
        # Count-based features are reduced by slowdown factor
        count_indices = list(range(0, 12))  # Syscall counts
        for idx in count_indices:
            manipulated[idx] /= slowdown
        # Rate-based features also decrease
        if len(manipulated) > 35:
            manipulated[35] /= slowdown  # child_process_spawn_rate
            manipulated[8] /= slowdown   # memory_allocation_growth_rate
        return manipulated


def create_test_dataset(n_benign: int = 500, n_malicious: int = 200,
                         n_features: int = 47, seed: int = 42
                         ) -> tuple[np.ndarray, np.ndarray]:
    """Create a synthetic labeled dataset for testing."""
    rng = np.random.RandomState(seed)

    benign = np.abs(rng.randn(n_benign, n_features))
    malicious = np.abs(rng.randn(n_malicious, n_features))
    malicious[:, 0] += 5.0  # ptrace
    malicious[:, 1] += 3.0  # dns entropy
    malicious[:, 2] += 2.5  # unique IPs
    malicious[:, 3] += 4.0  # mmap exec

    X = np.vstack([benign, malicious])
    y = np.array([0] * n_benign + [1] * n_malicious)
    return X, y


class TestFeatureManipulation:
    """Test classifier resilience to adversarial feature manipulation."""

    @pytest.fixture
    def dataset(self) -> tuple[np.ndarray, np.ndarray]:
        """Create test dataset."""
        return create_test_dataset()

    @pytest.fixture
    def trained_model(self, dataset: tuple[np.ndarray, np.ndarray]
                      ) -> tuple[RandomForestClassifier, StandardScaler]:
        """Train a Random Forest classifier on the test dataset."""
        X, y = dataset
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
        model = RandomForestClassifier(
            n_estimators=100, max_depth=15, random_state=42, n_jobs=-1
        )
        model.fit(X_scaled, y)
        return model, scaler

    @pytest.fixture
    def manipulator(self, dataset: tuple[np.ndarray, np.ndarray]
                    ) -> FeatureManipulator:
        """Create a feature manipulator with benign profile."""
        X, y = dataset
        benign_mean = X[y == 0].mean(axis=0)
        return FeatureManipulator(benign_mean)

    @pytest.fixture
    def malicious_samples(self, dataset: tuple[np.ndarray, np.ndarray]
                          ) -> np.ndarray:
        """Extract malicious samples from dataset."""
        X, y = dataset
        return X[y == 1]

    def test_baseline_accuracy(self, trained_model, dataset) -> None:
        """Trained model should achieve high accuracy on clean data."""
        model, scaler = trained_model
        X, y = dataset
        X_scaled = scaler.transform(X)
        accuracy = model.score(X_scaled, y)
        assert accuracy > 0.90, f"Baseline accuracy {accuracy:.3f} below 90%"

    def test_mimicry_weak(self, trained_model, manipulator,
                           malicious_samples) -> None:
        """Weak mimicry (strength=0.3) should not evade detection."""
        model, scaler = trained_model
        attacked = np.array([
            manipulator.mimicry_attack(f, strength=0.3)
            for f in malicious_samples
        ])
        X_scaled = scaler.transform(attacked)
        probs = model.predict_proba(X_scaled)[:, 1]
        detection_rate = np.mean(probs > 0.5)
        assert detection_rate > 0.80, (
            f"Weak mimicry detection rate {detection_rate:.3f} below 80%"
        )

    def test_mimicry_strong(self, trained_model, manipulator,
                             malicious_samples) -> None:
        """Strong mimicry (strength=0.7) may evade but not below 60%."""
        model, scaler = trained_model
        attacked = np.array([
            manipulator.mimicry_attack(f, strength=0.7)
            for f in malicious_samples
        ])
        X_scaled = scaler.transform(attacked)
        probs = model.predict_proba(X_scaled)[:, 1]
        detection_rate = np.mean(probs > 0.5)
        assert detection_rate > 0.60, (
            f"Strong mimicry detection rate {detection_rate:.3f} below 60%"
        )

    def test_feature_padding(self, trained_model, manipulator,
                              malicious_samples) -> None:
        """Feature padding should not significantly reduce detection."""
        model, scaler = trained_model
        attacked = np.array([
            manipulator.feature_padding_attack(f, padding_factor=2.0)
            for f in malicious_samples
        ])
        X_scaled = scaler.transform(attacked)
        probs = model.predict_proba(X_scaled)[:, 1]
        detection_rate = np.mean(probs > 0.5)
        assert detection_rate > 0.75, (
            f"Feature padding detection rate {detection_rate:.3f} below 75%"
        )

    def test_gradient_attack(self, trained_model, manipulator,
                              malicious_samples) -> None:
        """Gradient-based attack should have limited evasion success."""
        model, scaler = trained_model
        sample_subset = malicious_samples[:50]  # Smaller set for speed
        attacked = np.array([
            manipulator.gradient_based_attack(f, model, scaler, epsilon=0.2)
            for f in sample_subset
        ])
        X_scaled = scaler.transform(attacked)
        probs = model.predict_proba(X_scaled)[:, 1]
        detection_rate = np.mean(probs > 0.5)
        assert detection_rate > 0.65, (
            f"Gradient attack detection rate {detection_rate:.3f} below 65%"
        )

    def test_timing_manipulation(self, trained_model, manipulator,
                                  malicious_samples) -> None:
        """Timing manipulation should not fully evade detection."""
        model, scaler = trained_model
        attacked = np.array([
            manipulator.timing_manipulation(f, slowdown=3.0)
            for f in malicious_samples
        ])
        X_scaled = scaler.transform(attacked)
        probs = model.predict_proba(X_scaled)[:, 1]
        detection_rate = np.mean(probs > 0.5)
        assert detection_rate > 0.70, (
            f"Timing manipulation detection rate {detection_rate:.3f} below 70%"
        )

    def test_manipulated_features_remain_valid(self, manipulator,
                                                malicious_samples) -> None:
        """All manipulated features should remain physically valid."""
        for sample in malicious_samples[:20]:
            for attack_fn in [
                lambda f: manipulator.mimicry_attack(f, 0.5),
                lambda f: manipulator.feature_padding_attack(f, 2.0),
                lambda f: manipulator.timing_manipulation(f, 3.0),
            ]:
                result = attack_fn(sample)
                assert np.all(np.isfinite(result)), "Non-finite feature values"
                assert result.shape == sample.shape, "Feature shape changed"
