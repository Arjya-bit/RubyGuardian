"""
Tests for ML classifier handling of concept drift over time.

Verifies that the classifier detects concept drift (distributional shift
in attack patterns) and that retraining restores performance. Simulates
gradual and abrupt drift scenarios.
"""

from typing import Any

import numpy as np
import pytest
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, f1_score
from sklearn.preprocessing import StandardScaler


class ConceptDriftSimulator:
    """Simulates concept drift by gradually shifting feature distributions."""

    def __init__(self, seed: int = 42) -> None:
        self.rng = np.random.RandomState(seed)

    def gradual_drift(self, X: np.ndarray, y: np.ndarray,
                      drift_magnitude: float = 0.1,
                      n_steps: int = 10
                      ) -> list[tuple[np.ndarray, np.ndarray]]:
        """Simulate gradual concept drift over multiple time steps.

        Malicious samples slowly evolve their feature distributions,
        simulating attackers adapting techniques over time.

        Args:
            X: Original feature matrix.
            y: Labels.
            drift_magnitude: Total drift magnitude per step.
            n_steps: Number of drift steps.

        Returns:
            List of (X_drifted, y) tuples for each time step.
        """
        snapshots: list[tuple[np.ndarray, np.ndarray]] = []
        malicious_mask = y == 1
        current_X = X.copy()

        for step in range(n_steps):
            drift_vector = self.rng.randn(X.shape[1]) * drift_magnitude
            # Only drift malicious samples (attacks evolve, benign stays same)
            current_X[malicious_mask] += drift_vector
            current_X = np.maximum(current_X, 0)
            snapshots.append((current_X.copy(), y.copy()))

        return snapshots

    def abrupt_drift(self, X: np.ndarray, y: np.ndarray,
                     shift_features: list[int],
                     shift_magnitude: float = 3.0
                     ) -> tuple[np.ndarray, np.ndarray]:
        """Simulate abrupt concept drift (new attack technique appears).

        A sudden shift in attack patterns, e.g., attackers switch from
        DNS exfiltration to HTTP-based C2.

        Args:
            X: Original feature matrix.
            y: Labels.
            shift_features: Feature indices to shift.
            shift_magnitude: Magnitude of the shift.

        Returns:
            Drifted (X, y) tuple.
        """
        drifted_X = X.copy()
        malicious_mask = y == 1
        for feat_idx in shift_features:
            drifted_X[malicious_mask, feat_idx] += (
                shift_magnitude * self.rng.uniform(0.5, 1.5, malicious_mask.sum())
            )
            # Reduce old attack indicators
            if feat_idx > 0:
                old_feat = feat_idx - 1
                drifted_X[malicious_mask, old_feat] *= 0.3
        return drifted_X, y

    def seasonal_drift(self, X: np.ndarray, y: np.ndarray,
                       period_steps: int = 20
                       ) -> list[tuple[np.ndarray, np.ndarray]]:
        """Simulate periodic/seasonal drift patterns.

        Some feature distributions change cyclically (e.g., traffic patterns
        varying by time of day or week).

        Args:
            X: Original feature matrix.
            y: Labels.
            period_steps: Number of steps per cycle.

        Returns:
            List of snapshots over one cycle.
        """
        snapshots: list[tuple[np.ndarray, np.ndarray]] = []

        for step in range(period_steps):
            phase = 2 * np.pi * step / period_steps
            seasonal_factor = np.sin(phase) * 0.3

            current_X = X.copy()
            # Network features vary with traffic patterns
            for feat_idx in range(20, 35):
                current_X[:, feat_idx] *= (1 + seasonal_factor)
            current_X = np.maximum(current_X, 0)
            snapshots.append((current_X.copy(), y.copy()))

        return snapshots


class DriftDetector:
    """Detects concept drift using Page-Hinkley test."""

    def __init__(self, delta: float = 0.005, threshold: float = 50.0) -> None:
        """Initialize drift detector.

        Args:
            delta: Minimum difference to consider.
            threshold: Detection threshold (lambda).
        """
        self.delta = delta
        self.threshold = threshold
        self.reset()

    def reset(self) -> None:
        """Reset detector state."""
        self.sum: float = 0.0
        self.min_sum: float = float("inf")
        self.count: int = 0
        self.mean: float = 0.0

    def update(self, value: float) -> bool:
        """Update with new observation and check for drift.

        Args:
            value: New metric observation (e.g., accuracy).

        Returns:
            True if drift is detected.
        """
        self.count += 1
        self.mean += (value - self.mean) / self.count
        self.sum += value - self.mean - self.delta
        self.min_sum = min(self.min_sum, self.sum)

        return (self.sum - self.min_sum) > self.threshold


def create_dataset(n_samples: int = 800, n_features: int = 47,
                    seed: int = 42) -> tuple[np.ndarray, np.ndarray]:
    """Create a synthetic labeled dataset."""
    rng = np.random.RandomState(seed)
    n_malicious = int(n_samples * 0.3)
    n_benign = n_samples - n_malicious

    benign = np.abs(rng.randn(n_benign, n_features) + 1.0)
    malicious = np.abs(rng.randn(n_malicious, n_features) + 1.0)
    malicious[:, 0] += 5.0
    malicious[:, 1] += 3.0
    malicious[:, 3] += 4.0

    return np.vstack([benign, malicious]), np.array([0] * n_benign + [1] * n_malicious)


class TestConceptDrift:
    """Test classifier behavior under concept drift conditions."""

    @pytest.fixture(scope="class")
    def base_setup(self) -> dict[str, Any]:
        """Create dataset, train model, and return components."""
        X, y = create_dataset()
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)

        model = RandomForestClassifier(
            n_estimators=100, max_depth=15, random_state=42
        )
        model.fit(X_scaled, y)
        baseline_acc = accuracy_score(y, model.predict(X_scaled))

        return {
            "X": X, "y": y, "model": model, "scaler": scaler,
            "baseline_acc": baseline_acc,
        }

    @pytest.fixture
    def drift_simulator(self) -> ConceptDriftSimulator:
        return ConceptDriftSimulator(seed=42)

    def test_baseline_no_drift(self, base_setup: dict) -> None:
        """Model performs well when there is no drift."""
        assert base_setup["baseline_acc"] > 0.90

    def test_gradual_drift_degrades_performance(
        self, base_setup: dict, drift_simulator: ConceptDriftSimulator
    ) -> None:
        """Gradual drift should cause measurable performance degradation."""
        model = base_setup["model"]
        scaler = base_setup["scaler"]
        X, y = base_setup["X"], base_setup["y"]

        snapshots = drift_simulator.gradual_drift(X, y, drift_magnitude=0.3, n_steps=10)
        accuracies: list[float] = []

        for X_drifted, y_drifted in snapshots:
            X_s = scaler.transform(X_drifted)
            acc = accuracy_score(y_drifted, model.predict(X_s))
            accuracies.append(acc)

        # Performance should degrade over time
        assert accuracies[-1] < accuracies[0], (
            "Expected performance degradation under gradual drift"
        )
        # But should not collapse completely
        assert accuracies[-1] > 0.60, (
            f"Performance collapsed too much: {accuracies[-1]:.3f}"
        )

    def test_abrupt_drift_detected(
        self, base_setup: dict, drift_simulator: ConceptDriftSimulator
    ) -> None:
        """Abrupt drift should be detectable via drift detection."""
        model = base_setup["model"]
        scaler = base_setup["scaler"]
        X, y = base_setup["X"], base_setup["y"]

        X_drifted, y_drifted = drift_simulator.abrupt_drift(
            X, y, shift_features=[1, 2, 20], shift_magnitude=5.0
        )

        X_orig_s = scaler.transform(X)
        X_drift_s = scaler.transform(X_drifted)

        acc_before = accuracy_score(y, model.predict(X_orig_s))
        acc_after = accuracy_score(y_drifted, model.predict(X_drift_s))

        degradation = acc_before - acc_after
        assert degradation > 0.05, (
            f"Expected measurable degradation from abrupt drift, got {degradation:.3f}"
        )

    def test_retraining_restores_performance(
        self, base_setup: dict, drift_simulator: ConceptDriftSimulator
    ) -> None:
        """Retraining on drifted data should restore classifier performance."""
        X, y = base_setup["X"], base_setup["y"]

        X_drifted, y_drifted = drift_simulator.abrupt_drift(
            X, y, shift_features=[1, 2], shift_magnitude=4.0
        )

        # Retrain on drifted data
        scaler_new = StandardScaler()
        X_drifted_s = scaler_new.fit_transform(X_drifted)
        model_new = RandomForestClassifier(
            n_estimators=100, max_depth=15, random_state=42
        )
        model_new.fit(X_drifted_s, y_drifted)
        retrained_acc = accuracy_score(y_drifted, model_new.predict(X_drifted_s))

        assert retrained_acc > 0.90, (
            f"Retrained model accuracy {retrained_acc:.3f} below 90%"
        )

    def test_drift_detector_fires(
        self, base_setup: dict, drift_simulator: ConceptDriftSimulator
    ) -> None:
        """Page-Hinkley drift detector should fire under significant drift."""
        model = base_setup["model"]
        scaler = base_setup["scaler"]
        X, y = base_setup["X"], base_setup["y"]

        snapshots = drift_simulator.gradual_drift(
            X, y, drift_magnitude=0.5, n_steps=20
        )

        detector = DriftDetector(delta=0.005, threshold=15.0)
        drift_detected = False

        for X_drifted, y_drifted in snapshots:
            X_s = scaler.transform(X_drifted)
            acc = accuracy_score(y_drifted, model.predict(X_s))
            if detector.update(1.0 - acc):  # Feed error rate
                drift_detected = True
                break

        assert drift_detected, "Drift detector failed to detect significant drift"

    def test_seasonal_drift_is_tolerated(
        self, base_setup: dict, drift_simulator: ConceptDriftSimulator
    ) -> None:
        """Seasonal (cyclical) drift should not trigger false alarms."""
        model = base_setup["model"]
        scaler = base_setup["scaler"]
        X, y = base_setup["X"], base_setup["y"]

        snapshots = drift_simulator.seasonal_drift(X, y, period_steps=20)
        accuracies: list[float] = []

        for X_seasonal, y_seasonal in snapshots:
            X_s = scaler.transform(X_seasonal)
            acc = accuracy_score(y_seasonal, model.predict(X_s))
            accuracies.append(acc)

        # Seasonal drift should not cause sustained degradation
        min_acc = min(accuracies)
        max_acc = max(accuracies)
        assert min_acc > 0.80, f"Seasonal min accuracy {min_acc:.3f} too low"
        assert max_acc - min_acc < 0.15, (
            f"Seasonal accuracy swing too wide: {max_acc - min_acc:.3f}"
        )

    def test_incremental_update_mitigates_drift(
        self, drift_simulator: ConceptDriftSimulator
    ) -> None:
        """Incremental model updates should mitigate gradual drift."""
        X, y = create_dataset()
        snapshots = drift_simulator.gradual_drift(X, y, drift_magnitude=0.3, n_steps=10)

        scaler = StandardScaler()
        X_s = scaler.fit_transform(X)
        model = RandomForestClassifier(n_estimators=50, max_depth=10, random_state=42)
        model.fit(X_s, y)

        no_update_accs: list[float] = []
        update_accs: list[float] = []
        updated_model = RandomForestClassifier(n_estimators=50, max_depth=10, random_state=42)
        updated_model.fit(X_s, y)

        for i, (X_d, y_d) in enumerate(snapshots):
            X_d_s = scaler.transform(X_d)
            no_update_accs.append(accuracy_score(y_d, model.predict(X_d_s)))

            if i > 0 and i % 3 == 0:
                # Retrain on latest data
                scaler_u = StandardScaler()
                X_d_su = scaler_u.fit_transform(X_d)
                updated_model.fit(X_d_su, y_d)
                scaler = scaler_u

            update_accs.append(accuracy_score(y_d, updated_model.predict(
                scaler.transform(X_d)
            )))

        # Updated model should maintain better performance
        assert np.mean(update_accs[-3:]) >= np.mean(no_update_accs[-3:]) - 0.02
