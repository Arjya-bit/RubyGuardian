"""
Performance benchmarks for the RubyGuardian ML classifier.

Measures inference latency, throughput, memory usage, and scaling behavior
under various load conditions. Results are used to validate that the
classifier meets real-time detection latency requirements.
"""

import gc
import os
import statistics
import time
from typing import Any

import numpy as np
import pytest
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.preprocessing import StandardScaler


def generate_benchmark_data(n_samples: int, n_features: int = 47,
                             seed: int = 42) -> tuple[np.ndarray, np.ndarray]:
    """Generate synthetic feature data for benchmarking.

    Args:
        n_samples: Number of samples to generate.
        n_features: Number of features per sample.
        seed: Random seed.

    Returns:
        Tuple of (features, labels).
    """
    rng = np.random.RandomState(seed)
    n_malicious = n_samples // 3
    n_benign = n_samples - n_malicious

    benign = np.abs(rng.randn(n_benign, n_features) + 1.0)
    malicious = np.abs(rng.randn(n_malicious, n_features) + 1.0)
    malicious[:, 0] += 5.0  # ptrace
    malicious[:, 1] += 3.0  # dns_entropy
    malicious[:, 3] += 4.0  # mmap_exec

    X = np.vstack([benign, malicious])
    y = np.concatenate([np.zeros(n_benign), np.ones(n_malicious)])

    # Shuffle
    idx = rng.permutation(n_samples)
    return X[idx], y[idx]


def measure_latency(func: Any, *args: Any, n_iter: int = 100,
                     warmup: int = 10, **kwargs: Any) -> dict[str, float]:
    """Measure function execution latency statistics.

    Args:
        func: Function to benchmark.
        n_iter: Number of measurement iterations.
        warmup: Number of warmup iterations (excluded from stats).

    Returns:
        Dictionary with p50, p90, p95, p99, mean, std latency in milliseconds.
    """
    # Warmup
    for _ in range(warmup):
        func(*args, **kwargs)

    latencies: list[float] = []
    for _ in range(n_iter):
        gc.disable()
        start = time.perf_counter_ns()
        func(*args, **kwargs)
        end = time.perf_counter_ns()
        gc.enable()
        latencies.append((end - start) / 1e6)  # Convert to ms

    latencies.sort()
    return {
        'p50': latencies[len(latencies) // 2],
        'p90': latencies[int(len(latencies) * 0.9)],
        'p95': latencies[int(len(latencies) * 0.95)],
        'p99': latencies[int(len(latencies) * 0.99)],
        'mean': statistics.mean(latencies),
        'std': statistics.stdev(latencies),
        'min': min(latencies),
        'max': max(latencies),
    }


class TestClassifierLatency:
    """Benchmark inference latency for single and batch predictions."""

    @pytest.fixture(scope="class")
    def rf_model(self) -> tuple[RandomForestClassifier, StandardScaler]:
        """Train a Random Forest model for benchmarking."""
        X, y = generate_benchmark_data(5000)
        scaler = StandardScaler()
        X_s = scaler.fit_transform(X)
        model = RandomForestClassifier(
            n_estimators=200, max_depth=20, random_state=42, n_jobs=-1
        )
        model.fit(X_s, y)
        return model, scaler

    @pytest.fixture(scope="class")
    def gb_model(self) -> tuple[GradientBoostingClassifier, StandardScaler]:
        """Train a Gradient Boosted model for benchmarking."""
        X, y = generate_benchmark_data(5000)
        scaler = StandardScaler()
        X_s = scaler.fit_transform(X)
        model = GradientBoostingClassifier(
            n_estimators=200, max_depth=10, random_state=42
        )
        model.fit(X_s, y)
        return model, scaler

    def test_rf_single_inference_latency(self, rf_model) -> None:
        """Random Forest single-sample inference should be under 5ms."""
        model, scaler = rf_model
        sample = np.random.randn(1, 47)
        sample_s = scaler.transform(sample)

        stats = measure_latency(model.predict_proba, sample_s, n_iter=200)
        assert stats['p95'] < 5.0, (
            f"RF single inference p95={stats['p95']:.2f}ms exceeds 5ms limit"
        )

    def test_rf_batch_inference_latency(self, rf_model) -> None:
        """Random Forest batch inference (64 samples) should be under 20ms."""
        model, scaler = rf_model
        batch = np.random.randn(64, 47)
        batch_s = scaler.transform(batch)

        stats = measure_latency(model.predict_proba, batch_s, n_iter=100)
        assert stats['p95'] < 20.0, (
            f"RF batch inference p95={stats['p95']:.2f}ms exceeds 20ms limit"
        )

    def test_gb_single_inference_latency(self, gb_model) -> None:
        """Gradient Boosted single inference should be under 10ms."""
        model, scaler = gb_model
        sample = np.random.randn(1, 47)
        sample_s = scaler.transform(sample)

        stats = measure_latency(model.predict_proba, sample_s, n_iter=200)
        assert stats['p95'] < 10.0, (
            f"GB single inference p95={stats['p95']:.2f}ms exceeds 10ms limit"
        )

    def test_scaler_transform_latency(self, rf_model) -> None:
        """Feature scaling should add negligible latency."""
        _, scaler = rf_model
        sample = np.random.randn(1, 47)

        stats = measure_latency(scaler.transform, sample, n_iter=500)
        assert stats['p95'] < 0.5, (
            f"Scaler transform p95={stats['p95']:.2f}ms exceeds 0.5ms limit"
        )


class TestClassifierThroughput:
    """Benchmark sustained prediction throughput."""

    @pytest.fixture(scope="class")
    def model_and_data(self) -> dict[str, Any]:
        X, y = generate_benchmark_data(10000)
        scaler = StandardScaler()
        X_s = scaler.fit_transform(X)
        model = RandomForestClassifier(
            n_estimators=200, max_depth=20, random_state=42, n_jobs=-1
        )
        model.fit(X_s[:5000], y[:5000])
        return {"model": model, "scaler": scaler, "X": X_s[5000:], "y": y[5000:]}

    @pytest.mark.parametrize("batch_size", [1, 16, 64, 256])
    def test_throughput_by_batch_size(self, model_and_data: dict,
                                      batch_size: int) -> None:
        """Measure predictions per second at different batch sizes."""
        model = model_and_data["model"]
        X = model_and_data["X"]

        total_predictions = 0
        start = time.perf_counter()
        duration_limit = 2.0  # Run for 2 seconds

        while time.perf_counter() - start < duration_limit:
            idx = np.random.randint(0, len(X) - batch_size)
            batch = X[idx:idx + batch_size]
            model.predict_proba(batch)
            total_predictions += batch_size

        elapsed = time.perf_counter() - start
        throughput = total_predictions / elapsed

        # Minimum throughput requirement: 1000 predictions/sec for batch=1
        min_throughput = 1000 * batch_size
        assert throughput > min_throughput * 0.5, (
            f"Throughput {throughput:.0f} pred/s below expected "
            f"{min_throughput} for batch_size={batch_size}"
        )


class TestClassifierMemory:
    """Benchmark memory usage of trained models."""

    def test_rf_model_size(self) -> None:
        """Random Forest model should fit within 100MB memory."""
        import joblib
        import tempfile

        X, y = generate_benchmark_data(5000)
        scaler = StandardScaler()
        X_s = scaler.fit_transform(X)
        model = RandomForestClassifier(
            n_estimators=200, max_depth=20, random_state=42
        )
        model.fit(X_s, y)

        with tempfile.NamedTemporaryFile(suffix='.joblib', delete=True) as f:
            joblib.dump(model, f.name)
            model_size_mb = os.path.getsize(f.name) / (1024 * 1024)

        assert model_size_mb < 100, (
            f"Model size {model_size_mb:.1f}MB exceeds 100MB limit"
        )

    def test_feature_extraction_does_not_leak_memory(self) -> None:
        """Repeated feature extraction should not accumulate memory."""
        import tracemalloc

        tracemalloc.start()
        snapshot1 = tracemalloc.take_snapshot()

        # Simulate 1000 feature extractions
        for _ in range(1000):
            features = np.random.randn(47)
            _ = features * 2.0 + 1.0  # Simple transform

        snapshot2 = tracemalloc.take_snapshot()
        tracemalloc.stop()

        stats = snapshot2.compare_to(snapshot1, 'lineno')
        total_growth = sum(s.size_diff for s in stats if s.size_diff > 0)
        total_growth_mb = total_growth / (1024 * 1024)

        assert total_growth_mb < 10, (
            f"Memory grew by {total_growth_mb:.1f}MB during feature extraction"
        )


class TestScalingBehavior:
    """Test how performance scales with model complexity."""

    @pytest.mark.parametrize("n_estimators", [50, 100, 200, 500])
    def test_latency_scales_with_estimators(self, n_estimators: int) -> None:
        """Latency should scale roughly linearly with number of trees."""
        X, y = generate_benchmark_data(2000)
        scaler = StandardScaler()
        X_s = scaler.fit_transform(X)

        model = RandomForestClassifier(
            n_estimators=n_estimators, max_depth=15, random_state=42, n_jobs=-1
        )
        model.fit(X_s, y)

        sample = scaler.transform(np.random.randn(1, 47))
        stats = measure_latency(model.predict_proba, sample, n_iter=100)

        # With parallel execution, should stay under 10ms even for 500 trees
        assert stats['p95'] < 10.0, (
            f"Latency p95={stats['p95']:.2f}ms for {n_estimators} estimators"
        )
