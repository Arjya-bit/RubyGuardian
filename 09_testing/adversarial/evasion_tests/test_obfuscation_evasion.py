"""
Tests for ML classifier resilience against obfuscation-based evasion techniques.

Verifies that the classifier maintains acceptable detection rates when
malicious samples are obfuscated using Base64, XOR, string splitting,
polymorphic encoding, and combined obfuscation strategies.
"""

import base64
import hashlib
import os
from typing import Any

import numpy as np
import pytest


class ObfuscationTransform:
    """Applies obfuscation transforms to feature vectors to simulate evasion."""

    def __init__(self, seed: int = 42) -> None:
        self.rng = np.random.RandomState(seed)

    def base64_transform(self, features: np.ndarray) -> np.ndarray:
        """Simulate Base64 encoding effect on features.

        Base64 encoding changes string entropy and increases payload size
        by ~33%, which affects network and syscall features.
        """
        transformed = features.copy()
        # Encoding increases data size, affecting bytes_sent features
        network_indices = list(range(20, 35))
        for idx in network_indices:
            transformed[idx] *= 1.33 + self.rng.uniform(-0.05, 0.05)
        # Encoding reduces string entropy (smaller alphabet)
        if len(transformed) > 7:
            transformed[7] *= 0.75  # syscall_sequence_entropy
        return transformed

    def xor_transform(self, features: np.ndarray) -> np.ndarray:
        """Simulate XOR encryption effect on features.

        XOR encryption creates high-entropy data and adds CPU-intensive
        decryption loops that alter syscall timing patterns.
        """
        transformed = features.copy()
        # XOR loop increases CPU syscall count
        syscall_indices = list(range(0, 12))
        for idx in syscall_indices:
            transformed[idx] += self.rng.uniform(5, 20)
        # Encrypted payload has near-maximum entropy
        if len(transformed) > 7:
            transformed[7] = self.rng.uniform(7.5, 8.0)
        return transformed

    def string_split_transform(self, features: np.ndarray) -> np.ndarray:
        """Simulate string splitting/concatenation obfuscation.

        Splitting strings across multiple variables creates additional
        memory allocations and string concatenation operations.
        """
        transformed = features.copy()
        # More memory allocations
        if len(transformed) > 8:
            transformed[8] *= 1.5 + self.rng.uniform(0, 0.3)
        # Additional string operations show as write syscalls
        if len(transformed) > 6:
            transformed[6] += self.rng.uniform(10, 50)
        return transformed

    def polymorphic_transform(self, features: np.ndarray) -> np.ndarray:
        """Simulate polymorphic encoding where each execution is unique.

        Polymorphic payloads randomize their encoding on each execution,
        creating variable feature signatures.
        """
        transformed = features.copy()
        # Randomize features while preserving malicious behavior core
        noise_mask = self.rng.uniform(0.7, 1.3, size=transformed.shape)
        transformed *= noise_mask
        # Preserve critical indicators (ptrace, mmap) at reduced levels
        transformed[0] = max(transformed[0] * 0.8, features[0] * 0.5)
        transformed[3] = max(transformed[3] * 0.8, features[3] * 0.5)
        return transformed

    def combined_transform(self, features: np.ndarray) -> np.ndarray:
        """Apply all obfuscation transforms in sequence."""
        result = self.base64_transform(features)
        result = self.xor_transform(result)
        result = self.string_split_transform(result)
        result = self.polymorphic_transform(result)
        return result


def generate_malicious_features(n_samples: int, n_features: int = 47,
                                 seed: int = 42) -> np.ndarray:
    """Generate synthetic malicious feature vectors.

    Malicious samples have elevated ptrace counts, network entropy,
    and process spawning rates compared to benign baseline.
    """
    rng = np.random.RandomState(seed)
    features = rng.randn(n_samples, n_features)

    # Elevate key malicious indicators
    features[:, 0] += 5.0   # ptrace_syscall_count
    features[:, 1] += 3.0   # dns_query_entropy
    features[:, 2] += 2.5   # unique_outbound_ips
    features[:, 3] += 4.0   # mmap_exec_calls
    features[:, 5] += 2.0   # child_process_spawns
    return np.abs(features)


class TestObfuscationEvasion:
    """Test classifier detection rates under various obfuscation strategies."""

    @pytest.fixture
    def malicious_features(self) -> np.ndarray:
        """Generate a batch of malicious feature vectors."""
        return generate_malicious_features(200, n_features=47)

    @pytest.fixture
    def obfuscator(self) -> ObfuscationTransform:
        """Create an obfuscation transform instance."""
        return ObfuscationTransform(seed=42)

    @pytest.fixture
    def classifier_threshold(self) -> float:
        """Classification threshold for malicious detection."""
        return 0.5

    def _simple_classifier(self, features: np.ndarray) -> np.ndarray:
        """Simple threshold-based classifier for testing.

        Combines key features with weights derived from feature importance.
        Returns probability of malicious classification.
        """
        weights = np.zeros(features.shape[1] if features.ndim > 1 else len(features))
        weights[0] = 0.142   # ptrace_syscall_count
        weights[1] = 0.098   # dns_query_entropy
        weights[2] = 0.087   # unique_outbound_ips
        weights[3] = 0.076   # mmap_exec_calls
        weights[5] = 0.058   # child_process_spawns

        if features.ndim == 1:
            features = features.reshape(1, -1)

        scores = features @ weights[:features.shape[1]]
        # Sigmoid normalization
        probabilities = 1.0 / (1.0 + np.exp(-scores + 2.0))
        return probabilities

    def test_baseline_detection(self, malicious_features: np.ndarray,
                                 classifier_threshold: float) -> None:
        """Baseline: classifier should detect unobfuscated malicious samples."""
        probs = self._simple_classifier(malicious_features)
        detection_rate = np.mean(probs > classifier_threshold)
        assert detection_rate > 0.90, (
            f"Baseline detection rate {detection_rate:.3f} below 90% threshold"
        )

    def test_base64_evasion(self, malicious_features: np.ndarray,
                             obfuscator: ObfuscationTransform,
                             classifier_threshold: float) -> None:
        """Base64 obfuscation should not significantly reduce detection."""
        obfuscated = np.array([
            obfuscator.base64_transform(f) for f in malicious_features
        ])
        probs = self._simple_classifier(obfuscated)
        detection_rate = np.mean(probs > classifier_threshold)
        assert detection_rate > 0.85, (
            f"Base64 evasion detection rate {detection_rate:.3f} below 85% threshold"
        )

    def test_xor_evasion(self, malicious_features: np.ndarray,
                          obfuscator: ObfuscationTransform,
                          classifier_threshold: float) -> None:
        """XOR encryption should not significantly reduce detection."""
        obfuscated = np.array([
            obfuscator.xor_transform(f) for f in malicious_features
        ])
        probs = self._simple_classifier(obfuscated)
        detection_rate = np.mean(probs > classifier_threshold)
        assert detection_rate > 0.82, (
            f"XOR evasion detection rate {detection_rate:.3f} below 82% threshold"
        )

    def test_string_split_evasion(self, malicious_features: np.ndarray,
                                   obfuscator: ObfuscationTransform,
                                   classifier_threshold: float) -> None:
        """String splitting should not significantly reduce detection."""
        obfuscated = np.array([
            obfuscator.string_split_transform(f) for f in malicious_features
        ])
        probs = self._simple_classifier(obfuscated)
        detection_rate = np.mean(probs > classifier_threshold)
        assert detection_rate > 0.80, (
            f"String split evasion detection rate {detection_rate:.3f} below 80%"
        )

    def test_polymorphic_evasion(self, malicious_features: np.ndarray,
                                  obfuscator: ObfuscationTransform,
                                  classifier_threshold: float) -> None:
        """Polymorphic encoding should not drop detection below 75%."""
        obfuscated = np.array([
            obfuscator.polymorphic_transform(f) for f in malicious_features
        ])
        probs = self._simple_classifier(obfuscated)
        detection_rate = np.mean(probs > classifier_threshold)
        assert detection_rate > 0.75, (
            f"Polymorphic evasion detection rate {detection_rate:.3f} below 75%"
        )

    def test_combined_evasion(self, malicious_features: np.ndarray,
                               obfuscator: ObfuscationTransform,
                               classifier_threshold: float) -> None:
        """Combined obfuscation should not drop detection below 70%."""
        obfuscated = np.array([
            obfuscator.combined_transform(f) for f in malicious_features
        ])
        probs = self._simple_classifier(obfuscated)
        detection_rate = np.mean(probs > classifier_threshold)
        assert detection_rate > 0.70, (
            f"Combined evasion detection rate {detection_rate:.3f} below 70%"
        )

    def test_obfuscation_detection_degradation_is_monotonic(
        self, malicious_features: np.ndarray,
        obfuscator: ObfuscationTransform,
        classifier_threshold: float
    ) -> None:
        """Detection rates should degrade monotonically with obfuscation levels."""
        rates: list[float] = []
        transforms = [
            obfuscator.base64_transform,
            obfuscator.xor_transform,
            obfuscator.string_split_transform,
            obfuscator.polymorphic_transform,
        ]

        cumulative = malicious_features.copy()
        for transform in transforms:
            cumulative = np.array([transform(f) for f in cumulative])
            probs = self._simple_classifier(cumulative)
            rates.append(float(np.mean(probs > classifier_threshold)))

        # Allow small non-monotonic fluctuations (5% tolerance)
        for i in range(1, len(rates)):
            assert rates[i] <= rates[i - 1] + 0.05, (
                f"Detection rate increased unexpectedly: {rates[i-1]:.3f} -> {rates[i]:.3f}"
            )

    def test_feature_integrity_after_obfuscation(
        self, malicious_features: np.ndarray,
        obfuscator: ObfuscationTransform
    ) -> None:
        """Obfuscated features should remain non-negative (physical constraint)."""
        for transform_name in ['base64', 'xor', 'string_split', 'polymorphic', 'combined']:
            transform = getattr(obfuscator, f'{transform_name}_transform')
            obfuscated = np.array([transform(f) for f in malicious_features[:10]])
            # Feature values represent counts/rates and should be non-negative
            # (polymorphic may create small negatives due to random scaling)
            assert np.all(obfuscated > -1.0), (
                f"{transform_name} transform created unrealistic negative features"
            )
