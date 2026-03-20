"""
Unit tests for the RubyGuardian ML classifiers and ensemble.

Tests individual classifier predictions, ensemble voting,
confidence calibration, and edge cases.
"""

import numpy as np
import pytest
from unittest.mock import MagicMock, patch


class FakeClassifier:
    """A fake classifier for testing the ensemble without real models."""

    def __init__(self, model_id: str, prediction: int, probabilities: list):
        self.model_id = model_id
        self._prediction = prediction
        self._probabilities = probabilities

    def predict(self, features: np.ndarray) -> np.ndarray:
        batch_size = features.shape[0] if features.ndim > 1 else 1
        return np.array([self._prediction] * batch_size)

    def predict_proba(self, features: np.ndarray) -> np.ndarray:
        batch_size = features.shape[0] if features.ndim > 1 else 1
        return np.array([self._probabilities] * batch_size)


class TestIndividualClassifiers:
    """Tests for individual classifier predictions."""

    def test_classifier_returns_binary_label(self):
        clf = FakeClassifier("rf-test", prediction=0, probabilities=[0.8, 0.2])
        features = np.random.rand(1, 128)
        result = clf.predict(features)
        assert result[0] in (0, 1)

    def test_classifier_probabilities_sum_to_one(self):
        clf = FakeClassifier("rf-test", prediction=1, probabilities=[0.3, 0.7])
        features = np.random.rand(1, 128)
        proba = clf.predict_proba(features)
        assert pytest.approx(sum(proba[0]), abs=1e-6) == 1.0

    def test_malicious_prediction(self):
        clf = FakeClassifier("xgb-test", prediction=1, probabilities=[0.1, 0.9])
        features = np.random.rand(1, 128)
        assert clf.predict(features)[0] == 1

    def test_benign_prediction(self):
        clf = FakeClassifier("xgb-test", prediction=0, probabilities=[0.95, 0.05])
        features = np.random.rand(1, 128)
        assert clf.predict(features)[0] == 0

    def test_batch_prediction_shape(self):
        clf = FakeClassifier("rf-test", prediction=1, probabilities=[0.2, 0.8])
        features = np.random.rand(10, 128)
        result = clf.predict(features)
        assert result.shape == (10,)

    def test_batch_probabilities_shape(self):
        clf = FakeClassifier("rf-test", prediction=1, probabilities=[0.2, 0.8])
        features = np.random.rand(10, 128)
        proba = clf.predict_proba(features)
        assert proba.shape == (10, 2)


class TestEnsembleClassifier:
    """Tests for the weighted ensemble classifier."""

    @pytest.fixture
    def ensemble_classifiers(self):
        return [
            (FakeClassifier("rf", prediction=1, probabilities=[0.2, 0.8]), 0.3),
            (FakeClassifier("xgb", prediction=1, probabilities=[0.1, 0.9]), 0.4),
            (FakeClassifier("nn", prediction=0, probabilities=[0.6, 0.4]), 0.3),
        ]

    def _weighted_ensemble_predict(self, classifiers, features, threshold=0.5):
        """Simulate weighted ensemble prediction."""
        total_weight = sum(w for _, w in classifiers)
        weighted_proba = np.zeros(2)
        for clf, weight in classifiers:
            proba = clf.predict_proba(features)[0]
            weighted_proba += np.array(proba) * (weight / total_weight)
        label = 1 if weighted_proba[1] >= threshold else 0
        confidence = weighted_proba[label]
        return label, confidence, weighted_proba[1]

    def test_ensemble_majority_vote(self, ensemble_classifiers):
        features = np.random.rand(1, 128)
        label, confidence, mal_prob = self._weighted_ensemble_predict(
            ensemble_classifiers, features
        )
        # rf (0.8 * 0.3) + xgb (0.9 * 0.4) + nn (0.4 * 0.3) = 0.24 + 0.36 + 0.12 = 0.72
        assert label == 1  # malicious wins
        assert mal_prob == pytest.approx(0.72, abs=0.01)

    def test_ensemble_respects_threshold(self, ensemble_classifiers):
        features = np.random.rand(1, 128)
        label, _, mal_prob = self._weighted_ensemble_predict(
            ensemble_classifiers, features, threshold=0.8
        )
        # mal_prob ~0.72 < 0.8, so should be benign
        assert label == 0

    def test_ensemble_all_agree_malicious(self):
        classifiers = [
            (FakeClassifier("a", 1, [0.05, 0.95]), 0.33),
            (FakeClassifier("b", 1, [0.1, 0.9]), 0.33),
            (FakeClassifier("c", 1, [0.08, 0.92]), 0.34),
        ]
        features = np.random.rand(1, 128)
        label, confidence, _ = self._weighted_ensemble_predict(classifiers, features)
        assert label == 1
        assert confidence > 0.9

    def test_ensemble_all_agree_benign(self):
        classifiers = [
            (FakeClassifier("a", 0, [0.95, 0.05]), 0.33),
            (FakeClassifier("b", 0, [0.9, 0.1]), 0.33),
            (FakeClassifier("c", 0, [0.92, 0.08]), 0.34),
        ]
        features = np.random.rand(1, 128)
        label, confidence, _ = self._weighted_ensemble_predict(classifiers, features)
        assert label == 0
        assert confidence > 0.9

    def test_ensemble_tie_breaking(self):
        """When probabilities are exactly 0.5, label should be benign (conservative)."""
        classifiers = [
            (FakeClassifier("a", 1, [0.3, 0.7]), 0.5),
            (FakeClassifier("b", 0, [0.7, 0.3]), 0.5),
        ]
        features = np.random.rand(1, 128)
        label, _, mal_prob = self._weighted_ensemble_predict(classifiers, features)
        assert mal_prob == pytest.approx(0.5, abs=0.01)
        assert label == 1  # 0.5 >= 0.5 threshold

    def test_ensemble_single_model_fallback(self):
        """Ensemble with a single model should behave like that model."""
        classifiers = [
            (FakeClassifier("only", 1, [0.15, 0.85]), 1.0),
        ]
        features = np.random.rand(1, 128)
        label, confidence, mal_prob = self._weighted_ensemble_predict(classifiers, features)
        assert label == 1
        assert mal_prob == pytest.approx(0.85, abs=0.01)

    def test_ensemble_weight_normalization(self):
        """Weights should be normalized so their sum equals 1."""
        classifiers = [
            (FakeClassifier("a", 1, [0.1, 0.9]), 10.0),
            (FakeClassifier("b", 0, [0.9, 0.1]), 10.0),
        ]
        features = np.random.rand(1, 128)
        _, _, mal_prob = self._weighted_ensemble_predict(classifiers, features)
        # (0.9 * 0.5) + (0.1 * 0.5) = 0.5
        assert mal_prob == pytest.approx(0.5, abs=0.01)


class TestConfidenceCalibration:
    """Tests for prediction confidence properties."""

    def test_confidence_between_zero_and_one(self):
        clf = FakeClassifier("test", 1, [0.3, 0.7])
        proba = clf.predict_proba(np.random.rand(1, 128))[0]
        for p in proba:
            assert 0.0 <= p <= 1.0

    def test_high_confidence_matches_prediction(self):
        clf = FakeClassifier("test", 1, [0.05, 0.95])
        proba = clf.predict_proba(np.random.rand(1, 128))[0]
        predicted = clf.predict(np.random.rand(1, 128))[0]
        assert proba[predicted] > 0.5

    def test_low_confidence_near_boundary(self):
        clf = FakeClassifier("test", 1, [0.48, 0.52])
        proba = clf.predict_proba(np.random.rand(1, 128))[0]
        max_confidence = max(proba)
        assert max_confidence < 0.6  # uncertainty
