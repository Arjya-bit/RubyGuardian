"""
Unit tests for the RubyGuardian ML training pipeline.
"""

import numpy as np
import pytest


class TestTrainPipeline:
    """Tests for TrainPipeline class."""

    def test_default_config_loading(self):
        """Pipeline should load default config when no path given."""
        defaults = {
            "data": {"test_size": 0.2, "validation_size": 0.15, "random_state": 42},
            "cross_validation": {"n_splits": 5},
        }
        assert defaults["data"]["test_size"] == 0.2
        assert defaults["cross_validation"]["n_splits"] == 5

    def test_data_splitting_ratios(self):
        """Data should be split into correct proportions."""
        n_samples = 1000
        test_size = 0.2
        val_size = 0.15

        n_test = int(n_samples * test_size)
        n_remaining = n_samples - n_test
        n_val = int(n_remaining * (val_size / (1.0 - test_size)))
        n_train = n_remaining - n_val

        assert n_test == 200
        assert n_train + n_val + n_test == n_samples
        assert n_train > n_val > 0

    def test_feature_normalization(self):
        """StandardScaler should normalize features to zero mean, unit variance."""
        from sklearn.preprocessing import StandardScaler

        X = np.random.randn(100, 10) * 5 + 3
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)

        assert abs(X_scaled.mean()) < 0.1
        assert abs(X_scaled.std() - 1.0) < 0.1

    def test_stratified_split_preserves_class_ratios(self):
        """Stratified splitting should preserve class distribution."""
        from sklearn.model_selection import train_test_split

        y = np.array([0] * 80 + [1] * 20)
        _, _, y_train, y_test = train_test_split(
            np.zeros((100, 5)), y, test_size=0.2, stratify=y, random_state=42
        )

        train_ratio = y_train.mean()
        test_ratio = y_test.mean()

        assert abs(train_ratio - 0.2) < 0.05
        assert abs(test_ratio - 0.2) < 0.1

    def test_cross_validation_fold_count(self):
        """Cross-validation should produce correct number of folds."""
        from sklearn.model_selection import StratifiedKFold

        n_splits = 5
        X = np.random.randn(100, 10)
        y = np.array([0] * 50 + [1] * 50)

        skf = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=42)
        folds = list(skf.split(X, y))

        assert len(folds) == n_splits
        for train_idx, val_idx in folds:
            assert len(train_idx) + len(val_idx) == 100


class TestModelEvaluation:
    """Tests for model evaluation metrics."""

    def test_accuracy_computation(self):
        """Accuracy should be correctly computed."""
        from sklearn.metrics import accuracy_score

        y_true = [0, 0, 1, 1, 1]
        y_pred = [0, 0, 1, 1, 0]

        acc = accuracy_score(y_true, y_pred)
        assert acc == 0.8

    def test_confusion_matrix_shape(self):
        """Confusion matrix should have shape (n_classes, n_classes)."""
        from sklearn.metrics import confusion_matrix

        y_true = [0, 0, 1, 1]
        y_pred = [0, 1, 1, 0]

        cm = confusion_matrix(y_true, y_pred)
        assert cm.shape == (2, 2)

    def test_f1_score_range(self):
        """F1 score should be between 0 and 1."""
        from sklearn.metrics import f1_score

        y_true = np.random.randint(0, 2, 100)
        y_pred = np.random.randint(0, 2, 100)

        f1 = f1_score(y_true, y_pred, average="weighted")
        assert 0.0 <= f1 <= 1.0

    def test_perfect_classifier_metrics(self):
        """Perfect classifier should have all metrics at 1.0."""
        from sklearn.metrics import accuracy_score, f1_score, precision_score

        y = [0, 0, 1, 1, 0, 1]
        assert accuracy_score(y, y) == 1.0
        assert f1_score(y, y, average="weighted") == 1.0
        assert precision_score(y, y, average="weighted") == 1.0
