"""
Feature extraction pipeline orchestrator for RubyGuardian.

Coordinates all feature extractors (static, AST, string patterns,
API calls, imports, obfuscation, entropy, behavioral, network) into
a unified pipeline that produces consistent feature vectors for
both training and inference.
"""

import json
from pathlib import Path
from typing import Any, Optional

import numpy as np
import pandas as pd
import yaml
from loguru import logger

from feature_extraction.static_analyzer import StaticAnalyzer
from feature_extraction.ast_feature_extractor import ASTFeatureExtractor
from feature_extraction.string_pattern_extractor import StringPatternExtractor
from feature_extraction.api_call_extractor import APICallExtractor
from feature_extraction.import_analyzer import ImportAnalyzer
from feature_extraction.obfuscation_scorer import ObfuscationScorer
from feature_extraction.entropy_calculator import EntropyCalculator
from feature_extraction.behavioral_feature_extractor import BehavioralFeatureExtractor
from feature_extraction.network_feature_extractor import NetworkFeatureExtractor


class FeaturePipeline:
    """Unified pipeline that coordinates all feature extractors.

    Manages the full lifecycle from raw Ruby source code to
    processed feature matrices. Supports configurable extractor
    selection, feature ordering persistence, caching, and batch
    extraction for both training and real-time inference.
    """

    def __init__(
        self,
        config_path: Optional[str | Path] = None,
        feature_config_path: Optional[str | Path] = None,
        enabled_extractors: Optional[list[str]] = None,
    ) -> None:
        """Initialize the feature pipeline.

        Args:
            config_path: Path to training_config.yml for data paths.
            feature_config_path: Path to feature_config.yml for extractor settings.
            enabled_extractors: Optional list of extractor names to enable.
                If None, all extractors are enabled.
        """
        self.config = self._load_config(config_path)
        self.feature_config_path = feature_config_path

        # Initialize all extractors
        self._extractors: dict[str, Any] = {
            "static": StaticAnalyzer(),
            "ast": ASTFeatureExtractor(),
            "string_pattern": StringPatternExtractor(config_path=feature_config_path),
            "api_call": APICallExtractor(config_path=feature_config_path),
            "import": ImportAnalyzer(config_path=feature_config_path),
            "obfuscation": ObfuscationScorer(config_path=feature_config_path),
            "entropy": EntropyCalculator(config_path=feature_config_path),
            "behavioral": BehavioralFeatureExtractor(config_path=feature_config_path),
            "network": NetworkFeatureExtractor(config_path=feature_config_path),
        }

        # Filter to enabled extractors
        if enabled_extractors is not None:
            self._extractors = {
                name: ext
                for name, ext in self._extractors.items()
                if name in enabled_extractors
            }

        self.feature_names: list[str] = []
        self.feature_cache: dict[str, dict[str, float]] = {}
        self._feature_stats: Optional[dict[str, Any]] = None

        logger.info(
            "FeaturePipeline initialized with {} extractors: {}",
            len(self._extractors),
            list(self._extractors.keys()),
        )

    @staticmethod
    def _load_config(config_path: Optional[str | Path]) -> dict[str, Any]:
        """Load pipeline configuration from YAML.

        Args:
            config_path: Path to the config file.

        Returns:
            Configuration dictionary with defaults.
        """
        defaults: dict[str, Any] = {
            "data": {
                "raw_dir": "data/raw",
                "processed_dir": "data/processed",
            },
        }

        if config_path is None:
            return defaults

        path = Path(config_path)
        if not path.exists():
            return defaults

        with open(path) as f:
            config = yaml.safe_load(f) or {}

        for key in defaults:
            if key not in config:
                config[key] = defaults[key]

        return config

    def extract_from_source(self, source_code: str) -> dict[str, float]:
        """Extract all features from Ruby source code.

        Runs each enabled extractor and merges results into a
        single flat feature dictionary.

        Args:
            source_code: Raw Ruby source code.

        Returns:
            Dictionary mapping feature names to numeric values.
        """
        features: dict[str, float] = {}

        for name, extractor in self._extractors.items():
            try:
                result = extractor.extract(source_code)
                features.update(result.to_dict())
            except Exception as e:
                logger.warning("Extractor '{}' failed: {}", name, e)

        return features

    def extract_from_file(self, file_path: str | Path) -> dict[str, float]:
        """Extract features from a Ruby source file with caching.

        Args:
            file_path: Path to the Ruby source file.

        Returns:
            Feature dictionary.

        Raises:
            FileNotFoundError: If the file does not exist.
        """
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {path}")

        cache_key = str(path.resolve())
        if cache_key in self.feature_cache:
            return self.feature_cache[cache_key]

        source_code = path.read_text(encoding="utf-8", errors="replace")
        features = self.extract_from_source(source_code)

        self.feature_cache[cache_key] = features
        return features

    def extract_from_directory(
        self,
        directory: str | Path,
        label: Optional[int] = None,
        recursive: bool = True,
    ) -> tuple[list[dict[str, float]], list[str], list[int]]:
        """Extract features from all Ruby files in a directory.

        Args:
            directory: Directory containing Ruby source files.
            label: Optional label to assign to all files.
            recursive: Whether to search subdirectories.

        Returns:
            Tuple of (feature_dicts, file_paths, labels).
        """
        dir_path = Path(directory)
        if not dir_path.exists():
            raise FileNotFoundError(f"Directory not found: {dir_path}")

        ruby_files = sorted(
            dir_path.rglob("*.rb") if recursive else dir_path.glob("*.rb")
        )

        feature_dicts: list[dict[str, float]] = []
        file_paths: list[str] = []
        labels: list[int] = []

        for rb_file in ruby_files:
            try:
                features = self.extract_from_file(rb_file)
                feature_dicts.append(features)
                file_paths.append(str(rb_file))
                if label is not None:
                    labels.append(label)
            except Exception as e:
                logger.warning("Failed to extract features from {}: {}", rb_file, e)

        logger.info(
            "Extracted features from {} files in {}",
            len(feature_dicts),
            dir_path,
        )
        return feature_dicts, file_paths, labels

    def build_feature_matrix(
        self,
        feature_dicts: list[dict[str, float]],
    ) -> tuple[np.ndarray, list[str]]:
        """Convert feature dictionaries to a numpy matrix.

        Ensures consistent column ordering across all samples.
        If feature_names is already set (e.g. from a previous run),
        uses that ordering; otherwise derives it from the data.

        Args:
            feature_dicts: List of feature dictionaries.

        Returns:
            Tuple of (feature_matrix, feature_names).
        """
        if not feature_dicts:
            return np.empty((0, 0)), []

        if not self.feature_names:
            all_keys: set[str] = set()
            for d in feature_dicts:
                all_keys.update(d.keys())
            self.feature_names = sorted(all_keys)

        matrix = np.zeros((len(feature_dicts), len(self.feature_names)))
        for i, d in enumerate(feature_dicts):
            for j, name in enumerate(self.feature_names):
                matrix[i, j] = d.get(name, 0.0)

        logger.info(
            "Built feature matrix: {} samples x {} features",
            matrix.shape[0],
            matrix.shape[1],
        )
        return matrix, self.feature_names

    def extract_single_vector(self, source_code: str) -> np.ndarray:
        """Extract features and return as a numpy vector.

        Uses the current feature_names ordering. Missing features
        are filled with zeros.

        Args:
            source_code: Ruby source code string.

        Returns:
            Feature vector of shape (n_features,).
        """
        features = self.extract_from_source(source_code)

        if not self.feature_names:
            self.feature_names = sorted(features.keys())

        vector = np.zeros(len(self.feature_names))
        for i, name in enumerate(self.feature_names):
            vector[i] = features.get(name, 0.0)

        return vector

    def run_full_extraction(
        self,
        raw_dir: Optional[str | Path] = None,
        output_dir: Optional[str | Path] = None,
    ) -> tuple[np.ndarray, np.ndarray, list[str]]:
        """Run the full extraction pipeline on the raw data directory.

        Scans benign_scripts/ (label=0) and malicious_scripts/ (label=1),
        extracts features, and saves the processed results.

        Args:
            raw_dir: Path to the raw data directory.
            output_dir: Path to save processed features and labels.

        Returns:
            Tuple of (feature_matrix, labels, feature_names).
        """
        data_config = self.config.get("data", {})
        raw_dir = Path(raw_dir or data_config.get("raw_dir", "data/raw"))
        output_dir = Path(output_dir or data_config.get("processed_dir", "data/processed"))

        all_features: list[dict[str, float]] = []
        all_labels: list[int] = []

        # Benign scripts (label = 0)
        benign_dir = raw_dir / "benign_scripts"
        if benign_dir.exists():
            feats, _paths, labels = self.extract_from_directory(benign_dir, label=0)
            all_features.extend(feats)
            all_labels.extend(labels)
            logger.info("Extracted {} benign samples", len(feats))

        # Malicious scripts (label = 1)
        malicious_dir = raw_dir / "malicious_scripts"
        if malicious_dir.exists():
            feats, _paths, labels = self.extract_from_directory(malicious_dir, label=1)
            all_features.extend(feats)
            all_labels.extend(labels)
            logger.info("Extracted {} malicious samples", len(feats))

        if not all_features:
            logger.warning("No Ruby files found in {}", raw_dir)
            return np.empty((0, 0)), np.empty(0), []

        X, feature_names = self.build_feature_matrix(all_features)
        y = np.array(all_labels)

        self._save_results(X, y, feature_names, output_dir)

        return X, y, feature_names

    def _save_results(
        self,
        X: np.ndarray,
        y: np.ndarray,
        feature_names: list[str],
        output_dir: Path,
    ) -> None:
        """Save extracted features and labels to disk.

        Args:
            X: Feature matrix.
            y: Label array.
            feature_names: Ordered feature names.
            output_dir: Output directory path.
        """
        features_dir = output_dir / "features"
        labels_dir = output_dir / "labels"
        features_dir.mkdir(parents=True, exist_ok=True)
        labels_dir.mkdir(parents=True, exist_ok=True)

        # Save as CSV
        df = pd.DataFrame(X, columns=feature_names)
        df.to_csv(features_dir / "features.csv", index=False)

        labels_df = pd.DataFrame({"label": y})
        labels_df.to_csv(labels_dir / "labels.csv", index=False)

        # Save as numpy
        np.save(features_dir / "features.npy", X)
        np.save(labels_dir / "labels.npy", y)

        # Save feature names
        with open(features_dir / "feature_names.json", "w") as f:
            json.dump(feature_names, f, indent=2)

        # Compute and save statistics
        self._feature_stats = {
            "n_samples": int(X.shape[0]),
            "n_features": int(X.shape[1]),
            "class_distribution": {
                str(cls): int(count)
                for cls, count in zip(*np.unique(y, return_counts=True))
            },
            "feature_means": {
                name: float(mean)
                for name, mean in zip(feature_names, X.mean(axis=0))
            },
            "feature_stds": {
                name: float(std)
                for name, std in zip(feature_names, X.std(axis=0))
            },
        }

        with open(features_dir / "feature_stats.json", "w") as f:
            json.dump(self._feature_stats, f, indent=2)

        logger.info(
            "Saved features to {}: {} samples, {} features",
            output_dir,
            X.shape[0],
            X.shape[1],
        )

    def get_feature_names(self) -> list[str]:
        """Return the current ordered list of feature names.

        Returns:
            List of feature name strings.
        """
        return list(self.feature_names)

    def get_feature_stats(self) -> Optional[dict[str, Any]]:
        """Return computed feature statistics.

        Returns:
            Feature statistics dictionary, or None if not computed.
        """
        return self._feature_stats

    def clear_cache(self) -> None:
        """Clear the feature extraction cache."""
        self.feature_cache.clear()
        logger.debug("Feature cache cleared")

    def set_feature_names(self, names: list[str]) -> None:
        """Set the feature name ordering for inference consistency.

        Use this to ensure the same feature ordering as during training.

        Args:
            names: Ordered list of feature names.
        """
        self.feature_names = list(names)
        logger.info("Feature names set: {} features", len(self.feature_names))

    def load_feature_names(self, path: str | Path) -> list[str]:
        """Load feature names from a JSON file.

        Args:
            path: Path to the feature_names.json file.

        Returns:
            List of feature names.
        """
        with open(path) as f:
            names = json.load(f)
        self.feature_names = names
        logger.info("Loaded {} feature names from {}", len(names), path)
        return names


def main() -> None:
    """CLI entry point for the feature extraction pipeline."""
    import click

    @click.command()
    @click.option("--input", "input_dir", default="data/raw", help="Input directory")
    @click.option("--output", "output_dir", default="data/processed", help="Output directory")
    @click.option("--config", default="config/training_config.yml", help="Config path")
    @click.option(
        "--feature-config", default="config/feature_config.yml", help="Feature config"
    )
    def extract(
        input_dir: str,
        output_dir: str,
        config: str,
        feature_config: str,
    ) -> None:
        """Extract features from raw Ruby scripts."""
        pipeline = FeaturePipeline(
            config_path=config,
            feature_config_path=feature_config,
        )
        X, y, names = pipeline.run_full_extraction(input_dir, output_dir)
        logger.info(
            "Extraction complete: {} samples, {} features",
            X.shape[0],
            len(names),
        )

    extract()
