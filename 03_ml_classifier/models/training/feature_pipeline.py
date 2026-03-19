"""
Feature extraction orchestration for the training pipeline.

Coordinates all feature extractors (static, AST, string patterns,
API calls, imports, obfuscation, entropy, behavioral, network) and
produces unified feature matrices with consistent column ordering
for model training and inference.
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


class FeaturePipelineOrchestrator:
    """Orchestrates all feature extractors into a unified pipeline.

    Manages the lifecycle of feature extraction from raw Ruby scripts
    to processed feature matrices suitable for model training.
    Handles feature ordering, caching, selection, and persistence.
    """

    def __init__(
        self,
        config_path: Optional[str | Path] = None,
        feature_config_path: Optional[str | Path] = None,
    ) -> None:
        """Initialize the feature pipeline orchestrator.

        Args:
            config_path: Path to training_config.yml.
            feature_config_path: Path to feature_config.yml.
        """
        self.config = self._load_config(config_path)
        self.feature_config_path = feature_config_path

        # Initialize extractors
        self.static_analyzer = StaticAnalyzer()
        self.ast_extractor = ASTFeatureExtractor()
        self.string_extractor = StringPatternExtractor(
            config_path=feature_config_path,
        )
        self.api_extractor = APICallExtractor(
            config_path=feature_config_path,
        )
        self.import_analyzer = ImportAnalyzer(
            config_path=feature_config_path,
        )
        self.obfuscation_scorer = ObfuscationScorer(
            config_path=feature_config_path,
        )

        self.feature_names: list[str] = []
        self.feature_cache: dict[str, dict[str, float]] = {}
        self._feature_stats: Optional[dict[str, Any]] = None

        logger.info("FeaturePipelineOrchestrator initialized")

    @staticmethod
    def _load_config(config_path: Optional[str | Path]) -> dict[str, Any]:
        """Load pipeline configuration.

        Args:
            config_path: Path to config file.

        Returns:
            Configuration dictionary.
        """
        defaults: dict[str, Any] = {
            "data": {
                "raw_dir": "data/raw",
                "processed_dir": "data/processed",
            },
            "pipeline": {
                "steps": [
                    {"name": "feature_extraction", "enabled": True, "cache": True},
                ],
            },
        }

        if config_path is None:
            return defaults

        path = Path(config_path)
        if not path.exists():
            return defaults

        with open(path) as f:
            return yaml.safe_load(f)

    def extract_from_source(self, source_code: str) -> dict[str, float]:
        """Extract all features from a Ruby source code string.

        Runs all configured extractors and merges their outputs
        into a single flat dictionary.

        Args:
            source_code: Raw Ruby source code.

        Returns:
            Dictionary mapping feature names to numeric values.
        """
        features: dict[str, float] = {}

        # Static analysis features
        try:
            static_feats = self.static_analyzer.extract(source_code)
            features.update(static_feats.to_dict())
        except Exception as e:
            logger.warning("Static analysis failed: {}", e)

        # AST features
        try:
            ast_feats = self.ast_extractor.extract(source_code)
            features.update(ast_feats.to_dict())
        except Exception as e:
            logger.warning("AST extraction failed: {}", e)

        # String pattern features
        try:
            str_feats = self.string_extractor.extract(source_code)
            features.update(str_feats.to_dict())
        except Exception as e:
            logger.warning("String pattern extraction failed: {}", e)

        # API call features
        try:
            api_feats = self.api_extractor.extract(source_code)
            features.update(api_feats.to_dict())
        except Exception as e:
            logger.warning("API call extraction failed: {}", e)

        # Import analysis features
        try:
            import_feats = self.import_analyzer.extract(source_code)
            features.update(import_feats.to_dict())
        except Exception as e:
            logger.warning("Import analysis failed: {}", e)

        # Obfuscation scoring
        try:
            obf_feats = self.obfuscation_scorer.extract(source_code)
            features.update(obf_feats.to_dict())
        except Exception as e:
            logger.warning("Obfuscation scoring failed: {}", e)

        return features

    def extract_from_file(self, file_path: str | Path) -> dict[str, float]:
        """Extract features from a Ruby source file.

        Uses caching to avoid re-extracting features for the same file.

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
            label: Optional label to assign to all files in this directory.
            recursive: Whether to search subdirectories.

        Returns:
            Tuple of (feature_dicts, file_paths, labels).
        """
        dir_path = Path(directory)
        if not dir_path.exists():
            raise FileNotFoundError(f"Directory not found: {dir_path}")

        if recursive:
            ruby_files = sorted(dir_path.rglob("*.rb"))
        else:
            ruby_files = sorted(dir_path.glob("*.rb"))

        feature_dicts = []
        file_paths = []
        labels = []

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
            len(feature_dicts), dir_path,
        )
        return feature_dicts, file_paths, labels

    def build_feature_matrix(
        self,
        feature_dicts: list[dict[str, float]],
    ) -> tuple[np.ndarray, list[str]]:
        """Convert a list of feature dictionaries to a numpy matrix.

        Ensures consistent column ordering across all samples.

        Args:
            feature_dicts: List of feature dictionaries.

        Returns:
            Tuple of (feature_matrix, feature_names).
        """
        if not feature_dicts:
            return np.empty((0, 0)), []

        # Build consistent feature name ordering
        all_keys: set[str] = set()
        for d in feature_dicts:
            all_keys.update(d.keys())

        self.feature_names = sorted(all_keys)

        # Build matrix
        matrix = np.zeros((len(feature_dicts), len(self.feature_names)))
        for i, d in enumerate(feature_dicts):
            for j, name in enumerate(self.feature_names):
                matrix[i, j] = d.get(name, 0.0)

        logger.info(
            "Built feature matrix: {} samples x {} features",
            matrix.shape[0], matrix.shape[1],
        )
        return matrix, self.feature_names

    def run_full_extraction(
        self,
        raw_dir: Optional[str | Path] = None,
        output_dir: Optional[str | Path] = None,
    ) -> tuple[np.ndarray, np.ndarray, list[str]]:
        """Run the full feature extraction pipeline on raw data.

        Scans the raw data directory structure (benign_scripts/ and
        malicious_scripts/), extracts features, and saves the results.

        Args:
            raw_dir: Path to the raw data directory.
            output_dir: Path to save processed features and labels.

        Returns:
            Tuple of (feature_matrix, labels, feature_names).
        """
        data_config = self.config.get("data", {})
        raw_dir = Path(raw_dir or data_config.get("raw_dir", "data/raw"))
        output_dir = Path(output_dir or data_config.get("processed_dir", "data/processed"))

        all_features = []
        all_labels = []

        # Extract benign scripts (label = 0)
        benign_dir = raw_dir / "benign_scripts"
        if benign_dir.exists():
            feats, paths, labels = self.extract_from_directory(benign_dir, label=0)
            all_features.extend(feats)
            all_labels.extend(labels)
            logger.info("Extracted {} benign samples", len(feats))

        # Extract malicious scripts (label = 1)
        malicious_dir = raw_dir / "malicious_scripts"
        if malicious_dir.exists():
            feats, paths, labels = self.extract_from_directory(malicious_dir, label=1)
            all_features.extend(feats)
            all_labels.extend(labels)
            logger.info("Extracted {} malicious samples", len(feats))

        if not all_features:
            logger.warning("No Ruby files found in {}", raw_dir)
            return np.empty((0, 0)), np.empty(0), []

        X, feature_names = self.build_feature_matrix(all_features)
        y = np.array(all_labels)

        # Save results
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
            feature_names: Feature names.
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

        # Compute and save feature statistics
        self._feature_stats = {
            "n_samples": int(X.shape[0]),
            "n_features": int(X.shape[1]),
            "class_distribution": {
                str(cls): int(count)
                for cls, count in zip(*np.unique(y, return_counts=True))
            },
            "feature_means": {
                name: float(mean) for name, mean in zip(feature_names, X.mean(axis=0))
            },
            "feature_stds": {
                name: float(std) for name, std in zip(feature_names, X.std(axis=0))
            },
        }

        with open(features_dir / "feature_stats.json", "w") as f:
            json.dump(self._feature_stats, f, indent=2)

        logger.info(
            "Saved features to {}: {} samples, {} features",
            output_dir, X.shape[0], X.shape[1],
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

    def extract_single_vector(self, source_code: str) -> np.ndarray:
        """Extract features and return as a numpy vector.

        Uses the current feature_names ordering. Features not present
        in the extraction result are filled with zeros.

        Args:
            source_code: Ruby source code.

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


def main() -> None:
    """CLI entry point for feature extraction."""
    import click

    @click.command()
    @click.option("--input", "input_dir", default="data/raw", help="Input directory")
    @click.option("--output", "output_dir", default="data/processed", help="Output directory")
    @click.option("--config", default="config/training_config.yml", help="Config path")
    @click.option("--feature-config", default="config/feature_config.yml", help="Feature config")
    def extract(input_dir: str, output_dir: str, config: str, feature_config: str) -> None:
        """Extract features from raw Ruby scripts."""
        pipeline = FeaturePipelineOrchestrator(
            config_path=config,
            feature_config_path=feature_config,
        )
        X, y, names = pipeline.run_full_extraction(input_dir, output_dir)
        logger.info("Extraction complete: {} samples, {} features", X.shape[0], len(names))

    extract()
