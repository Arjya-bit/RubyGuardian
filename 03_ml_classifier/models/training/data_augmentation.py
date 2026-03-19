"""
Data augmentation for Ruby malware training samples.

Generates synthetic samples through source-level transformations
(variable renaming, whitespace variation, comment injection, statement
reordering) and feature-space augmentation (SMOTE, noise injection,
interpolation) to improve classifier robustness.
"""

import re
import random
import string
from pathlib import Path
from typing import Any, Optional

import numpy as np
import yaml
from loguru import logger


class SourceCodeAugmentor:
    """Augments Ruby source code through syntactically-safe transformations.

    Applies deterministic and stochastic rewrites to Ruby scripts to
    generate training variants that preserve the semantic label while
    varying surface-level features.
    """

    RUBY_KEYWORDS = frozenset({
        "def", "end", "class", "module", "if", "else", "elsif", "unless",
        "while", "until", "for", "do", "begin", "rescue", "ensure",
        "raise", "return", "yield", "self", "super", "true", "false",
        "nil", "and", "or", "not", "in", "then", "when", "case",
        "require", "require_relative", "include", "extend", "prepend",
        "puts", "print", "p", "attr_reader", "attr_writer", "attr_accessor",
        "private", "protected", "public", "lambda", "proc", "new",
    })

    VARIABLE_PATTERN = re.compile(r'\b([a-z_][a-z0-9_]*)\b')
    METHOD_DEF_PATTERN = re.compile(r'^(\s*def\s+)(\w+)', re.MULTILINE)
    COMMENT_PATTERN = re.compile(r'^\s*#.*$', re.MULTILINE)
    BLANK_LINE_PATTERN = re.compile(r'^\s*$', re.MULTILINE)

    BENIGN_COMMENTS = [
        "# Initialize configuration",
        "# Process input data",
        "# Validate parameters",
        "# Helper method for formatting",
        "# TODO: Add error handling",
        "# Cache the result for performance",
        "# Apply the transformation",
        "# Return the computed value",
        "# Check boundary conditions",
        "# Update internal state",
    ]

    def __init__(
        self,
        config_path: Optional[str | Path] = None,
        random_state: int = 42,
    ) -> None:
        """Initialize the source code augmentor.

        Args:
            config_path: Path to training_config.yml.
            random_state: Seed for random number generator.
        """
        self.rng = random.Random(random_state)
        self.techniques: list[str] = [
            "variable_renaming",
            "whitespace_variation",
            "comment_injection",
            "statement_reordering",
        ]
        self.multiplier = 2

        if config_path:
            self._load_config(config_path)

        logger.debug(
            "SourceCodeAugmentor initialized with techniques: {}",
            self.techniques,
        )

    def _load_config(self, config_path: str | Path) -> None:
        """Load augmentation config.

        Args:
            config_path: Path to the training config.
        """
        path = Path(config_path)
        if not path.exists():
            return

        with open(path) as f:
            config = yaml.safe_load(f)

        aug_config = config.get("class_balancing", {}).get("augmentation", {})
        if aug_config.get("enabled", True):
            self.techniques = aug_config.get("techniques", self.techniques)
            self.multiplier = aug_config.get("multiplier", self.multiplier)

    def augment(self, source_code: str, n_variants: int = 1) -> list[str]:
        """Generate augmented variants of a Ruby source file.

        Args:
            source_code: Original Ruby source code.
            n_variants: Number of variants to generate.

        Returns:
            List of augmented source code strings.
        """
        variants = []

        for _ in range(n_variants):
            augmented = source_code

            # Apply a random subset of techniques
            selected = self.rng.sample(
                self.techniques,
                k=self.rng.randint(1, len(self.techniques)),
            )

            for technique in selected:
                if technique == "variable_renaming":
                    augmented = self._rename_variables(augmented)
                elif technique == "whitespace_variation":
                    augmented = self._vary_whitespace(augmented)
                elif technique == "comment_injection":
                    augmented = self._inject_comments(augmented)
                elif technique == "statement_reordering":
                    augmented = self._reorder_statements(augmented)

            variants.append(augmented)

        return variants

    def _rename_variables(self, source: str) -> str:
        """Rename local variables to random identifiers.

        Preserves Ruby keywords and method definitions.

        Args:
            source: Ruby source code.

        Returns:
            Source code with renamed variables.
        """
        identifiers = set(self.VARIABLE_PATTERN.findall(source))
        identifiers -= self.RUBY_KEYWORDS

        # Only rename a fraction of identifiers
        to_rename = self.rng.sample(
            list(identifiers),
            k=min(len(identifiers), max(1, len(identifiers) // 3)),
        )

        rename_map = {}
        for ident in to_rename:
            new_name = self._generate_variable_name(len(ident))
            rename_map[ident] = new_name

        result = source
        for old, new in sorted(rename_map.items(), key=lambda x: -len(x[0])):
            result = re.sub(rf'\b{re.escape(old)}\b', new, result)

        return result

    def _generate_variable_name(self, target_length: int) -> str:
        """Generate a random Ruby-style variable name.

        Args:
            target_length: Approximate desired length.

        Returns:
            Random variable name string.
        """
        length = max(2, target_length + self.rng.randint(-2, 2))
        prefixes = ["var", "tmp", "val", "data", "item", "buf", "obj", "res"]
        prefix = self.rng.choice(prefixes)
        suffix_len = max(1, length - len(prefix) - 1)
        suffix = "".join(
            self.rng.choices(string.ascii_lowercase + string.digits, k=suffix_len)
        )
        return f"{prefix}_{suffix}"

    def _vary_whitespace(self, source: str) -> str:
        """Apply random whitespace variations.

        Adds or removes blank lines and adjusts spacing while
        preserving indentation structure.

        Args:
            source: Ruby source code.

        Returns:
            Source with varied whitespace.
        """
        lines = source.split("\n")
        result = []

        for line in lines:
            result.append(line)

            # Randomly add blank lines after some statements
            if line.strip() and self.rng.random() < 0.15:
                result.append("")

        # Randomly remove some existing blank lines
        final = []
        for line in result:
            if line.strip() == "" and self.rng.random() < 0.3:
                continue
            final.append(line)

        return "\n".join(final)

    def _inject_comments(self, source: str) -> str:
        """Insert benign comments at random positions.

        Args:
            source: Ruby source code.

        Returns:
            Source with injected comments.
        """
        lines = source.split("\n")
        result = []
        n_injections = self.rng.randint(1, min(5, max(1, len(lines) // 10)))
        injection_points = set(
            self.rng.sample(range(len(lines)), k=min(n_injections, len(lines)))
        )

        for i, line in enumerate(lines):
            if i in injection_points:
                # Match indentation of the current line
                indent = len(line) - len(line.lstrip())
                comment = self.rng.choice(self.BENIGN_COMMENTS)
                result.append(" " * indent + comment)
            result.append(line)

        return "\n".join(result)

    def _reorder_statements(self, source: str) -> str:
        """Reorder independent top-level statements.

        Only reorders require/require_relative statements and
        constant assignments that are order-independent.

        Args:
            source: Ruby source code.

        Returns:
            Source with reordered independent statements.
        """
        lines = source.split("\n")
        require_lines = []
        require_indices = []
        other_lines = []

        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("require ") or stripped.startswith("require_relative "):
                require_lines.append(line)
                require_indices.append(i)
            else:
                other_lines.append((i, line))

        if len(require_lines) > 1:
            self.rng.shuffle(require_lines)

        result = list(lines)
        for idx, req_line in zip(require_indices, require_lines):
            result[idx] = req_line

        return "\n".join(result)


class FeatureSpaceAugmentor:
    """Generates synthetic samples in feature space.

    Uses SMOTE-inspired interpolation, Gaussian noise injection,
    and feature-space mixup to generate synthetic training samples.
    """

    def __init__(
        self,
        random_state: int = 42,
        k_neighbors: int = 5,
    ) -> None:
        """Initialize the feature space augmentor.

        Args:
            random_state: Random seed.
            k_neighbors: Number of neighbors for SMOTE-like interpolation.
        """
        self.rng = np.random.RandomState(random_state)
        self.k_neighbors = k_neighbors
        logger.debug("FeatureSpaceAugmentor initialized")

    def smote_oversample(
        self,
        X: np.ndarray,
        y: np.ndarray,
        target_ratio: float = 1.0,
    ) -> tuple[np.ndarray, np.ndarray]:
        """Oversample minority classes using SMOTE-like interpolation.

        Args:
            X: Feature matrix of shape (n_samples, n_features).
            y: Label array of shape (n_samples,).
            target_ratio: Target ratio of minority to majority class.

        Returns:
            Tuple of (augmented_X, augmented_y).
        """
        classes, counts = np.unique(y, return_counts=True)
        max_count = int(counts.max() * target_ratio)

        X_aug = [X.copy()]
        y_aug = [y.copy()]

        for cls, count in zip(classes, counts):
            if count >= max_count:
                continue

            n_synthetic = max_count - count
            cls_mask = y == cls
            X_cls = X[cls_mask]

            if len(X_cls) < 2:
                # Duplicate with noise if too few samples
                synthetic = self._noise_augment(X_cls, n_synthetic)
            else:
                synthetic = self._interpolate_samples(X_cls, n_synthetic)

            X_aug.append(synthetic)
            y_aug.append(np.full(n_synthetic, cls))

            logger.debug(
                "SMOTE: generated {} synthetic samples for class {}",
                n_synthetic, cls,
            )

        return np.vstack(X_aug), np.concatenate(y_aug)

    def _interpolate_samples(
        self,
        X_class: np.ndarray,
        n_samples: int,
    ) -> np.ndarray:
        """Generate samples by interpolating between nearest neighbors.

        Args:
            X_class: Feature matrix for a single class.
            n_samples: Number of synthetic samples to generate.

        Returns:
            Synthetic feature matrix.
        """
        from sklearn.neighbors import NearestNeighbors

        k = min(self.k_neighbors, len(X_class) - 1)
        nn = NearestNeighbors(n_neighbors=k + 1)
        nn.fit(X_class)

        synthetic = np.zeros((n_samples, X_class.shape[1]))

        for i in range(n_samples):
            idx = self.rng.randint(0, len(X_class))
            distances, indices = nn.kneighbors(X_class[idx].reshape(1, -1))
            neighbor_idx = indices[0][self.rng.randint(1, k + 1)]

            alpha = self.rng.uniform(0.0, 1.0)
            synthetic[i] = X_class[idx] + alpha * (
                X_class[neighbor_idx] - X_class[idx]
            )

        return synthetic

    def _noise_augment(
        self,
        X: np.ndarray,
        n_samples: int,
        noise_scale: float = 0.05,
    ) -> np.ndarray:
        """Generate samples by adding Gaussian noise to existing ones.

        Args:
            X: Source feature matrix.
            n_samples: Number of synthetic samples.
            noise_scale: Standard deviation multiplier for noise.

        Returns:
            Synthetic feature matrix.
        """
        indices = self.rng.randint(0, len(X), size=n_samples)
        base_samples = X[indices]
        feature_stds = np.std(X, axis=0) + 1e-8
        noise = self.rng.randn(n_samples, X.shape[1]) * feature_stds * noise_scale
        return base_samples + noise

    def mixup_augment(
        self,
        X: np.ndarray,
        y: np.ndarray,
        n_samples: int,
        alpha: float = 0.2,
    ) -> tuple[np.ndarray, np.ndarray]:
        """Generate samples using mixup data augmentation.

        Creates new samples by convex combinations of existing pairs
        within the same class.

        Args:
            X: Feature matrix.
            y: Label array.
            n_samples: Number of mixup samples to generate.
            alpha: Beta distribution parameter for mixing coefficient.

        Returns:
            Tuple of (mixup_X, mixup_y).
        """
        classes = np.unique(y)
        X_mix = []
        y_mix = []

        samples_per_class = max(1, n_samples // len(classes))

        for cls in classes:
            cls_mask = y == cls
            X_cls = X[cls_mask]

            if len(X_cls) < 2:
                continue

            for _ in range(samples_per_class):
                idx1, idx2 = self.rng.choice(len(X_cls), size=2, replace=False)
                lam = self.rng.beta(alpha, alpha)
                mixed = lam * X_cls[idx1] + (1 - lam) * X_cls[idx2]
                X_mix.append(mixed)
                y_mix.append(cls)

        if not X_mix:
            return np.empty((0, X.shape[1])), np.empty(0)

        return np.array(X_mix), np.array(y_mix)


class DataAugmentor:
    """Unified data augmentation interface.

    Coordinates source-level and feature-space augmentation
    strategies based on training configuration.
    """

    def __init__(
        self,
        config_path: Optional[str | Path] = None,
        random_state: int = 42,
    ) -> None:
        """Initialize the data augmentor.

        Args:
            config_path: Path to training configuration.
            random_state: Random seed.
        """
        self.config_path = config_path
        self.random_state = random_state

        self.source_augmentor = SourceCodeAugmentor(
            config_path=config_path,
            random_state=random_state,
        )
        self.feature_augmentor = FeatureSpaceAugmentor(
            random_state=random_state,
        )

        logger.info("DataAugmentor initialized")

    def augment_source_files(
        self,
        input_dir: str | Path,
        output_dir: str | Path,
        n_variants: int = 2,
    ) -> int:
        """Augment all Ruby files in a directory.

        Args:
            input_dir: Directory containing Ruby source files.
            output_dir: Directory to write augmented files.
            n_variants: Number of variants per original file.

        Returns:
            Number of augmented files created.
        """
        input_path = Path(input_dir)
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        count = 0
        ruby_files = list(input_path.rglob("*.rb"))

        for rb_file in ruby_files:
            try:
                source = rb_file.read_text(encoding="utf-8", errors="replace")
                variants = self.source_augmentor.augment(source, n_variants)

                for i, variant in enumerate(variants):
                    out_name = f"{rb_file.stem}_aug{i}{rb_file.suffix}"
                    rel_dir = rb_file.parent.relative_to(input_path)
                    out_file = output_path / rel_dir / out_name
                    out_file.parent.mkdir(parents=True, exist_ok=True)
                    out_file.write_text(variant, encoding="utf-8")
                    count += 1
            except Exception as e:
                logger.warning("Failed to augment {}: {}", rb_file, e)

        logger.info("Generated {} augmented source files", count)
        return count

    def augment_features(
        self,
        X: np.ndarray,
        y: np.ndarray,
        method: str = "smote",
        **kwargs: Any,
    ) -> tuple[np.ndarray, np.ndarray]:
        """Augment the feature matrix.

        Args:
            X: Feature matrix.
            y: Label array.
            method: Augmentation method ('smote', 'noise', 'mixup').
            **kwargs: Additional arguments for the chosen method.

        Returns:
            Tuple of (augmented_X, augmented_y).
        """
        if method == "smote":
            return self.feature_augmentor.smote_oversample(X, y, **kwargs)
        elif method == "mixup":
            n_samples = kwargs.get("n_samples", X.shape[0] // 2)
            alpha = kwargs.get("alpha", 0.2)
            X_mix, y_mix = self.feature_augmentor.mixup_augment(
                X, y, n_samples, alpha
            )
            return (
                np.vstack([X, X_mix]) if len(X_mix) > 0 else X,
                np.concatenate([y, y_mix]) if len(y_mix) > 0 else y,
            )
        elif method == "noise":
            n_samples = kwargs.get("n_samples", X.shape[0] // 4)
            noise_scale = kwargs.get("noise_scale", 0.05)
            X_noise = self.feature_augmentor._noise_augment(X, n_samples, noise_scale)
            indices = np.random.RandomState(self.random_state).randint(0, len(y), size=n_samples)
            y_noise = y[indices]
            return np.vstack([X, X_noise]), np.concatenate([y, y_noise])
        else:
            raise ValueError(f"Unknown augmentation method: {method}")

    def balance_classes(
        self,
        X: np.ndarray,
        y: np.ndarray,
    ) -> tuple[np.ndarray, np.ndarray]:
        """Balance classes using SMOTE oversampling.

        Args:
            X: Feature matrix.
            y: Label array.

        Returns:
            Balanced (X, y) tuple.
        """
        return self.feature_augmentor.smote_oversample(X, y, target_ratio=1.0)
