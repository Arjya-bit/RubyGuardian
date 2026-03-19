"""
Entropy-based feature extractor for Ruby scripts.

Computes Shannon entropy metrics at the file level, string level,
and block level to detect encoded payloads, encrypted content,
and compressed data commonly found in obfuscated malware.
"""

import math
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import numpy as np
import yaml
from loguru import logger


@dataclass
class EntropyFeatures:
    """Container for entropy-based features."""

    file_entropy: float = 0.0
    string_entropy_mean: float = 0.0
    string_entropy_max: float = 0.0
    string_entropy_std: float = 0.0
    block_entropy_variance: float = 0.0
    high_entropy_block_count: int = 0
    high_entropy_string_count: int = 0
    normalized_file_entropy: float = 0.0
    entropy_delta_first_last_quarter: float = 0.0
    printable_ratio: float = 0.0

    def to_dict(self) -> dict:
        """Convert to a flat dictionary with prefixed keys."""
        return {
            "ent_file_entropy": self.file_entropy,
            "ent_string_entropy_mean": self.string_entropy_mean,
            "ent_string_entropy_max": self.string_entropy_max,
            "ent_string_entropy_std": self.string_entropy_std,
            "ent_block_entropy_variance": self.block_entropy_variance,
            "ent_high_entropy_block_count": self.high_entropy_block_count,
            "ent_high_entropy_string_count": self.high_entropy_string_count,
            "ent_normalized_file_entropy": self.normalized_file_entropy,
            "ent_entropy_delta_first_last_quarter": self.entropy_delta_first_last_quarter,
            "ent_printable_ratio": self.printable_ratio,
        }

    def to_array(self) -> np.ndarray:
        """Convert features to numpy array."""
        return np.array(list(self.to_dict().values()), dtype=np.float64)


class EntropyCalculator:
    """Computes entropy-based features from Ruby source code.

    Shannon entropy is a strong indicator of obfuscation and encoding.
    Legitimate Ruby code typically has entropy between 4.0 and 5.5,
    while Base64-encoded, encrypted, or compressed payloads tend to
    have entropy above 6.0.
    """

    # Maximum theoretical entropy for byte data
    MAX_BYTE_ENTROPY = 8.0

    # Pattern to extract string literals from Ruby source
    STRING_LITERAL_PATTERN = re.compile(
        r'"(?:[^"\\]|\\.)*"|'
        r"'(?:[^'\\]|\\.)*'"
    )

    # Printable ASCII range
    PRINTABLE_RANGE = set(range(32, 127))

    def __init__(
        self,
        config_path: Optional[str | Path] = None,
        block_size: int = 256,
        high_entropy_threshold: float = 6.0,
    ) -> None:
        """Initialize the entropy calculator.

        Args:
            config_path: Optional path to feature config YAML.
            block_size: Size of blocks for block-level entropy analysis.
            high_entropy_threshold: Threshold above which a block or
                string is considered high-entropy.
        """
        self.block_size = block_size
        self.high_entropy_threshold = high_entropy_threshold

        if config_path:
            self._load_config(config_path)

        logger.debug(
            "EntropyCalculator initialized (block_size={}, threshold={})",
            self.block_size,
            self.high_entropy_threshold,
        )

    def _load_config(self, config_path: str | Path) -> None:
        """Load entropy settings from a YAML config file.

        Args:
            config_path: Path to the feature configuration file.
        """
        path = Path(config_path)
        if not path.exists():
            return

        with open(path) as f:
            config = yaml.safe_load(f)

        ent_config = config.get("entropy_features", {})
        self.block_size = ent_config.get("block_size", self.block_size)
        self.high_entropy_threshold = ent_config.get(
            "high_entropy_threshold", self.high_entropy_threshold
        )

    def extract(self, source_code: str) -> EntropyFeatures:
        """Extract entropy-based features from Ruby source code.

        Args:
            source_code: Raw Ruby source code.

        Returns:
            EntropyFeatures with all computed metrics.
        """
        features = EntropyFeatures()

        if not source_code:
            return features

        raw_bytes = source_code.encode("utf-8", errors="replace")

        # File-level entropy
        features.file_entropy = self._shannon_entropy(raw_bytes)
        features.normalized_file_entropy = (
            features.file_entropy / self.MAX_BYTE_ENTROPY
        )

        # Printable character ratio
        printable_count = sum(1 for b in raw_bytes if b in self.PRINTABLE_RANGE)
        features.printable_ratio = (
            printable_count / len(raw_bytes) if raw_bytes else 0.0
        )

        # String-level entropy analysis
        string_entropies = self._compute_string_entropies(source_code)
        if string_entropies:
            features.string_entropy_mean = float(np.mean(string_entropies))
            features.string_entropy_max = float(np.max(string_entropies))
            features.string_entropy_std = float(np.std(string_entropies))
            features.high_entropy_string_count = sum(
                1 for e in string_entropies if e > self.high_entropy_threshold
            )

        # Block-level entropy analysis
        block_entropies = self._compute_block_entropies(raw_bytes)
        if block_entropies:
            features.block_entropy_variance = float(np.var(block_entropies))
            features.high_entropy_block_count = sum(
                1 for e in block_entropies if e > self.high_entropy_threshold
            )

            # Entropy delta between first and last quarter
            quarter_len = max(1, len(block_entropies) // 4)
            first_quarter_mean = float(np.mean(block_entropies[:quarter_len]))
            last_quarter_mean = float(np.mean(block_entropies[-quarter_len:]))
            features.entropy_delta_first_last_quarter = abs(
                last_quarter_mean - first_quarter_mean
            )

        logger.debug(
            "Entropy features: file={:.3f}, string_mean={:.3f}, blocks={}",
            features.file_entropy,
            features.string_entropy_mean,
            len(block_entropies),
        )
        return features

    def extract_from_file(self, file_path: str | Path) -> EntropyFeatures:
        """Extract entropy features from a Ruby file.

        Args:
            file_path: Path to the Ruby source file.

        Returns:
            EntropyFeatures dataclass.

        Raises:
            FileNotFoundError: If the file does not exist.
        """
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Ruby file not found: {path}")
        source_code = path.read_text(encoding="utf-8", errors="replace")
        return self.extract(source_code)

    @staticmethod
    def _shannon_entropy(data: bytes) -> float:
        """Compute Shannon entropy for a byte sequence.

        Args:
            data: Raw byte sequence.

        Returns:
            Shannon entropy in bits (0.0 to 8.0 for byte data).
        """
        if not data:
            return 0.0

        counter = Counter(data)
        length = len(data)
        entropy = 0.0

        for count in counter.values():
            if count > 0:
                probability = count / length
                entropy -= probability * math.log2(probability)

        return entropy

    def _compute_string_entropies(self, source_code: str) -> list[float]:
        """Compute entropy for each string literal in the source.

        Args:
            source_code: Raw Ruby source code.

        Returns:
            List of entropy values for each string literal.
        """
        string_literals = self.STRING_LITERAL_PATTERN.findall(source_code)
        entropies: list[float] = []

        for literal in string_literals:
            # Strip surrounding quotes
            content = literal[1:-1]
            if len(content) < 4:
                continue
            raw = content.encode("utf-8", errors="replace")
            entropies.append(self._shannon_entropy(raw))

        return entropies

    def _compute_block_entropies(self, data: bytes) -> list[float]:
        """Compute entropy for fixed-size blocks of the data.

        Args:
            data: Raw byte data.

        Returns:
            List of entropy values, one per block.
        """
        if len(data) < self.block_size:
            return [self._shannon_entropy(data)] if data else []

        entropies: list[float] = []
        for offset in range(0, len(data), self.block_size):
            block = data[offset : offset + self.block_size]
            if len(block) >= self.block_size // 2:
                entropies.append(self._shannon_entropy(block))

        return entropies
