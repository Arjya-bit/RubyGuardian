"""
Entropy-based feature extractor for Ruby source code.

Calculates Shannon entropy, byte-level distribution statistics, and
encoding characteristics. High entropy and non-uniform byte distributions
are indicators of obfuscated or encrypted payloads.
"""

import logging
import math
import string
from collections import Counter
from typing import Any

logger = logging.getLogger("rubyguardian.features.entropy_extractor")

_PRINTABLE_SET = set(string.printable)
_COMMON_ENCODINGS = ["utf-8", "ascii", "latin-1", "shift_jis", "euc-jp", "iso-8859-1"]


class EntropyFeatureExtractor:
    """
    Extracts entropy and byte-distribution features from source code.

    These features help identify obfuscated, packed, or encrypted
    payloads embedded within Ruby scripts.
    """

    name = "entropy"
    version = "1.1.0"

    def extract(self, source: str) -> dict[str, Any]:
        """
        Extract entropy-based features from the given source text.

        Args:
            source: Ruby source code string.

        Returns:
            Dictionary of feature name to numeric value.
        """
        if not source:
            return self._empty_features()

        raw_bytes = source.encode("utf-8", errors="replace")
        byte_counts = Counter(raw_bytes)
        total_bytes = len(raw_bytes)

        features: dict[str, Any] = {}

        # Shannon entropy
        features["entropy"] = self._shannon_entropy(byte_counts, total_bytes)

        # Byte distribution analysis
        features["byte_distribution_uniformity"] = self._distribution_uniformity(
            byte_counts, total_bytes
        )
        features["unique_byte_count"] = len(byte_counts)
        features["unique_byte_ratio"] = len(byte_counts) / 256.0

        # Character class ratios
        features["printable_ratio"] = self._printable_ratio(source)
        features["alpha_ratio"] = self._char_class_ratio(source, str.isalpha)
        features["digit_ratio"] = self._char_class_ratio(source, str.isdigit)
        features["whitespace_ratio"] = self._char_class_ratio(source, str.isspace)
        features["special_char_ratio"] = 1.0 - (
            features["alpha_ratio"] + features["digit_ratio"] + features["whitespace_ratio"]
        )

        # Encoding detection
        features["detected_encoding"] = self._detect_encoding(raw_bytes)
        features["is_ascii_compatible"] = all(b < 128 for b in raw_bytes)

        # Substring entropy (sliding window)
        features["max_window_entropy"] = self._max_window_entropy(raw_bytes, window_size=256)
        features["min_window_entropy"] = self._min_window_entropy(raw_bytes, window_size=256)
        features["entropy_variance"] = self._entropy_variance(raw_bytes, window_size=256)

        # Base64 / hex indicators
        features["base64_segment_count"] = self._count_base64_segments(source)
        features["hex_segment_count"] = self._count_hex_segments(source)
        features["long_string_count"] = self._count_long_strings(source, min_length=100)

        return features

    def _shannon_entropy(self, byte_counts: Counter, total: int) -> float:
        """Calculate Shannon entropy in bits (0.0 to 8.0 for bytes)."""
        if total == 0:
            return 0.0
        entropy = 0.0
        for count in byte_counts.values():
            if count > 0:
                p = count / total
                entropy -= p * math.log2(p)
        return round(entropy, 4)

    def _distribution_uniformity(self, byte_counts: Counter, total: int) -> float:
        """
        Calculate how uniform the byte distribution is (0.0 to 1.0).
        A perfectly uniform distribution of 256 byte values scores 1.0.
        """
        if total == 0:
            return 0.0
        expected = total / 256.0
        chi_squared = sum(
            (byte_counts.get(i, 0) - expected) ** 2 / expected
            for i in range(256)
        )
        max_chi = total * 255.0  # worst case: all same byte
        uniformity = 1.0 - (chi_squared / max_chi) if max_chi > 0 else 0.0
        return round(max(0.0, min(1.0, uniformity)), 4)

    def _printable_ratio(self, source: str) -> float:
        """Fraction of characters that are printable ASCII."""
        if not source:
            return 0.0
        printable_count = sum(1 for c in source if c in _PRINTABLE_SET)
        return round(printable_count / len(source), 4)

    def _char_class_ratio(self, source: str, predicate) -> float:
        """Fraction of characters matching the given predicate."""
        if not source:
            return 0.0
        count = sum(1 for c in source if predicate(c))
        return round(count / len(source), 4)

    def _detect_encoding(self, raw_bytes: bytes) -> str:
        """Attempt to detect the text encoding of the raw bytes."""
        for encoding in _COMMON_ENCODINGS:
            try:
                raw_bytes.decode(encoding)
                return encoding
            except (UnicodeDecodeError, LookupError):
                continue
        return "unknown"

    def _window_entropies(self, raw_bytes: bytes, window_size: int) -> list[float]:
        """Calculate Shannon entropy for each sliding window position."""
        if len(raw_bytes) <= window_size:
            counts = Counter(raw_bytes)
            return [self._shannon_entropy(counts, len(raw_bytes))]
        entropies = []
        for i in range(0, len(raw_bytes) - window_size + 1, window_size // 4):
            window = raw_bytes[i : i + window_size]
            counts = Counter(window)
            entropies.append(self._shannon_entropy(counts, len(window)))
        return entropies

    def _max_window_entropy(self, raw_bytes: bytes, window_size: int) -> float:
        entropies = self._window_entropies(raw_bytes, window_size)
        return round(max(entropies) if entropies else 0.0, 4)

    def _min_window_entropy(self, raw_bytes: bytes, window_size: int) -> float:
        entropies = self._window_entropies(raw_bytes, window_size)
        return round(min(entropies) if entropies else 0.0, 4)

    def _entropy_variance(self, raw_bytes: bytes, window_size: int) -> float:
        entropies = self._window_entropies(raw_bytes, window_size)
        if len(entropies) < 2:
            return 0.0
        mean = sum(entropies) / len(entropies)
        variance = sum((e - mean) ** 2 for e in entropies) / len(entropies)
        return round(variance, 6)

    def _count_base64_segments(self, source: str) -> int:
        """Count segments that look like Base64-encoded data."""
        import re
        matches = re.findall(r"[A-Za-z0-9+/]{20,}={0,2}", source)
        return len(matches)

    def _count_hex_segments(self, source: str) -> int:
        """Count segments that look like hex-encoded data."""
        import re
        matches = re.findall(r"(?:\\x[0-9a-fA-F]{2}){4,}", source)
        return len(matches)

    def _count_long_strings(self, source: str, min_length: int = 100) -> int:
        """Count string literals longer than min_length characters."""
        import re
        matches = re.findall(r"""(["'])(.+?)\1""", source, re.DOTALL)
        return sum(1 for _, content in matches if len(content) >= min_length)

    def _empty_features(self) -> dict[str, Any]:
        return {
            "entropy": 0.0,
            "byte_distribution_uniformity": 0.0,
            "unique_byte_count": 0,
            "unique_byte_ratio": 0.0,
            "printable_ratio": 0.0,
            "alpha_ratio": 0.0,
            "digit_ratio": 0.0,
            "whitespace_ratio": 0.0,
            "special_char_ratio": 0.0,
            "detected_encoding": "unknown",
            "is_ascii_compatible": True,
            "max_window_entropy": 0.0,
            "min_window_entropy": 0.0,
            "entropy_variance": 0.0,
            "base64_segment_count": 0,
            "hex_segment_count": 0,
            "long_string_count": 0,
        }
