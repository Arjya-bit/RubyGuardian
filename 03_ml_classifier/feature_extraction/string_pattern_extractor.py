"""
String pattern feature extractor for Ruby scripts.

Scans source code for suspicious string patterns including IP addresses,
URLs, Base64 encoded data, hex strings, shell commands, and encoded payloads.
"""

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import numpy as np
import yaml
from loguru import logger


@dataclass
class StringPatternFeatures:
    """Container for string pattern features."""

    ip_address_count: int = 0
    url_count: int = 0
    base64_string_count: int = 0
    hex_string_count: int = 0
    shell_command_count: int = 0
    encoded_payload_count: int = 0
    network_port_count: int = 0
    suspicious_string_score: float = 0.0
    total_string_literal_count: int = 0
    avg_string_length: float = 0.0
    max_string_length: int = 0
    long_string_count: int = 0

    def to_dict(self) -> dict:
        """Convert to a flat dictionary with prefixed keys."""
        return {
            "strpat_ip_address_count": self.ip_address_count,
            "strpat_url_count": self.url_count,
            "strpat_base64_string_count": self.base64_string_count,
            "strpat_hex_string_count": self.hex_string_count,
            "strpat_shell_command_count": self.shell_command_count,
            "strpat_encoded_payload_count": self.encoded_payload_count,
            "strpat_network_port_count": self.network_port_count,
            "strpat_suspicious_string_score": self.suspicious_string_score,
            "strpat_total_string_literal_count": self.total_string_literal_count,
            "strpat_avg_string_length": self.avg_string_length,
            "strpat_max_string_length": self.max_string_length,
            "strpat_long_string_count": self.long_string_count,
        }

    def to_array(self) -> np.ndarray:
        """Convert features to numpy array."""
        return np.array(list(self.to_dict().values()), dtype=np.float64)


class StringPatternExtractor:
    """Extracts string-pattern-based features from Ruby source code.

    Identifies suspicious string patterns that are commonly found in
    malicious Ruby scripts, such as encoded payloads, hardcoded IPs,
    shell command strings, and obfuscated data.
    """

    DEFAULT_PATTERNS = {
        "ip_addresses": {
            "regex": r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
            "weight": 1.5,
        },
        "urls": {
            "regex": r'https?://[^\s"\x27\)]+',
            "weight": 1.0,
        },
        "base64_strings": {
            "regex": r'[A-Za-z0-9+/]{40,}={0,2}',
            "weight": 2.0,
        },
        "hex_strings": {
            "regex": r'(?:0x|\\x)[0-9a-fA-F]{2,}',
            "weight": 1.8,
        },
        "shell_commands": {
            "regex": r'(?:system|exec|`|%x)\s*[\(\[]?\s*["\x27]',
            "weight": 2.5,
        },
        "encoded_payloads": {
            "regex": r'eval\s*\(\s*(?:Base64\.decode|decode64|unpack)',
            "weight": 3.0,
        },
        "network_ports": {
            "regex": r'(?:bind|connect|listen)\s*\(.*\b\d{2,5}\b',
            "weight": 2.0,
        },
    }

    # Pattern to extract string literals from Ruby
    STRING_LITERAL_PATTERN = re.compile(
        r'"(?:[^"\\]|\\.)*"|' r"'(?:[^'\\]|\\.)*'"
    )

    LONG_STRING_THRESHOLD = 100

    def __init__(
        self,
        config_path: Optional[str | Path] = None,
        patterns: Optional[dict] = None,
    ) -> None:
        """Initialize the string pattern extractor.

        Args:
            config_path: Optional path to feature config YAML.
            patterns: Optional custom pattern definitions.
        """
        if patterns:
            self.patterns = patterns
        elif config_path:
            self.patterns = self._load_patterns_from_config(config_path)
        else:
            self.patterns = self.DEFAULT_PATTERNS

        self._compiled_patterns: dict[str, re.Pattern] = {}
        for name, spec in self.patterns.items():
            try:
                self._compiled_patterns[name] = re.compile(spec["regex"])
            except re.error as e:
                logger.warning("Invalid regex for pattern '{}': {}", name, e)

        logger.debug(
            "StringPatternExtractor initialized with {} patterns",
            len(self._compiled_patterns),
        )

    def _load_patterns_from_config(self, config_path: str | Path) -> dict:
        """Load pattern definitions from a YAML config file.

        Args:
            config_path: Path to the feature config YAML.

        Returns:
            Dictionary of pattern specifications.
        """
        path = Path(config_path)
        if not path.exists():
            logger.warning("Config not found at {}, using defaults", path)
            return self.DEFAULT_PATTERNS

        with open(path) as f:
            config = yaml.safe_load(f)

        return config.get("string_pattern_features", {}).get(
            "patterns", self.DEFAULT_PATTERNS
        )

    def extract(self, source_code: str) -> StringPatternFeatures:
        """Extract string pattern features from Ruby source code.

        Args:
            source_code: Raw Ruby source code.

        Returns:
            StringPatternFeatures with all computed metrics.
        """
        features = StringPatternFeatures()

        # Count pattern matches
        pattern_counts = {}
        for name, pattern in self._compiled_patterns.items():
            matches = pattern.findall(source_code)
            pattern_counts[name] = len(matches)

        features.ip_address_count = pattern_counts.get("ip_addresses", 0)
        features.url_count = pattern_counts.get("urls", 0)
        features.base64_string_count = pattern_counts.get("base64_strings", 0)
        features.hex_string_count = pattern_counts.get("hex_strings", 0)
        features.shell_command_count = pattern_counts.get("shell_commands", 0)
        features.encoded_payload_count = pattern_counts.get("encoded_payloads", 0)
        features.network_port_count = pattern_counts.get("network_ports", 0)

        # Compute weighted suspicious score
        weighted_score = 0.0
        for name, count in pattern_counts.items():
            weight = self.patterns.get(name, {}).get("weight", 1.0)
            weighted_score += count * weight
        features.suspicious_string_score = weighted_score

        # Analyze string literals
        string_literals = self.STRING_LITERAL_PATTERN.findall(source_code)
        features.total_string_literal_count = len(string_literals)

        if string_literals:
            lengths = [len(s) - 2 for s in string_literals]  # Subtract quotes
            features.avg_string_length = float(np.mean(lengths))
            features.max_string_length = max(lengths)
            features.long_string_count = sum(
                1 for l in lengths if l > self.LONG_STRING_THRESHOLD
            )

        logger.debug(
            "Extracted string patterns: suspicious_score={:.2f}",
            features.suspicious_string_score,
        )
        return features

    def extract_from_file(self, file_path: str | Path) -> StringPatternFeatures:
        """Extract string pattern features from a Ruby file.

        Args:
            file_path: Path to the Ruby source file.

        Returns:
            StringPatternFeatures dataclass.
        """
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Ruby file not found: {path}")
        source_code = path.read_text(encoding="utf-8", errors="replace")
        return self.extract(source_code)
