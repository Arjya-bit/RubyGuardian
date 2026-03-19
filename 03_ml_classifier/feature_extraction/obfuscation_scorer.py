"""
Obfuscation scoring feature extractor for Ruby scripts.

Computes an obfuscation score based on indicators such as single-character
variable names, hex character usage, eval chains, encoding layers, and
other techniques commonly used to hide malicious intent.
"""

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import numpy as np
import yaml
from loguru import logger


@dataclass
class ObfuscationFeatures:
    """Container for obfuscation scoring features."""

    single_char_variables_ratio: float = 0.0
    hex_char_usage_count: int = 0
    eval_chain_depth: int = 0
    string_concatenation_complexity: int = 0
    encoding_layer_count: int = 0
    unicode_escape_usage: int = 0
    marshal_load_usage: int = 0
    dynamic_constant_resolution: int = 0
    overall_obfuscation_score: float = 0.0
    obfuscation_level: str = "none"

    def to_dict(self) -> dict:
        """Convert to a flat dictionary with prefixed keys."""
        return {
            "obf_single_char_var_ratio": self.single_char_variables_ratio,
            "obf_hex_char_usage": self.hex_char_usage_count,
            "obf_eval_chain_depth": self.eval_chain_depth,
            "obf_string_concat_complexity": self.string_concatenation_complexity,
            "obf_encoding_layer_count": self.encoding_layer_count,
            "obf_unicode_escape_usage": self.unicode_escape_usage,
            "obf_marshal_load_usage": self.marshal_load_usage,
            "obf_dynamic_const_resolution": self.dynamic_constant_resolution,
            "obf_overall_score": self.overall_obfuscation_score,
            "obf_level_encoded": self._encode_level(),
        }

    def _encode_level(self) -> float:
        """Encode obfuscation level as a numeric value."""
        levels = {"none": 0.0, "low": 0.25, "medium": 0.5, "high": 0.85}
        return levels.get(self.obfuscation_level, 0.0)

    def to_array(self) -> np.ndarray:
        """Convert features to numpy array."""
        return np.array(list(self.to_dict().values()), dtype=np.float64)


class ObfuscationScorer:
    """Scores Ruby scripts for obfuscation indicators.

    Analyzes multiple obfuscation signals and produces an overall
    obfuscation score that indicates the likelihood that the script
    uses deliberate obfuscation techniques.
    """

    # Patterns for obfuscation detection
    SINGLE_CHAR_VAR = re.compile(r'\b([a-z_])\s*=\s', re.MULTILINE)
    ALL_VARIABLES = re.compile(r'\b([a-z_]\w*)\s*=\s', re.MULTILINE)
    HEX_CHARS = re.compile(r'\\x[0-9a-fA-F]{2}')
    EVAL_CHAIN = re.compile(r'eval\s*\(', re.MULTILINE)
    NESTED_EVAL = re.compile(r'eval\s*\(\s*eval', re.MULTILINE)
    STRING_CONCAT = re.compile(r'(?:["\x27]\s*\+\s*["\x27])|(?:\s*<<\s*["\x27])')
    ENCODING_METHODS = re.compile(
        r'(?:Base64\.(?:encode64|decode64|strict_encode64|strict_decode64)|'
        r'\.pack\s*\(|\.unpack\s*\(|'
        r'encode\s*\(\s*["\x27]|decode\s*\(\s*["\x27]|'
        r'URI\.(?:encode|decode)|CGI\.(?:escape|unescape))',
        re.MULTILINE,
    )
    UNICODE_ESCAPE = re.compile(r'\\u[0-9a-fA-F]{4}')
    MARSHAL_LOAD = re.compile(r'Marshal\.(?:load|restore)', re.MULTILINE)
    DYNAMIC_CONST = re.compile(
        r'(?:const_get|const_set|Object\.const_get)\s*\(', re.MULTILINE
    )

    # Thresholds
    DEFAULT_THRESHOLDS = {"low": 0.3, "medium": 0.6, "high": 0.85}

    # Weights for each indicator in the overall score
    INDICATOR_WEIGHTS = {
        "single_char_variables_ratio": 0.10,
        "hex_char_usage": 0.15,
        "eval_chain_depth": 0.20,
        "string_concat_complexity": 0.10,
        "encoding_layer_count": 0.20,
        "unicode_escape_usage": 0.05,
        "marshal_load_usage": 0.10,
        "dynamic_constant_resolution": 0.10,
    }

    def __init__(
        self,
        config_path: Optional[str | Path] = None,
        thresholds: Optional[dict[str, float]] = None,
    ) -> None:
        """Initialize the obfuscation scorer.

        Args:
            config_path: Optional path to feature config YAML.
            thresholds: Optional custom thresholds for levels.
        """
        self.thresholds = thresholds or self.DEFAULT_THRESHOLDS

        if config_path:
            self._load_config(config_path)

        logger.debug("ObfuscationScorer initialized")

    def _load_config(self, config_path: str | Path) -> None:
        """Load thresholds from config file.

        Args:
            config_path: Path to feature config YAML.
        """
        path = Path(config_path)
        if not path.exists():
            return

        with open(path) as f:
            config = yaml.safe_load(f)

        obf_config = config.get("obfuscation_features", {})
        if "thresholds" in obf_config:
            self.thresholds.update(obf_config["thresholds"])

    def extract(self, source_code: str) -> ObfuscationFeatures:
        """Extract obfuscation features and compute overall score.

        Args:
            source_code: Raw Ruby source code.

        Returns:
            ObfuscationFeatures with computed metrics and score.
        """
        features = ObfuscationFeatures()

        # Single-char variable ratio
        all_vars = self.ALL_VARIABLES.findall(source_code)
        single_char_vars = self.SINGLE_CHAR_VAR.findall(source_code)
        if all_vars:
            features.single_char_variables_ratio = len(single_char_vars) / len(all_vars)

        # Hex character usage
        features.hex_char_usage_count = len(self.HEX_CHARS.findall(source_code))

        # Eval chain depth
        eval_count = len(self.EVAL_CHAIN.findall(source_code))
        nested_eval_count = len(self.NESTED_EVAL.findall(source_code))
        features.eval_chain_depth = eval_count + nested_eval_count * 2

        # String concatenation complexity
        features.string_concatenation_complexity = len(
            self.STRING_CONCAT.findall(source_code)
        )

        # Encoding layers
        features.encoding_layer_count = len(
            self.ENCODING_METHODS.findall(source_code)
        )

        # Unicode escape usage
        features.unicode_escape_usage = len(
            self.UNICODE_ESCAPE.findall(source_code)
        )

        # Marshal load usage
        features.marshal_load_usage = len(
            self.MARSHAL_LOAD.findall(source_code)
        )

        # Dynamic constant resolution
        features.dynamic_constant_resolution = len(
            self.DYNAMIC_CONST.findall(source_code)
        )

        # Compute overall obfuscation score (0.0 to 1.0)
        features.overall_obfuscation_score = self._compute_overall_score(features)

        # Determine obfuscation level
        features.obfuscation_level = self._determine_level(
            features.overall_obfuscation_score
        )

        logger.debug(
            "Obfuscation score: {:.3f} (level={})",
            features.overall_obfuscation_score,
            features.obfuscation_level,
        )
        return features

    def extract_from_file(self, file_path: str | Path) -> ObfuscationFeatures:
        """Extract obfuscation features from a Ruby file.

        Args:
            file_path: Path to the Ruby source file.

        Returns:
            ObfuscationFeatures dataclass.
        """
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Ruby file not found: {path}")
        source_code = path.read_text(encoding="utf-8", errors="replace")
        return self.extract(source_code)

    def _compute_overall_score(self, features: ObfuscationFeatures) -> float:
        """Compute a normalized overall obfuscation score.

        Combines individual indicator scores using weighted averaging
        with sigmoid normalization for count-based features.

        Args:
            features: Partially populated ObfuscationFeatures.

        Returns:
            Overall score between 0.0 and 1.0.
        """
        # Normalize count features using sigmoid
        normalized = {
            "single_char_variables_ratio": features.single_char_variables_ratio,
            "hex_char_usage": self._sigmoid_normalize(
                features.hex_char_usage_count, midpoint=5
            ),
            "eval_chain_depth": self._sigmoid_normalize(
                features.eval_chain_depth, midpoint=2
            ),
            "string_concat_complexity": self._sigmoid_normalize(
                features.string_concatenation_complexity, midpoint=10
            ),
            "encoding_layer_count": self._sigmoid_normalize(
                features.encoding_layer_count, midpoint=3
            ),
            "unicode_escape_usage": self._sigmoid_normalize(
                features.unicode_escape_usage, midpoint=5
            ),
            "marshal_load_usage": self._sigmoid_normalize(
                features.marshal_load_usage, midpoint=1
            ),
            "dynamic_constant_resolution": self._sigmoid_normalize(
                features.dynamic_constant_resolution, midpoint=2
            ),
        }

        score = sum(
            normalized[key] * weight
            for key, weight in self.INDICATOR_WEIGHTS.items()
        )
        return float(min(1.0, max(0.0, score)))

    @staticmethod
    def _sigmoid_normalize(value: float, midpoint: float = 5.0) -> float:
        """Normalize a count value to [0, 1] using a sigmoid function.

        Args:
            value: Raw count value.
            midpoint: Value at which the sigmoid outputs 0.5.

        Returns:
            Normalized value between 0.0 and 1.0.
        """
        return float(1.0 / (1.0 + np.exp(-1.0 * (value - midpoint))))

    def _determine_level(self, score: float) -> str:
        """Determine the obfuscation level label from the score.

        Args:
            score: Overall obfuscation score (0.0 to 1.0).

        Returns:
            Level string: 'none', 'low', 'medium', or 'high'.
        """
        if score >= self.thresholds["high"]:
            return "high"
        elif score >= self.thresholds["medium"]:
            return "medium"
        elif score >= self.thresholds["low"]:
            return "low"
        return "none"
