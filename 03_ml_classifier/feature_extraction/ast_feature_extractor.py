"""
AST-based feature extractor for Ruby scripts.

Parses Ruby source code into an abstract syntax tree representation
and extracts structural features related to code complexity,
control flow, and potentially suspicious patterns.
"""

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import numpy as np
from loguru import logger


@dataclass
class ASTFeatures:
    """Container for AST-derived features."""

    ast_depth: int = 0
    ast_node_count: int = 0
    method_call_count: int = 0
    block_count: int = 0
    conditional_count: int = 0
    loop_count: int = 0
    assignment_count: int = 0
    exception_handling_count: int = 0
    yield_count: int = 0
    lambda_count: int = 0
    dynamic_dispatch_count: int = 0
    node_type_entropy: float = 0.0

    def to_dict(self) -> dict:
        """Convert to a flat dictionary with prefixed keys."""
        return {
            "ast_depth": self.ast_depth,
            "ast_node_count": self.ast_node_count,
            "ast_method_call_count": self.method_call_count,
            "ast_block_count": self.block_count,
            "ast_conditional_count": self.conditional_count,
            "ast_loop_count": self.loop_count,
            "ast_assignment_count": self.assignment_count,
            "ast_exception_handling_count": self.exception_handling_count,
            "ast_yield_count": self.yield_count,
            "ast_lambda_count": self.lambda_count,
            "ast_dynamic_dispatch_count": self.dynamic_dispatch_count,
            "ast_node_type_entropy": self.node_type_entropy,
        }

    def to_array(self) -> np.ndarray:
        """Convert features to a numpy array."""
        return np.array(list(self.to_dict().values()), dtype=np.float64)


class ASTFeatureExtractor:
    """Extracts features from an approximate AST representation of Ruby code.

    Since full Ruby AST parsing requires a Ruby runtime, this extractor
    uses regex-based heuristics to approximate AST-level features from
    the source text. For production use, consider integrating with
    the `parser` gem via subprocess.
    """

    # Patterns for various Ruby constructs
    PATTERNS = {
        "method_call": re.compile(
            r'(?<!\bdef\s)(?<!\bclass\s)(?<!\bmodule\s)'
            r'\b([a-z_]\w*)\s*[\(.]'
        ),
        "dot_call": re.compile(r'\.\s*([a-z_]\w*)\s*[\(\s]?'),
        "block": re.compile(r'\b(?:do\b|\{)\s*\|'),
        "block_brace": re.compile(r'\{\s*(?:\|[^|]*\|)?'),
        "conditional": re.compile(r'\b(?:if|unless|elsif|case|when)\b'),
        "ternary": re.compile(r'\?.*:'),
        "loop": re.compile(r'\b(?:while|until|for|loop|each|map|select|reject|collect)\b'),
        "assignment": re.compile(r'[^!=<>]=[^=~>]'),
        "exception": re.compile(r'\b(?:begin|rescue|ensure|raise|retry)\b'),
        "yield_kw": re.compile(r'\byield\b'),
        "lambda": re.compile(r'(?:->|lambda)\s*[\{\(]'),
        "proc_new": re.compile(r'Proc\.new'),
        "dynamic_dispatch": re.compile(
            r'\b(?:send|public_send|__send__|method|define_method|'
            r'method_missing|respond_to_missing\?|instance_variable_get|'
            r'instance_variable_set|const_get|const_set)\b'
        ),
        "nesting_open": re.compile(
            r'\b(?:def|class|module|do|if|unless|while|until|for|case|begin)\b'
        ),
        "nesting_close": re.compile(r'\bend\b'),
    }

    def __init__(self) -> None:
        """Initialize the AST feature extractor."""
        logger.debug("ASTFeatureExtractor initialized")

    def extract(self, source_code: str) -> ASTFeatures:
        """Extract AST-approximate features from Ruby source code.

        Args:
            source_code: Raw Ruby source code.

        Returns:
            ASTFeatures dataclass with computed metrics.
        """
        features = ASTFeatures()
        lines = source_code.splitlines()

        # Strip comments and string literals for more accurate counting
        cleaned = self._strip_comments_and_strings(source_code)

        features.method_call_count = (
            len(self.PATTERNS["method_call"].findall(cleaned))
            + len(self.PATTERNS["dot_call"].findall(cleaned))
        )
        features.block_count = (
            len(self.PATTERNS["block"].findall(cleaned))
            + len(self.PATTERNS["block_brace"].findall(cleaned))
        )
        features.conditional_count = (
            len(self.PATTERNS["conditional"].findall(cleaned))
            + len(self.PATTERNS["ternary"].findall(cleaned))
        )
        features.loop_count = len(self.PATTERNS["loop"].findall(cleaned))
        features.assignment_count = len(self.PATTERNS["assignment"].findall(cleaned))
        features.exception_handling_count = len(
            self.PATTERNS["exception"].findall(cleaned)
        )
        features.yield_count = len(self.PATTERNS["yield_kw"].findall(cleaned))
        features.lambda_count = (
            len(self.PATTERNS["lambda"].findall(cleaned))
            + len(self.PATTERNS["proc_new"].findall(cleaned))
        )
        features.dynamic_dispatch_count = len(
            self.PATTERNS["dynamic_dispatch"].findall(cleaned)
        )

        # Approximate AST depth via nesting
        features.ast_depth = self._compute_nesting_depth(cleaned)

        # Approximate node count as sum of all detected constructs
        features.ast_node_count = (
            features.method_call_count
            + features.block_count
            + features.conditional_count
            + features.loop_count
            + features.assignment_count
            + features.exception_handling_count
            + features.yield_count
            + features.lambda_count
            + features.dynamic_dispatch_count
        )

        # Compute node type distribution entropy
        features.node_type_entropy = self._compute_node_type_entropy(features)

        logger.debug(
            "Extracted AST features: {} nodes, depth={}",
            features.ast_node_count,
            features.ast_depth,
        )
        return features

    def extract_from_file(self, file_path: str | Path) -> ASTFeatures:
        """Extract AST features from a Ruby file.

        Args:
            file_path: Path to the Ruby source file.

        Returns:
            ASTFeatures dataclass.

        Raises:
            FileNotFoundError: If the file does not exist.
        """
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Ruby file not found: {path}")
        source_code = path.read_text(encoding="utf-8", errors="replace")
        return self.extract(source_code)

    def _strip_comments_and_strings(self, source_code: str) -> str:
        """Remove comments and string literals to avoid false matches.

        Args:
            source_code: Raw Ruby source code.

        Returns:
            Cleaned source code with comments and strings removed.
        """
        # Remove block comments (=begin ... =end)
        cleaned = re.sub(
            r'^=begin.*?^=end', '', source_code, flags=re.MULTILINE | re.DOTALL
        )
        # Remove single-line comments
        cleaned = re.sub(r'#.*$', '', cleaned, flags=re.MULTILINE)
        # Remove double-quoted strings (simplified, doesn't handle escapes perfectly)
        cleaned = re.sub(r'"(?:[^"\\]|\\.)*"', '""', cleaned)
        # Remove single-quoted strings
        cleaned = re.sub(r"'(?:[^'\\]|\\.)*'", "''", cleaned)
        # Remove heredocs (simplified)
        cleaned = re.sub(r'<<~?\w+.*?\n.*?\n\s*\w+', '', cleaned, flags=re.DOTALL)
        return cleaned

    def _compute_nesting_depth(self, source_code: str) -> int:
        """Compute maximum nesting depth from keyword analysis.

        Args:
            source_code: Cleaned Ruby source code.

        Returns:
            Maximum nesting depth.
        """
        max_depth = 0
        current_depth = 0

        for line in source_code.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            opens = len(self.PATTERNS["nesting_open"].findall(stripped))
            closes = len(self.PATTERNS["nesting_close"].findall(stripped))

            current_depth += opens
            max_depth = max(max_depth, current_depth)
            current_depth = max(0, current_depth - closes)

        return max_depth

    def _compute_node_type_entropy(self, features: ASTFeatures) -> float:
        """Compute Shannon entropy of the node type distribution.

        Higher entropy indicates a more diverse mix of constructs,
        while lower entropy may indicate repetitive/generated code.

        Args:
            features: Partially populated ASTFeatures.

        Returns:
            Shannon entropy value.
        """
        counts = [
            features.method_call_count,
            features.block_count,
            features.conditional_count,
            features.loop_count,
            features.assignment_count,
            features.exception_handling_count,
            features.yield_count,
            features.lambda_count,
            features.dynamic_dispatch_count,
        ]

        total = sum(counts)
        if total == 0:
            return 0.0

        probabilities = [c / total for c in counts if c > 0]
        entropy = -sum(p * np.log2(p) for p in probabilities)
        return float(entropy)
