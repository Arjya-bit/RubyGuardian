"""
Static analysis feature extractor for Ruby scripts.

Extracts structural metrics such as line counts, method counts,
nesting depth, and complexity indicators without executing the code.
"""

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import numpy as np
from loguru import logger


@dataclass
class StaticFeatures:
    """Container for static analysis features."""

    line_count: int = 0
    method_count: int = 0
    class_count: int = 0
    module_count: int = 0
    avg_method_length: float = 0.0
    max_method_length: int = 0
    nesting_depth: int = 0
    cyclomatic_complexity: int = 0
    comment_ratio: float = 0.0
    blank_line_ratio: float = 0.0
    avg_identifier_length: float = 0.0
    unique_identifier_count: int = 0

    def to_dict(self) -> dict:
        """Convert features to a flat dictionary."""
        return {
            "static_line_count": self.line_count,
            "static_method_count": self.method_count,
            "static_class_count": self.class_count,
            "static_module_count": self.module_count,
            "static_avg_method_length": self.avg_method_length,
            "static_max_method_length": self.max_method_length,
            "static_nesting_depth": self.nesting_depth,
            "static_cyclomatic_complexity": self.cyclomatic_complexity,
            "static_comment_ratio": self.comment_ratio,
            "static_blank_line_ratio": self.blank_line_ratio,
            "static_avg_identifier_length": self.avg_identifier_length,
            "static_unique_identifier_count": self.unique_identifier_count,
        }

    def to_array(self) -> np.ndarray:
        """Convert features to a numpy array."""
        return np.array(list(self.to_dict().values()), dtype=np.float64)


class StaticAnalyzer:
    """Extracts static structural features from Ruby source code.

    Analyzes Ruby scripts without execution to extract metrics related
    to code structure, complexity, and style that may indicate malicious
    intent or obfuscation.
    """

    # Ruby keywords that affect control flow / nesting
    NESTING_KEYWORDS = {"def", "class", "module", "do", "if", "unless",
                        "while", "until", "for", "case", "begin"}
    NESTING_CLOSERS = {"end"}

    # Branching keywords for cyclomatic complexity
    BRANCH_KEYWORDS = {"if", "elsif", "unless", "while", "until", "for",
                       "when", "rescue", "&&", "||", "and", "or", "?"}

    # Pattern for Ruby identifiers (variables, methods, etc.)
    IDENTIFIER_PATTERN = re.compile(
        r'\b([a-z_][a-z0-9_]*)\b', re.IGNORECASE
    )
    METHOD_DEF_PATTERN = re.compile(
        r'^\s*def\s+(?:self\.)?(\w+)', re.MULTILINE
    )
    CLASS_DEF_PATTERN = re.compile(
        r'^\s*class\s+(\w+)', re.MULTILINE
    )
    MODULE_DEF_PATTERN = re.compile(
        r'^\s*module\s+(\w+)', re.MULTILINE
    )
    COMMENT_PATTERN = re.compile(r'^\s*#', re.MULTILINE)
    BLANK_LINE_PATTERN = re.compile(r'^\s*$', re.MULTILINE)

    def __init__(self) -> None:
        """Initialize the static analyzer."""
        logger.debug("StaticAnalyzer initialized")

    def extract(self, source_code: str) -> StaticFeatures:
        """Extract all static features from Ruby source code.

        Args:
            source_code: Raw Ruby source code as a string.

        Returns:
            StaticFeatures dataclass with all computed metrics.
        """
        features = StaticFeatures()
        lines = source_code.splitlines()
        features.line_count = len(lines)

        if features.line_count == 0:
            return features

        features.method_count = len(self.METHOD_DEF_PATTERN.findall(source_code))
        features.class_count = len(self.CLASS_DEF_PATTERN.findall(source_code))
        features.module_count = len(self.MODULE_DEF_PATTERN.findall(source_code))

        method_lengths = self._compute_method_lengths(lines)
        if method_lengths:
            features.avg_method_length = float(np.mean(method_lengths))
            features.max_method_length = max(method_lengths)

        features.nesting_depth = self._compute_max_nesting(lines)
        features.cyclomatic_complexity = self._compute_cyclomatic_complexity(
            source_code
        )

        comment_count = len(self.COMMENT_PATTERN.findall(source_code))
        blank_count = len(self.BLANK_LINE_PATTERN.findall(source_code))
        features.comment_ratio = comment_count / features.line_count
        features.blank_line_ratio = blank_count / features.line_count

        identifiers = self._extract_identifiers(source_code)
        if identifiers:
            features.avg_identifier_length = float(
                np.mean([len(i) for i in identifiers])
            )
            features.unique_identifier_count = len(set(identifiers))

        logger.debug(
            "Extracted static features: {} methods, complexity={}",
            features.method_count,
            features.cyclomatic_complexity,
        )
        return features

    def extract_from_file(self, file_path: str | Path) -> StaticFeatures:
        """Extract static features from a Ruby file.

        Args:
            file_path: Path to the Ruby source file.

        Returns:
            StaticFeatures dataclass with computed metrics.

        Raises:
            FileNotFoundError: If the file does not exist.
        """
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Ruby file not found: {path}")

        source_code = path.read_text(encoding="utf-8", errors="replace")
        return self.extract(source_code)

    def _compute_method_lengths(self, lines: list[str]) -> list[int]:
        """Compute the length (in lines) of each method definition.

        Args:
            lines: Source code lines.

        Returns:
            List of method lengths in lines.
        """
        method_lengths = []
        in_method = False
        method_depth = 0
        current_length = 0

        for line in lines:
            stripped = line.strip()
            if re.match(r'^def\s+', stripped):
                if in_method:
                    method_lengths.append(current_length)
                in_method = True
                method_depth = 1
                current_length = 1
                continue

            if in_method:
                current_length += 1
                for kw in self.NESTING_KEYWORDS:
                    if re.match(rf'^{kw}\b', stripped):
                        method_depth += 1
                        break
                if stripped == "end":
                    method_depth -= 1
                    if method_depth == 0:
                        method_lengths.append(current_length)
                        in_method = False
                        current_length = 0

        if in_method and current_length > 0:
            method_lengths.append(current_length)

        return method_lengths

    def _compute_max_nesting(self, lines: list[str]) -> int:
        """Compute the maximum nesting depth in the source code.

        Args:
            lines: Source code lines.

        Returns:
            Maximum nesting depth as an integer.
        """
        max_depth = 0
        current_depth = 0

        for line in lines:
            stripped = line.strip()
            if stripped.startswith("#") or not stripped:
                continue

            for kw in self.NESTING_KEYWORDS:
                if re.search(rf'\b{kw}\b', stripped):
                    current_depth += 1
                    max_depth = max(max_depth, current_depth)
                    break

            if stripped == "end" or stripped.startswith("end "):
                current_depth = max(0, current_depth - 1)

        return max_depth

    def _compute_cyclomatic_complexity(self, source_code: str) -> int:
        """Compute McCabe cyclomatic complexity.

        Counts the number of branching points in the code plus one.

        Args:
            source_code: Ruby source code string.

        Returns:
            Cyclomatic complexity score.
        """
        complexity = 1
        for keyword in self.BRANCH_KEYWORDS:
            escaped = re.escape(keyword)
            matches = re.findall(rf'\b{escaped}\b', source_code)
            complexity += len(matches)
        return complexity

    def _extract_identifiers(self, source_code: str) -> list[str]:
        """Extract all identifiers from the source code.

        Filters out Ruby keywords and very short identifiers.

        Args:
            source_code: Ruby source code string.

        Returns:
            List of identifier strings.
        """
        ruby_keywords = {
            "def", "end", "class", "module", "if", "else", "elsif",
            "unless", "while", "until", "for", "do", "begin", "rescue",
            "ensure", "raise", "return", "yield", "self", "super",
            "true", "false", "nil", "and", "or", "not", "in", "then",
            "when", "case", "require", "require_relative", "include",
            "extend", "prepend", "attr_reader", "attr_writer",
            "attr_accessor", "puts", "print", "p",
        }
        identifiers = self.IDENTIFIER_PATTERN.findall(source_code)
        return [i for i in identifiers if i.lower() not in ruby_keywords]
