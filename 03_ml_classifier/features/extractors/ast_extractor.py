"""
AST-based feature extractor for Ruby source code.

Parses Ruby code structure to extract features related to the abstract
syntax tree: node counts by type, tree depth, cyclomatic complexity,
and structural patterns commonly associated with malicious code.
"""

import logging
import re
from collections import Counter
from typing import Any

logger = logging.getLogger("rubyguardian.features.ast_extractor")

# Ruby keyword patterns used to approximate AST structure without a full parser
_CLASS_DEF_RE = re.compile(r"^\s*class\s+\w+", re.MULTILINE)
_MODULE_DEF_RE = re.compile(r"^\s*module\s+\w+", re.MULTILINE)
_METHOD_DEF_RE = re.compile(r"^\s*def\s+\w+", re.MULTILINE)
_BLOCK_START_RE = re.compile(r"\b(do|begin)\b")
_BLOCK_END_RE = re.compile(r"\bend\b")
_CONDITIONAL_RE = re.compile(r"\b(if|unless|elsif|case|when)\b")
_LOOP_RE = re.compile(r"\b(while|until|for|loop|each|times|upto|downto)\b")
_RESCUE_RE = re.compile(r"\brescue\b")
_LAMBDA_RE = re.compile(r"(->|lambda)\s*[\({]")
_YIELD_RE = re.compile(r"\byield\b")
_SEND_RE = re.compile(r"\bsend\s*\(")
_EVAL_RE = re.compile(r"\b(eval|class_eval|module_eval|instance_eval)\b")
_STRING_LITERAL_RE = re.compile(r"""(["'])(?:(?=(\\?))\2.)*?\1""")
_COMMENT_RE = re.compile(r"#.*$", re.MULTILINE)


class ASTFeatureExtractor:
    """
    Extracts AST-approximation features from Ruby source code.

    Since we operate without a Ruby runtime, features are extracted
    via regex-based structural analysis of the source text.
    """

    name = "ast"
    version = "1.2.0"

    def extract(self, source: str) -> dict[str, Any]:
        """
        Extract AST-based features from Ruby source code.

        Args:
            source: Raw Ruby source code string.

        Returns:
            Dictionary of feature name to numeric value.
        """
        if not source or not source.strip():
            return self._empty_features()

        lines = source.splitlines()
        code_lines = [line for line in lines if line.strip() and not line.strip().startswith("#")]

        features: dict[str, Any] = {}

        # Structural counts
        features["ast_node_count"] = self._estimate_node_count(source)
        features["ast_max_depth"] = self._estimate_max_depth(lines)
        features["cyclomatic_complexity"] = self._cyclomatic_complexity(source)

        # Definition counts
        features["class_def_count"] = len(_CLASS_DEF_RE.findall(source))
        features["module_def_count"] = len(_MODULE_DEF_RE.findall(source))
        features["method_def_count"] = len(_METHOD_DEF_RE.findall(source))

        # Control flow
        features["conditional_count"] = len(_CONDITIONAL_RE.findall(source))
        features["loop_count"] = len(_LOOP_RE.findall(source))
        features["rescue_count"] = len(_RESCUE_RE.findall(source))

        # Metaprogramming indicators
        features["lambda_count"] = len(_LAMBDA_RE.findall(source))
        features["yield_count"] = len(_YIELD_RE.findall(source))
        features["send_count"] = len(_SEND_RE.findall(source))
        features["eval_in_ast_count"] = len(_EVAL_RE.findall(source))

        # Code metrics
        features["total_lines"] = len(lines)
        features["code_lines"] = len(code_lines)
        features["comment_lines"] = len(lines) - len(code_lines)
        features["comment_ratio"] = (
            features["comment_lines"] / max(features["total_lines"], 1)
        )
        features["string_literal_count"] = len(_STRING_LITERAL_RE.findall(source))
        features["avg_line_length"] = (
            sum(len(line) for line in code_lines) / max(len(code_lines), 1)
        )
        features["max_line_length"] = max((len(line) for line in lines), default=0)

        return features

    def _estimate_node_count(self, source: str) -> int:
        """Estimate the total number of AST nodes based on tokens and keywords."""
        stripped = _COMMENT_RE.sub("", source)
        tokens = re.findall(r"\b\w+\b", stripped)
        operators = re.findall(r"[+\-*/=<>!&|^~%]+", stripped)
        return len(tokens) + len(operators)

    def _estimate_max_depth(self, lines: list[str]) -> int:
        """Estimate maximum nesting depth by tracking block openers/closers."""
        depth = 0
        max_depth = 0
        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            # Count block openers
            openers = len(_BLOCK_START_RE.findall(stripped))
            openers += len(_CLASS_DEF_RE.findall(stripped))
            openers += len(_MODULE_DEF_RE.findall(stripped))
            openers += len(_METHOD_DEF_RE.findall(stripped))
            openers += len(_CONDITIONAL_RE.findall(stripped))
            openers += len(_LOOP_RE.findall(stripped))
            # Count block closers
            closers = stripped.count("end")
            depth += openers
            max_depth = max(max_depth, depth)
            depth = max(0, depth - closers)
        return max_depth

    def _cyclomatic_complexity(self, source: str) -> int:
        """
        Estimate cyclomatic complexity from control flow keywords.

        Complexity = 1 + number of decision points (if, unless, while, etc.)
        """
        decision_points = (
            len(_CONDITIONAL_RE.findall(source))
            + len(_LOOP_RE.findall(source))
            + len(_RESCUE_RE.findall(source))
        )
        return 1 + decision_points

    def _empty_features(self) -> dict[str, Any]:
        """Return zeroed feature dictionary for empty inputs."""
        return {
            "ast_node_count": 0,
            "ast_max_depth": 0,
            "cyclomatic_complexity": 1,
            "class_def_count": 0,
            "module_def_count": 0,
            "method_def_count": 0,
            "conditional_count": 0,
            "loop_count": 0,
            "rescue_count": 0,
            "lambda_count": 0,
            "yield_count": 0,
            "send_count": 0,
            "eval_in_ast_count": 0,
            "total_lines": 0,
            "code_lines": 0,
            "comment_lines": 0,
            "comment_ratio": 0.0,
            "string_literal_count": 0,
            "avg_line_length": 0.0,
            "max_line_length": 0,
        }
