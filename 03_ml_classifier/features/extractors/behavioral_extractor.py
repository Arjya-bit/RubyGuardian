"""
Behavioral feature extractor for Ruby source code.

Identifies behavioral indicators associated with malicious code:
network communication, file system manipulation, code evaluation,
process execution, obfuscation patterns, and privilege escalation.
"""

import logging
import re
from typing import Any

logger = logging.getLogger("rubyguardian.features.behavioral_extractor")

# --- Network-related patterns ---
_NETWORK_PATTERNS = [
    re.compile(r"\brequire\s+['\"]net/http['\"]"),
    re.compile(r"\brequire\s+['\"]open-uri['\"]"),
    re.compile(r"\brequire\s+['\"]socket['\"]"),
    re.compile(r"\bTCPSocket\b"),
    re.compile(r"\bUDPSocket\b"),
    re.compile(r"\bNet::HTTP\b"),
    re.compile(r"\bHTTParty\b"),
    re.compile(r"\bFaraday\b"),
    re.compile(r"\bRestClient\b"),
    re.compile(r"\bopen\s*\(\s*['\"]https?://"),
    re.compile(r"\bURI\s*\(\s*['\"]https?://"),
    re.compile(r"\bWebSocket\b"),
]

# --- File operation patterns ---
_FILE_OP_PATTERNS = [
    re.compile(r"\bFile\.(open|read|write|delete|rename|chmod|chown|unlink|exist\?|size)\b"),
    re.compile(r"\bFileUtils\.\w+"),
    re.compile(r"\bDir\.(mkdir|rmdir|glob|entries|delete)\b"),
    re.compile(r"\bIO\.(read|write|popen|foreach)\b"),
    re.compile(r"\bPathname\b.*\.(read|write|delete|rename)"),
    re.compile(r"\bTempfile\b"),
]

# --- Code evaluation / metaprogramming patterns ---
_EVAL_PATTERNS = [
    re.compile(r"\beval\s*\("),
    re.compile(r"\beval\s+['\"]"),
    re.compile(r"\bclass_eval\b"),
    re.compile(r"\bmodule_eval\b"),
    re.compile(r"\binstance_eval\b"),
    re.compile(r"\bdefine_method\b"),
    re.compile(r"\bmethod_missing\b"),
    re.compile(r"\bsend\s*\("),
    re.compile(r"\b__send__\s*\("),
    re.compile(r"\bBinding\b.*\beval\b"),
]

# --- Process execution patterns ---
_EXEC_PATTERNS = [
    re.compile(r"\bsystem\s*\("),
    re.compile(r"\bexec\s*\("),
    re.compile(r"`[^`]+`"),  # backtick execution
    re.compile(r"\b%x\{[^}]+\}"),
    re.compile(r"\bIO\.popen\b"),
    re.compile(r"\bOpen3\.\w+"),
    re.compile(r"\bProcess\.(spawn|fork|exec|kill)\b"),
    re.compile(r"\bKernel\.(system|exec|spawn)\b"),
]

# --- Obfuscation indicators ---
_OBFUSCATION_PATTERNS = [
    re.compile(r"(?:\\x[0-9a-fA-F]{2}){3,}"),        # hex escapes
    re.compile(r"(?:\\[0-7]{3}){3,}"),                 # octal escapes
    re.compile(r"\bBase64\.(decode64|encode64)\b"),    # Base64 usage
    re.compile(r"\bMarshal\.(load|dump)\b"),           # serialization
    re.compile(r"\bpack\s*\(\s*['\"]H"),               # hex packing
    re.compile(r"\bunpack\s*\(\s*['\"]"),              # unpacking
    re.compile(r"\balias_method\b"),                   # method aliasing
    re.compile(r"_0x[0-9a-fA-F]+"),                   # hex variable names
    re.compile(r"\b[a-zA-Z]\s*=\s*['\"]\\x"),         # hex string assignment
]

# --- Require statements ---
_REQUIRE_RE = re.compile(r"\brequire(?:_relative)?\s+['\"]([^'\"]+)['\"]")

# --- Suspicious require targets ---
_SUSPICIOUS_REQUIRES = {
    "net/http", "socket", "open-uri", "base64", "openssl",
    "fiddle", "dl", "drb", "win32ole", "etc", "shellwords",
}


class BehavioralFeatureExtractor:
    """
    Extracts behavioral features indicating potentially malicious activity.

    Analyzes Ruby source for patterns related to network access, file
    manipulation, code evaluation, process execution, and obfuscation.
    """

    name = "behavioral"
    version = "1.3.0"

    def extract(self, source: str) -> dict[str, Any]:
        """
        Extract behavioral features from Ruby source code.

        Args:
            source: Raw Ruby source code string.

        Returns:
            Dictionary of feature name to numeric value.
        """
        if not source:
            return self._empty_features()

        features: dict[str, Any] = {}

        # Network indicators
        network_matches = self._count_pattern_matches(source, _NETWORK_PATTERNS)
        features["network_call_count"] = network_matches
        features["has_network_activity"] = int(network_matches > 0)

        # File operation indicators
        file_matches = self._count_pattern_matches(source, _FILE_OP_PATTERNS)
        features["file_op_count"] = file_matches
        features["has_file_ops"] = int(file_matches > 0)

        # Eval / metaprogramming
        eval_matches = self._count_pattern_matches(source, _EVAL_PATTERNS)
        features["eval_count"] = eval_matches
        features["has_eval"] = int(eval_matches > 0)

        # Process execution
        exec_matches = self._count_pattern_matches(source, _EXEC_PATTERNS)
        features["exec_count"] = exec_matches
        features["has_exec"] = int(exec_matches > 0)

        # Obfuscation indicators
        obfuscation_matches = self._count_pattern_matches(source, _OBFUSCATION_PATTERNS)
        features["obfuscation_indicator_count"] = obfuscation_matches
        features["obfuscation_score"] = self._compute_obfuscation_score(
            source, obfuscation_matches
        )

        # Require analysis
        requires = _REQUIRE_RE.findall(source)
        features["require_count"] = len(requires)
        suspicious_requires = [r for r in requires if r in _SUSPICIOUS_REQUIRES]
        features["suspicious_require_count"] = len(suspicious_requires)
        features["suspicious_requires"] = suspicious_requires

        # Composite risk score
        features["behavioral_risk_score"] = self._compute_risk_score(features)

        return features

    def _count_pattern_matches(self, source: str, patterns: list[re.Pattern]) -> int:
        """Count total matches across a list of regex patterns."""
        total = 0
        for pattern in patterns:
            total += len(pattern.findall(source))
        return total

    def _compute_obfuscation_score(self, source: str, indicator_count: int) -> float:
        """
        Compute an obfuscation score between 0.0 and 1.0.

        Factors: number of obfuscation indicators, ratio of non-printable
        characters, average identifier length, and hex/octal escape density.
        """
        if not source:
            return 0.0

        score = 0.0

        # Indicator density
        lines = max(source.count("\n") + 1, 1)
        indicator_density = min(indicator_count / lines, 1.0)
        score += indicator_density * 0.4

        # Non-printable character ratio
        non_printable = sum(1 for c in source if ord(c) < 32 and c not in "\n\r\t")
        non_printable_ratio = non_printable / max(len(source), 1)
        score += min(non_printable_ratio * 10, 1.0) * 0.2

        # Hex escape density
        hex_escapes = len(re.findall(r"\\x[0-9a-fA-F]{2}", source))
        hex_density = hex_escapes / max(len(source), 1) * 100
        score += min(hex_density, 1.0) * 0.25

        # Short/meaningless variable names
        identifiers = re.findall(r"\b([a-z_]\w*)\b", source)
        if identifiers:
            avg_len = sum(len(i) for i in identifiers) / len(identifiers)
            short_name_score = max(0.0, 1.0 - avg_len / 8.0)
            score += short_name_score * 0.15

        return round(min(score, 1.0), 4)

    def _compute_risk_score(self, features: dict[str, Any]) -> float:
        """
        Compute a composite behavioral risk score (0.0 to 1.0).

        Weighs different behavioral categories by their relative risk.
        """
        weights = {
            "eval_count": 0.25,
            "exec_count": 0.20,
            "network_call_count": 0.15,
            "obfuscation_score": 0.20,
            "suspicious_require_count": 0.10,
            "file_op_count": 0.10,
        }

        score = 0.0
        for feature, weight in weights.items():
            value = features.get(feature, 0)
            if isinstance(value, float):
                normalized = min(value, 1.0)
            else:
                normalized = min(value / 5.0, 1.0)
            score += normalized * weight

        return round(min(score, 1.0), 4)

    def _empty_features(self) -> dict[str, Any]:
        return {
            "network_call_count": 0,
            "has_network_activity": 0,
            "file_op_count": 0,
            "has_file_ops": 0,
            "eval_count": 0,
            "has_eval": 0,
            "exec_count": 0,
            "has_exec": 0,
            "obfuscation_indicator_count": 0,
            "obfuscation_score": 0.0,
            "require_count": 0,
            "suspicious_require_count": 0,
            "suspicious_requires": [],
            "behavioral_risk_score": 0.0,
        }
