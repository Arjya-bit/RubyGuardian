"""
API call feature extractor for Ruby scripts.

Identifies and categorizes calls to dangerous or suspicious Ruby APIs
including system execution, file operations, network operations,
process management, and dynamic evaluation.
"""

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import numpy as np
import yaml
from loguru import logger


@dataclass
class APICallFeatures:
    """Container for API call features."""

    system_exec_count: int = 0
    file_operation_count: int = 0
    network_operation_count: int = 0
    process_operation_count: int = 0
    eval_operation_count: int = 0
    total_dangerous_api_count: int = 0
    dangerous_api_density: float = 0.0
    unique_dangerous_api_count: int = 0
    api_category_diversity: float = 0.0
    max_category_concentration: float = 0.0

    def to_dict(self) -> dict:
        """Convert to a flat dictionary with prefixed keys."""
        return {
            "api_system_exec_count": self.system_exec_count,
            "api_file_operation_count": self.file_operation_count,
            "api_network_operation_count": self.network_operation_count,
            "api_process_operation_count": self.process_operation_count,
            "api_eval_operation_count": self.eval_operation_count,
            "api_total_dangerous_count": self.total_dangerous_api_count,
            "api_dangerous_density": self.dangerous_api_density,
            "api_unique_dangerous_count": self.unique_dangerous_api_count,
            "api_category_diversity": self.api_category_diversity,
            "api_max_category_concentration": self.max_category_concentration,
        }

    def to_array(self) -> np.ndarray:
        """Convert features to numpy array."""
        return np.array(list(self.to_dict().values()), dtype=np.float64)


class APICallExtractor:
    """Extracts API call features from Ruby source code.

    Scans for usage of dangerous or security-sensitive Ruby APIs
    and computes aggregate metrics about their frequency and distribution.
    """

    DEFAULT_DANGEROUS_APIS = {
        "system_execution": [
            "system", "exec", "spawn", "popen", "Open3",
            "IO.popen", "Kernel.exec", "Kernel.system",
            "%x", "``",
        ],
        "file_operations": [
            "File.open", "File.write", "File.read", "File.delete",
            "File.unlink", "File.rename", "File.chmod", "File.chown",
            "FileUtils.rm_rf", "FileUtils.rm", "FileUtils.cp",
            "FileUtils.mv", "Dir.glob", "Dir.mkdir", "Dir.rmdir",
        ],
        "network_operations": [
            "TCPSocket", "UDPSocket", "Net::HTTP", "Socket",
            "OpenURI", "Resolv", "Net::FTP", "Net::SMTP",
            "TCPServer", "UDPSocket.new", "Socket.new",
            "Net::HTTP.get", "Net::HTTP.post",
        ],
        "process_operations": [
            "Process.fork", "Process.spawn", "Process.kill",
            "Process.daemon", "Process.detach", "Process.exec",
            "Thread.new", "Thread.start", "Fiber.new",
            "Signal.trap",
        ],
        "eval_operations": [
            "eval", "instance_eval", "class_eval", "module_eval",
            "send", "public_send", "method_missing",
            "define_method", "remove_method", "undef_method",
            "const_get", "const_set", "instance_variable_set",
            "instance_variable_get", "binding",
        ],
    }

    def __init__(
        self,
        config_path: Optional[str | Path] = None,
        dangerous_apis: Optional[dict[str, list[str]]] = None,
    ) -> None:
        """Initialize the API call extractor.

        Args:
            config_path: Optional path to feature config YAML.
            dangerous_apis: Optional custom dangerous API definitions.
        """
        if dangerous_apis:
            self.dangerous_apis = dangerous_apis
        elif config_path:
            self.dangerous_apis = self._load_from_config(config_path)
        else:
            self.dangerous_apis = self.DEFAULT_DANGEROUS_APIS

        # Build compiled regex patterns per API
        self._api_patterns: dict[str, dict[str, re.Pattern]] = {}
        for category, apis in self.dangerous_apis.items():
            self._api_patterns[category] = {}
            for api in apis:
                escaped = re.escape(api)
                # Match the API name as a word boundary or with :: / .
                pattern = re.compile(
                    rf'(?:^|[^a-zA-Z_])({escaped})(?:\s*[\(.\s]|$)',
                    re.MULTILINE,
                )
                self._api_patterns[category][api] = pattern

        logger.debug(
            "APICallExtractor initialized with {} categories",
            len(self.dangerous_apis),
        )

    def _load_from_config(self, config_path: str | Path) -> dict[str, list[str]]:
        """Load dangerous API definitions from config.

        Args:
            config_path: Path to feature config YAML.

        Returns:
            Dictionary mapping category to list of API names.
        """
        path = Path(config_path)
        if not path.exists():
            logger.warning("Config not found at {}, using defaults", path)
            return self.DEFAULT_DANGEROUS_APIS

        with open(path) as f:
            config = yaml.safe_load(f)

        return config.get("api_call_features", {}).get(
            "dangerous_apis", self.DEFAULT_DANGEROUS_APIS
        )

    def extract(self, source_code: str) -> APICallFeatures:
        """Extract API call features from Ruby source code.

        Args:
            source_code: Raw Ruby source code.

        Returns:
            APICallFeatures with computed metrics.
        """
        features = APICallFeatures()
        line_count = max(len(source_code.splitlines()), 1)

        category_counts = {}
        unique_apis_found: set[str] = set()

        for category, patterns in self._api_patterns.items():
            count = 0
            for api_name, pattern in patterns.items():
                matches = pattern.findall(source_code)
                match_count = len(matches)
                if match_count > 0:
                    unique_apis_found.add(api_name)
                    count += match_count
            category_counts[category] = count

        features.system_exec_count = category_counts.get("system_execution", 0)
        features.file_operation_count = category_counts.get("file_operations", 0)
        features.network_operation_count = category_counts.get("network_operations", 0)
        features.process_operation_count = category_counts.get("process_operations", 0)
        features.eval_operation_count = category_counts.get("eval_operations", 0)

        features.total_dangerous_api_count = sum(category_counts.values())
        features.dangerous_api_density = features.total_dangerous_api_count / line_count
        features.unique_dangerous_api_count = len(unique_apis_found)

        # Category diversity (entropy of category distribution)
        total = features.total_dangerous_api_count
        if total > 0:
            proportions = [c / total for c in category_counts.values() if c > 0]
            features.api_category_diversity = float(
                -sum(p * np.log2(p) for p in proportions)
            )
            features.max_category_concentration = max(category_counts.values()) / total
        else:
            features.api_category_diversity = 0.0
            features.max_category_concentration = 0.0

        logger.debug(
            "Extracted API features: {} dangerous calls, {} unique APIs",
            features.total_dangerous_api_count,
            features.unique_dangerous_api_count,
        )
        return features

    def extract_from_file(self, file_path: str | Path) -> APICallFeatures:
        """Extract API call features from a Ruby file.

        Args:
            file_path: Path to the Ruby source file.

        Returns:
            APICallFeatures dataclass.
        """
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Ruby file not found: {path}")
        source_code = path.read_text(encoding="utf-8", errors="replace")
        return self.extract(source_code)

    def get_detailed_report(self, source_code: str) -> dict[str, dict[str, int]]:
        """Generate a detailed report of all dangerous API calls found.

        Args:
            source_code: Raw Ruby source code.

        Returns:
            Nested dictionary of category -> api_name -> count.
        """
        report: dict[str, dict[str, int]] = {}
        for category, patterns in self._api_patterns.items():
            report[category] = {}
            for api_name, pattern in patterns.items():
                count = len(pattern.findall(source_code))
                if count > 0:
                    report[category][api_name] = count
        return report
