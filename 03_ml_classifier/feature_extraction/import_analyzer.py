"""
Import analysis feature extractor for Ruby scripts.

Analyzes require statements, gem usage, and dynamic loading patterns
to identify suspicious dependency chains and risky library imports.
"""

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import numpy as np
import yaml
from loguru import logger


@dataclass
class ImportFeatures:
    """Container for import analysis features."""

    require_count: int = 0
    require_relative_count: int = 0
    gem_count: int = 0
    dynamic_require_count: int = 0
    load_path_manipulation_count: int = 0
    high_risk_gem_count: int = 0
    medium_risk_gem_count: int = 0
    total_import_count: int = 0
    unique_import_count: int = 0
    stdlib_ratio: float = 0.0
    import_density: float = 0.0

    def to_dict(self) -> dict:
        """Convert to a flat dictionary with prefixed keys."""
        return {
            "import_require_count": self.require_count,
            "import_require_relative_count": self.require_relative_count,
            "import_gem_count": self.gem_count,
            "import_dynamic_require_count": self.dynamic_require_count,
            "import_load_path_manipulation_count": self.load_path_manipulation_count,
            "import_high_risk_gem_count": self.high_risk_gem_count,
            "import_medium_risk_gem_count": self.medium_risk_gem_count,
            "import_total_count": self.total_import_count,
            "import_unique_count": self.unique_import_count,
            "import_stdlib_ratio": self.stdlib_ratio,
            "import_density": self.import_density,
        }

    def to_array(self) -> np.ndarray:
        """Convert features to numpy array."""
        return np.array(list(self.to_dict().values()), dtype=np.float64)


class ImportAnalyzer:
    """Analyzes import and require patterns in Ruby source code.

    Identifies suspicious import patterns including use of high-risk
    gems (FFI, Fiddle, etc.), dynamic requires, and load path
    manipulation that could indicate malicious intent.
    """

    REQUIRE_PATTERN = re.compile(
        r'''require\s+['"]([^'"]+)['"]''', re.MULTILINE
    )
    REQUIRE_RELATIVE_PATTERN = re.compile(
        r'''require_relative\s+['"]([^'"]+)['"]''', re.MULTILINE
    )
    GEM_PATTERN = re.compile(
        r'''gem\s+['"]([^'"]+)['"]''', re.MULTILINE
    )
    DYNAMIC_REQUIRE_PATTERN = re.compile(
        r'require\s+(?:[a-z_]\w*|".*#\{)',  re.MULTILINE
    )
    LOAD_PATH_PATTERN = re.compile(
        r'\$(?:LOAD_PATH|:)\s*(?:<<|\.(?:push|unshift|prepend))',
        re.MULTILINE,
    )

    HIGH_RISK_GEMS = {
        "fiddle", "dl", "inline", "ffi", "sys-proctable",
        "rubyinline", "win32ole",
    }
    MEDIUM_RISK_GEMS = {
        "open-uri", "net-ssh", "net-scp", "mechanize",
        "selenium-webdriver", "watir", "curb", "typhoeus",
        "eventmachine", "celluloid",
    }
    RUBY_STDLIB = {
        "abbrev", "base64", "benchmark", "bigdecimal", "cgi",
        "csv", "date", "dbm", "debug", "delegate", "digest",
        "drb", "english", "erb", "etc", "expect", "fcntl",
        "fiddle", "fileutils", "find", "forwardable", "gdbm",
        "getoptlong", "io/console", "io/nonblock", "io/wait",
        "ipaddr", "irb", "json", "logger", "matrix", "minitest",
        "monitor", "mutex_m", "net/ftp", "net/http", "net/imap",
        "net/pop", "net/smtp", "nkf", "objspace", "observer",
        "open-uri", "open3", "openssl", "optparse", "ostruct",
        "pathname", "pp", "prettyprint", "prime", "pstore",
        "psych", "pty", "racc", "readline", "reline", "resolv",
        "rinda", "ripper", "rss", "ruby2_keywords", "rubygems",
        "securerandom", "set", "shellwords", "singleton",
        "socket", "stringio", "strscan", "syslog", "tempfile",
        "time", "timeout", "tmpdir", "tracer", "tsort", "un",
        "uri", "weakref", "webrick", "yaml", "zlib",
    }

    def __init__(
        self,
        config_path: Optional[str | Path] = None,
    ) -> None:
        """Initialize the import analyzer.

        Args:
            config_path: Optional path to feature config YAML.
        """
        if config_path:
            self._load_config(config_path)
        logger.debug("ImportAnalyzer initialized")

    def _load_config(self, config_path: str | Path) -> None:
        """Load risk classifications from config.

        Args:
            config_path: Path to feature config YAML.
        """
        path = Path(config_path)
        if not path.exists():
            return

        with open(path) as f:
            config = yaml.safe_load(f)

        import_config = config.get("import_features", {})
        suspicious = import_config.get("suspicious_gems", {})
        if "high_risk" in suspicious:
            self.HIGH_RISK_GEMS = set(suspicious["high_risk"])
        if "medium_risk" in suspicious:
            self.MEDIUM_RISK_GEMS = set(suspicious["medium_risk"])

    def extract(self, source_code: str) -> ImportFeatures:
        """Extract import analysis features from Ruby source code.

        Args:
            source_code: Raw Ruby source code.

        Returns:
            ImportFeatures with computed metrics.
        """
        features = ImportFeatures()
        line_count = max(len(source_code.splitlines()), 1)

        requires = self.REQUIRE_PATTERN.findall(source_code)
        require_relatives = self.REQUIRE_RELATIVE_PATTERN.findall(source_code)
        gems = self.GEM_PATTERN.findall(source_code)
        dynamic_requires = self.DYNAMIC_REQUIRE_PATTERN.findall(source_code)
        load_path_mods = self.LOAD_PATH_PATTERN.findall(source_code)

        features.require_count = len(requires)
        features.require_relative_count = len(require_relatives)
        features.gem_count = len(gems)
        features.dynamic_require_count = len(dynamic_requires)
        features.load_path_manipulation_count = len(load_path_mods)

        all_imports = set(requires + require_relatives + gems)
        features.unique_import_count = len(all_imports)
        features.total_import_count = (
            features.require_count
            + features.require_relative_count
            + features.gem_count
        )

        # Count risk categories
        for imp in all_imports:
            base_name = imp.split("/")[0].lower()
            if base_name in self.HIGH_RISK_GEMS:
                features.high_risk_gem_count += 1
            elif base_name in self.MEDIUM_RISK_GEMS:
                features.medium_risk_gem_count += 1

        # Stdlib ratio
        stdlib_count = sum(
            1 for imp in all_imports
            if imp.split("/")[0].lower() in self.RUBY_STDLIB
        )
        if all_imports:
            features.stdlib_ratio = stdlib_count / len(all_imports)

        features.import_density = features.total_import_count / line_count

        logger.debug(
            "Extracted import features: {} total, {} high-risk",
            features.total_import_count,
            features.high_risk_gem_count,
        )
        return features

    def extract_from_file(self, file_path: str | Path) -> ImportFeatures:
        """Extract import features from a Ruby file.

        Args:
            file_path: Path to the Ruby source file.

        Returns:
            ImportFeatures dataclass.
        """
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Ruby file not found: {path}")
        source_code = path.read_text(encoding="utf-8", errors="replace")
        return self.extract(source_code)

    def get_imports_list(self, source_code: str) -> dict[str, list[str]]:
        """Get categorized lists of all imports found.

        Args:
            source_code: Raw Ruby source code.

        Returns:
            Dictionary with categorized import lists.
        """
        requires = self.REQUIRE_PATTERN.findall(source_code)
        require_relatives = self.REQUIRE_RELATIVE_PATTERN.findall(source_code)
        gems = self.GEM_PATTERN.findall(source_code)

        all_imports = set(requires + require_relatives + gems)

        high_risk = [i for i in all_imports if i.split("/")[0].lower() in self.HIGH_RISK_GEMS]
        medium_risk = [i for i in all_imports if i.split("/")[0].lower() in self.MEDIUM_RISK_GEMS]
        normal = [i for i in all_imports if i not in high_risk and i not in medium_risk]

        return {
            "high_risk": sorted(high_risk),
            "medium_risk": sorted(medium_risk),
            "normal": sorted(normal),
        }
