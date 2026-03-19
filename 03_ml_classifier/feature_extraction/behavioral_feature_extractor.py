"""
Behavioral feature extractor for Ruby scripts.

Analyzes syscall traces and runtime behavior logs to extract features
related to file access patterns, network activity, process manipulation,
and memory operations that distinguish malicious from benign scripts.
"""

import json
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import numpy as np
import yaml
from loguru import logger


@dataclass
class BehavioralFeatures:
    """Container for behavioral analysis features."""

    # Syscall category counts
    file_access_syscall_count: int = 0
    network_syscall_count: int = 0
    process_syscall_count: int = 0
    memory_syscall_count: int = 0

    # Syscall statistics
    unique_syscall_count: int = 0
    total_syscall_count: int = 0
    syscall_diversity_ratio: float = 0.0
    syscall_burst_rate: float = 0.0

    # Sequence features
    suspicious_sequence_count: int = 0
    max_syscall_frequency: float = 0.0
    syscall_entropy: float = 0.0

    # Static behavioral indicators (from source analysis)
    file_write_indicator: int = 0
    network_connect_indicator: int = 0
    process_spawn_indicator: int = 0
    privilege_escalation_indicator: int = 0
    persistence_indicator: int = 0

    def to_dict(self) -> dict:
        """Convert to a flat dictionary with prefixed keys."""
        return {
            "beh_file_access_syscall_count": self.file_access_syscall_count,
            "beh_network_syscall_count": self.network_syscall_count,
            "beh_process_syscall_count": self.process_syscall_count,
            "beh_memory_syscall_count": self.memory_syscall_count,
            "beh_unique_syscall_count": self.unique_syscall_count,
            "beh_total_syscall_count": self.total_syscall_count,
            "beh_syscall_diversity_ratio": self.syscall_diversity_ratio,
            "beh_syscall_burst_rate": self.syscall_burst_rate,
            "beh_suspicious_sequence_count": self.suspicious_sequence_count,
            "beh_max_syscall_frequency": self.max_syscall_frequency,
            "beh_syscall_entropy": self.syscall_entropy,
            "beh_file_write_indicator": self.file_write_indicator,
            "beh_network_connect_indicator": self.network_connect_indicator,
            "beh_process_spawn_indicator": self.process_spawn_indicator,
            "beh_privilege_escalation_indicator": self.privilege_escalation_indicator,
            "beh_persistence_indicator": self.persistence_indicator,
        }

    def to_array(self) -> np.ndarray:
        """Convert features to numpy array."""
        return np.array(list(self.to_dict().values()), dtype=np.float64)


class BehavioralFeatureExtractor:
    """Extracts behavioral features from syscall logs and source code.

    Combines dynamic analysis (syscall trace logs) with static analysis
    (code pattern matching) to produce behavioral features that capture
    how a Ruby script interacts with the operating system.
    """

    # Default syscall category mappings
    DEFAULT_SYSCALL_CATEGORIES: dict[str, list[str]] = {
        "file_access": [
            "open", "read", "write", "close", "unlink", "rename",
            "chmod", "stat", "lstat", "fstat", "openat", "readlink",
        ],
        "network": [
            "socket", "connect", "bind", "listen", "accept",
            "send", "recv", "sendto", "recvfrom", "sendmsg", "recvmsg",
        ],
        "process": [
            "fork", "execve", "clone", "kill", "ptrace", "wait4",
            "exit_group", "getpid", "getppid", "setsid",
        ],
        "memory": [
            "mmap", "mprotect", "brk", "munmap", "mremap", "madvise",
        ],
    }

    # Suspicious syscall sequences (ordered pairs that suggest malicious behavior)
    SUSPICIOUS_SEQUENCES: list[tuple[str, str]] = [
        ("socket", "connect"),
        ("fork", "execve"),
        ("open", "write"),
        ("mmap", "mprotect"),
        ("socket", "bind"),
        ("ptrace", "kill"),
        ("clone", "execve"),
        ("socket", "sendto"),
    ]

    # Static patterns for behavioral indicators in Ruby source
    BEHAVIORAL_PATTERNS = {
        "file_write": re.compile(
            r'(?:File\.(?:open|write|new)\s*\(.*["\x27]w|'
            r'IO\.write|FileUtils\.(?:cp|mv|install|mkdir_p|touch))',
            re.MULTILINE,
        ),
        "network_connect": re.compile(
            r'(?:TCPSocket\.(?:new|open)|UDPSocket\.new|'
            r'Net::HTTP\.(?:get|post|start)|'
            r'Socket\.new|open-uri|URI\.open|'
            r'\.connect\s*\()',
            re.MULTILINE,
        ),
        "process_spawn": re.compile(
            r'(?:Process\.(?:fork|spawn|exec|daemon)|'
            r'Kernel\.(?:fork|exec|spawn)|'
            r'system\s*\(|`[^`]+`|%x\[)',
            re.MULTILINE,
        ),
        "privilege_escalation": re.compile(
            r'(?:Process\.(?:euid|uid|egid|gid)\s*=|'
            r'File\.chmod\s*\(\s*0?[0-7]*7|'
            r'sudo|chown|setuid|setgid)',
            re.MULTILINE,
        ),
        "persistence": re.compile(
            r'(?:crontab|at\s+|systemctl|launchctl|'
            r'\.plist|init\.d|rc\.local|'
            r'/etc/(?:cron|init)|\.bashrc|\.profile|'
            r'at_exit\s*\{|Signal\.trap)',
            re.MULTILINE,
        ),
    }

    def __init__(
        self,
        config_path: Optional[str | Path] = None,
        syscall_categories: Optional[dict[str, list[str]]] = None,
    ) -> None:
        """Initialize the behavioral feature extractor.

        Args:
            config_path: Optional path to feature config YAML.
            syscall_categories: Optional custom syscall category mappings.
        """
        self.syscall_categories = (
            syscall_categories or dict(self.DEFAULT_SYSCALL_CATEGORIES)
        )

        if config_path:
            self._load_config(config_path)

        # Build reverse lookup: syscall_name -> category
        self._syscall_to_category: dict[str, str] = {}
        for category, syscalls in self.syscall_categories.items():
            for syscall in syscalls:
                self._syscall_to_category[syscall] = category

        logger.debug("BehavioralFeatureExtractor initialized")

    def _load_config(self, config_path: str | Path) -> None:
        """Load behavioral feature settings from YAML config.

        Args:
            config_path: Path to the feature configuration file.
        """
        path = Path(config_path)
        if not path.exists():
            return

        with open(path) as f:
            config = yaml.safe_load(f)

        beh_config = config.get("behavioral_features", {})
        if "syscall_categories" in beh_config:
            self.syscall_categories = beh_config["syscall_categories"]

    def extract(self, source_code: str) -> BehavioralFeatures:
        """Extract behavioral features from Ruby source code.

        Performs static analysis of the source to detect behavioral
        patterns. For dynamic features from syscall logs, use
        extract_from_syscall_log().

        Args:
            source_code: Raw Ruby source code.

        Returns:
            BehavioralFeatures with static behavioral indicators populated.
        """
        features = BehavioralFeatures()

        # Static behavioral pattern matching
        features.file_write_indicator = min(
            len(self.BEHAVIORAL_PATTERNS["file_write"].findall(source_code)), 10
        )
        features.network_connect_indicator = min(
            len(self.BEHAVIORAL_PATTERNS["network_connect"].findall(source_code)), 10
        )
        features.process_spawn_indicator = min(
            len(self.BEHAVIORAL_PATTERNS["process_spawn"].findall(source_code)), 10
        )
        features.privilege_escalation_indicator = min(
            len(self.BEHAVIORAL_PATTERNS["privilege_escalation"].findall(source_code)), 10
        )
        features.persistence_indicator = min(
            len(self.BEHAVIORAL_PATTERNS["persistence"].findall(source_code)), 10
        )

        logger.debug(
            "Behavioral static indicators: file_write={}, network={}, process={}",
            features.file_write_indicator,
            features.network_connect_indicator,
            features.process_spawn_indicator,
        )
        return features

    def extract_from_file(self, file_path: str | Path) -> BehavioralFeatures:
        """Extract behavioral features from a Ruby source file.

        Args:
            file_path: Path to the Ruby source file.

        Returns:
            BehavioralFeatures dataclass.

        Raises:
            FileNotFoundError: If the file does not exist.
        """
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Ruby file not found: {path}")
        source_code = path.read_text(encoding="utf-8", errors="replace")
        return self.extract(source_code)

    def extract_from_syscall_log(
        self,
        log_path: str | Path,
        source_code: Optional[str] = None,
    ) -> BehavioralFeatures:
        """Extract behavioral features from a syscall trace log.

        Combines dynamic syscall analysis with optional static analysis
        of the corresponding source code.

        Args:
            log_path: Path to a JSON syscall trace file.
            source_code: Optional source code for static analysis.

        Returns:
            BehavioralFeatures with dynamic and static features.

        Raises:
            FileNotFoundError: If the log file does not exist.
        """
        path = Path(log_path)
        if not path.exists():
            raise FileNotFoundError(f"Syscall log not found: {path}")

        with open(path) as f:
            log_data = json.load(f)

        syscalls = self._parse_syscall_log(log_data)
        features = self._analyze_syscalls(syscalls)

        # Merge static indicators if source code is provided
        if source_code:
            static_features = self.extract(source_code)
            features.file_write_indicator = static_features.file_write_indicator
            features.network_connect_indicator = static_features.network_connect_indicator
            features.process_spawn_indicator = static_features.process_spawn_indicator
            features.privilege_escalation_indicator = static_features.privilege_escalation_indicator
            features.persistence_indicator = static_features.persistence_indicator

        return features

    def _parse_syscall_log(self, log_data: Any) -> list[str]:
        """Parse syscall names from a log data structure.

        Supports both list-of-strings and list-of-dicts formats.

        Args:
            log_data: Parsed JSON log data.

        Returns:
            Ordered list of syscall names.
        """
        syscalls: list[str] = []

        if isinstance(log_data, list):
            for entry in log_data:
                if isinstance(entry, str):
                    syscalls.append(entry)
                elif isinstance(entry, dict):
                    name = entry.get("syscall") or entry.get("name", "")
                    if name:
                        syscalls.append(str(name))

        elif isinstance(log_data, dict):
            entries = log_data.get("syscalls", log_data.get("events", []))
            return self._parse_syscall_log(entries)

        return syscalls

    def _analyze_syscalls(self, syscalls: list[str]) -> BehavioralFeatures:
        """Analyze a sequence of syscalls to extract behavioral features.

        Args:
            syscalls: Ordered list of syscall names.

        Returns:
            BehavioralFeatures with dynamic features populated.
        """
        features = BehavioralFeatures()

        if not syscalls:
            return features

        features.total_syscall_count = len(syscalls)
        counter = Counter(syscalls)
        features.unique_syscall_count = len(counter)
        features.syscall_diversity_ratio = (
            features.unique_syscall_count / features.total_syscall_count
        )

        # Category counts
        for syscall in syscalls:
            category = self._syscall_to_category.get(syscall)
            if category == "file_access":
                features.file_access_syscall_count += 1
            elif category == "network":
                features.network_syscall_count += 1
            elif category == "process":
                features.process_syscall_count += 1
            elif category == "memory":
                features.memory_syscall_count += 1

        # Max frequency
        if counter:
            max_count = counter.most_common(1)[0][1]
            features.max_syscall_frequency = max_count / features.total_syscall_count

        # Syscall entropy
        features.syscall_entropy = self._compute_entropy(counter, len(syscalls))

        # Burst rate: max consecutive identical syscalls / total
        features.syscall_burst_rate = self._compute_burst_rate(syscalls)

        # Suspicious sequences
        features.suspicious_sequence_count = self._count_suspicious_sequences(syscalls)

        return features

    @staticmethod
    def _compute_entropy(counter: Counter, total: int) -> float:
        """Compute Shannon entropy of the syscall distribution.

        Args:
            counter: Syscall frequency counter.
            total: Total number of syscalls.

        Returns:
            Shannon entropy value.
        """
        if total == 0:
            return 0.0

        entropy = 0.0
        for count in counter.values():
            if count > 0:
                p = count / total
                entropy -= p * np.log2(p)

        return float(entropy)

    @staticmethod
    def _compute_burst_rate(syscalls: list[str]) -> float:
        """Compute the maximum burst rate in the syscall sequence.

        A burst is a contiguous run of identical syscalls. The burst
        rate is the length of the longest burst divided by total length.

        Args:
            syscalls: Ordered syscall list.

        Returns:
            Burst rate between 0.0 and 1.0.
        """
        if not syscalls:
            return 0.0

        max_run = 1
        current_run = 1

        for i in range(1, len(syscalls)):
            if syscalls[i] == syscalls[i - 1]:
                current_run += 1
                max_run = max(max_run, current_run)
            else:
                current_run = 1

        return max_run / len(syscalls)

    def _count_suspicious_sequences(self, syscalls: list[str]) -> int:
        """Count occurrences of suspicious syscall pairs.

        Looks for known dangerous syscall pairs that appear in
        order (not necessarily adjacent) within a sliding window.

        Args:
            syscalls: Ordered syscall list.

        Returns:
            Count of suspicious sequence occurrences.
        """
        window_size = 10
        count = 0

        for i in range(len(syscalls)):
            window = syscalls[i : i + window_size]
            for first, second in self.SUSPICIOUS_SEQUENCES:
                if first in window:
                    first_idx = window.index(first)
                    remaining = window[first_idx + 1 :]
                    if second in remaining:
                        count += 1

        return count
